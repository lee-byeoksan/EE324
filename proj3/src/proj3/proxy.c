#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#define SP ' '
#define CR '\r'
#define LF '\n'
#define HT '\t'
#define NIL '\0'

#define LINE_SIZE 2048
#define BUFF_SIZE 4096
#define HOST_SIZE 128
#define PATH_SIZE 1024
#define PORT_SIZE 8
#define STATUS_SIZE 4
#define HEADER_SIZE 128
#define PARSE_BUFF_SIZE 1024
#define STATUS_SIZE 4
#define REASON_SIZE 32

#define DEBUG

/*
 * Client -> Server
 * This can be done by oscillating between read from client write to server.
 * In the read callback we prepare buffer to write to server and write it.
 * If EAGAIN occurs, we make event for write callback.
 * In write callback we consume this buffer.
 * Once we consume this buffer, we register event for reading.
 *
 * Server -> Client
 * This is same as client->server except that direction is opposite.
 */

enum http_state {
    st_start,

    /* request start-line */
    st_method,
    st_uri,

    /* response status-line */
    st_status,
    st_reason,

    /* common */
    st_version,
    st_line_end,

    /* header */
    st_field,
    st_before_value,
    st_value,
    st_value_cr,
    st_field_cr,

    st_body,
    st_done,
};

enum uri_state {
    uri_host,
    uri_port,
    uri_path,
};

/*
 * Make sure that at most one event should be registered about
 * a context.
 * Do not make any persist events.
 */
struct context {
    /* event */
    struct event_base *base;

    /* common data */
    uint8_t parse_buff[PARSE_BUFF_SIZE];
    size_t parse_buff_len;
    bool skip_header;
    bool is_content_length;

    /* client data */
    evutil_socket_t csock;
    struct sockaddr_storage caddr;
    socklen_t caddrlen;
    enum http_state cstate;
    const uint8_t *cwrite_ptr;
    uint8_t cbuff[BUFF_SIZE];
    uint8_t host[HOST_SIZE];
    uint8_t path[PATH_SIZE];
    uint8_t port[PORT_SIZE];
    size_t cbuff_len;
    size_t cwrite_len;
    size_t host_len;
    size_t path_len;
    size_t port_len;
    uint32_t ccontent_len;

    /* server data */
    evutil_socket_t ssock;
    struct sockaddr_storage saddr;
    socklen_t saddrlen;
    enum http_state sstate;
    const uint8_t *swrite_ptr;
    uint8_t sbuff[BUFF_SIZE];
    uint8_t status[STATUS_SIZE];
    uint8_t reason[REASON_SIZE];
    size_t sbuff_len;
    size_t swrite_len;
    size_t status_len;
    size_t reason_len;
    uint32_t scontent_len;
};

static evutil_socket_t create_listen_sock(const char *service);
static void accept_callback(struct evconnlistener *listener,
                            evutil_socket_t sock,
                            struct sockaddr *addr,
                            int len, void *ptr);
static void cread_callback(evutil_socket_t sock, short what, void *arg);
static void cwrite_callback(evutil_socket_t sock, short what, void *arg);
static void sread_callback(evutil_socket_t sock, short what, void *arg);
static void swrite_callback(evutil_socket_t sock, short what, void *arg);
static void parse_uri(struct context *ctx, const uint8_t *uri, const size_t len);
static void copy_path_to_cbuff(struct context *ctx);
static bool is_valid_version(const uint8_t *version, const size_t len);
static bool skippable_header(const uint8_t *header, const size_t len);
static bool is_content_length_header(const uint8_t *header, const size_t len);
static void internal_error(struct context *ctx);
static void bad_request(struct context *ctx);
static void bad_response(struct context *ctx);
static void not_found(struct context *ctx);
static void add_host_header(struct context *ctx);
static void add_connection_header(struct context *ctx);
static void connect_to_server(struct context *ctx);
static void register_client_read_event(struct context *ctx);
static void register_client_write_event(struct context *ctx);
static void register_server_read_event(struct context *ctx);
static void register_server_write_event(struct context *ctx);
static void write_to_server(struct context *ctx);
static void write_to_client(struct context *ctx);
static void context_init(struct context *ctx);
static void context_destroy(struct context *ctx);
static void add_to_parse_buff(struct context *ctx, const uint8_t *ptr, const size_t len);
static void clear_parse_buff(struct context *ctx);

int
main(int argc, char *argv[])
{
    const char *port;
    long port_number;
    struct event_base *base;
    evutil_socket_t listen_sock;
    struct evconnlistener *listener;
    struct sigaction sa;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    port = argv[1];
    port_number = strtol(port, NULL, 10);
    if (port_number < 1024 || port_number > 65535) {
        fprintf(stderr, "Port number should be between 1024 and 65535\n");
        exit(EXIT_FAILURE);
    }

    /* Signal masking */
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGPIPE, &sa, NULL);

    listen_sock = create_listen_sock(port);
    if (listen_sock == -1) {
        fprintf(stderr, "cannot create listen socket\n");
        exit(EXIT_FAILURE);
    }
    evutil_make_socket_nonblocking(listen_sock);

    base = event_base_new();
    listener = evconnlistener_new(base, accept_callback, NULL,
                                  LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                  -1, listen_sock);
    event_base_dispatch(base);
    exit(EXIT_SUCCESS);
}

static evutil_socket_t
create_listen_sock(const char *service)
{
    struct addrinfo hint, *res, *aip;
    evutil_socket_t sock;
    int s;

    bzero(&hint, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    if(getaddrinfo(NULL, service, &hint, &res)) {
        return -1;
    }

    for (aip = res; aip != NULL; aip = aip->ai_next) {
        sock = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
        if (sock == -1) {
            continue;
        }

        if (!bind(sock, aip->ai_addr, aip->ai_addrlen)) {
            break;
        }

        close(sock);
    }

    freeaddrinfo(res);

    if (aip == NULL) {
        return -1;
    }

    return sock;
}

static void
accept_callback(struct evconnlistener *listener, evutil_socket_t sock,
                struct sockaddr *addr, int len, void *ptr)
{
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    struct event_base *base = evconnlistener_get_base(listener);
    struct context *ctx = (struct context *)malloc(sizeof(*ctx));

    if (ctx == NULL) {
        if (getnameinfo(addr, len, host, sizeof(host), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV)) {
            fprintf(stderr, "cannot create connection context for unknown client.\n");
        } else {
            fprintf(stderr, "cannot create connection context for %s:%s\n", host, service);
        }
        close(sock);
        return;
    }

#ifdef DEBUG
    if (getnameinfo(addr, len, host, sizeof(host), service, sizeof(service), NI_NUMERICHOST | NI_NUMERICSERV)) {
        fprintf(stderr, "connection from unknown client.\n");
    } else {
        fprintf(stderr, "connection from %s:%s\n", host, service);
    }
#endif

    context_init(ctx);
    ctx->base = base;
    ctx->csock = sock;
    memcpy(&ctx->caddr, addr, len);
    ctx->caddrlen = len;
    register_client_read_event(ctx);
}

static void
cread_callback(evutil_socket_t sock, short what, void *arg)
{
    ssize_t n;
    uint8_t *ch;
    uint8_t line[LINE_SIZE];
    struct context *ctx = (struct context *)arg;

    assert(sock == ctx->csock);
    assert((what & EV_READ) && !(what & EV_WRITE));

    n = recv(sock, line, LINE_SIZE, 0);
    if (n == -1) {
        /* internal error */
        internal_error(ctx);
        return;
    }

    /* state machine */
    /* ctx->cbuff will contain content to send to server. */
    ctx->cbuff_len = 0;
    for (ch = line; ch < line+n; ch++) {
reparse:
        switch (ctx->cstate) {
        case st_start:
            if (*ch == SP || *ch == HT) {
                /* skip */
            } else if (*ch == CR || *ch == LF) {
                /* bad request */
                bad_request(ctx);
                return;
            } else {
                /* not that strict */
                ctx->cstate = st_method;
                goto reparse;
            }
            break;

        case st_method:
            if (*ch == SP) {
                ctx->cstate = st_uri;
            } else if (*ch == CR || *ch == LF) {
                /* bad request */
                bad_request(ctx);
                return;
            } else {
                ctx->cbuff[ctx->cbuff_len++] = *ch;
            }
            break;

        case st_uri:
            if (*ch == SP) {
                parse_uri(ctx, ctx->parse_buff, ctx->parse_buff_len);
                if (ctx->host[0] == NIL) {
                    /* bad request */
                    bad_request(ctx);
                    return;
                } else {
                    ctx->cbuff[ctx->cbuff_len++] = SP;
                    copy_path_to_cbuff(ctx);
                }
                clear_parse_buff(ctx);
                ctx->cstate = st_version;
            } else if (*ch == CR || *ch == LF) {
                /* bad request */
                bad_request(ctx);
                return;
            } else {
                add_to_parse_buff(ctx, ch, 1);
            }
            break;

        case st_version:
            if (*ch == SP) {
                /* bad request */
                bad_request(ctx);
                return;
            } else if (*ch == CR || *ch == LF) {
                if (is_valid_version(ctx->parse_buff, ctx->parse_buff_len)) {
                    ctx->cbuff[ctx->cbuff_len++] = SP;
                    memcpy(ctx->cbuff+ctx->cbuff_len, "HTTP/1.0\r\n", sizeof("HTTP/1.0\r\n")-1);
                    ctx->cbuff_len += sizeof("HTTP/1.0\r\n")-1;
                } else {
                    /* bad request */
                    bad_request(ctx);
                    return;
                }

                clear_parse_buff(ctx);
                if (*ch == CR) {
                    ctx->cstate = st_line_end;
                } else {
                    ctx->cstate = st_field;
                }
            } else {
                add_to_parse_buff(ctx, ch, 1);
            }
            break;

        case st_line_end:
            if (*ch == LF) {
                ctx->cstate = st_field;
            } else {
                /* bad request */
                bad_request(ctx);
                return;
            }
            break;

        case st_field:
            if (*ch == CR) {
                ctx->cstate = st_field_cr;
            } else if (*ch == LF) {
                add_host_header(ctx);
                add_connection_header(ctx);
                memcpy(ctx->cbuff+ctx->cbuff_len, "\r\n", sizeof("\r\n ")-1);
                ctx->cbuff_len += sizeof("\r\n")-1;
                if (ctx->ccontent_len == 0) {
                    ctx->cstate = st_done;
                } else {
                    ctx->cstate = st_body;
                }
            } else if (*ch == SP || *ch == HT) {
                ctx->cstate = st_value;
            } else if (*ch == ':') {
                ctx->skip_header = skippable_header(ctx->parse_buff, ctx->parse_buff_len);
                ctx->is_content_length = is_content_length_header(ctx->parse_buff, ctx->parse_buff_len);
                if (!ctx->skip_header) {
                    memcpy(ctx->cbuff+ctx->cbuff_len, ctx->parse_buff, ctx->parse_buff_len);
                    ctx->cbuff_len += ctx->parse_buff_len;
                    memcpy(ctx->cbuff+ctx->cbuff_len, ": ", sizeof(": ")-1);
                    ctx->cbuff_len += sizeof(": ")-1;
                }

                if (ctx->is_content_length) {
                    ctx->ccontent_len = 0;
                }

                clear_parse_buff(ctx);
                ctx->cstate = st_before_value;
            } else {
                add_to_parse_buff(ctx, ch, 1);
            }
            break;

        case st_before_value:
            if (*ch == SP || *ch == HT) {
                /* skip */
            } else {
                ctx->cstate = st_value;
                goto reparse;
            }
            break;

        case st_value:
            if (*ch == CR) {
                ctx->cstate = st_value_cr;
            } else if (*ch == LF) {
                ctx->cstate = st_field;
            } else {
                if (!ctx->skip_header) {
                    ctx->cbuff[ctx->cbuff_len++] = *ch;
                }

                if (ctx->is_content_length) {
                    ctx->ccontent_len *= 10;
                    ctx->ccontent_len += *ch - '0';
                }
            }
            break;

        case st_value_cr:
            if (*ch == LF) {
                ctx->cstate = st_field;
            } else {
                /* bad request */
                bad_request(ctx);
                return;
            }
            break;

        case st_field_cr:
            if (*ch == LF) {
                add_host_header(ctx);
                add_connection_header(ctx);
                memcpy(ctx->cbuff+ctx->cbuff_len, "\r\n", sizeof("\r\n ")-1);
                ctx->cbuff_len += sizeof("\r\n")-1;
                if (ctx->ccontent_len == 0) {
                    ctx->cstate = st_done;
                } else {
                    ctx->cstate = st_body;
                }
            } else {
                /* bad request */
                bad_request(ctx);
                return;
            }
            break;

        case st_body:
            ctx->cbuff[ctx->cbuff_len++] = *ch;
            ctx->ccontent_len--;
            if (ctx->ccontent_len == 0) {
                ctx->cstate = st_done;
            }
            break;

        case st_done:
            goto done;
        }
    }

done:
    /* If we can connect to server, connect */
    if (ctx->ssock == -1 && ctx->host[0] != NIL) {
        connect_to_server(ctx);
        if (ctx->ssock == -1) {
            not_found(ctx);
            return;
        }
    }

    /* it's time to write */
    ctx->swrite_ptr = ctx->cbuff;
    ctx->swrite_len = ctx->cbuff_len;
    write_to_server(ctx);
}

static void
cwrite_callback(evutil_socket_t sock, short what, void *arg)
{
    write_to_client((struct context *)arg);
}

static void
sread_callback(evutil_socket_t sock, short what, void *arg)
{
    ssize_t n;
    uint8_t *ch;
    uint8_t line[LINE_SIZE];
    struct context *ctx = (struct context *)arg;

    assert(sock == ctx->ssock);
    assert((what & EV_READ) && !(what & EV_WRITE));

    n = recv(sock, line, LINE_SIZE, 0);
    if (n == -1) {
        /* internal error */
        internal_error(ctx);
        return;
    }

    /* update the state */
    ctx->sbuff_len = 0;
    for (ch = line; ch < line+n; ch++) {
reparse:
        switch (ctx->sstate) {
        case st_start:
            if (*ch == SP || *ch == HT) {
                /* skip */
            } else if (*ch == CR || *ch == LF) {
                /* bad response */
                bad_response(ctx);
                return;
            } else {
                /* not that strict */
                ctx->sstate = st_version;
                goto reparse;
            }
            break;

        case st_version:
            if (*ch == CR || *ch == LF) {
                /* bad response */
                bad_response(ctx);
                return;
            } else if (*ch == SP) {
                if (is_valid_version(ctx->parse_buff, ctx->parse_buff_len)) {
                    memcpy(ctx->sbuff+ctx->sbuff_len, "HTTP/1.0", sizeof("HTTP/1.0")-1);
                    ctx->sbuff_len += sizeof("HTTP/1.0")-1;
                } else {
                    /* bad response */
                    bad_response(ctx);
                    return;
                }

                clear_parse_buff(ctx);
                ctx->sstate = st_status;
            } else {
                add_to_parse_buff(ctx, ch, 1);
            }
            break;

        case st_status:
            if (*ch == SP || *ch == HT) {
                ctx->sstate = st_reason;
            } else if (*ch == CR || *ch == LF) {
                /* bad response */
                bad_response(ctx);
            } else {
                /* TODO: should we check if it is number? */
                ctx->status[ctx->status_len++] = *ch;
                ctx->sbuff[ctx->sbuff_len++] = *ch;
            }
            break;

        case st_reason:
            if (*ch == CR) {
                ctx->sstate = st_line_end;
            } else if (*ch == LF) {
                ctx->sstate = st_field;
            } else {
                ctx->reason[ctx->reason_len++] = *ch;
                ctx->sbuff[ctx->sbuff_len++] = *ch;
            }
            break;

        case st_line_end:
            if (*ch == LF) {
                ctx->sstate = st_field;
            } else {
                /* bad response */
                bad_response(ctx);
                return;
            }
            break;

        case st_field:
            if (*ch == CR) {
                ctx->sstate = st_field_cr;
            } else if (*ch == LF) {
                memcpy(ctx->sbuff+ctx->sbuff_len, "\r\n", sizeof("\r\n ")-1);
                ctx->sbuff_len += sizeof("\r\n")-1;
                if (ctx->scontent_len == 0) {
                    ctx->sstate = st_done;
                } else {
                    ctx->sstate = st_body;
                }
            } else if (*ch == SP || *ch == HT) {
                ctx->sbuff[ctx->sbuff_len++] = ',';
                ctx->sstate = st_before_value;
            } else if (*ch == ':') {
                ctx->is_content_length = is_content_length_header(ctx->parse_buff, ctx->parse_buff_len);
                memcpy(ctx->sbuff+ctx->sbuff_len, ctx->parse_buff, ctx->parse_buff_len);
                ctx->sbuff_len += ctx->parse_buff_len;
                memcpy(ctx->sbuff+ctx->sbuff_len, ": ", sizeof(": ")-1);
                ctx->sbuff_len += sizeof(": ")-1;

                if (ctx->is_content_length) {
                    ctx->scontent_len = 0;
                }

                clear_parse_buff(ctx);
                ctx->sstate = st_before_value;
            } else {
                add_to_parse_buff(ctx, ch, 1);
            }
            break;

        case st_before_value:
            if (*ch == SP || *ch == HT) {
                /* skip */
            } else {
                ctx->sstate = st_value;
                goto reparse;
            }
            break;

        case st_value:
            if (*ch == CR) {
                ctx->sstate = st_value_cr;
            } else if (*ch == LF) {
                memcpy(ctx->sbuff+ctx->sbuff_len, "\r\n", sizeof("\r\n ")-1);
                ctx->sbuff_len += sizeof("\r\n")-1;
                ctx->sstate = st_field;
            } else {
                if (!ctx->skip_header) {
                    ctx->sbuff[ctx->sbuff_len++] = *ch;
                }

                if (ctx->is_content_length) {
                    ctx->scontent_len *= 10;
                    ctx->scontent_len += *ch - '0';
                }
            }
            break;

        case st_value_cr:
            if (*ch == LF) {
                memcpy(ctx->sbuff+ctx->sbuff_len, "\r\n", sizeof("\r\n ")-1);
                ctx->sbuff_len += sizeof("\r\n")-1;
                ctx->sstate = st_field;
            } else {
                /* bad response */
                bad_response(ctx);
                return;
            }
            break;

        case st_field_cr:
            if (*ch == LF) {
                memcpy(ctx->sbuff+ctx->sbuff_len, "\r\n", sizeof("\r\n ")-1);
                ctx->sbuff_len += sizeof("\r\n")-1;
                if (ctx->scontent_len == 0) {
                    ctx->sstate = st_done;
                } else {
                    ctx->sstate = st_body;
                }
            } else {
                /* bad response */
                bad_response(ctx);
                return;
            }
            break;

        case st_body:
            ctx->sbuff[ctx->sbuff_len++] = *ch;
            ctx->scontent_len--;
            if (ctx->scontent_len == 0) {
                ctx->sstate = st_done;
            }
            break;

        case st_done:
            goto done;
        }
    }
done:

    /* just forward it */
    ctx->cwrite_ptr = ctx->sbuff;
    ctx->cwrite_len = ctx->sbuff_len;
    write_to_client(ctx);
}

static void
swrite_callback(evutil_socket_t sock, short what, void *arg)
{
    struct context *ctx = (struct context *)arg;
    write_to_server(ctx);
}

static void
parse_uri(struct context *ctx, const uint8_t *uri, const size_t len)
{
    const uint8_t *ch;
    ctx->host[0] = NIL;
    ctx->port[0] = NIL;
    ctx->path[0] = NIL;

    if (strncmp(uri, "http://", sizeof("http://")-1)) {
        /* invalid uri */
        return;
    }

    size_t host_len = 0;
    size_t port_len = 0;
    size_t path_len = 0;
    enum uri_state state = uri_host;
    for (ch = uri+7; ch < uri+len; ch++) {
        switch (state) {
        case uri_host:
            if (*ch == ':') {
                if (ctx->host[0] == NIL) {
                    goto invalid;
                }
                state = uri_port;
            } else if (*ch == '/') {
                if (ctx->host[0] == NIL) {
                    goto invalid;
                }
                ctx->path[path_len++] = '/';
                state = uri_path;
            } else {
                ctx->host[host_len++] = *ch;
            }
            break;

        case uri_port:
            if (*ch == '/') {
                if (ctx->port[0] == NIL) {
                    goto invalid;
                }
                ctx->path[path_len++] = '/';
                state = uri_path;
            } else if ('0' <= *ch && *ch <= '9') {
                ctx->port[port_len++] = *ch;
            } else {
                goto invalid;
            }
            break;

        case uri_path:
            ctx->path[path_len++] = *ch;
            break;
        }
    }

    ctx->host[host_len++] = NIL;
    ctx->port[port_len++] = NIL;
    ctx->path[path_len++] = NIL;

    if (ctx->host[0] == NIL) {
        goto invalid;
    }

    if (ctx->port[0] == NIL) {
        strcpy(ctx->port, "80");
    }

    if (ctx->path[0] == NIL) {
        strcpy(ctx->path, "/");
    }
    return;

invalid:
    ctx->host[0] = NIL;
    ctx->port[0] = NIL;
    ctx->path[0] = NIL;
}

static void
copy_path_to_cbuff(struct context *ctx)
{
    int i;
    size_t path_len = strlen(ctx->path);
    for (i = 0; i < path_len; i++) {
        ctx->cbuff[ctx->cbuff_len++] = ctx->path[i];
    }
}

static bool
is_valid_version(const uint8_t *version, const size_t len)
{
    if (!strncasecmp(version, "HTTP/1.0", len) ||
        !strncasecmp(version, "HTTP/1.1", len)) {
        return true;
    }

    return false;
}

static bool
skippable_header(const uint8_t *header, const size_t len)
{
    if (header[0] == NIL) {
        return true;
    }

    if (!strncasecmp(header, "Connection", len) ||
        !strncasecmp(header, "Keep-alive", len) ||
        !strncasecmp(header, "Host", len)) {
        return true;
    }

    return false;
}

static bool
is_content_length_header(const uint8_t *header, const size_t len)
{
    if (!strncasecmp(header, "Content-Length", len)) {
        return true;
    }

    return false;
}

static void
internal_error(struct context *ctx)
{
    static const int8_t internal_error_msg[] = "HTTP/1.0 500 Internal Error\r\n\r\n";
    static const size_t internal_error_msg_len = sizeof(internal_error_msg)-1;

    fprintf(stderr, "internal error\n");
    if (ctx->ssock != -1) {
        close(ctx->ssock);
    }
    ctx->cwrite_ptr = internal_error_msg;
    ctx->cwrite_len = internal_error_msg_len;
    register_client_write_event(ctx);
}

static void
bad_request(struct context *ctx)
{
    static const int8_t bad_request_error_msg[] = "HTTP/1.0 400 Bad Request\r\n\r\n";
    static const size_t bad_request_error_msg_len = sizeof(bad_request_error_msg)-1;

    fprintf(stderr, "bad request\n");
    if (ctx->ssock != -1) {
        close(ctx->ssock);
    }
    ctx->cwrite_ptr = bad_request_error_msg;
    ctx->cwrite_len = bad_request_error_msg_len;
    register_client_write_event(ctx);
}

static void
bad_response(struct context *ctx)
{
    /* TODO: ??? */
    fprintf(stderr, "bad response\n");
}

static void
not_found(struct context *ctx)
{
    static const int8_t not_found_error_msg[] = "HTTP/1.0 404 Not Found\r\n\r\n";
    static const size_t not_found_error_msg_len = sizeof(not_found_error_msg)-1;

    fprintf(stderr, "server not found\n");
    if (ctx->ssock != -1) {
        close(ctx->ssock);
    }

    ctx->cwrite_ptr = not_found_error_msg;
    ctx->cwrite_len = not_found_error_msg_len;
    register_client_write_event(ctx);
}

static void
add_host_header(struct context *ctx)
{
    size_t hostlen = strlen(ctx->host);
    memcpy(ctx->cbuff+ctx->cbuff_len, "Host: ", sizeof("Host: ")-1);
    ctx->cbuff_len += sizeof("Host: ")-1;
    memcpy(ctx->cbuff+ctx->cbuff_len, ctx->host, hostlen);
    ctx->cbuff_len += hostlen;
    memcpy(ctx->cbuff+ctx->cbuff_len, "\r\n", sizeof("\r\n ")-1);
    ctx->cbuff_len += sizeof("\r\n")-1;
}

static void
add_connection_header(struct context *ctx)
{
    memcpy(ctx->cbuff+ctx->cbuff_len, "Connection: close\r\n", sizeof("Connection: close\r\n")-1);
    ctx->cbuff_len += sizeof("Connection: close\r\n")-1;
}

static void
connect_to_server(struct context *ctx)
{
    struct addrinfo hint, *res, *aip;
    evutil_socket_t sock;
    int s;

    bzero(&hint, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_NUMERICSERV;

    if(getaddrinfo(ctx->host, ctx->port, &hint, &res)) {
        return;
    }

    for (aip = res; aip != NULL; aip = aip->ai_next) {
        sock = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
        if (sock == -1) {
            continue;
        }

        s = connect(sock, aip->ai_addr, aip->ai_addrlen);
        if (!s) {
            break;
        }

        close(sock);
    }

    if (aip != NULL) {
        /* initialize server context */
        ctx->ssock = sock;
        memcpy(&ctx->saddr, aip->ai_addr, aip->ai_addrlen);
        ctx->saddrlen = aip->ai_addrlen;

        evutil_make_socket_nonblocking(ctx->ssock);
    }

    freeaddrinfo(res);
}

static void
register_client_read_event(struct context *ctx)
{
    struct event *ev = event_new(ctx->base, ctx->csock, EV_READ, cread_callback, ctx);
    event_add(ev, NULL);
}

static void
register_client_write_event(struct context *ctx)
{
    struct event *ev = event_new(ctx->base, ctx->csock, EV_WRITE, cwrite_callback, ctx);
    event_add(ev, NULL);
}

static void
register_server_read_event(struct context *ctx)
{
    struct event *ev = event_new(ctx->base, ctx->ssock, EV_READ, sread_callback, ctx);
    event_add(ev, NULL);
}

static void
register_server_write_event(struct context *ctx)
{
    struct event *ev = event_new(ctx->base, ctx->ssock, EV_WRITE, swrite_callback, ctx);
    event_add(ev, NULL);
}

static void
write_to_server(struct context *ctx)
{
    ssize_t n;
    while (ctx->swrite_len > 0) {
        n = send(ctx->ssock, ctx->swrite_ptr, ctx->swrite_len, 0);
        if (n == -1) {
            if (errno = EAGAIN) {
                /* register write event */
                register_server_write_event(ctx);
                return;
            } else {
                /* internal error */
                internal_error(ctx);
                return;
            }
        }

        ctx->swrite_ptr += n;
        ctx->swrite_len -= n;
    }

    if (ctx->cstate != st_done) {
        register_client_read_event(ctx);
    } else {
        register_server_read_event(ctx);
    }
}

static void
write_to_client(struct context *ctx)
{
    ssize_t n;
    while (ctx->cwrite_len > 0) {
        n = send(ctx->csock, ctx->cwrite_ptr, ctx->cwrite_len, 0);
        if (n == -1) {
            if (errno = EAGAIN) {
                /* register write event */
                register_client_write_event(ctx);
                return;
            } else {
                /* internal error */
                return;
            }
        }

        ctx->cwrite_ptr += n;
        ctx->cwrite_len -= n;
    }

    if (ctx->ssock == -1) {
        /* this is write for error handling */
        /* we are done */
        context_destroy(ctx);
        return;
    }

    if (ctx->sstate != st_done) {
        register_server_read_event(ctx);
    } else {
        context_destroy(ctx);
    }
}

static void
context_init(struct context *ctx)
{
    /* event */
    ctx->base = NULL;

    /* common */
    ctx->parse_buff_len = 0;
    ctx->skip_header = false;
    ctx->is_content_length = false;

    /* client */
    ctx->csock = -1;
    ctx->caddrlen = 0;
    ctx->cstate = st_start;
    ctx->cwrite_ptr = NULL;
    ctx->cbuff_len = 0;
    ctx->cwrite_len = 0;
    ctx->host[0] = NIL;
    ctx->port[0] = NIL;
    ctx->path[0] = NIL;
    ctx->host_len = 0;
    ctx->path_len = 0;
    ctx->port_len = 0;
    ctx->ccontent_len = 0;

    /* server */
    ctx->ssock = -1;
    ctx->saddrlen = 0;
    ctx->sstate = st_start;
    ctx->sbuff_len = 0;
    ctx->swrite_len = 0;
    ctx->status[0] = NIL;
    ctx->reason[0] = NIL;
    ctx->status_len = 0;
    ctx->reason_len = 0;
    ctx->scontent_len = 0;
}

static void
context_destroy(struct context *ctx)
{
    fprintf(stderr, "context destroyed\n");
    if (ctx->csock != -1) {
        close(ctx->csock);
    }

    if (ctx->ssock != -1) {
        close(ctx->ssock);
    }

    free(ctx);
}

static void
add_to_parse_buff(struct context *ctx, const uint8_t *ptr, const size_t len)
{
    memcpy(ctx->parse_buff + ctx->parse_buff_len, ptr, len);
    ctx->parse_buff_len += len;
}

static void
clear_parse_buff(struct context *ctx)
{
    ctx->parse_buff_len = 0;
}
