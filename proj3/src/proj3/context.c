#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <event2/event.h>

#include "context.h"
#include "defs.h"

#define LINE_SIZE 2048
#define BUFFER_SIZE 8192
#define PBUFFER_SIZE 4096
#define HOST_SIZE 128
#define PATH_SIZE 1024
#define PORT_SIZE 8
#define FIELD_SIZE 128
#define VALUE_SIZE 4096
#define STATUS_SIZE 4
#define REASON_SIZE 32

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
    /* ending */
    st_body,
    st_done,
};

enum uri_state {
    uri_host,
    uri_port,
    uri_path,
};

struct context {
    /* event */
    struct event_base *base;

    /* common data */
    uint8_t pbuffer[PBUFFER_SIZE];
    size_t pbuffer_len;
    bool skip_header;
    bool is_content_length;
    uint8_t buffer[BUFFER_SIZE];
    size_t buffer_len;

    /* Temporary Header */
    uint8_t field[FIELD_SIZE];
    uint8_t value[VALUE_SIZE];
    size_t field_len;
    size_t value_len;

    /* client data */
    evutil_socket_t csock;
    struct sockaddr_storage caddr;
    socklen_t caddrlen;
    enum http_state cstate;
    const uint8_t *cwrite_ptr;
    uint8_t host[HOST_SIZE];
    uint8_t path[PATH_SIZE];
    uint8_t port[PORT_SIZE];
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
    size_t swrite_len;
    uint32_t scontent_len;
};

static void context_init(struct context *ctx);
static void register_client_read_event(struct context *ctx);
static void register_client_write_event(struct context *ctx);
static void register_server_read_event(struct context *ctx);
static void register_server_write_event(struct context *ctx);

/***********************
 * Callbacks           *
 ***********************/
static void cread_callback(evutil_socket_t sock, short what, void *arg);
static void cwrite_callback(evutil_socket_t sock, short what, void *arg);
static void sread_callback(evutil_socket_t sock, short what, void *arg);
static void swrite_callback(evutil_socket_t sock, short what, void *arg);

/***********************
 * Utils               *
 ***********************/
static bool is_content_length_header(const uint8_t *header, const size_t len);
static bool is_valid_version(const uint8_t *version, const size_t len);
static bool skippable_header(const uint8_t *header, const size_t len);
static void add_connection_header(struct context *ctx);
static void add_host_header(struct context *ctx);
static void add_to_pbuffer(struct context *ctx, const uint8_t *ptr, const size_t len);
static void bad_request(struct context *ctx);
static void bad_response(struct context *ctx);
static void clear_pbuffer(struct context *ctx);
static void connect_to_server(struct context *ctx);
static void copy_path_to_buffer(struct context *ctx);
static void internal_error(struct context *ctx);
static void not_found(struct context *ctx);
static void parse_uri(struct context *ctx, const uint8_t *uri, const size_t len);
static void write_to_client(struct context *ctx);
static void write_to_server(struct context *ctx);
static void append_pbuffer_to_buffer(struct context *ctx);
static void pbuffer_to_field(struct context *ctx);
static void pbuffer_to_value(struct context *ctx);

struct context *
context_new()
{
    struct context *ctx = (struct context *)malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    context_init(ctx);
    return ctx;
}

void
context_destroy(struct context *ctx)
{
    if (ctx->csock != -1) {
        close(ctx->csock);
    }

    if (ctx->ssock != -1) {
        close(ctx->ssock);
    }

    free(ctx);
}

void
context_set_base(struct context *ctx, struct event_base *base)
{
    ctx->base = base;
}

void
context_set_client(struct context *ctx, evutil_socket_t sock, struct sockaddr *addr, socklen_t addrlen)
{
    ctx->csock = sock;
    ctx->caddrlen = addrlen;
    memcpy(&ctx->caddr, addr, addrlen);
}

void
context_start_process(struct context *ctx)
{
    register_client_read_event(ctx);
}

static void
context_init(struct context *ctx)
{
    /* event */
    ctx->base = NULL;

    /* common */
    ctx->pbuffer_len = 0;
    ctx->skip_header = false;
    ctx->is_content_length = false;
    ctx->buffer_len = 0;

    ctx->field_len = 0;
    ctx->value_len = 0;

    /* client */
    ctx->csock = -1;
    ctx->caddrlen = 0;
    ctx->cstate = st_start;
    ctx->cwrite_ptr = NULL;
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
    ctx->swrite_len = 0;
    ctx->scontent_len = UINT32_MAX;
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
    /* ctx->buffer will contain content to send to server. */
    ctx->buffer_len = 0;
    for (ch = line; ch < line+n; ch++) {
again:
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
                goto again;
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
                ctx->buffer[ctx->buffer_len++] = *ch;
            }
            break;

        case st_uri:
            if (*ch == SP) {
                parse_uri(ctx, ctx->pbuffer, ctx->pbuffer_len);
                if (ctx->host[0] == NIL) {
                    /* bad request */
                    bad_request(ctx);
                    return;
                } else {
                    ctx->buffer[ctx->buffer_len++] = SP;
                    copy_path_to_buffer(ctx);
                }
                clear_pbuffer(ctx);
                ctx->cstate = st_version;
            } else if (*ch == CR || *ch == LF) {
                /* bad request */
                bad_request(ctx);
                return;
            } else {
                add_to_pbuffer(ctx, ch, 1);
            }
            break;

        case st_version:
            if (*ch == SP) {
                /* bad request */
                bad_request(ctx);
                return;
            } else if (*ch == CR || *ch == LF) {
                if (is_valid_version(ctx->pbuffer, ctx->pbuffer_len)) {
                    ctx->buffer[ctx->buffer_len++] = SP;
                    memcpy(ctx->buffer+ctx->buffer_len, "HTTP/1.0\r\n", sizeof("HTTP/1.0\r\n")-1);
                    ctx->buffer_len += sizeof("HTTP/1.0\r\n")-1;
                } else {
                    /* bad request */
                    bad_request(ctx);
                    return;
                }

                clear_pbuffer(ctx);
                if (*ch == CR) {
                    ctx->cstate = st_line_end;
                } else {
                    ctx->cstate = st_field;
                }
            } else {
                add_to_pbuffer(ctx, ch, 1);
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
            if (*ch == CR || *ch == LF) {
                add_host_header(ctx);
                add_connection_header(ctx);
                ctx->buffer[ctx->buffer_len++] = CR;
                if (*ch == LF) {
                    ctx->buffer[ctx->buffer_len++] = LF;
                }

                clear_pbuffer(ctx);
                if (*ch == CR) {
                    ctx->cstate = st_field_cr;
                } else if (ctx->ccontent_len == 0) {
                    ctx->cstate = st_done;
                } else {
                    ctx->cstate = st_body;
                }
            } else if (*ch == ':') {
                pbuffer_to_field(ctx);
                ctx->skip_header = skippable_header(ctx->field, ctx->field_len);
                ctx->is_content_length = is_content_length_header(ctx->field, ctx->field_len);

                if (!ctx->skip_header) {
                    append_pbuffer_to_buffer(ctx);
                    ctx->buffer[ctx->buffer_len++] = ':';
                    ctx->buffer[ctx->buffer_len++] = SP;
                }

                if (ctx->is_content_length) {
                    ctx->ccontent_len = 0;
                }

                clear_pbuffer(ctx);
                ctx->cstate = st_before_value;
            } else {
                add_to_pbuffer(ctx, ch, 1);
            }
            break;

        case st_before_value:
            if (*ch == SP || *ch == HT) {
                /* skip */
            } else {
                ctx->cstate = st_value;
                goto again;
            }
            break;

        case st_value:
            if (*ch == CR) {
                if (!ctx->skip_header) {
                    pbuffer_to_value(ctx);
                    append_pbuffer_to_buffer(ctx);
                    ctx->buffer[ctx->buffer_len++] = CR;
                }
                clear_pbuffer(ctx);
                ctx->cstate = st_value_cr;
            } else if (*ch == LF) {
                if (!ctx->skip_header) {
                    pbuffer_to_value(ctx);
                    append_pbuffer_to_buffer(ctx);
                    ctx->buffer[ctx->buffer_len++] = CR;
                    ctx->buffer[ctx->buffer_len++] = LF;
                }
                clear_pbuffer(ctx);
                ctx->cstate = st_field;
            } else {
                if (!ctx->skip_header) {
                    add_to_pbuffer(ctx, ch, 1);
                }

                if (ctx->is_content_length) {
                    ctx->ccontent_len *= 10;
                    ctx->ccontent_len += *ch - '0';
                }
            }
            break;

        case st_value_cr:
            if (*ch == LF) {
                if (!ctx->skip_header) {
                    ctx->buffer[ctx->buffer_len++] = LF;
                }
                ctx->cstate = st_field;
            } else {
                /* bad request */
                bad_request(ctx);
                return;
            }
            break;

        case st_field_cr:
            if (*ch == LF) {
                ctx->buffer[ctx->buffer_len++] = LF;
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
            ctx->buffer[ctx->buffer_len++] = *ch;
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
    ctx->swrite_ptr = ctx->buffer;
    ctx->swrite_len = ctx->buffer_len;
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

    n = recv(sock, line, LINE_SIZE-1, 0);
    if (n == -1) {
        /* internal error */
        internal_error(ctx);
        return;
    }

    /* update the state */
    ctx->buffer_len = 0;
    for (ch = line; ch < line+n; ch++) {
again:
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
                goto again;
            }
            break;

        case st_version:
            if (*ch == CR || *ch == LF) {
                /* bad response */
                bad_response(ctx);
                return;
            } else if (*ch == SP) {
                if (!is_valid_version(ctx->pbuffer, ctx->pbuffer_len)) {
                    /* bad response */
                    bad_response(ctx);
                    return;
                }

                append_pbuffer_to_buffer(ctx);
                clear_pbuffer(ctx);
                ctx->buffer[ctx->buffer_len++] = SP;
                ctx->sstate = st_status;
            } else {
                add_to_pbuffer(ctx, ch, 1);
            }
            break;

        case st_status:
            if (*ch == SP || *ch == HT) {
                append_pbuffer_to_buffer(ctx);
                clear_pbuffer(ctx);
                ctx->buffer[ctx->buffer_len++] = SP;
                ctx->sstate = st_reason;
            } else if (*ch == CR || *ch == LF) {
                /* bad response */
                bad_response(ctx);
            } else {
                /* TODO: should we check if it is number? */
                add_to_pbuffer(ctx, ch, 1);
            }
            break;

        case st_reason:
            if (*ch == CR) {
                append_pbuffer_to_buffer(ctx);
                clear_pbuffer(ctx);
                ctx->buffer[ctx->buffer_len++] = CR;
                ctx->sstate = st_line_end;
            } else if (*ch == LF) {
                append_pbuffer_to_buffer(ctx);
                clear_pbuffer(ctx);
                ctx->buffer[ctx->buffer_len++] = CR;
                ctx->buffer[ctx->buffer_len++] = LF;
                ctx->sstate = st_field;
            } else {
                add_to_pbuffer(ctx, ch, 1);
            }
            break;

        case st_line_end:
            if (*ch == LF) {
                ctx->buffer[ctx->buffer_len++] = LF;
                ctx->sstate = st_field;
            } else {
                /* bad response */
                bad_response(ctx);
                return;
            }
            break;

        case st_field:
            if (*ch == CR) {
                ctx->buffer[ctx->buffer_len++] = CR;
                ctx->sstate = st_field_cr;
            } else if (*ch == LF) {
                ctx->buffer[ctx->buffer_len++] = CR;
                ctx->buffer[ctx->buffer_len++] = LF;
                if (ctx->scontent_len == 0) {
                    ctx->sstate = st_done;
                } else {
                    ctx->sstate = st_body;
                }
            } else if (*ch == ':') {
                pbuffer_to_field(ctx);
                ctx->is_content_length = is_content_length_header(ctx->field, ctx->field_len);
                append_pbuffer_to_buffer(ctx);
                ctx->buffer[ctx->buffer_len++] = ':';
                ctx->buffer[ctx->buffer_len++] = SP;

                if (ctx->is_content_length) {
                    ctx->scontent_len = 0;
                }

                clear_pbuffer(ctx);
                ctx->sstate = st_before_value;
            } else {
                add_to_pbuffer(ctx, ch, 1);
            }
            break;

        case st_before_value:
            if (*ch == SP || *ch == HT) {
                /* skip */
            } else {
                ctx->sstate = st_value;
                goto again;
            }
            break;

        case st_value:
            if (*ch == CR) {
                pbuffer_to_value(ctx);
                append_pbuffer_to_buffer(ctx);
                clear_pbuffer(ctx);
                ctx->buffer[ctx->buffer_len++] = CR;
                ctx->sstate = st_value_cr;
            } else if (*ch == LF) {
                pbuffer_to_value(ctx);
                append_pbuffer_to_buffer(ctx);
                clear_pbuffer(ctx);
                ctx->buffer[ctx->buffer_len++] = CR;
                ctx->buffer[ctx->buffer_len++] = LF;
                ctx->sstate = st_field;
            } else {
                add_to_pbuffer(ctx, ch, 1);
                if (ctx->is_content_length) {
                    ctx->scontent_len *= 10;
                    ctx->scontent_len += *ch - '0';
                }
            }
            break;

        case st_value_cr:
            if (*ch == LF) {
                ctx->buffer[ctx->buffer_len++] = LF;
                ctx->sstate = st_field;
            } else {
                /* bad response */
                bad_response(ctx);
                return;
            }
            break;

        case st_field_cr:
            if (*ch == LF) {
                ctx->buffer[ctx->buffer_len++] = LF;
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
            ctx->buffer[ctx->buffer_len++] = *ch;
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

    if (n == 0) {
        ctx->sstate = st_done;
    }

    /* just forward it */
    ctx->cwrite_ptr = ctx->buffer;
    ctx->cwrite_len = ctx->buffer_len;
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
copy_path_to_buffer(struct context *ctx)
{
    int i;
    size_t path_len = strlen(ctx->path);
    for (i = 0; i < path_len; i++) {
        ctx->buffer[ctx->buffer_len++] = ctx->path[i];
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
    memcpy(ctx->buffer+ctx->buffer_len, "Host: ", sizeof("Host: ")-1);
    ctx->buffer_len += sizeof("Host: ")-1;
    memcpy(ctx->buffer+ctx->buffer_len, ctx->host, hostlen);
    ctx->buffer_len += hostlen;
    memcpy(ctx->buffer+ctx->buffer_len, "\r\n", sizeof("\r\n ")-1);
    ctx->buffer_len += sizeof("\r\n")-1;
}

static void
add_connection_header(struct context *ctx)
{
    memcpy(ctx->buffer+ctx->buffer_len, "Connection: close\r\n", sizeof("Connection: close\r\n")-1);
    ctx->buffer_len += sizeof("Connection: close\r\n")-1;
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
add_to_pbuffer(struct context *ctx, const uint8_t *ptr, const size_t len)
{
    memcpy(ctx->pbuffer + ctx->pbuffer_len, ptr, len);
    ctx->pbuffer_len += len;
}

static void
clear_pbuffer(struct context *ctx)
{
    ctx->pbuffer_len = 0;
}

static void
append_pbuffer_to_buffer(struct context *ctx)
{
    memcpy(ctx->buffer+ctx->buffer_len, ctx->pbuffer, ctx->pbuffer_len);
    ctx->buffer_len += ctx->pbuffer_len;
}

static void
pbuffer_to_field(struct context *ctx)
{
    memcpy(ctx->field, ctx->pbuffer, ctx->pbuffer_len);
    ctx->field_len = ctx->pbuffer_len;
}

static void
pbuffer_to_value(struct context *ctx)
{
    memcpy(ctx->value, ctx->pbuffer, ctx->pbuffer_len);
    ctx->value_len = ctx->pbuffer_len;
}
