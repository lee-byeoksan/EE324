/*
 * proxy.c
 * 
 * EE324 Assignment 2
 * Part I   - sequential web proxy (not implemented)
 * Part II  - concurrent web proxy (not implemented)
 * Part III - caching web objects (not implemented)
 *
 * Author: Lee, Byeoksan <lbs6170@kaist.ac.kr>
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <arpa/inet.h>
#include <time.h>

#define SP ' '
#define HT '\t'
#define CR '\r'
#define LF '\n'
#define CRLF "\r\n"

#define LOGFILE "proxy.log"

#define DEFAULT_PORT "80"
#define DEFAULT_ABS_PATH "/"

#define HTTP_SCHEME "http://"

/*
 * TODO:
 * - Logging
 * - Split into multiple files
 */

#define LIS_DEFAULT_BACKLOG 10

#define CONN_BUF_LEN 1024

struct listener;
struct connection;
struct httpuri;

static struct logger *logger_new(const char *filename);
static void logger_del(struct logger *logger);
static int logger_init(struct logger *logger, const char *filename);
static void logger_log(struct logger *logger, struct connection *conn, struct httpuri *httpuri, size_t size);

static struct listener *listener_new(void);
static void listener_del(struct listener *listener);
static void listener_init(struct listener *listener);
static void listener_set_backlog(struct listener *listener, int backlog);
static int listener_open_and_bind(struct listener *listener, const char *service);
static int listener_listen(struct listener *listener);
static struct connection *listener_accept(struct listener *listener);

static struct connection *connection_new(void);
static void connection_del(struct connection *conn);
static void connection_init(struct connection *conn);
static void connection_set_sock(struct connection *conn, int sock);
static int connection_connect(struct connection *conn, const char *host, const char *service);
static void connection_close(struct connection *conn);
static ssize_t connection_recv(struct connection *conn, void *buf, size_t len);
static ssize_t connection_peek(struct connection *conn, void *buf, size_t len);
static ssize_t connection_send(struct connection *conn, const void *buf, size_t len);
static ssize_t connection_readline(struct connection *conn, void *buf, size_t len);
static void connection_skip_space(struct connection *conn);
static ssize_t connection_readword(struct connection *conn, void *buf, size_t len);
static int connection_getpeername(struct connection *conn, struct sockaddr *addr, socklen_t *addrlen);

static struct httpuri *httpuri_new(void);
static void httpuri_del(struct httpuri *httpuri);
static void httpuri_init(struct httpuri *httpuri);
static struct httpuri *httpuri_uri_to_httpuri(const char *uri);

static int is_valid_method(const char *method);
static int is_valid_version(const char *version);

struct logger {
    char *filename;
    FILE *file;
};

struct listener {
    int sock;
    int backlog;
};

struct connection {
    int sock;
    uint8_t rbuffer[CONN_BUF_LEN];
    uint32_t rstart;
    uint32_t rlen;
};

struct httpuri {
    char *host;
    char *abs_path;
    char *port;
};

int main(int argc, char *argv[])
{
    int result;
    const char *port;
    long port_num;
    struct listener *listener = NULL;
    struct connection *conn_from_client = NULL;
    struct connection *conn_to_server = NULL;
    struct logger *logger = NULL;
    struct sigaction action;

    if (argc < 2) {
        fprintf(stderr, "%s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    port = argv[1];
    port_num = strtol(port, NULL, 10);

    if (port_num < 1024 || port_num > 65535) {
        fprintf(stderr, "port number should be in range between 0 and 65535\n");
        exit(EXIT_FAILURE);
    }

    /* ignore SIGPIPE signal */
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    sigaction(SIGPIPE, &action, NULL);

    logger = logger_new(LOGFILE);
    if (logger == NULL) {
        fprintf(stderr, "cannot create logger\n");
        goto fail;
    }

    listener = listener_new();
    if (listener == NULL) {
        fprintf(stderr, "Not enough memory\n");
        goto fail;
    }

    if (listener_open_and_bind(listener, port)) {
        fprintf(stderr, "failed to open or bind\n");
        goto fail;
    }

    if (listener_listen(listener)) {
        fprintf(stderr, "failed to listen\n");
        goto fail;
    }

    while ((conn_from_client = listener_accept(listener)) != NULL) {
        int s;
        ssize_t n;
        char method[16];
        char uri[512];
        char version[16];
        char line[512];
        char addr[NI_MAXHOST];
        uint32_t content_length;
        int host_header_found = 0;
        const char *header_end;
        size_t header_len;
        int do_not_forward;
        struct httpuri *httpuri = NULL;
        size_t response_size = 0;

        /* method, uri and version */
        connection_readline(conn_from_client, line, sizeof(line));
        sscanf(line, "%s %s %s", method, uri, version);

        if (!is_valid_method(method)) {
            /* leave this for original server to handle it? */
            fprintf(stderr, "invalid method is given: %s\n", method);
            goto disconnect;
        }

        if (!is_valid_version(version)) {
            fprintf(stderr, "invalid version is given: %s\n", version);
            goto disconnect;
        }

        /* parse the uri */
        httpuri = httpuri_uri_to_httpuri(uri);
        if (httpuri == NULL) {
            fprintf(stderr, "uri is invalid or memory allocation fails\n");
            goto disconnect;
        }

        /* connect to original server */
        conn_to_server = connection_new();
        if (conn_to_server == NULL) {
            fprintf(stderr, "no enough memory\n");
            goto disconnect;
        }

        s = connection_connect(conn_to_server, httpuri->host, httpuri->port);
        if (s) {
            fprintf(stderr, "failed to connect to the original server\n");
            goto disconnect;
        }

        /* forward the start-line */
        /* we always send as HTTP/1.0 */
        n = snprintf(line, sizeof(line), "%s %s %s" CRLF, method, httpuri->abs_path, "HTTP/1.0");
        if (n < 0) {
            fprintf(stderr, "failed to build start-line\n");
            goto disconnect;
        }
        connection_send(conn_to_server, line, n);

        /* forward the headers */
        content_length = 0;
        n = connection_readline(conn_from_client, line, sizeof(line));
        while (n > 2) {
            if (line[0] != SP && line[0] != HT) {
                /* new header field */
                do_not_forward = 0;
            }

            header_end = strchr(line, ':');
            if (header_end != NULL) {
                header_len = header_end - line;
                if (!strncasecmp(line, "host", header_len)) {
                    host_header_found = 1;
                } else if (!strncasecmp(line, "content-length", header_len)) {
                    content_length = strtoul(header_end + 1, NULL, 10);
                } else if (!strncasecmp(line, "connection", header_len)) {
                    do_not_forward = 1;
                } else if (!strncasecmp(line, "keep-alive", header_len)) {
                    do_not_forward = 1;
                }
            }

            if (!do_not_forward) {
                connection_send(conn_to_server, line, n);
            }

            n = connection_readline(conn_from_client, line, sizeof(line));
        }

        if (!host_header_found) {
            n = snprintf(line, sizeof(line), "Host: %s" CRLF, httpuri->host);
            if (n < 0) {
                fprintf(stderr, "failed to build 'Host' header\n");
                goto disconnect;
            }
            connection_send(conn_to_server, line, n);
        }

        n = snprintf(line, sizeof(line), "Connection: close" CRLF);
        connection_send(conn_to_server, line, n);

        n = snprintf(line, sizeof(line), "Proxy-Connection: close" CRLF);
        connection_send(conn_to_server, line, n);

        connection_send(conn_to_server, CRLF, sizeof(CRLF) - 1);

        /* forward the body */
        size_t left = content_length;
        if (left > 0) {
            n = connection_recv(conn_from_client, line, sizeof(line));
            connection_send(conn_to_server, line, n);
            left -= n;
        }

        /* forward the response */
        n = connection_recv(conn_to_server, line, sizeof(line));
        response_size += n;
        while (n > 0) {
            connection_send(conn_from_client, line, n);
            n = connection_recv(conn_to_server, line, sizeof(line));
            response_size += n;
        }

        logger_log(logger, conn_from_client, httpuri, response_size);

disconnect:
        httpuri_del(httpuri);
        connection_del(conn_from_client);
        connection_del(conn_to_server);
        conn_from_client = NULL;
        conn_to_server = NULL;
        httpuri = NULL;
    }

    result = EXIT_SUCCESS;
    goto out;

fail:
    result = EXIT_FAILURE;
out:
    listener_del(listener);
    logger_del(logger);
    exit(EXIT_SUCCESS);
}

static struct logger *logger_new(const char *filename)
{
    assert(filename != NULL);
    struct logger *logger;
    logger = calloc(1, sizeof(*logger));
    if (!logger_init(logger, filename)) {
        return NULL;
    }

    return logger;
}

static void logger_del(struct logger *logger)
{
    if (logger != NULL) {
        return;
    }

    fclose(logger->file);
    free(logger->filename);
    free(logger);
}

static int logger_init(struct logger *logger, const char *filename)
{
    assert(logger != NULL);
    assert(filename != NULL);

    logger->filename = strdup(filename);
    if (logger->filename == NULL) {
        return 0;
    }

    logger->file = fopen(logger->filename, "w");
    if (logger->file == NULL) {
        free(logger->filename);
        return 0;
    }

    return 1;
}

static void logger_log(struct logger *logger, struct connection *conn, struct httpuri *httpuri, size_t size)
{
    assert(logger != NULL);
    assert(logger->file != NULL);
    assert(conn != NULL);
    assert(httpuri != NULL);

    time_t t;
    char time_str[64];
    char hostip[NI_MAXHOST];
    struct tm tm;
    int s;

    struct sockaddr_storage addr = {0};
    socklen_t addrlen;

    time(&t);
    localtime_r(&t, &tm);
    strftime(time_str, sizeof(time_str), "%a %d %b %G %T %Z", &tm);

    s = connection_getpeername(conn, (struct sockaddr *)&addr, &addrlen);
    if (s || addr.ss_family == AF_UNSPEC) {
        strcpy(hostip, "(unknown)");
    } else {
        s = getnameinfo((struct sockaddr *)&addr, addrlen, hostip, sizeof(hostip), NULL, 0, NI_NUMERICHOST);
        if (s) {
            strcpy(hostip, "(unknown)");
        }
    }

    fprintf(logger->file, "%s: %s http://%s%s %zd\n", time_str, hostip, httpuri->host, httpuri->abs_path, size);
    fflush(logger->file);
}

static struct listener *listener_new()
{
    struct listener *listener;
    listener = calloc(1, sizeof(*listener));
    if (listener != NULL) {
        listener_init(listener);
    }

    return listener;
}

static void listener_del(struct listener *listener)
{
    if (listener == NULL) {
        return;
    }

    if (listener->sock != -1) {
        close(listener->sock);
    }

    free(listener);
}

static void listener_init(struct listener *listener)
{
    assert(listener != NULL);

    listener->sock = -1;
    listener->backlog = LIS_DEFAULT_BACKLOG;
}

static void listener_set_backlog(struct listener *listener, int backlog)
{
    assert(listener != NULL);
    listener->backlog = backlog;
}

static int listener_open_and_bind(struct listener *listener, const char *service)
{
    assert(listener != NULL);

    int s;
    int sock;
    struct addrinfo hint;
    struct addrinfo *res;
    struct addrinfo *aip;

    bzero(&hint, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    /* find an available passive socket and bind it */
    s = getaddrinfo(NULL, service, &hint, &res);
    if (s) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    for (aip = res; aip != NULL; aip = aip->ai_next) {
        sock = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
        if (sock == -1) {
            perror("socket");
            continue;
        }

        s = bind(sock, aip->ai_addr, aip->ai_addrlen);
        if (!s) {
            break;
        }

        perror("listener_bind");
        close(sock);
    }

    if (aip == NULL) {
        fprintf(stderr, "No available socket\n");
        freeaddrinfo(res);
        return -1;
    }

    listener->sock = sock;
    freeaddrinfo(res);

    return 0;
}

static int listener_listen(struct listener *listener)
{
    assert(listener != NULL);
    assert(listener->sock != -1);
    return listen(listener->sock, listener->backlog);
}

static struct connection *listener_accept(struct listener *listener)
{
    assert(listener != NULL);
    assert(listener->sock != -1);

    struct connection *conn = connection_new();
    if (conn == NULL) {
        return NULL;
    }

    int sock = accept(listener->sock, NULL, 0);
    if (sock == -1) {
        connection_del(conn);
        return NULL;
    }

    connection_set_sock(conn, sock);
    return conn;
}

static struct connection *connection_new(void)
{
    struct connection *conn = NULL;
    conn = calloc(1, sizeof(*conn));

    if (conn != NULL) {
        connection_init(conn);
    }

    return conn;
}

static void connection_del(struct connection *conn)
{
    if (conn == NULL) {
        return;
    }

    if (conn->sock != -1) {
        close(conn->sock);
    }

    free(conn);
}

static void connection_init(struct connection *conn)
{
    assert(conn != NULL);
    conn->sock = -1;
    conn->rstart = 0;
    conn->rlen = 0;
}

static int connection_connect(struct connection *conn, const char *host, const char *service)
{
    assert(conn != NULL);
    assert(host != NULL);
    assert(service != NULL);
    assert(conn->sock == -1);

    int s;
    int sock;
    struct addrinfo hint;
    struct addrinfo *res;
    struct addrinfo *aip;

    bzero(&hint, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_STREAM;

    /* find an available passive socket and bind it */
    s = getaddrinfo(host, service, &hint, &res);
    if (s) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    for (aip = res; aip != NULL; aip = aip->ai_next) {
        sock = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol);
        if (sock == -1) {
            perror("socket");
            continue;
        }

        s = connect(sock, aip->ai_addr, aip->ai_addrlen);
        if (!s) {
            break;
        }

        perror("bind");
        close(sock);
    }

    if (aip == NULL) {
        fprintf(stderr, "No available socket\n");
        freeaddrinfo(res);
        return -1;
    }

    conn->sock = sock;
    freeaddrinfo(res);

    return 0;
}

static void connection_set_sock(struct connection *conn, int sock)
{
    assert(conn != NULL);
    conn->sock = sock;
}

static void connection_close(struct connection *conn)
{
    assert(conn != NULL);
    if (conn->sock != -1) {
        close(conn->sock);
        conn->sock = -1;
    }
}

static ssize_t connection_recv(struct connection *conn, void *buf, size_t len)
{
    ssize_t rlen = connection_peek(conn, buf, len);
    conn->rstart += rlen;
    conn->rlen -= rlen;

    return rlen;
}

static ssize_t connection_peek(struct connection *conn, void *buf, size_t len)
{
    assert(conn != NULL);
    assert(conn->sock != -1);

    /* if buffer is empty fill it */
    ssize_t rlen;
    if (conn->rlen == 0) {
        conn->rstart = 0;
        rlen = recv(conn->sock, conn->rbuffer, CONN_BUF_LEN, 0);
        if (rlen == -1) {
            return -1;
        }

        conn->rlen = rlen;
    }

    len = (len < conn->rlen) ? len : conn->rlen;
    memcpy(buf, conn->rbuffer+conn->rstart, len);

    return len;
}

static ssize_t connection_send(struct connection *conn, const void *buf, size_t len)
{
    assert(conn != NULL);
    assert(conn->sock != -1);
    assert(buf != NULL);
    ssize_t left = len;
    ssize_t n;

    while (left > 0) {
        n = send(conn->sock, buf, left, 0);
        if (n == -1) {
            return -1;
        }

        left -= n;
        buf += n;
    }

    return len;
}

static ssize_t connection_readline(struct connection *conn, void *buf, size_t len)
{
    assert(conn != NULL);
    assert(conn->sock != -1);
    assert(buf != NULL);

    ssize_t s;
    uint8_t c;

    uint8_t *bufp = buf;
    uint8_t *bufend = buf + len - 1;
    ssize_t count = 0;
    int cr_found = 0;
    /* CRLF at the boundary? */
    while (bufp != bufend) {
        s = connection_recv(conn, &c, 1);

        if (s != 1) {
            break;
        }

        switch (c) {
        case CR:
            *(bufp++) = CR;
            count++;

            s = connection_peek(conn, &c, 1);
            if (s != 1) {
                goto out;
            }

            if (c != LF) {
                *(bufp++) = LF;
                count++;
                goto out;
            }
            break;
        case LF:
            *(bufp++) = LF;
            count++;
            goto out;
        default:
            *(bufp++) = c;
            count++;
            break;
        }
    }

out:
    *bufp = '\0';
    return count;
}

static void connection_skip_space(struct connection *conn)
{
    assert(conn != NULL);
    assert(conn->sock != -1);

    char c;
    connection_peek(conn, &c, 1);
    while (c == SP || c == HT) {
        connection_recv(conn, &c, 1);
        connection_peek(conn, &c, 1);
    }
}


static ssize_t connection_readword(struct connection *conn, void *buf, size_t len)
{
    assert(conn != NULL);
    assert(conn->sock != -1);

    connection_skip_space(conn);

    char *p = buf;
    char *bufend = p + len - 1;
    int s;

    connection_peek(conn, p, 1);
    while (p < bufend && *p != SP && *p != HT && *p != CR && *p != LF) {
        s = connection_recv(conn, p++, 1);
        if (s == 0 || s == -1) {
            break;
        }
        connection_peek(conn, p, 1);
    }

    *p = '\0';
    return p - (char *)buf;
}

static int connection_getpeername(struct connection *conn, struct sockaddr *addr, socklen_t *addrlen)
{
    return getpeername(conn->sock, addr, addrlen);
}

static struct httpuri *httpuri_new(void)
{
    struct httpuri *httpuri;
    httpuri = calloc(1, sizeof(*httpuri));

    if (httpuri != NULL) {
        httpuri_init(httpuri);
    }

    return httpuri;
}

static void httpuri_del(struct httpuri *httpuri)
{
    if (httpuri == NULL) {
        return;
    }

    free(httpuri->host);
    free(httpuri->abs_path);
    free(httpuri->port);
    free(httpuri);
}

static void httpuri_init(struct httpuri *httpuri)
{
    assert(httpuri != NULL);
    httpuri->host = NULL;
    httpuri->abs_path = NULL;
    httpuri->port = NULL;
}

static struct httpuri *httpuri_uri_to_httpuri(const char *uri)
{
    size_t uri_len;
    const char *host, *host_end;
    const char *abs_path;
    const char *port;

    size_t host_len;
    size_t abs_path_len;
    size_t port_len;

    struct httpuri *httpuri;

    if (uri == NULL) {
        return NULL;
    }

    if (strncasecmp(uri, HTTP_SCHEME, sizeof(HTTP_SCHEME)-1)) {
        return NULL;
    }

    httpuri = httpuri_new();
    if (httpuri == NULL) {
        return NULL;
    }

    /* uri without the scheme */
    uri = uri + sizeof(HTTP_SCHEME) - 1;
    uri_len = strlen(uri);

    host = uri;
    abs_path = strchr(uri, '/');
    port = strchr(uri, ':');

    if (abs_path == NULL) {
        abs_path = uri + uri_len;
    }

    if (port != NULL && port > abs_path) {
        port = NULL;
    }

    host_end = (port == NULL) ? abs_path : port;
    port = (port == NULL) ? DEFAULT_PORT : port + 1;
    if (*abs_path == '\0') {
        abs_path = DEFAULT_ABS_PATH;
    }

    host_len = host_end - host;
    abs_path_len = strlen(abs_path);
    if (port == DEFAULT_PORT) {
        port_len = sizeof(DEFAULT_PORT) - 1;
    } else {
        port_len = abs_path - port;
    }

    /* any absence? */
    if (host_len == 0 || abs_path_len == 0 || port_len == 0) {
        goto fail;
    }

    /* copy those */
    httpuri->host = malloc(host_len + 1);
    if (httpuri->host == NULL) {
        goto fail;
    }

    httpuri->abs_path = malloc(abs_path_len + 1);
    if (httpuri->abs_path == NULL) {
        goto fail;
    }

    httpuri->port = malloc(port_len + 1);
    if (httpuri->port == NULL) {
        goto fail;
    }

    memcpy(httpuri->host, host, host_len);
    memcpy(httpuri->abs_path, abs_path, abs_path_len);
    memcpy(httpuri->port, port, port_len);
    httpuri->host[host_len] = '\0';
    httpuri->abs_path[abs_path_len] = '\0';
    httpuri->port[port_len] = '\0';

    return httpuri;

fail:
    httpuri_del(httpuri);
    return NULL;
}

static int is_valid_method(const char *method)
{
    int invalid = 1;
    invalid = strcmp(method, "OPTIONS") &&
              strcmp(method, "GET") &&
              strcmp(method, "HEAD") &&
              strcmp(method, "POST") &&
              strcmp(method, "PUT") &&
              strcmp(method, "DELETE") &&
              strcmp(method, "TRACE") &&
              strcmp(method, "CONNECT");

    return !invalid;
}

static int is_valid_version(const char *version)
{
    int invalid = 1;
    invalid = strcmp(version, "HTTP/1.0") &&
              strcmp(version, "HTTP/1.1");

    return !invalid;
}

