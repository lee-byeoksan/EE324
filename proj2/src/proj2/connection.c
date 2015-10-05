#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "connection.h"
#include "definition.h"

#define CONN_BUF_LEN 1024

struct connection {
    int sock;
    uint8_t rbuffer[CONN_BUF_LEN];
    uint32_t rstart;
    uint32_t rlen;
};

static void connection_init(struct connection *conn);

struct connection *connection_new(void)
{
    struct connection *conn = NULL;
    conn = calloc(1, sizeof(*conn));

    if (conn != NULL) {
        connection_init(conn);
    }

    return conn;
}

void connection_del(struct connection *conn)
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

int connection_connect(struct connection *conn, const char *host, const char *service)
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

void connection_set_sock(struct connection *conn, int sock)
{
    assert(conn != NULL);
    conn->sock = sock;
}

void connection_close(struct connection *conn)
{
    assert(conn != NULL);
    if (conn->sock != -1) {
        close(conn->sock);
        conn->sock = -1;
    }
}

ssize_t connection_recv(struct connection *conn, void *buf, size_t len)
{
    ssize_t rlen = connection_peek(conn, buf, len);
    conn->rstart += rlen;
    conn->rlen -= rlen;

    return rlen;
}

ssize_t connection_peek(struct connection *conn, void *buf, size_t len)
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

ssize_t connection_send(struct connection *conn, const void *buf, size_t len)
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

ssize_t connection_readline(struct connection *conn, void *buf, size_t len)
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

void connection_skip_space(struct connection *conn)
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


ssize_t connection_readword(struct connection *conn, void *buf, size_t len)
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

int connection_getpeername(struct connection *conn, struct sockaddr *addr, socklen_t *addrlen)
{
    return getpeername(conn->sock, addr, addrlen);
}

