#include <assert.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "connection.h"
#include "definition.h"
#include "listener.h"

struct listener {
    int sock;
    int backlog;
};

static void listener_init(struct listener *listener);

struct listener *listener_new()
{
    struct listener *listener;
    listener = calloc(1, sizeof(*listener));
    if (listener != NULL) {
        listener_init(listener);
    }

    return listener;
}

void listener_del(struct listener *listener)
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

void listener_set_backlog(struct listener *listener, int backlog)
{
    assert(listener != NULL);
    listener->backlog = backlog;
}

int listener_open_and_bind(struct listener *listener, const char *service)
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

int listener_listen(struct listener *listener)
{
    assert(listener != NULL);
    assert(listener->sock != -1);
    return listen(listener->sock, listener->backlog);
}

struct connection *listener_accept(struct listener *listener)
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
