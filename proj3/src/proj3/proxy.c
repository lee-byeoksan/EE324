#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/util.h>

#include "context.h"
#include "defs.h"

#define DEBUG

static evutil_socket_t create_listen_sock(const char *service);
static void accept_callback(struct evconnlistener *listener,
                            evutil_socket_t sock,
                            struct sockaddr *addr,
                            int len, void *ptr);

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
                                  1000, listen_sock);
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

    evutil_make_listen_socket_reuseable(sock);
    return sock;
}

static void
accept_callback(struct evconnlistener *listener, evutil_socket_t sock,
                struct sockaddr *addr, int len, void *ptr)
{
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    struct event_base *base = evconnlistener_get_base(listener);
    struct context *ctx = context_new();

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

    context_set_base(ctx, base);
    context_set_client(ctx, sock, addr, len);
    context_start_process(ctx);
}

