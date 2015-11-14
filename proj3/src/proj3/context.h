#ifndef PROJ3_CONTEXT_H
#define PROJ3_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>

#include <event2/event.h>

struct context;

struct context *context_new();
void context_destroy(struct context *ctx);
void context_set_base(struct context *ctx, struct event_base *base);
void context_set_client(struct context *ctx, evutil_socket_t sock, struct sockaddr *addr, socklen_t addrlen);
void register_client_read_event(struct context *ctx);
void register_client_write_event(struct context *ctx);
void register_server_read_event(struct context *ctx);
void register_server_write_event(struct context *ctx);

#endif /* PROJ3_CONTEXT_H */
