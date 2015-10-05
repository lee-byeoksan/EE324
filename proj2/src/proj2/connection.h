#ifndef PROJ2_CONNECTION_H
#define PROJ2_CONNECTION_H

#include "definition.h"
#include <sys/socket.h>

struct connection;

struct connection *connection_new(void);
void connection_del(struct connection *conn);
void connection_set_sock(struct connection *conn, int sock);
int connection_connect(struct connection *conn, const char *host, const char *service);
void connection_close(struct connection *conn);
ssize_t connection_recv(struct connection *conn, void *buf, size_t len);
ssize_t connection_peek(struct connection *conn, void *buf, size_t len);
ssize_t connection_send(struct connection *conn, const void *buf, size_t len);
ssize_t connection_readline(struct connection *conn, void *buf, size_t len);
void connection_skip_space(struct connection *conn);
ssize_t connection_readword(struct connection *conn, void *buf, size_t len);
int connection_getpeername(struct connection *conn, struct sockaddr *addr, socklen_t *addrlen);

#endif /* PROJ2_CONNECTION_H */
