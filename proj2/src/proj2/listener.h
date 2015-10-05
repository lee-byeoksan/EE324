#ifndef PROJ2_LISTENER_H
#define PROJ2_LISTENER_H

#include "definition.h"
#define LIS_DEFAULT_BACKLOG 10

struct listener;

struct listener *listener_new(void);
void listener_del(struct listener *listener);
void listener_set_backlog(struct listener *listener, int backlog);
int listener_open_and_bind(struct listener *listener, const char *service);
int listener_listen(struct listener *listener);
struct connection *listener_accept(struct listener *listener);

#endif /* PROJ2_LISTENER_H */
