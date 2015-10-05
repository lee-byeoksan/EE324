#ifndef PROJ2_LOGGER_H
#define PROJ2_LOGGER_H

#include <sys/types.h>

#include "connection.h"
#include "httpuri.h"
#include "definition.h"

struct logger;

struct logger *logger_new(const char *filename);
void logger_del(struct logger *logger);
void logger_log(struct logger *logger, struct connection *conn, struct httpuri *httpuri, size_t size);

#endif /* PROJ2_LOGGER_H */
