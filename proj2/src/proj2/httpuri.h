#ifndef PROJ2_HTTPURI_H
#define PROJ2_HTTPURI_H

#include "definition.h"

struct httpuri;

struct httpuri *httpuri_new(void);
void httpuri_del(struct httpuri *httpuri);
struct httpuri *httpuri_uri_to_httpuri(const char *uri);
const char *httpuri_get_host(struct httpuri *httpuri);
const char *httpuri_get_port(struct httpuri *httpuri);
const char *httpuri_get_abs_path(struct httpuri *httpuri);

#endif /* PROJ2_HTTPURI_H */
