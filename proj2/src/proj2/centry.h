#ifndef PROJ2_CENTRY_H
#define PROJ2_CENTRY_H

#include <stdlib.h>

struct centry;

struct centry *centry_new();
void centry_del(struct centry *entry);
struct centry *centry_next(struct centry *entry);
struct centry *centry_prev(struct centry *entry);
void centry_add_next(struct centry *entry, struct centry *new_entry);
void centry_add_prev(struct centry *entry, struct centry *new_entry);
void centry_set_key(struct centry *entry, char *key);
void centry_set_data(struct centry *entry, void *data);
void centry_set_size(struct centry *entry, size_t size);
void centry_remove(struct centry *entry);
const char *centry_key(struct centry *entry);
size_t centry_size(struct centry *entry);
void *centry_data(struct centry *entry);

#endif /* PROJ2_CENTRY_H */
