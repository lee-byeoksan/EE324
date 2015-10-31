#include "centry.h"
#include <stdlib.h>
#include <stddef.h>

struct centry {
    size_t size;
    void *data;
    void *key;
    struct centry *next;
    struct centry *prev;
};

struct centry *centry_new()
{
    struct centry *entry;
    entry = (struct centry *)malloc(sizeof(*entry));
    if (entry != NULL) {
        entry->size = 0;
        entry->key = NULL;
        entry->data = NULL;
        entry->next = entry->prev = NULL;
    }

    return entry;
}

void centry_del(struct centry *entry)
{
    if (entry->data != NULL) {
        free(entry->data);
    }

    if (entry->key != NULL) {
        free(entry->key);
    }

    free(entry);
}

struct centry *centry_next(struct centry *entry)
{
    return entry->next;
}

struct centry *centry_prev(struct centry *entry)
{
    return entry->prev;
}

void centry_add_next(struct centry *entry, struct centry *new_entry)
{
    struct centry *next_entry = entry->next;
    entry->next = new_entry;
    new_entry->next = next_entry;
    new_entry->prev = entry;
    if (next_entry != NULL) {
        next_entry->prev = new_entry;
    }
}

void centry_add_prev(struct centry *entry, struct centry *new_entry)
{
    struct centry *prev_entry = entry->prev;
    entry->prev = new_entry;
    new_entry->prev = prev_entry;
    new_entry->next = entry;
    if (prev_entry != NULL) {
        prev_entry->next = new_entry;
    }
}

void centry_remove(struct centry *entry)
{
    struct centry *prev_entry, *next_entry;
    prev_entry = entry->prev;
    next_entry = entry->next;

    if (prev_entry != NULL) {
        prev_entry->next = next_entry;
    }

    if (next_entry != NULL) {
        next_entry->prev = prev_entry;
    }

    entry->next = entry->prev = NULL;
}

const char *centry_key(struct centry *entry)
{
    return entry->key;
}

size_t centry_size(struct centry *entry)
{
    return entry->size;
}

void *centry_data(struct centry *entry)
{
    return entry->data;
}

void centry_set_key(struct centry *entry, char *key)
{
    if (entry->key != NULL) {
        free(entry->key);
    }

    entry->key = key;
}

void centry_set_data(struct centry *entry, void *data)
{
    if (entry->data != NULL) {
        free(entry->data);
    }

    entry->data = data;
}

void centry_set_size(struct centry *entry, size_t size)
{
    entry->size = size;
}
