/*
 * pending.h - the pending pool: signed lending records waiting to be mined.
 */
#ifndef PENDING_H
#define PENDING_H

#include <openssl/evp.h>
#include <stddef.h>

#include "common.h"

typedef struct {
    Block *items;     /* oldest first; mined in this order */
    size_t count;
    size_t cap;
} PendingPool;

void pending_init(PendingPool *p);
void pending_free(PendingPool *p);
int  pending_add(PendingPool *p, const Block *record);
void pending_remove_front(PendingPool *p);
void pending_pop_back(PendingPool *p);
/* 1 if a record for this book is already waiting to be mined */
int  pending_has_book(const PendingPool *p, const char *book_id);

int  pending_save(const PendingPool *p, const char *path);
/* 0 = loaded (or no file), -1 = error. Records with bad signatures are rejected. */
int  pending_load(PendingPool *p, const char *path, EVP_PKEY *pub);
void pending_print(const PendingPool *p, EVP_PKEY *pub);

#endif /* PENDING_H */
