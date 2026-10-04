/*
 * registry.h - book and member registries loaded from text files.
 */
#ifndef REGISTRY_H
#define REGISTRY_H

#include <stddef.h>

#include "common.h"

typedef struct {
    Book  *items;
    size_t count;
} BookRegistry;

typedef struct {
    Member *items;
    size_t  count;
} MemberRegistry;

/* Return 0 on success, -1 if the file is missing, unreadable or has no valid entries. */
int  load_books(const char *path, BookRegistry *reg);
int  load_members(const char *path, MemberRegistry *reg);

const Book   *find_book(const BookRegistry *reg, const char *book_id);
const Member *find_member(const MemberRegistry *reg, const char *member_id);

void print_books(const BookRegistry *reg);
void print_members(const MemberRegistry *reg);

void free_books(BookRegistry *reg);
void free_members(MemberRegistry *reg);

#endif /* REGISTRY_H */
