/*
 * registry.c - loads books.txt and members.txt into arrays of structs.
 *
 * Line format:  ID,middle field,last field
 * The ID is everything before the first comma and the last field is everything
 * after the last comma, so a title with a comma in it still parses correctly.
 * Bad lines are reported with their line number and skipped; a file with no
 * valid lines at all is treated as an error.
 */
#include "registry.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#define LINE_MAX_LEN 512

static char *skip_prefix(char *s)
{
    while (isspace((unsigned char)*s))
        s++;
    if (s[0] == '-' && s[1] == ' ')   /* tolerate "- " bullets copied from the brief */
        s += 2;
    while (isspace((unsigned char)*s))
        s++;
    return s;
}

static int split3(char *line, char **a, char **b, char **c)
{
    char *first = strchr(line, ',');
    char *last  = strrchr(line, ',');
    if (!first || first == last)
        return -1;
    *first = '\0';
    *last  = '\0';
    *a = line;
    *b = first + 1;
    *c = last + 1;
    trim(*a);
    trim(*b);
    trim(*c);
    return (**a && **b && **c) ? 0 : -1;
}

/* Reads the next line. Returns 1 ok, 0 EOF, -1 line too long (rest discarded). */
static int next_line(FILE *fp, char *buf, size_t n)
{
    if (!fgets(buf, (int)n, fp))
        return 0;
    if (!strchr(buf, '\n') && !feof(fp)) {
        char junk[LINE_MAX_LEN];
        while (fgets(junk, sizeof junk, fp) && !strchr(junk, '\n'))
            ;
        return -1;
    }
    buf[strcspn(buf, "\r\n")] = '\0';
    return 1;
}

static FILE *open_registry(const char *path, const char *what)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        fprintf(stderr, "ERROR: Cannot open %s (%s). The %s registry is required.\n",
                path, strerror(errno), what);
    return fp;
}

int load_books(const char *path, BookRegistry *reg)
{
    reg->items = NULL;
    reg->count = 0;
    size_t cap = 0;
    int line_no = 0, skipped = 0, rc;
    char line[LINE_MAX_LEN];

    FILE *fp = open_registry(path, "book");
    if (!fp)
        return -1;

    while ((rc = next_line(fp, line, sizeof line)) != 0) {
        line_no++;
        if (rc < 0) {
            fprintf(stderr, "WARNING: %s line %d is too long, skipped.\n", path, line_no);
            skipped++;
            continue;
        }
        char *p = skip_prefix(line);
        if (*p == '\0' || *p == '#')
            continue;

        char *id, *title, *author;
        if (split3(p, &id, &title, &author) != 0) {
            fprintf(stderr, "WARNING: %s line %d is malformed (expected book_id,title,author), skipped.\n",
                    path, line_no);
            skipped++;
            continue;
        }
        str_upper(id);
        if (!is_valid_id(id, sizeof(((Book *)0)->book_id))) {
            fprintf(stderr, "WARNING: %s line %d has an invalid book ID '%s', skipped.\n", path, line_no, id);
            skipped++;
            continue;
        }
        if (strchr(title, '|') || strchr(author, '|') ||
            strlen(title) >= sizeof(((Book *)0)->title) ||
            strlen(author) >= sizeof(((Book *)0)->author)) {
            fprintf(stderr, "WARNING: %s line %d has a field that is too long or contains '|', skipped.\n",
                    path, line_no);
            skipped++;
            continue;
        }
        if (find_book(reg, id)) {
            fprintf(stderr, "WARNING: %s line %d duplicates book ID %s, skipped.\n", path, line_no, id);
            skipped++;
            continue;
        }
        if (reg->count == cap) {
            size_t new_cap = cap ? cap * 2 : 16;
            Book *tmp = realloc(reg->items, new_cap * sizeof *tmp);
            if (!tmp) {
                fprintf(stderr, "ERROR: Out of memory loading %s.\n", path);
                fclose(fp);
                free_books(reg);
                return -1;
            }
            reg->items = tmp;
            cap = new_cap;
        }
        Book *b = &reg->items[reg->count++];
        memset(b, 0, sizeof *b);
        safe_copy(b->book_id, sizeof b->book_id, id);
        safe_copy(b->title, sizeof b->title, title);
        safe_copy(b->author, sizeof b->author, author);
    }
    fclose(fp);

    if (reg->count == 0) {
        fprintf(stderr, "ERROR: %s is empty or has no valid entries.\n", path);
        free_books(reg);
        return -1;
    }
    printf("[OK] Loaded %zu book(s) from %s", reg->count, path);
    if (skipped)
        printf(" (%d line(s) skipped)", skipped);
    printf("\n");
    return 0;
}

int load_members(const char *path, MemberRegistry *reg)
{
    reg->items = NULL;
    reg->count = 0;
    size_t cap = 0;
    int line_no = 0, skipped = 0, rc;
    char line[LINE_MAX_LEN];

    FILE *fp = open_registry(path, "member");
    if (!fp)
        return -1;

    while ((rc = next_line(fp, line, sizeof line)) != 0) {
        line_no++;
        if (rc < 0) {
            fprintf(stderr, "WARNING: %s line %d is too long, skipped.\n", path, line_no);
            skipped++;
            continue;
        }
        char *p = skip_prefix(line);
        if (*p == '\0' || *p == '#')
            continue;

        char *id, *name, *course;
        if (split3(p, &id, &name, &course) != 0) {
            fprintf(stderr, "WARNING: %s line %d is malformed (expected member_id,full_name,course_code), skipped.\n",
                    path, line_no);
            skipped++;
            continue;
        }
        str_upper(id);
        if (!is_valid_id(id, sizeof(((Member *)0)->member_id))) {
            fprintf(stderr, "WARNING: %s line %d has an invalid member ID '%s', skipped.\n", path, line_no, id);
            skipped++;
            continue;
        }
        if (strchr(name, '|') || strchr(course, '|') ||
            strlen(name) >= sizeof(((Member *)0)->full_name) ||
            strlen(course) >= sizeof(((Member *)0)->course_code)) {
            fprintf(stderr, "WARNING: %s line %d has a field that is too long or contains '|', skipped.\n",
                    path, line_no);
            skipped++;
            continue;
        }
        if (find_member(reg, id)) {
            fprintf(stderr, "WARNING: %s line %d duplicates member ID %s, skipped.\n", path, line_no, id);
            skipped++;
            continue;
        }
        if (reg->count == cap) {
            size_t new_cap = cap ? cap * 2 : 16;
            Member *tmp = realloc(reg->items, new_cap * sizeof *tmp);
            if (!tmp) {
                fprintf(stderr, "ERROR: Out of memory loading %s.\n", path);
                fclose(fp);
                free_members(reg);
                return -1;
            }
            reg->items = tmp;
            cap = new_cap;
        }
        Member *m = &reg->items[reg->count++];
        memset(m, 0, sizeof *m);
        safe_copy(m->member_id, sizeof m->member_id, id);
        safe_copy(m->full_name, sizeof m->full_name, name);
        safe_copy(m->course_code, sizeof m->course_code, course);
    }
    fclose(fp);

    if (reg->count == 0) {
        fprintf(stderr, "ERROR: %s is empty or has no valid entries.\n", path);
        free_members(reg);
        return -1;
    }
    printf("[OK] Loaded %zu member(s) from %s", reg->count, path);
    if (skipped)
        printf(" (%d line(s) skipped)", skipped);
    printf("\n");
    return 0;
}

const Book *find_book(const BookRegistry *reg, const char *book_id)
{
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->items[i].book_id, book_id) == 0)
            return &reg->items[i];
    return NULL;
}

const Member *find_member(const MemberRegistry *reg, const char *member_id)
{
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->items[i].member_id, member_id) == 0)
            return &reg->items[i];
    return NULL;
}

void print_books(const BookRegistry *reg)
{
    printf("\nBOOK REGISTRY (%zu books)\n", reg->count);
    printf("  %-8s %-36s %s\n", "ID", "Title", "Author");
    for (size_t i = 0; i < reg->count; i++)
        printf("  %-8s %-36s %s\n", reg->items[i].book_id, reg->items[i].title, reg->items[i].author);
}

void print_members(const MemberRegistry *reg)
{
    printf("\nMEMBER REGISTRY (%zu members)\n", reg->count);
    printf("  %-8s %-28s %s\n", "ID", "Full name", "Course");
    for (size_t i = 0; i < reg->count; i++)
        printf("  %-8s %-28s %s\n", reg->items[i].member_id, reg->items[i].full_name,
               reg->items[i].course_code);
}

void free_books(BookRegistry *reg)
{
    free(reg->items);
    reg->items = NULL;
    reg->count = 0;
}

void free_members(MemberRegistry *reg)
{
    free(reg->items);
    reg->items = NULL;
    reg->count = 0;
}
