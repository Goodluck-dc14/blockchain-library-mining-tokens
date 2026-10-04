/*
 * pending.c - pending pool of unconfirmed lending records.
 *
 * Borrow, return and overdue events are signed straight away but are NOT
 * added to the chain. They wait here until a miner confirms them with
 * proof-of-work. The pool is saved to pending.dat so nothing is lost if the
 * program closes before mining.
 *
 * File format (one record per line):
 *   timestamp|book_id|book_title|member_id|member_name|action|token_reward|tx_id|signature_hex
 */
#include "pending.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blockchain.h"
#include "crypto_utils.h"
#include "util.h"

#define LINE_MAX_LEN 1024
#define FIELD_COUNT  9

void pending_init(PendingPool *p)
{
    p->items = NULL;
    p->count = 0;
    p->cap = 0;
}

void pending_free(PendingPool *p)
{
    free(p->items);
    pending_init(p);
}

int pending_add(PendingPool *p, const Block *record)
{
    if (p->count == p->cap) {
        size_t new_cap = p->cap ? p->cap * 2 : 8;
        Block *tmp = realloc(p->items, new_cap * sizeof *tmp);
        if (!tmp) {
            fprintf(stderr, "ERROR: Out of memory growing the pending pool.\n");
            return -1;
        }
        p->items = tmp;
        p->cap = new_cap;
    }
    p->items[p->count++] = *record;
    return 0;
}

void pending_remove_front(PendingPool *p)
{
    if (p->count == 0)
        return;
    memmove(p->items, p->items + 1, (p->count - 1) * sizeof *p->items);
    p->count--;
}

void pending_pop_back(PendingPool *p)
{
    if (p->count > 0)
        p->count--;
}

int pending_has_book(const PendingPool *p, const char *book_id)
{
    for (size_t i = 0; i < p->count; i++)
        if (strcmp(p->items[i].book_id, book_id) == 0)
            return 1;
    return 0;
}

int pending_save(const PendingPool *p, const char *path)
{
    char tmp_path[512], sig_hex[2 * SIG_MAX_LEN + 1];
    FILE *fp;

    if (atomic_write_begin(path, tmp_path, sizeof tmp_path, &fp) != 0)
        return -1;
    int ok = fprintf(fp, "# PENDING v1: timestamp|book_id|book_title|member_id|member_name|"
                         "action|token_reward|tx_id|signature_hex\n") > 0;
    for (size_t i = 0; ok && i < p->count; i++) {
        const Block *b = &p->items[i];
        bytes_to_hex(b->signature, b->sig_len, sig_hex);
        ok = fprintf(fp, "%lld|%s|%s|%s|%s|%s|%d|%s|%s\n", (long long)b->timestamp,
                     b->book_id, b->book_title, b->member_id, b->member_name,
                     b->action, b->token_reward, b->tx_id, sig_hex) > 0;
    }
    if (!ok) {
        fclose(fp);
        fprintf(stderr, "ERROR: Failed writing %s.\n", path);
        return -1;
    }
    return atomic_write_commit(fp, tmp_path, path);
}

int pending_load(PendingPool *p, const char *path, EVP_PKEY *pub)
{
    pending_init(p);
    FILE *fp = fopen(path, "r");
    if (!fp)
        return errno == ENOENT ? 0 : -1;

    char line[LINE_MAX_LEN];
    int line_no = 0;
    while (fgets(line, sizeof line, fp)) {
        line_no++;
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;

        char *f[FIELD_COUNT];
        Block b;
        size_t sig_len = 0;
        char *end;
        memset(&b, 0, sizeof b);

        if (split_fields(line, '|', f, FIELD_COUNT) != FIELD_COUNT) {
            fprintf(stderr, "ERROR: %s line %d is malformed.\n", path, line_no);
            goto fail;
        }
        errno = 0;
        long long ts = strtoll(f[0], &end, 10);
        long reward = strtol(f[6], NULL, 10);
        if (errno || *end != '\0' || ts < 0 ||
            safe_copy(b.book_id, sizeof b.book_id, f[1]) != 0 ||
            safe_copy(b.book_title, sizeof b.book_title, f[2]) != 0 ||
            safe_copy(b.member_id, sizeof b.member_id, f[3]) != 0 ||
            safe_copy(b.member_name, sizeof b.member_name, f[4]) != 0 ||
            safe_copy(b.action, sizeof b.action, f[5]) != 0 ||
            safe_copy(b.tx_id, sizeof b.tx_id, f[7]) != 0 ||
            hex_to_bytes(f[8], b.signature, SIG_MAX_LEN, &sig_len) != 0) {
            fprintf(stderr, "ERROR: %s line %d has a bad field.\n", path, line_no);
            goto fail;
        }
        b.timestamp = (time_t)ts;
        b.token_reward = (int)reward;
        b.sig_len = (unsigned int)sig_len;
        /* A pending record must still carry a valid librarian signature */
        if (!verify_block_signature(&b, pub)) {
            fprintf(stderr, "ERROR: %s line %d: INVALID SIGNATURE. The pending pool was tampered with.\n",
                    path, line_no);
            goto fail;
        }
        if (pending_add(p, &b) != 0)
            goto fail;
    }
    fclose(fp);
    return 0;

fail:
    fclose(fp);
    pending_free(p);
    return -1;
}

void pending_print(const PendingPool *p, EVP_PKEY *pub)
{
    printf("\n================ PENDING POOL (%zu unconfirmed) ================\n", p->count);
    if (p->count == 0) {
        printf("  The pool is empty. Nothing is waiting to be mined.\n");
        return;
    }
    for (size_t i = 0; i < p->count; i++) {
        printf("\nPending #%zu  [UNCONFIRMED - waiting for a miner]\n", i + 1);
        block_print(&p->items[i], pub, 0);
    }
    printf("\n================================================================\n");
}
