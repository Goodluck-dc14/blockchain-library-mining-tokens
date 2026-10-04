/*
 * blockchain.c - core blockchain logic.
 *
 * Two layers of protection per block:
 *
 * 1. Signature (added when the lending event happens, by the librarian):
 *      timestamp|book_id|book_title|member_id|member_name|action|token_reward|tx_id
 *    This proves the record came from the librarian and was not altered.
 *
 * 2. Proof-of-work hash (added by a miner when the block is confirmed):
 *      SHA-256( index|<signed record>|previous_hash|signature_hex|difficulty|nonce )
 *    The miner increments nonce until the hash starts with `difficulty` zeros.
 *    previous_hash links the block to the one before it.
 */
#include "blockchain.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto_utils.h"
#include "util.h"

#define LINE_MAX_LEN 1024
#define FIELD_COUNT  14

static void zero_hash(char out[HASH_HEX_LEN])
{
    memset(out, '0', HASH_HEX_LEN - 1);
    out[HASH_HEX_LEN - 1] = '\0';
}

int is_zero_hash(const char *h)
{
    for (int i = 0; i < HASH_HEX_LEN - 1; i++)
        if (h[i] != '0')
            return 0;
    return h[HASH_HEX_LEN - 1] == '\0';
}

void chain_init(Blockchain *c)
{
    c->blocks = NULL;
    c->count = 0;
    c->cap = 0;
}

void chain_free(Blockchain *c)
{
    free(c->blocks);
    chain_init(c);
}

int chain_copy(Blockchain *dst, const Blockchain *src)
{
    chain_init(dst);
    if (src->count == 0)
        return 0;
    dst->blocks = malloc(src->count * sizeof *dst->blocks);
    if (!dst->blocks)
        return -1;
    memcpy(dst->blocks, src->blocks, src->count * sizeof *dst->blocks);
    dst->count = dst->cap = src->count;
    return 0;
}

/* ---------------------------------------------------------------- records */

static int record_payload(const Block *b, char *buf, size_t n)
{
    int w = snprintf(buf, n, "%lld|%s|%s|%s|%s|%s|%d|%s",
                     (long long)b->timestamp, b->book_id, b->book_title,
                     b->member_id, b->member_name, b->action, b->token_reward, b->tx_id);
    return (w < 0 || (size_t)w >= n) ? -1 : w;
}

int compute_reward_txid(const char *member_id, const char *book_id, int reward,
                        time_t when, char out[HASH_HEX_LEN])
{
    char buf[256];
    int w = snprintf(buf, sizeof buf, "REWARD|%s|%s|%s|%d|%d|%lld",
                     SYSTEM_ACCOUNT, member_id, book_id, reward, TX_FEE, (long long)when);
    if (w < 0 || (size_t)w >= sizeof buf)
        return -1;
    return sha256_hex(buf, (size_t)w, out);
}

int record_create(Block *b, EVP_PKEY *priv, time_t when,
                  const char *book_id, const char *book_title,
                  const char *member_id, const char *member_name,
                  const char *action, int token_reward)
{
    char payload[LINE_MAX_LEN];

    memset(b, 0, sizeof *b);
    b->timestamp = when;
    b->token_reward = token_reward;
    if (safe_copy(b->book_id, sizeof b->book_id, book_id) != 0 ||
        safe_copy(b->book_title, sizeof b->book_title, book_title) != 0 ||
        safe_copy(b->member_id, sizeof b->member_id, member_id) != 0 ||
        safe_copy(b->member_name, sizeof b->member_name, member_name) != 0 ||
        safe_copy(b->action, sizeof b->action, action) != 0) {
        fprintf(stderr, "ERROR: A record field is too long.\n");
        return -1;
    }
    /* Only a reward creates a transaction; everything else gets a zero id */
    if (token_reward > 0) {
        if (compute_reward_txid(member_id, book_id, token_reward, when, b->tx_id) != 0)
            return -1;
    } else {
        zero_hash(b->tx_id);
    }
    zero_hash(b->previous_hash);
    zero_hash(b->hash);

    int w = record_payload(b, payload, sizeof payload);
    if (w < 0 || !priv ||
        sign_data(priv, (const unsigned char *)payload, (size_t)w, b->signature, &b->sig_len) != 0) {
        fprintf(stderr, "ERROR: Could not sign the lending record.\n");
        return -1;
    }
    return 0;
}

int verify_block_signature(const Block *b, EVP_PKEY *pub)
{
    char buf[LINE_MAX_LEN];
    int w = record_payload(b, buf, sizeof buf);
    if (w < 0)
        return 0;
    return verify_signature(pub, (const unsigned char *)buf, (size_t)w, b->signature, b->sig_len);
}

/* ---------------------------------------------------------------- proof-of-work */

void block_prepare(const Blockchain *c, Block *b, int difficulty)
{
    b->index = (int)c->count;
    if (c->count == 0)
        zero_hash(b->previous_hash);
    else
        memcpy(b->previous_hash, c->blocks[c->count - 1].hash, HASH_HEX_LEN);
    b->difficulty = difficulty;
    b->nonce = 0;
    zero_hash(b->hash);
}

int block_hash_prefix(const Block *b, char *buf, size_t n)
{
    char sig_hex[2 * SIG_MAX_LEN + 1];
    if (b->sig_len > SIG_MAX_LEN)
        return -1;
    bytes_to_hex(b->signature, b->sig_len, sig_hex);
    int w = snprintf(buf, n, "%d|%lld|%s|%s|%s|%s|%s|%d|%s|%s|%s|%d|",
                     b->index, (long long)b->timestamp, b->book_id, b->book_title,
                     b->member_id, b->member_name, b->action, b->token_reward, b->tx_id,
                     b->previous_hash, sig_hex, b->difficulty);
    return (w < 0 || (size_t)w >= n - 24) ? -1 : w;   /* leave room for the nonce */
}

int hash_meets_difficulty(const char *hash, int difficulty)
{
    for (int i = 0; i < difficulty; i++)
        if (hash[i] != '0')
            return 0;
    return 1;
}

/* The prefix buffer must have room for the nonce digits after prefix_len. */
int pow_attempt(Block *b, const char *prefix, int prefix_len, unsigned long nonce)
{
    char buf[HASH_PREFIX_MAX];
    memcpy(buf, prefix, (size_t)prefix_len);
    int w = snprintf(buf + prefix_len, sizeof buf - (size_t)prefix_len, "%lu", nonce);
    b->nonce = nonce;
    if (sha256_hex(buf, (size_t)(prefix_len + w), b->hash) != 0)
        return 0;
    return hash_meets_difficulty(b->hash, b->difficulty);
}

int compute_block_hash(const Block *b, char out[HASH_HEX_LEN])
{
    char buf[HASH_PREFIX_MAX];
    int w = block_hash_prefix(b, buf, sizeof buf);
    if (w < 0)
        return -1;
    int w2 = snprintf(buf + w, sizeof buf - (size_t)w, "%lu", b->nonce);
    return sha256_hex(buf, (size_t)(w + w2), out);
}

/* ---------------------------------------------------------------- chain ops */

static int chain_push(Blockchain *c, const Block *b)
{
    if (c->count == c->cap) {
        size_t new_cap = c->cap ? c->cap * 2 : 16;
        Block *tmp = realloc(c->blocks, new_cap * sizeof *tmp);
        if (!tmp) {
            fprintf(stderr, "ERROR: Out of memory growing the chain.\n");
            return -1;
        }
        c->blocks = tmp;
        c->cap = new_cap;
    }
    c->blocks[c->count++] = *b;
    return 0;
}

int chain_push_mined(Blockchain *c, const Block *b)
{
    char calc[HASH_HEX_LEN];
    const char *expected_prev = c->count ? c->blocks[c->count - 1].hash : NULL;

    if (b->index != (int)c->count ||
        (expected_prev && strcmp(b->previous_hash, expected_prev) != 0) ||
        (!expected_prev && !is_zero_hash(b->previous_hash))) {
        fprintf(stderr, "ERROR: Mined block does not link to the end of the chain.\n");
        return -1;
    }
    if (compute_block_hash(b, calc) != 0 || strcmp(calc, b->hash) != 0 ||
        !hash_meets_difficulty(b->hash, b->difficulty)) {
        fprintf(stderr, "ERROR: Mined block has an invalid proof-of-work.\n");
        return -1;
    }
    return chain_push(c, b);
}

void chain_pop(Blockchain *c)
{
    if (c->count > 0)
        c->count--;
}

int chain_create_genesis(Blockchain *c, EVP_PKEY *priv, int difficulty)
{
    Block g;
    char prefix[HASH_PREFIX_MAX];

    if (record_create(&g, priv, time(NULL), "GENESIS", "Genesis Block", "SYSTEM", "System",
                      "GENESIS", 0) != 0)
        return -1;
    block_prepare(c, &g, difficulty);
    int plen = block_hash_prefix(&g, prefix, sizeof prefix);
    if (plen < 0)
        return -1;
    for (unsigned long nonce = 0;; nonce++)
        if (pow_attempt(&g, prefix, plen, nonce))
            break;
    return chain_push_mined(c, &g);
}

/* ---------------------------------------------------------------- persistence */

int atomic_write_begin(const char *path, char *tmp_path, size_t n, FILE **fp)
{
    snprintf(tmp_path, n, "%s.tmp", path);
    *fp = fopen(tmp_path, "w");
    if (!*fp) {
        perror(tmp_path);
        return -1;
    }
    return 0;
}

int atomic_write_commit(FILE *fp, const char *tmp_path, const char *path)
{
    int ok = (fflush(fp) == 0 && fsync(fileno(fp)) == 0);
    if (fclose(fp) != 0)
        ok = 0;
    if (!ok || rename(tmp_path, path) != 0) {
        fprintf(stderr, "ERROR: Failed to save %s (%s).\n", path, strerror(errno));
        unlink(tmp_path);
        return -1;
    }
    return 0;
}

int chain_save(const Blockchain *c, const char *path)
{
    char tmp_path[512], sig_hex[2 * SIG_MAX_LEN + 1];
    FILE *fp;

    if (atomic_write_begin(path, tmp_path, sizeof tmp_path, &fp) != 0)
        return -1;
    int ok = fprintf(fp, "# LIBCHAIN v2: index|timestamp|book_id|book_title|member_id|member_name|"
                         "action|token_reward|tx_id|previous_hash|difficulty|nonce|signature_hex|hash\n") > 0;
    for (size_t i = 0; ok && i < c->count; i++) {
        const Block *b = &c->blocks[i];
        bytes_to_hex(b->signature, b->sig_len, sig_hex);
        ok = fprintf(fp, "%d|%lld|%s|%s|%s|%s|%s|%d|%s|%s|%d|%lu|%s|%s\n",
                     b->index, (long long)b->timestamp, b->book_id, b->book_title,
                     b->member_id, b->member_name, b->action, b->token_reward, b->tx_id,
                     b->previous_hash, b->difficulty, b->nonce, sig_hex, b->hash) > 0;
    }
    if (!ok) {
        fclose(fp);
        unlink(tmp_path);
        fprintf(stderr, "ERROR: Failed writing %s.\n", path);
        return -1;
    }
    return atomic_write_commit(fp, tmp_path, path);
}

static int parse_ll(const char *s, long long min, long long max, long long *out)
{
    char *end;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno || end == s || *end != '\0' || v < min || v > max)
        return -1;
    *out = v;
    return 0;
}

static int parse_ul(const char *s, unsigned long *out)
{
    char *end;
    if (*s == '-' || *s == '\0')
        return -1;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || *end != '\0')
        return -1;
    *out = v;
    return 0;
}

int chain_load(Blockchain *c, const char *path)
{
    chain_init(c);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (errno == ENOENT)
            return 1;
        perror(path);
        return -1;
    }

    char line[LINE_MAX_LEN];
    int line_no = 0;
    while (fgets(line, sizeof line, fp)) {
        line_no++;
        if (!strchr(line, '\n') && !feof(fp)) {
            fprintf(stderr, "ERROR: %s line %d is too long.\n", path, line_no);
            goto fail;
        }
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;

        char *f[FIELD_COUNT];
        int nf = split_fields(line, '|', f, FIELD_COUNT);
        if (nf != FIELD_COUNT) {
            fprintf(stderr, "ERROR: %s line %d: expected %d fields, found %d.\n",
                    path, line_no, FIELD_COUNT, nf > FIELD_COUNT ? FIELD_COUNT + 1 : nf);
            goto fail;
        }

        Block b;
        long long idx, ts, reward, diff;
        size_t sig_len = 0;
        memset(&b, 0, sizeof b);
        if (parse_ll(f[0], 0, INT_MAX, &idx) != 0 || parse_ll(f[1], 0, LLONG_MAX, &ts) != 0 ||
            parse_ll(f[7], 0, 1000, &reward) != 0 || parse_ll(f[10], 0, 64, &diff) != 0 ||
            parse_ul(f[11], &b.nonce) != 0) {
            fprintf(stderr, "ERROR: %s line %d: bad number field.\n", path, line_no);
            goto fail;
        }
        b.index = (int)idx;
        b.timestamp = (time_t)ts;
        b.token_reward = (int)reward;
        b.difficulty = (int)diff;
        if (safe_copy(b.book_id, sizeof b.book_id, f[2]) != 0 ||
            safe_copy(b.book_title, sizeof b.book_title, f[3]) != 0 ||
            safe_copy(b.member_id, sizeof b.member_id, f[4]) != 0 ||
            safe_copy(b.member_name, sizeof b.member_name, f[5]) != 0 ||
            safe_copy(b.action, sizeof b.action, f[6]) != 0 ||
            safe_copy(b.tx_id, sizeof b.tx_id, f[8]) != 0 ||
            safe_copy(b.previous_hash, sizeof b.previous_hash, f[9]) != 0 ||
            safe_copy(b.hash, sizeof b.hash, f[13]) != 0) {
            fprintf(stderr, "ERROR: %s line %d: a field is too long.\n", path, line_no);
            goto fail;
        }
        if (hex_to_bytes(f[12], b.signature, SIG_MAX_LEN, &sig_len) != 0) {
            fprintf(stderr, "ERROR: %s line %d: signature is not valid hex.\n", path, line_no);
            goto fail;
        }
        b.sig_len = (unsigned int)sig_len;
        if (chain_push(c, &b) != 0)
            goto fail;
    }
    fclose(fp);
    return 0;

fail:
    fclose(fp);
    chain_free(c);
    return -1;
}

/* ---------------------------------------------------------------- validation */

static int valid_action(const char *action, int is_genesis)
{
    if (is_genesis)
        return strcmp(action, "GENESIS") == 0;
    return strcmp(action, "BORROWED") == 0 || strcmp(action, "RETURNED") == 0 ||
           strcmp(action, "OVERDUE") == 0;
}

/* Rewards only on RETURNED (10 or 5); tx_id must match the reward exactly. */
static const char *reward_problem(const Block *b)
{
    char expected[HASH_HEX_LEN];
    if (strcmp(b->action, "RETURNED") == 0) {
        if (b->token_reward != REWARD_ON_TIME && b->token_reward != REWARD_LATE)
            return "RETURNED block must carry a reward of 10 or 5";
        if (compute_reward_txid(b->member_id, b->book_id, b->token_reward, b->timestamp, expected) != 0 ||
            strcmp(expected, b->tx_id) != 0)
            return "tx_id does not match the reward transaction";
        return NULL;
    }
    if (b->token_reward != 0)
        return "only RETURNED blocks may carry a token reward";
    if (!is_zero_hash(b->tx_id))
        return "a block without a reward must not have a tx_id";
    return NULL;
}

int chain_validate(const Blockchain *c, EVP_PKEY *pub, int verbose)
{
    char zeros[HASH_HEX_LEN];
    int problems = 0;

    if (c->count == 0) {
        printf("Chain is empty: nothing to validate.\n");
        return 0;
    }
    zero_hash(zeros);
    if (verbose)
        printf("\nValidating %zu block(s): hash, link, proof-of-work, signature and reward checks...\n",
               c->count);

    for (size_t i = 0; i < c->count; i++) {
        const Block *b = &c->blocks[i];
        char calc[HASH_HEX_LEN] = {0};
        const char *why;
        int bad = 0;

        if (b->index != (int)i) {
            printf("  [FAIL] Block #%zu: index field says %d\n", i, b->index);
            bad++;
        }
        /* (a) stored hash must match a fresh hash of the contents */
        if (compute_block_hash(b, calc) != 0) {
            printf("  [FAIL] Block #%zu: could not compute hash\n", i);
            bad++;
        } else if (strcmp(calc, b->hash) != 0) {
            printf("  [FAIL] Block #%zu: HASH MISMATCH\n", i);
            printf("         stored:     %s\n", b->hash);
            printf("         recomputed: %s\n", calc);
            bad++;
        }
        /* (b) previous_hash must match the preceding block */
        const char *expected = (i == 0) ? zeros : c->blocks[i - 1].hash;
        if (strcmp(b->previous_hash, expected) != 0) {
            printf("  [FAIL] Block #%zu: BROKEN LINK, previous_hash does not match %s\n", i,
                   i == 0 ? "64 zeros" : "the block before it");
            bad++;
        }
        /* (c) proof-of-work: the hash of the block AS IT IS NOW must meet the target.
         *     Editing any field changes that hash, so the old work no longer counts. */
        if (b->difficulty < MIN_DIFFICULTY || b->difficulty > MAX_DIFFICULTY ||
            !hash_meets_difficulty(b->hash, b->difficulty) ||
            (calc[0] && !hash_meets_difficulty(calc, b->difficulty))) {
            printf("  [FAIL] Block #%zu: PROOF-OF-WORK FAILED (hash must start with %d zero(s))\n",
                   i, b->difficulty);
            bad++;
        }
        /* (d) the librarian's signature must verify */
        if (verify_block_signature(b, pub) != 1) {
            printf("  [FAIL] Block #%zu: INVALID SIGNATURE, record was not signed by the librarian\n", i);
            bad++;
        }
        if (!valid_action(b->action, i == 0)) {
            printf("  [FAIL] Block #%zu: INVALID ACTION '%s'\n", i, b->action);
            bad++;
        }
        if (i > 0 && (why = reward_problem(b)) != NULL) {
            printf("  [FAIL] Block #%zu: BAD REWARD, %s\n", i, why);
            bad++;
        }
        if (!bad && verbose)
            printf("  [ OK ] Block #%-3zu %-8s reward %-2d  diff %d  nonce %-7lu hash %.14s...\n",
                   i, b->action, b->token_reward, b->difficulty, b->nonce, b->hash);
        problems += bad;
    }

    if (problems == 0)
        printf("CHAIN VALID: all %zu block(s) passed hash, link, proof-of-work and signature checks.\n",
               c->count);
    else
        printf("CHAIN INVALID: %d problem(s) found. The ledger has been tampered with.\n", problems);
    return problems;
}

void block_print(const Block *b, EVP_PKEY *pub, int mined)
{
    char when[32], sig_hex[2 * SIG_MAX_LEN + 1];
    format_time(b->timestamp, when, sizeof when);
    bytes_to_hex(b->signature, b->sig_len, sig_hex);

    if (mined)
        printf("\nBlock #%d%s\n", b->index, b->index == 0 ? "  (Genesis Block)" : "");
    printf("  Timestamp     : %s\n", when);
    printf("  Book          : %s - %s\n", b->book_id, b->book_title);
    printf("  Member        : %s - %s\n", b->member_id, b->member_name);
    printf("  Action        : %s\n", b->action);
    printf("  Token reward  : %d%s\n", b->token_reward,
           b->token_reward == REWARD_ON_TIME ? " (returned on time)" :
           b->token_reward == REWARD_LATE ? " (returned late)" : " (no transaction)");
    if (b->token_reward > 0)
        printf("  Tx ID         : %s\n", b->tx_id);
    if (mined) {
        printf("  Previous hash : %s\n", b->previous_hash);
        printf("  Hash          : %s\n", b->hash);
        printf("  Proof-of-work : difficulty %d, nonce %lu\n", b->difficulty, b->nonce);
    }
    printf("  Signature     : %.24s... (%u bytes)  %s\n", sig_hex, b->sig_len,
           verify_block_signature(b, pub) ? "VALID" : "INVALID");
}

void chain_print(const Blockchain *c, EVP_PKEY *pub)
{
    if (c->count == 0) {
        printf("No confirmed records yet.\n");
        return;
    }
    printf("\n============ CONFIRMED LENDING RECORDS (%zu blocks) ============\n", c->count);
    for (size_t i = 0; i < c->count; i++)
        block_print(&c->blocks[i], pub, 1);
    printf("\n================================================================\n");
}

/* ---------------------------------------------------------------- loan queries */

const Block *chain_active_loan(const Blockchain *c, const char *book_id)
{
    for (size_t i = c->count; i-- > 1;) {
        const Block *b = &c->blocks[i];
        if (strcmp(b->book_id, book_id) != 0)
            continue;
        if (strcmp(b->action, "RETURNED") == 0)
            return NULL;
        if (strcmp(b->action, "BORROWED") == 0)
            return b;
        /* OVERDUE: the book is still out, keep looking for its BORROWED block */
    }
    return NULL;
}

int chain_flagged_overdue(const Blockchain *c, const char *book_id)
{
    for (size_t i = c->count; i-- > 1;) {
        const Block *b = &c->blocks[i];
        if (strcmp(b->book_id, book_id) == 0)
            return strcmp(b->action, "OVERDUE") == 0;
    }
    return 0;
}
