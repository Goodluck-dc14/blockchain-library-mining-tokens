/*
 * blockchain.h - the confirmed lending chain: signing, proof-of-work
 * hashing, validation and persistence.
 */
#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include <openssl/evp.h>
#include <stddef.h>

#include "common.h"

typedef struct {
    Block *blocks;
    size_t count;
    size_t cap;
} Blockchain;

#define HASH_PREFIX_MAX 1024

void chain_init(Blockchain *c);
void chain_free(Blockchain *c);
int  chain_copy(Blockchain *dst, const Blockchain *src);

/* ---- lending records (signed by the librarian when the event happens) ---- */
/* Fills in a new unmined record and signs it. Returns 0 on success. */
int  record_create(Block *b, EVP_PKEY *priv, time_t when,
                   const char *book_id, const char *book_title,
                   const char *member_id, const char *member_name,
                   const char *action, int token_reward);
int  verify_block_signature(const Block *b, EVP_PKEY *pub);
/* SHA-256 id of the reward transaction linked to a RETURNED record. */
int  compute_reward_txid(const char *member_id, const char *book_id, int reward,
                         time_t when, char out[HASH_HEX_LEN]);
int  is_zero_hash(const char *h);

/* ---- proof-of-work ---- */
/* Sets index, previous_hash, difficulty and nonce = 0, ready for mining. */
void block_prepare(const Blockchain *c, Block *b, int difficulty);
/* Everything that goes into the hash except the nonce. Returns its length or -1. */
int  block_hash_prefix(const Block *b, char *buf, size_t n);
/* One mining attempt: set nonce, hash, return 1 if the target is met. */
int  pow_attempt(Block *b, const char *prefix, int prefix_len, unsigned long nonce);
int  hash_meets_difficulty(const char *hash, int difficulty);
int  compute_block_hash(const Block *b, char out[HASH_HEX_LEN]);

/* Appends a mined block after checking its index, link and proof-of-work. */
int  chain_push_mined(Blockchain *c, const Block *b);
void chain_pop(Blockchain *c);
/* Creates, signs and mines the genesis block. */
int  chain_create_genesis(Blockchain *c, EVP_PKEY *priv, int difficulty);

int  chain_save(const Blockchain *c, const char *path);
/* 0 = loaded, 1 = file does not exist, -1 = parse or read error */
int  chain_load(Blockchain *c, const char *path);

/* Returns the number of problems found (0 means valid). */
int  chain_validate(const Blockchain *c, EVP_PKEY *pub, int verbose);
void chain_print(const Blockchain *c, EVP_PKEY *pub);
void block_print(const Block *b, EVP_PKEY *pub, int mined);

/* Most recent confirmed BORROWED block for a book with no RETURNED after it. */
const Block *chain_active_loan(const Blockchain *c, const char *book_id);
/* 1 if the current loan for this book has already been flagged OVERDUE. */
int  chain_flagged_overdue(const Blockchain *c, const char *book_id);

/* Writes a file atomically: temp file, fsync, rename. */
int  atomic_write_begin(const char *path, char *tmp_path, size_t n, FILE **fp);
int  atomic_write_commit(FILE *fp, const char *tmp_path, const char *path);

#endif /* BLOCKCHAIN_H */
