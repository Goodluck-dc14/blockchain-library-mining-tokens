/*
 * common.h - shared constants and data structures for the
 * Blockchain-Based Library Book Lending Tracker (Formative 2:
 * token rewards, transaction models and mining).
 */
#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <time.h>

/* ---------------------------------------------------------------- files */
#define BOOKS_FILE     "books.txt"
#define MEMBERS_FILE   "members.txt"
#define CHAIN_FILE     "chain.dat"          /* confirmed (mined) blocks          */
#define PENDING_FILE   "pending.dat"        /* signed blocks waiting to be mined */
#define TXLOG_FILE     "transactions.dat"   /* confirmed member-to-member transfers */
#define AUTH_FILE      "librarian.dat"
#define PRIV_KEY_FILE  "private_key.pem"
#define PUB_KEY_FILE   "public_key.pem"

/* ---------------------------------------------------------------- sizes */
#define HASH_HEX_LEN   65      /* 64 hex chars + '\0' for SHA-256 */
#define SIG_MAX_LEN    72      /* max DER size of an ECDSA P-256 signature */
#define ID_LEN         20

/* ---------------------------------------------------------------- lending */
#define DEFAULT_LOAN_PERIOD_SECONDS (14L * 24 * 60 * 60)   /* 14 days */

/* ---------------------------------------------------------------- tokens */
#define REWARD_ON_TIME   10    /* coins for a book returned on time    */
#define REWARD_LATE       5    /* coins for a book returned late       */
#define TX_FEE            1    /* fixed fee on every token transaction */
#define SYSTEM_ACCOUNT   "LIBRARY"   /* sender of reward transactions */

/* ---------------------------------------------------------------- mining */
#define DEFAULT_DIFFICULTY  2      /* leading '0' hex characters required */
#define MIN_DIFFICULTY      1
#define MAX_DIFFICULTY      4
#define BLOCK_REWARD       50.0    /* coins paid to whoever mines a block */
#define POOL_FEE_PERCENT    2.0    /* pool operator's cut                 */
#define POOL_MIN_HASHRATE  50      /* attempts per round per pool miner   */
#define POOL_MAX_HASHRATE 500
#define CLOUD_HASH_POWER  600      /* attempts per round for rented power */
#define CLOUD_RENTAL_FEE   20.0    /* coins per round                     */
#define CLOUD_MAINT_PERCENT 10.0   /* maintenance fee taken from rewards  */
#define CLOUD_MAX_ROUNDS    5

/* Registry record for a book (loaded from books.txt) */
typedef struct {
    char book_id[ID_LEN];
    char title[80];
    char author[50];
} Book;

/* Registry record for a library member (loaded from members.txt) */
typedef struct {
    char member_id[ID_LEN];
    char full_name[50];
    char course_code[10];
} Member;

/*
 * One block in the lending chain.
 * Formative 2 adds token_reward and tx_id (required), plus nonce and
 * difficulty, which proof-of-work needs.
 */
typedef struct {
    int           index;                     /* position in chain, 0 = genesis     */
    time_t        timestamp;                 /* when the lending event happened    */
    char          book_id[ID_LEN];
    char          book_title[80];            /* copied from the registry           */
    char          member_id[ID_LEN];
    char          member_name[50];           /* copied from the registry           */
    char          action[10];                /* BORROWED, RETURNED or OVERDUE      */
    int           token_reward;              /* 10 on time, 5 late, 0 otherwise    */
    char          tx_id[HASH_HEX_LEN];       /* SHA-256 of the reward transaction  */
    char          previous_hash[HASH_HEX_LEN];
    unsigned char signature[SIG_MAX_LEN];    /* librarian's ECDSA signature        */
    unsigned int  sig_len;                   /* DER signatures are 70-72 bytes     */
    int           difficulty;                /* leading zeros required by PoW      */
    unsigned long nonce;                     /* proof-of-work counter              */
    char          hash[HASH_HEX_LEN];        /* SHA-256 of everything above        */
} Block;

#endif /* COMMON_H */
