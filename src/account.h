/*
 * account.h - account-balance token model.
 *
 * Each member is an account with a balance and a nonce. The nonce counts
 * the member's outgoing transactions; a transfer must quote the next nonce,
 * so a copied (replayed) or out-of-order transaction is rejected.
 * Every account keeps its own transaction history as a linked list.
 */
#ifndef ACCOUNT_H
#define ACCOUNT_H

#include <stddef.h>
#include <time.h>

#include "common.h"
#include "registry.h"

typedef struct TxRecord {
    char            txid[HASH_HEX_LEN];
    char            sender[ID_LEN];
    char            recipient[ID_LEN];
    long            amount;        /* coins the recipient received */
    long            fee;
    unsigned long   nonce;         /* sender's nonce for this transaction */
    time_t          ts;
    struct TxRecord *next;
} TxRecord;

typedef struct {
    char          member_id[ID_LEN];
    long          balance;
    unsigned long nonce;           /* next nonce this account must use */
    TxRecord     *head;            /* history, oldest first */
    TxRecord     *tail;
    size_t        tx_count;
} Account;

typedef struct {
    Account      *items;
    size_t        count;
    unsigned long system_nonce;    /* nonce of the LIBRARY reward account */
} AccountBook;

int      account_book_init(AccountBook *ab, const MemberRegistry *members);
void     account_book_free(AccountBook *ab);
Account *account_find(AccountBook *ab, const char *member_id);

/* Credits a confirmed reward: member receives gross - fee. */
int  account_credit_reward(AccountBook *ab, const char *member_id, long gross, long fee,
                           const char *txid, time_t ts);
/* Checks a transfer without changing anything. Returns 0 if valid. */
int  account_check_transfer(AccountBook *ab, const char *sender, const char *recipient,
                            long amount, long fee, unsigned long nonce, char *err, size_t errn);
/* Applies a checked transfer: debits amount + fee, credits amount, bumps nonce. */
int  account_apply_transfer(AccountBook *ab, const char *sender, const char *recipient,
                            long amount, long fee, unsigned long nonce, time_t ts);

void account_print_balances(const AccountBook *ab);
int  account_print_history(AccountBook *ab, const char *member_id);

#endif /* ACCOUNT_H */
