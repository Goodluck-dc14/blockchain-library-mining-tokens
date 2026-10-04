/*
 * account.c - account-balance model implementation.
 */
#include "account.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_utils.h"
#include "util.h"

int account_book_init(AccountBook *ab, const MemberRegistry *members)
{
    ab->count = members->count;
    ab->system_nonce = 0;
    ab->items = calloc(members->count, sizeof *ab->items);
    if (!ab->items)
        return -1;
    /* one account per registered member, all starting at 0 */
    for (size_t i = 0; i < members->count; i++)
        safe_copy(ab->items[i].member_id, sizeof ab->items[i].member_id, members->items[i].member_id);
    return 0;
}

void account_book_free(AccountBook *ab)
{
    for (size_t i = 0; i < ab->count; i++) {
        TxRecord *r = ab->items[i].head;
        while (r) {
            TxRecord *next = r->next;
            free(r);
            r = next;
        }
    }
    free(ab->items);
    ab->items = NULL;
    ab->count = 0;
}

Account *account_find(AccountBook *ab, const char *member_id)
{
    for (size_t i = 0; i < ab->count; i++)
        if (strcmp(ab->items[i].member_id, member_id) == 0)
            return &ab->items[i];
    return NULL;
}

/* Appends one entry to an account's linked-list history. */
static int history_append(Account *a, const char *txid, const char *sender, const char *recipient,
                          long amount, long fee, unsigned long nonce, time_t ts)
{
    TxRecord *r = calloc(1, sizeof *r);
    if (!r) {
        fprintf(stderr, "ERROR: Out of memory recording transaction history.\n");
        return -1;
    }
    safe_copy(r->txid, sizeof r->txid, txid);
    safe_copy(r->sender, sizeof r->sender, sender);
    safe_copy(r->recipient, sizeof r->recipient, recipient);
    r->amount = amount;
    r->fee = fee;
    r->nonce = nonce;
    r->ts = ts;
    if (a->tail)
        a->tail->next = r;
    else
        a->head = r;
    a->tail = r;
    a->tx_count++;
    return 0;
}

int account_credit_reward(AccountBook *ab, const char *member_id, long gross, long fee,
                          const char *txid, time_t ts)
{
    Account *a = account_find(ab, member_id);
    if (!a) {
        fprintf(stderr, "ERROR: No account for member %s.\n", member_id);
        return -1;
    }
    if (gross <= fee)
        return 0;
    a->balance += gross - fee;
    return history_append(a, txid, SYSTEM_ACCOUNT, member_id, gross - fee, fee, ab->system_nonce++, ts);
}

int account_check_transfer(AccountBook *ab, const char *sender, const char *recipient,
                           long amount, long fee, unsigned long nonce, char *err, size_t errn)
{
    Account *s = account_find(ab, sender);
    Account *r = account_find(ab, recipient);
    if (!s || !r) {
        snprintf(err, errn, "unknown account %s", !s ? sender : recipient);
        return -1;
    }
    if (strcmp(sender, recipient) == 0) {
        snprintf(err, errn, "sender and recipient must be different");
        return -1;
    }
    if (amount <= 0) {
        snprintf(err, errn, "amount must be greater than 0");
        return -1;
    }
    if (nonce != s->nonce) {
        snprintf(err, errn, "%s: nonce %lu given, but %s's next nonce is %lu%s",
                 nonce < s->nonce ? "REUSED NONCE" : "INCORRECT NONCE", nonce, sender, s->nonce,
                 nonce < s->nonce ? " (already used, possible replay)" : "");
        return -1;
    }
    if (s->balance < amount + fee) {
        snprintf(err, errn, "INSUFFICIENT BALANCE: %s has %ld, needs %ld (%ld + %ld fee)",
                 sender, s->balance, amount + fee, amount, fee);
        return -1;
    }
    return 0;
}

int account_apply_transfer(AccountBook *ab, const char *sender, const char *recipient,
                           long amount, long fee, unsigned long nonce, time_t ts)
{
    Account *s = account_find(ab, sender);
    Account *r = account_find(ab, recipient);
    char buf[256], txid[HASH_HEX_LEN];
    if (!s || !r)
        return -1;

    int w = snprintf(buf, sizeof buf, "ACCT|%s|%s|%ld|%ld|%lu|%lld", sender, recipient, amount, fee,
                     nonce, (long long)ts);
    if (w < 0 || sha256_hex(buf, (size_t)w, txid) != 0)
        return -1;

    s->balance -= amount + fee;   /* debit */
    r->balance += amount;         /* credit */
    s->nonce++;
    if (history_append(s, txid, sender, recipient, amount, fee, nonce, ts) != 0 ||
        history_append(r, txid, sender, recipient, amount, fee, nonce, ts) != 0)
        return -1;
    return 0;
}

void account_print_balances(const AccountBook *ab)
{
    printf("\n  ACCOUNT BALANCES\n");
    printf("  +----------+---------+-------+--------------+\n");
    printf("  | Member   | Balance | Nonce | Transactions |\n");
    printf("  +----------+---------+-------+--------------+\n");
    for (size_t i = 0; i < ab->count; i++)
        printf("  | %-8s | %7ld | %5lu | %12zu |\n", ab->items[i].member_id, ab->items[i].balance,
               ab->items[i].nonce, ab->items[i].tx_count);
    printf("  +----------+---------+-------+--------------+\n");
}

int account_print_history(AccountBook *ab, const char *member_id)
{
    char when[32];
    Account *a = account_find(ab, member_id);
    if (!a) {
        printf("ERROR: No account for %s.\n", member_id);
        return -1;
    }
    printf("\n  TRANSACTION HISTORY for %s (balance %ld, next nonce %lu)\n", member_id, a->balance, a->nonce);
    printf("  %-19s  %-8s  %-8s  %6s  %3s  %5s  %s\n", "Time", "Sender", "Recipient", "Amount", "Fee",
           "Nonce", "Tx ID");
    if (!a->head)
        printf("  (no transactions yet)\n");
    for (TxRecord *r = a->head; r; r = r->next) {
        format_time(r->ts, when, sizeof when);
        printf("  %-19s  %-8s  %-8s  %6ld  %3ld  %5lu  %.12s...\n", when, r->sender, r->recipient,
               r->amount, r->fee, r->nonce, r->txid);
    }
    return 0;
}
