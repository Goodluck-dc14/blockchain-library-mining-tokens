/*
 * ledger.c - dispatches token operations to the chosen model and keeps
 * the transfer log (transactions.dat) so balances survive a restart.
 *
 * Log format: timestamp|sender|recipient|amount|fee
 */
#include "ledger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

const char *ledger_model_name(LedgerModel m)
{
    return m == MODEL_UTXO ? "UTXO" : "Account-based";
}

int ledger_init(Ledger *l, LedgerModel model, const MemberRegistry *members)
{
    memset(l, 0, sizeof *l);
    l->model = model;
    utxo_init(&l->utxo);
    if (model == MODEL_ACCOUNT)
        return account_book_init(&l->acct, members);
    return 0;
}

void ledger_free(Ledger *l)
{
    utxo_free(&l->utxo);
    if (l->model == MODEL_ACCOUNT)
        account_book_free(&l->acct);
}

int ledger_apply_reward(Ledger *l, const Block *b)
{
    if (b->token_reward <= 0)
        return 0;   /* borrow and overdue blocks create no transaction */
    long credited = b->token_reward - TX_FEE;
    if (l->model == MODEL_UTXO)
        return utxo_add_coinbase(&l->utxo, b->tx_id, b->member_id, credited);
    return account_credit_reward(&l->acct, b->member_id, b->token_reward, TX_FEE, b->tx_id, b->timestamp);
}

static int log_append(const char *sender, const char *recipient, long amount, time_t ts)
{
    FILE *fp = fopen(TXLOG_FILE, "a");
    if (!fp) {
        perror(TXLOG_FILE);
        return -1;
    }
    int ok = fprintf(fp, "%lld|%s|%s|%ld|%d\n", (long long)ts, sender, recipient, amount, TX_FEE) > 0 &&
             fflush(fp) == 0 && fsync(fileno(fp)) == 0;
    if (fclose(fp) != 0)
        ok = 0;
    if (!ok)
        fprintf(stderr, "ERROR: Could not write the transfer log.\n");
    return ok ? 0 : -1;
}

int ledger_transfer(Ledger *l, const char *sender, const char *recipient, long amount,
                    long long nonce, time_t ts, int verbose, int write_log)
{
    char err[256];

    if (l->model == MODEL_UTXO) {
        UtxoTx tx;
        if (strcmp(sender, recipient) == 0) {
            if (verbose) printf("REJECTED: sender and recipient must be different.\n");
            return -1;
        }
        if (utxo_build_transfer(&l->utxo, sender, recipient, amount, TX_FEE, ts, &tx, err, sizeof err) != 0) {
            if (verbose) printf("REJECTED: %s\n", err);
            return -1;
        }
        if (write_log && log_append(sender, recipient, amount, ts) != 0)
            return -1;
        if (utxo_apply_tx(&l->utxo, &tx) != 0)
            return -1;
        if (verbose) {
            printf("ACCEPTED: %s sent %ld coin(s) to %s (fee %d).\n", sender, amount, recipient, TX_FEE);
            utxo_print_tx(&tx);
        }
        return 0;
    }

    Account *a = account_find(&l->acct, sender);
    unsigned long n = (nonce < 0 && a) ? a->nonce : (unsigned long)(nonce < 0 ? 0 : nonce);
    if (account_check_transfer(&l->acct, sender, recipient, amount, TX_FEE, n, err, sizeof err) != 0) {
        if (verbose) printf("REJECTED: %s\n", err);
        return -1;
    }
    if (write_log && log_append(sender, recipient, amount, ts) != 0)
        return -1;
    if (account_apply_transfer(&l->acct, sender, recipient, amount, TX_FEE, n, ts) != 0)
        return -1;
    if (verbose)
        printf("ACCEPTED: %s sent %ld coin(s) to %s (fee %d, nonce %lu). %s now has %ld, next nonce %lu.\n",
               sender, amount, recipient, TX_FEE, n, sender, a->balance, a->nonce);
    return 0;
}

int ledger_rebuild(Ledger *l, const Blockchain *c, const char *txlog_path)
{
    /* 1. rewards from every confirmed RETURNED block */
    for (size_t i = 1; i < c->count; i++)
        if (ledger_apply_reward(l, &c->blocks[i]) != 0)
            return -1;

    /* 2. replay confirmed member-to-member transfers in order */
    FILE *fp = fopen(txlog_path, "r");
    if (!fp)
        return 0;
    char line[256];
    int line_no = 0, bad = 0;
    while (fgets(line, sizeof line, fp)) {
        line_no++;
        line[strcspn(line, "\r\n")] = '\0';
        char *f[5];
        if (line[0] == '\0' || split_fields(line, '|', f, 5) != 5) {
            bad++;
            continue;
        }
        if (ledger_transfer(l, f[1], f[2], strtol(f[3], NULL, 10), -1, (time_t)strtoll(f[0], NULL, 10), 0, 0) != 0)
            bad++;
    }
    fclose(fp);
    if (bad)
        fprintf(stderr, "WARNING: %d transfer(s) in %s could not be replayed.\n", bad, txlog_path);
    return 0;
}

long ledger_balance(Ledger *l, const char *member_id)
{
    if (l->model == MODEL_UTXO)
        return utxo_balance(&l->utxo, member_id);
    Account *a = account_find(&l->acct, member_id);
    return a ? a->balance : 0;
}

void ledger_print(const Ledger *l)
{
    if (l->model == MODEL_UTXO)
        utxo_print_set(&l->utxo);
    else
        account_print_balances(&l->acct);
}

void ledger_history(Ledger *l, const char *member_id)
{
    if (l->model == MODEL_UTXO)
        utxo_print_owner(&l->utxo, member_id);
    else
        account_print_history(&l->acct, member_id);
}
