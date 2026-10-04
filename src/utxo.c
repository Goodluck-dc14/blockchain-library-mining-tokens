/*
 * utxo.c - UTXO model implementation.
 */
#include "utxo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_utils.h"
#include "util.h"

void utxo_init(UtxoSet *s)
{
    s->items = NULL;
    s->count = 0;
    s->cap = 0;
}

void utxo_free(UtxoSet *s)
{
    free(s->items);
    utxo_init(s);
}

int utxo_copy(UtxoSet *dst, const UtxoSet *src)
{
    utxo_init(dst);
    if (src->count == 0)
        return 0;
    dst->items = malloc(src->count * sizeof *dst->items);
    if (!dst->items)
        return -1;
    memcpy(dst->items, src->items, src->count * sizeof *dst->items);
    dst->count = dst->cap = src->count;
    return 0;
}

static int utxo_push(UtxoSet *s, const char *txid, int vout, const char *owner, long amount)
{
    if (s->count == s->cap) {
        size_t new_cap = s->cap ? s->cap * 2 : 16;
        Utxo *tmp = realloc(s->items, new_cap * sizeof *tmp);
        if (!tmp) {
            fprintf(stderr, "ERROR: Out of memory growing the UTXO set.\n");
            return -1;
        }
        s->items = tmp;
        s->cap = new_cap;
    }
    Utxo *u = &s->items[s->count++];
    memset(u, 0, sizeof *u);
    safe_copy(u->txid, sizeof u->txid, txid);
    safe_copy(u->owner, sizeof u->owner, owner);
    u->vout = vout;
    u->amount = amount;
    return 0;
}

static long find_utxo(const UtxoSet *s, const char *txid, int vout)
{
    for (size_t i = 0; i < s->count; i++)
        if (s->items[i].vout == vout && strcmp(s->items[i].txid, txid) == 0)
            return (long)i;
    return -1;
}

int utxo_add_coinbase(UtxoSet *s, const char *txid, const char *owner, long amount)
{
    if (amount <= 0)
        return 0;   /* nothing to credit */
    if (find_utxo(s, txid, 0) >= 0) {
        fprintf(stderr, "ERROR: Reward transaction %.16s... already credited.\n", txid);
        return -1;
    }
    return utxo_push(s, txid, 0, owner, amount);
}

static int compute_txid(UtxoTx *tx)
{
    char buf[8192];
    size_t len = 0;
    int w = snprintf(buf, sizeof buf, "TX|%s|%lld|fee=%ld|in:", tx->sender, (long long)tx->ts, tx->fee);
    if (w < 0)
        return -1;
    len = (size_t)w;
    for (int i = 0; i < tx->n_in && len < sizeof buf; i++) {
        w = snprintf(buf + len, sizeof buf - len, "%s:%d,", tx->in[i].txid, tx->in[i].vout);
        if (w < 0)
            return -1;
        len += (size_t)w;
    }
    for (int i = 0; i < tx->n_out && len < sizeof buf; i++) {
        w = snprintf(buf + len, sizeof buf - len, "|out:%s:%ld", tx->out[i].owner, tx->out[i].amount);
        if (w < 0)
            return -1;
        len += (size_t)w;
    }
    if (len >= sizeof buf)
        return -1;
    return sha256_hex(buf, len, tx->txid);
}

int utxo_build_transfer(const UtxoSet *s, const char *sender, const char *recipient,
                        long amount, long fee, time_t ts, UtxoTx *tx, char *err, size_t errn)
{
    long gathered = 0, needed = amount + fee;

    memset(tx, 0, sizeof *tx);
    safe_copy(tx->sender, sizeof tx->sender, sender);
    tx->ts = ts;
    tx->fee = fee;
    if (amount <= 0) {
        snprintf(err, errn, "amount must be greater than 0");
        return -1;
    }

    /* Coin selection: take the sender's outputs, oldest first, until we have enough */
    for (size_t i = 0; i < s->count && gathered < needed; i++) {
        if (strcmp(s->items[i].owner, sender) != 0)
            continue;
        if (tx->n_in == TX_MAX_INPUTS) {
            snprintf(err, errn, "too many small inputs needed (max %d)", TX_MAX_INPUTS);
            return -1;
        }
        safe_copy(tx->in[tx->n_in].txid, sizeof tx->in[0].txid, s->items[i].txid);
        tx->in[tx->n_in].vout = s->items[i].vout;
        tx->n_in++;
        gathered += s->items[i].amount;
    }
    if (gathered < needed) {
        snprintf(err, errn, "INSUFFICIENT INPUTS: %s has %ld coin(s) in UTXOs, needs %ld (%ld + %ld fee)",
                 sender, gathered, needed, amount, fee);
        return -1;
    }

    /* Output 0 pays the recipient; output 1 returns any excess to the sender as change */
    safe_copy(tx->out[0].owner, sizeof tx->out[0].owner, recipient);
    tx->out[0].amount = amount;
    tx->n_out = 1;
    if (gathered > needed) {
        safe_copy(tx->out[1].owner, sizeof tx->out[1].owner, sender);
        tx->out[1].amount = gathered - needed;
        tx->n_out = 2;
    }
    if (compute_txid(tx) != 0) {
        snprintf(err, errn, "could not hash the transaction");
        return -1;
    }
    return utxo_validate_tx(s, tx, err, errn);
}

int utxo_validate_tx(const UtxoSet *s, const UtxoTx *tx, char *err, size_t errn)
{
    long in_sum = 0, out_sum = 0;

    if (tx->n_in <= 0) {
        snprintf(err, errn, "a transfer must spend at least one input");
        return -1;
    }
    for (int i = 0; i < tx->n_in; i++) {
        /* the same output listed twice inside one transaction is also a double spend */
        for (int j = 0; j < i; j++)
            if (tx->in[j].vout == tx->in[i].vout && strcmp(tx->in[j].txid, tx->in[i].txid) == 0) {
                snprintf(err, errn, "DOUBLE SPEND: input %.16s...:%d is used twice", tx->in[i].txid,
                         tx->in[i].vout);
                return -1;
            }
        long k = find_utxo(s, tx->in[i].txid, tx->in[i].vout);
        if (k < 0) {
            snprintf(err, errn, "DOUBLE SPEND: input %.16s...:%d is not in the UTXO set (already spent)",
                     tx->in[i].txid, tx->in[i].vout);
            return -1;
        }
        if (strcmp(s->items[k].owner, tx->sender) != 0) {
            snprintf(err, errn, "input %.16s...:%d belongs to %s, not %s", tx->in[i].txid,
                     tx->in[i].vout, s->items[k].owner, tx->sender);
            return -1;
        }
        in_sum += s->items[k].amount;
    }
    for (int i = 0; i < tx->n_out; i++) {
        if (tx->out[i].amount <= 0 || tx->out[i].owner[0] == '\0') {
            snprintf(err, errn, "output %d is invalid", i);
            return -1;
        }
        out_sum += tx->out[i].amount;
    }
    if (tx->fee < 0 || in_sum < out_sum + tx->fee) {
        snprintf(err, errn, "INSUFFICIENT INPUTS: inputs %ld < outputs %ld + fee %ld", in_sum, out_sum, tx->fee);
        return -1;
    }
    if (in_sum != out_sum + tx->fee) {
        snprintf(err, errn, "inputs %ld do not equal outputs %ld + fee %ld (missing change output)",
                 in_sum, out_sum, tx->fee);
        return -1;
    }
    return 0;
}

int utxo_apply_tx(UtxoSet *s, const UtxoTx *tx)
{
    for (int i = 0; i < tx->n_in; i++) {
        long k = find_utxo(s, tx->in[i].txid, tx->in[i].vout);
        if (k < 0)
            return -1;
        memmove(&s->items[k], &s->items[k + 1], (s->count - (size_t)k - 1) * sizeof *s->items);
        s->count--;
    }
    for (int i = 0; i < tx->n_out; i++)
        if (utxo_push(s, tx->txid, i, tx->out[i].owner, tx->out[i].amount) != 0)
            return -1;
    return 0;
}

long utxo_balance(const UtxoSet *s, const char *owner)
{
    long total = 0;
    for (size_t i = 0; i < s->count; i++)
        if (strcmp(s->items[i].owner, owner) == 0)
            total += s->items[i].amount;
    return total;
}

void utxo_print_set(const UtxoSet *s)
{
    long total = 0;
    printf("\n  UTXO SET (%zu unspent output(s))\n", s->count);
    printf("  +----------------------+------+----------+--------+\n");
    printf("  | Transaction ID       | vout | Owner    | Amount |\n");
    printf("  +----------------------+------+----------+--------+\n");
    for (size_t i = 0; i < s->count; i++) {
        printf("  | %.16s...  | %4d | %-8s | %6ld |\n", s->items[i].txid, s->items[i].vout,
               s->items[i].owner, s->items[i].amount);
        total += s->items[i].amount;
    }
    if (s->count == 0)
        printf("  | (empty)              |      |          |        |\n");
    printf("  +----------------------+------+----------+--------+\n");
    printf("  Total coins in circulation: %ld\n", total);
}

void utxo_print_owner(const UtxoSet *s, const char *owner)
{
    int n = 0;
    printf("\n  Unspent outputs owned by %s:\n", owner);
    for (size_t i = 0; i < s->count; i++)
        if (strcmp(s->items[i].owner, owner) == 0) {
            printf("    %.16s...:%d  %ld coin(s)\n", s->items[i].txid, s->items[i].vout, s->items[i].amount);
            n++;
        }
    if (!n)
        printf("    (none)\n");
    printf("  Balance: %ld coin(s)\n", utxo_balance(s, owner));
}

void utxo_print_tx(const UtxoTx *tx)
{
    printf("  Transaction %.16s...\n", tx->txid);
    for (int i = 0; i < tx->n_in; i++)
        printf("    input  %d: %.16s...:%d\n", i, tx->in[i].txid, tx->in[i].vout);
    for (int i = 0; i < tx->n_out; i++)
        printf("    output %d: %ld coin(s) -> %s%s\n", i, tx->out[i].amount, tx->out[i].owner,
               i == 1 ? "  (change)" : "");
    printf("    fee     : %ld coin(s)\n", tx->fee);
}

void utxo_double_spend_demo(const UtxoSet *s, const char *sender, const char *recipient)
{
    UtxoSet copy;
    UtxoTx tx1, tx2;
    char err[256];

    printf("\n--- Double-spend test (runs on a COPY of the UTXO set) ---\n");
    if (utxo_copy(&copy, s) != 0) {
        printf("ERROR: Out of memory.\n");
        return;
    }
    if (utxo_build_transfer(&copy, sender, recipient, 1, TX_FEE, time(NULL), &tx1, err, sizeof err) != 0) {
        printf("Cannot run the test: %s.\n%s needs at least %d coins. Mine a return first.\n",
               err, sender, 1 + TX_FEE);
        utxo_free(&copy);
        return;
    }
    printf("Step 1: %s sends 1 coin to %s.\n", sender, recipient);
    utxo_print_tx(&tx1);
    utxo_apply_tx(&copy, &tx1);
    printf("  ACCEPTED. Its inputs are now spent and removed from the UTXO set.\n");

    /* Step 2: same inputs again, different payment: a classic double spend */
    tx2 = tx1;
    tx2.ts = tx1.ts + 1;
    tx2.out[0].amount = 1;
    safe_copy(tx2.out[0].owner, sizeof tx2.out[0].owner, sender);
    compute_txid(&tx2);
    printf("\nStep 2: %s tries to spend the SAME input again, this time paying it back to themselves.\n", sender);
    utxo_print_tx(&tx2);
    if (utxo_validate_tx(&copy, &tx2, err, sizeof err) != 0)
        printf("  REJECTED: %s\n", err);
    else
        printf("  (unexpected) accepted\n");
    printf("\nThe real UTXO set is untouched.\n");
    utxo_free(&copy);
}
