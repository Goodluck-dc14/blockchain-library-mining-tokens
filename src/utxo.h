/*
 * utxo.h - UTXO (unspent transaction output) token model.
 *
 * Coins are not stored as balances. Each transaction consumes earlier
 * outputs (inputs) and creates new outputs. A member's balance is the sum
 * of the unspent outputs they own.
 */
#ifndef UTXO_H
#define UTXO_H

#include <stddef.h>
#include <time.h>

#include "common.h"

#define TX_MAX_INPUTS 64

typedef struct {
    char txid[HASH_HEX_LEN];   /* transaction that created this output */
    int  vout;                 /* output number inside that transaction */
    char owner[ID_LEN];        /* member ID that can spend it */
    long amount;
} Utxo;

typedef struct {
    Utxo  *items;
    size_t count;
    size_t cap;
} UtxoSet;

typedef struct {
    char txid[HASH_HEX_LEN];
    int  vout;
} TxInput;

typedef struct {
    char owner[ID_LEN];
    long amount;
} TxOutput;

typedef struct {
    char     txid[HASH_HEX_LEN];
    char     sender[ID_LEN];
    time_t   ts;
    TxInput  in[TX_MAX_INPUTS];
    int      n_in;
    TxOutput out[2];           /* [0] = payment, [1] = change back to sender */
    int      n_out;
    long     fee;
} UtxoTx;

void utxo_init(UtxoSet *s);
void utxo_free(UtxoSet *s);
int  utxo_copy(UtxoSet *dst, const UtxoSet *src);

/* Reward transaction: no inputs, one output to the member. */
int  utxo_add_coinbase(UtxoSet *s, const char *txid, const char *owner, long amount);

/* Picks the sender's UTXOs, adds change, computes the txid. Does not change the set. */
int  utxo_build_transfer(const UtxoSet *s, const char *sender, const char *recipient,
                         long amount, long fee, time_t ts, UtxoTx *tx, char *err, size_t errn);
/* Full check: inputs exist and belong to sender, no double spend, inputs = outputs + fee. */
int  utxo_validate_tx(const UtxoSet *s, const UtxoTx *tx, char *err, size_t errn);
/* Removes the inputs and adds the outputs. Call only after validation. */
int  utxo_apply_tx(UtxoSet *s, const UtxoTx *tx);

long utxo_balance(const UtxoSet *s, const char *owner);
void utxo_print_set(const UtxoSet *s);
void utxo_print_owner(const UtxoSet *s, const char *owner);
void utxo_print_tx(const UtxoTx *tx);
/* Demonstrates double-spend rejection on a copy of the set. */
void utxo_double_spend_demo(const UtxoSet *s, const char *sender, const char *recipient);

#endif /* UTXO_H */
