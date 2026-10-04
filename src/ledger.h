/*
 * ledger.h - one interface over the two token models.
 * The model is chosen once per session; everything else calls these functions.
 */
#ifndef LEDGER_H
#define LEDGER_H

#include "account.h"
#include "blockchain.h"
#include "common.h"
#include "registry.h"
#include "utxo.h"

typedef enum { MODEL_UTXO = 1, MODEL_ACCOUNT = 2 } LedgerModel;

typedef struct {
    LedgerModel model;
    UtxoSet     utxo;      /* used when model == MODEL_UTXO    */
    AccountBook acct;      /* used when model == MODEL_ACCOUNT */
} Ledger;

const char *ledger_model_name(LedgerModel m);
int  ledger_init(Ledger *l, LedgerModel model, const MemberRegistry *members);
void ledger_free(Ledger *l);

/* Credits the reward carried by a confirmed RETURNED block (minus the fee). */
int  ledger_apply_reward(Ledger *l, const Block *b);
/*
 * Member-to-member transfer. nonce < 0 means "use the account's next nonce"
 * (always the case for UTXO, and when replaying the log). Returns 0 on success.
 */
int  ledger_transfer(Ledger *l, const char *sender, const char *recipient, long amount,
                     long long nonce, time_t ts, int verbose, int write_log);
/* Rebuilds balances from the confirmed chain plus the transfer log. */
int  ledger_rebuild(Ledger *l, const Blockchain *c, const char *txlog_path);

long ledger_balance(Ledger *l, const char *member_id);
void ledger_print(const Ledger *l);
void ledger_history(Ledger *l, const char *member_id);

#endif /* LEDGER_H */
