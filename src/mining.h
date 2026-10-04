/*
 * mining.h - proof-of-work mining simulations (solo, pool, cloud).
 * All three confirm blocks from the same pending pool.
 */
#ifndef MINING_H
#define MINING_H

#include <stddef.h>

#include "blockchain.h"
#include "common.h"
#include "pending.h"

/* Called once for every newly confirmed block (saves files, pays rewards). */
typedef int (*ConfirmFn)(const Block *b, void *ctx);

typedef struct {
    char          id[32];
    double        earned;        /* coins earned from mining this session */
    unsigned long attempts;      /* total hash attempts */
    unsigned long blocks;        /* blocks this miner found */
} MinerStat;

typedef struct {
    MinerStat *items;
    size_t     count;
    size_t     cap;
} MinerBook;

typedef struct {
    Blockchain  *chain;
    PendingPool *pool;
    int          difficulty;
    ConfirmFn    confirm;
    void        *ctx;
    MinerBook   *miners;
    long        *carry_fees;     /* transfer fees waiting to be paid to a miner */
} MiningContext;

void miners_init(MinerBook *mb);
void miners_free(MinerBook *mb);
void miners_print(const MinerBook *mb);

/* Each returns the number of blocks confirmed, or -1 on error. */
int  mine_solo(MiningContext *mc, const char *miner_id);
int  mine_pool(MiningContext *mc, int n_miners);
int  mine_cloud(MiningContext *mc, const char *renter, int rounds);

/* Mines throw-away blocks at difficulty 1 to 4 and reports the effort. */
void difficulty_benchmark(int trials);

#endif /* MINING_H */
