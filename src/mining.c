/*
 * mining.c - proof-of-work mining simulations.
 *
 * Proof-of-work: the miner fixes every field of the block, then keeps
 * changing the nonce and recomputing SHA-256 until the hash starts with
 * `difficulty` zero characters. Each extra zero makes this about 16 times
 * harder, because each hex character has 16 possible values.
 *
 * Rewards: every mined block pays BLOCK_REWARD, plus the 1-coin fee of the
 * reward transaction it carries (if any), plus any member-to-member transfer
 * fees waiting to be collected.
 */
#include "mining.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "util.h"

/* ---------------------------------------------------------------- miner book */

void miners_init(MinerBook *mb)
{
    mb->items = NULL;
    mb->count = 0;
    mb->cap = 0;
}

void miners_free(MinerBook *mb)
{
    free(mb->items);
    miners_init(mb);
}

static void miners_credit(MinerBook *mb, const char *id, double amount, unsigned long attempts,
                          unsigned long blocks)
{
    for (size_t i = 0; i < mb->count; i++)
        if (strcmp(mb->items[i].id, id) == 0) {
            mb->items[i].earned += amount;
            mb->items[i].attempts += attempts;
            mb->items[i].blocks += blocks;
            return;
        }
    if (mb->count == mb->cap) {
        size_t new_cap = mb->cap ? mb->cap * 2 : 8;
        MinerStat *tmp = realloc(mb->items, new_cap * sizeof *tmp);
        if (!tmp)
            return;
        mb->items = tmp;
        mb->cap = new_cap;
    }
    MinerStat *m = &mb->items[mb->count++];
    memset(m, 0, sizeof *m);
    safe_copy(m->id, sizeof m->id, id);
    m->earned = amount;
    m->attempts = attempts;
    m->blocks = blocks;
}

void miners_print(const MinerBook *mb)
{
    printf("\n  MINER EARNINGS (this session)\n");
    if (mb->count == 0) {
        printf("  No mining has been done yet.\n");
        return;
    }
    printf("  +------------------+--------+------------+-----------+\n");
    printf("  | Miner            | Blocks | Attempts   | Earned    |\n");
    printf("  +------------------+--------+------------+-----------+\n");
    for (size_t i = 0; i < mb->count; i++)
        printf("  | %-16s | %6lu | %10lu | %9.2f |\n", mb->items[i].id, mb->items[i].blocks,
               mb->items[i].attempts, mb->items[i].earned);
    printf("  +------------------+--------+------------+-----------+\n");
}

/* ---------------------------------------------------------------- helpers */

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void print_target(int difficulty)
{
    char zeros[8] = {0};
    memset(zeros, '0', (size_t)difficulty);
    printf("Difficulty %d: a valid hash must start with \"%s\" (about 1 in %ld hashes).\n",
           difficulty, zeros, 1L << (4 * difficulty));
}

/* Pushes a mined block, removes it from the pool and runs the confirm callback. */
static int confirm_block(MiningContext *mc, const Block *b)
{
    if (chain_push_mined(mc->chain, b) != 0)
        return -1;
    pending_remove_front(mc->pool);
    if (mc->confirm && mc->confirm(&mc->chain->blocks[mc->chain->count - 1], mc->ctx) != 0) {
        printf("ERROR: Could not save the confirmed block. Mining stopped.\n");
        return -1;
    }
    return 0;
}

static int block_fee(const Block *b)
{
    return b->token_reward > 0 ? TX_FEE : 0;
}

/* ---------------------------------------------------------------- solo */

int mine_solo(MiningContext *mc, const char *miner_id)
{
    char prefix[HASH_PREFIX_MAX];
    unsigned long total_attempts = 0;
    int blocks = 0;
    long fees = 0;

    printf("\n=== SOLO MINING by %s ===\n", miner_id);
    if (mc->pool->count == 0) {
        printf("The pending pool is empty. Nothing to mine.\n");
        return 0;
    }
    print_target(mc->difficulty);
    printf("Pending blocks to confirm: %zu\n\n", mc->pool->count);

    double start = now_ms();
    while (mc->pool->count > 0) {
        Block b = mc->pool->items[0];
        block_prepare(mc->chain, &b, mc->difficulty);
        int plen = block_hash_prefix(&b, prefix, sizeof prefix);
        if (plen < 0)
            return -1;

        unsigned long attempts = 0;
        double t0 = now_ms();
        for (unsigned long nonce = 0;; nonce++) {
            attempts++;
            if (pow_attempt(&b, prefix, plen, nonce))
                break;
        }
        double t1 = now_ms();
        total_attempts += attempts;
        printf("  Block #%d %-8s %s/%s: nonce %lu found after %lu attempts (%.1f ms)\n"
               "           hash %s\n", b.index, b.action, b.book_id, b.member_id, b.nonce, attempts,
               t1 - t0, b.hash);
        fees += block_fee(&b);
        if (confirm_block(mc, &b) != 0)
            return -1;
        blocks++;
    }
    double elapsed = now_ms() - start;

    long carry = *mc->carry_fees;
    double reward = blocks * BLOCK_REWARD + fees + carry;
    *mc->carry_fees = 0;
    miners_credit(mc->miners, miner_id, reward, total_attempts, (unsigned long)blocks);

    printf("\nSOLO MINING SUMMARY\n");
    printf("  Blocks confirmed      : %d\n", blocks);
    printf("  Total hash attempts   : %lu (average %.0f per block)\n", total_attempts,
           (double)total_attempts / blocks);
    printf("  Time taken            : %.1f ms\n", elapsed);
    printf("  Mining reward         : %d x %.0f block reward + %ld reward-tx fee(s) + %ld transfer fee(s)\n",
           blocks, BLOCK_REWARD, fees, carry);
    printf("                        = %.2f coins, all paid to %s\n", reward, miner_id);
    return blocks;
}

/* ---------------------------------------------------------------- pool */

#define MAX_POOL_MINERS 8
#define NONCE_STRIDE    1000000000UL   /* each miner searches its own nonce range */

int mine_pool(MiningContext *mc, int n)
{
    char prefix[HASH_PREFIX_MAX];
    int rate[MAX_POOL_MINERS];
    unsigned long attempts[MAX_POOL_MINERS] = {0}, wins[MAX_POOL_MINERS] = {0}, total = 0;
    int blocks = 0;
    long fees = 0;

    printf("\n=== POOL MINING with %d miners ===\n", n);
    if (mc->pool->count == 0) {
        printf("The pending pool is empty. Nothing to mine.\n");
        return 0;
    }
    print_target(mc->difficulty);
    printf("Each miner gets a random hash rate (attempts per round):\n");
    for (int i = 0; i < n; i++) {
        rate[i] = POOL_MIN_HASHRATE + rand() % (POOL_MAX_HASHRATE - POOL_MIN_HASHRATE + 1);
        printf("  POOL-M%d: %d attempts/round\n", i + 1, rate[i]);
    }
    printf("\n");

    while (mc->pool->count > 0) {
        Block b = mc->pool->items[0], winner_block;
        unsigned long counter[MAX_POOL_MINERS] = {0};
        int found = -1, round = 0;

        block_prepare(mc->chain, &b, mc->difficulty);
        int plen = block_hash_prefix(&b, prefix, sizeof prefix);
        if (plen < 0)
            return -1;

        /* Miners work at the same time. Each round is split into small time
         * steps; in every step, each miner still within its hash rate makes one
         * attempt from its own nonce range. Faster miners make more attempts. */
        while (found < 0) {
            round++;
            for (int step = 0; step < POOL_MAX_HASHRATE && found < 0; step++)
                for (int i = 0; i < n; i++) {
                    if (step >= rate[i])
                        continue;
                    Block trial = b;
                    unsigned long nonce = (unsigned long)i * NONCE_STRIDE + counter[i]++;
                    attempts[i]++;
                    if (pow_attempt(&trial, prefix, plen, nonce)) {
                        found = i;
                        winner_block = trial;
                        break;
                    }
                }
        }
        wins[found]++;
        printf("  Block #%d %-8s %s/%s: found by POOL-M%d in round %d (nonce %lu)\n",
               winner_block.index, winner_block.action, winner_block.book_id, winner_block.member_id,
               found + 1, round, winner_block.nonce);
        fees += block_fee(&winner_block);
        if (confirm_block(mc, &winner_block) != 0)
            return -1;
        blocks++;
    }
    for (int i = 0; i < n; i++)
        total += attempts[i];

    long carry = *mc->carry_fees;
    *mc->carry_fees = 0;
    double gross = blocks * BLOCK_REWARD + fees + carry;
    double pool_fee = gross * POOL_FEE_PERCENT / 100.0;
    double shared = gross - pool_fee;

    printf("\nPOOL REWARD SHARING  (reward = attempts / total attempts x rewards after pool fee)\n");
    printf("  Total rewards  : %d x %.0f + %ld fee(s) + %ld transfer fee(s) = %.2f coins\n",
           blocks, BLOCK_REWARD, fees, carry, gross);
    printf("  Pool fee (%.0f%%): %.2f coins\n", POOL_FEE_PERCENT, pool_fee);
    printf("  Shared         : %.2f coins\n\n", shared);
    printf("  +----------+-----------+------------+--------+---------+-----------+\n");
    printf("  | Miner ID | Hash rate | Attempts   | Blocks | Share %%  | Reward    |\n");
    printf("  +----------+-----------+------------+--------+---------+-----------+\n");
    for (int i = 0; i < n; i++) {
        char id[24];
        double share = total ? (double)attempts[i] / (double)total : 0.0;
        snprintf(id, sizeof id, "POOL-M%d", i + 1);
        printf("  | %-8s | %9d | %10lu | %6lu | %6.2f%% | %9.2f |\n", id, rate[i], attempts[i], wins[i],
               share * 100.0, share * shared);
        miners_credit(mc->miners, id, share * shared, attempts[i], wins[i]);
    }
    printf("  +----------+-----------+------------+--------+---------+-----------+\n");
    printf("  | TOTAL    |           | %10lu | %6d | 100.00%% | %9.2f |\n", total, blocks, shared);
    printf("  +----------+-----------+------------+--------+---------+-----------+\n");
    miners_credit(mc->miners, "POOL-OPERATOR", pool_fee, 0, 0);
    return blocks;
}

/* ---------------------------------------------------------------- cloud */

int mine_cloud(MiningContext *mc, const char *renter, int rounds)
{
    typedef struct { unsigned long attempts; int blocks; double reward, maint, net, cumulative; int unprofitable; } Row;
    Row rows[CLOUD_MAX_ROUNDS];
    char prefix[HASH_PREFIX_MAX];
    Block job;
    int job_active = 0, plen = 0, blocks = 0, warned = 0;
    unsigned long counter = 0, total_attempts = 0;
    double gross = 0, rental_total = 0, maint_total = 0;

    if (rounds < 1 || rounds > CLOUD_MAX_ROUNDS)
        return -1;
    printf("\n=== CLOUD MINING for %s ===\n", renter);
    print_target(mc->difficulty);
    printf("Rented power: %d attempts/round | rental fee: %.2f/round | maintenance: %.0f%% of rewards\n",
           CLOUD_HASH_POWER, CLOUD_RENTAL_FEE, CLOUD_MAINT_PERCENT);
    printf("Rental duration: %d round(s). Pending blocks: %zu\n", rounds, mc->pool->count);

    for (int r = 1; r <= rounds; r++) {
        int budget = CLOUD_HASH_POWER, round_blocks = 0;
        unsigned long round_attempts = 0;
        double round_reward = 0;

        printf("\n-- Round %d --\n", r);
        /* the rented rig keeps working on the same block across rounds until it is found */
        while (budget > 0 && (job_active || mc->pool->count > 0)) {
            if (!job_active) {
                job = mc->pool->items[0];
                block_prepare(mc->chain, &job, mc->difficulty);
                plen = block_hash_prefix(&job, prefix, sizeof prefix);
                if (plen < 0)
                    return -1;
                counter = 0;
                job_active = 1;
            }
            budget--;
            round_attempts++;
            if (pow_attempt(&job, prefix, plen, counter++)) {
                if (confirm_block(mc, &job) != 0)
                    return -1;
                round_reward += BLOCK_REWARD + block_fee(&job);
                round_blocks++;
                job_active = 0;
            }
        }
        if (round_blocks > 0 && *mc->carry_fees > 0) {
            round_reward += (double)*mc->carry_fees;
            *mc->carry_fees = 0;
        }
        /* rewards are credited each round, minus maintenance; rent is charged every round */
        double maint = round_reward * CLOUD_MAINT_PERCENT / 100.0;
        gross += round_reward;
        maint_total += maint;
        rental_total += CLOUD_RENTAL_FEE;
        blocks += round_blocks;
        total_attempts += round_attempts;

        Row *row = &rows[r - 1];
        row->attempts = round_attempts;
        row->blocks = round_blocks;
        row->reward = round_reward;
        row->maint = maint;
        row->net = round_reward - maint - CLOUD_RENTAL_FEE;
        row->cumulative = gross - maint_total - rental_total;
        row->unprofitable = (rental_total + maint_total > gross);
        printf("   %lu attempts, %d block(s) confirmed, reward %.2f, net this round %.2f, running total %.2f\n",
               round_attempts, round_blocks, round_reward, row->net, row->cumulative);
        if (row->unprofitable) {
            printf("   WARNING: rental is UNPROFITABLE after round %d: fees so far %.2f > rewards so far %.2f\n",
                   r, rental_total + maint_total, gross);
            warned = 1;
        }
    }
    if (job_active)
        printf("\nNote: the block for %s was not finished in time. It stays in the pending pool.\n", job.book_id);

    printf("\nCLOUD MINING EARNINGS BY ROUND\n");
    printf("  +-------+----------+--------+---------+-------------+--------+---------+------------+\n");
    printf("  | Round | Attempts | Blocks | Reward  | Maintenance | Rental | Net     | Cumulative |\n");
    printf("  +-------+----------+--------+---------+-------------+--------+---------+------------+\n");
    for (int r = 0; r < rounds; r++)
        printf("  | %5d | %8lu | %6d | %7.2f | %11.2f | %6.2f | %7.2f | %10.2f |%s\n", r + 1, rows[r].attempts,
               rows[r].blocks, rows[r].reward, rows[r].maint, CLOUD_RENTAL_FEE, rows[r].net, rows[r].cumulative,
               rows[r].unprofitable ? " <- unprofitable" : "");
    printf("  +-------+----------+--------+---------+-------------+--------+---------+------------+\n");

    double fees_total = rental_total + maint_total, net = gross - fees_total;
    printf("\nCLOUD MINING SUMMARY (%d round(s))\n", rounds);
    printf("  Blocks confirmed  : %d (%lu hash attempts)\n", blocks, total_attempts);
    printf("  Gross earnings    : %.2f coins\n", gross);
    printf("  Total fees paid   : %.2f coins (rental %.2f + maintenance %.2f)\n", fees_total, rental_total,
           maint_total);
    printf("  Net profit        : %.2f coins  -> %s\n", net, net >= 0 ? "PROFITABLE" : "UNPROFITABLE");
    if (warned && net >= 0)
        printf("  (It was unprofitable during the rental but recovered by the end.)\n");
    miners_credit(mc->miners, renter, net, total_attempts, (unsigned long)blocks);
    return blocks;
}

/* ---------------------------------------------------------------- benchmark */

void difficulty_benchmark(int trials)
{
    char prefix[HASH_PREFIX_MAX];
    Blockchain empty;
    chain_init(&empty);

    printf("\n=== DIFFICULTY BENCHMARK (%d trial(s) per level, throw-away blocks) ===\n", trials);
    printf("  +------------+-----------+-------------------+-----------------+-------------+\n");
    printf("  | Difficulty | Target    | Expected attempts | Average attempts| Average time|\n");
    printf("  +------------+-----------+-------------------+-----------------+-------------+\n");
    for (int d = MIN_DIFFICULTY; d <= MAX_DIFFICULTY; d++) {
        double total_attempts = 0, total_ms = 0;
        for (int t = 0; t < trials; t++) {
            Block b;
            memset(&b, 0, sizeof b);
            b.timestamp = time(NULL) + t * 97 + d;   /* different data each trial */
            safe_copy(b.book_id, sizeof b.book_id, "BENCH");
            safe_copy(b.book_title, sizeof b.book_title, "Benchmark");
            safe_copy(b.member_id, sizeof b.member_id, "BENCH");
            safe_copy(b.member_name, sizeof b.member_name, "Benchmark");
            safe_copy(b.action, sizeof b.action, "BORROWED");
            block_prepare(&empty, &b, d);
            memset(b.tx_id, '0', HASH_HEX_LEN - 1);
            int plen = block_hash_prefix(&b, prefix, sizeof prefix);
            double t0 = now_ms();
            unsigned long n = 0;
            while (!pow_attempt(&b, prefix, plen, n))
                n++;
            total_ms += now_ms() - t0;
            total_attempts += (double)(n + 1);
        }
        char zeros[8] = {0};
        memset(zeros, '0', (size_t)d);
        printf("  | %10d | %-9s | %17ld | %15.0f | %8.2f ms |\n", d, zeros, 1L << (4 * d),
               total_attempts / trials, total_ms / trials);
    }
    printf("  +------------+-----------+-------------------+-----------------+-------------+\n");
    printf("  Each extra leading zero makes mining about 16 times harder.\n");
}
