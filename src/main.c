/*
 * main.c - CLI for the Blockchain-Based Library Book Lending Tracker,
 * Formative 2: token rewards, UTXO / account models and mining.
 *
 * Flow:  borrow/return  ->  signed record in the PENDING POOL
 *        mining (solo / pool / cloud)  ->  proof-of-work  ->  CONFIRMED block
 *        confirmed RETURNED block  ->  reward transaction credited to the member
 *
 * Usage: ./library_chain [--model utxo|account] [--difficulty 1-4]
 */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "auth.h"
#include "blockchain.h"
#include "common.h"
#include "crypto_utils.h"
#include "ledger.h"
#include "mining.h"
#include "pending.h"
#include "registry.h"
#include "util.h"

typedef struct {
    BookRegistry   books;
    MemberRegistry members;
    Blockchain     chain;
    PendingPool    pool;
    Ledger         ledger;
    MinerBook      miners;
    EVP_PKEY      *priv;           /* only loaded for the librarian */
    EVP_PKEY      *pub;
    int            is_librarian;
    int            chain_ok;
    int            difficulty;
    long           loan_period;
    long           carry_fees;     /* transfer fees waiting for the next miner */
    char           user[USERNAME_MAX];
} App;

/* ------------------------------------------------------------------ helpers */

static long get_loan_period(void)
{
    const char *env = getenv("LOAN_PERIOD_SECONDS");
    if (env) {
        char *end;
        long v = strtol(env, &end, 10);
        if (end != env && *end == '\0' && v > 0)
            return v;
        fprintf(stderr, "WARNING: Ignoring invalid LOAN_PERIOD_SECONDS='%s'.\n", env);
    }
    return DEFAULT_LOAN_PERIOD_SECONDS;
}

/* Returns 0 ok, -1 EOF, -2 invalid input (message already printed). */
static int prompt_id(const char *prompt, char *out, size_t cap)
{
    char buf[128];
    int rc = read_line(prompt, buf, sizeof buf);
    if (rc == -1)
        return -1;
    if (rc == -2) {
        printf("ERROR: Input too long.\n");
        return -2;
    }
    trim(buf);
    str_upper(buf);
    if (buf[0] == '\0') {
        printf("ERROR: ID cannot be empty.\n");
        return -2;
    }
    if (!is_valid_id(buf, cap)) {
        printf("ERROR: '%s' is not a valid ID (letters, digits, - or _, max %zu characters).\n", buf, cap - 1);
        return -2;
    }
    safe_copy(out, cap, buf);
    return 0;
}

/* Reads a whole number in [min, max]. Returns 0 ok, -1 EOF, -2 invalid. */
static int prompt_long(const char *prompt, long min, long max, long *out)
{
    char buf[64], *end;
    int rc = read_line(prompt, buf, sizeof buf);
    if (rc == -1)
        return -1;
    trim(buf);
    long v = strtol(buf, &end, 10);
    if (rc != 0 || buf[0] == '\0' || *end != '\0' || v < min || v > max) {
        printf("ERROR: Enter a whole number from %ld to %ld.\n", min, max);
        return -2;
    }
    *out = v;
    return 0;
}

static int require_write(const App *a)
{
    if (!a->is_librarian) {
        printf("ACCESS DENIED: This action requires a librarian login. Guest sessions are read-only.\n");
        return 0;
    }
    if (!a->chain_ok) {
        printf("ERROR: The chain failed validation. Write operations are disabled until it is restored.\n");
        return 0;
    }
    return 1;
}

static int read_book_and_member(const App *a, const Book **bk, const Member **m, char *bid, char *mid)
{
    int rc = prompt_id("Book ID   : ", bid, ID_LEN);
    if (rc != 0)
        return rc;
    rc = prompt_id("Member ID : ", mid, ID_LEN);
    if (rc != 0)
        return rc;
    *bk = find_book(&a->books, bid);
    *m  = find_member(&a->members, mid);
    if (!*bk || !*m) {
        printf("ERROR: Book or Member not found\n");
        if (!*bk)
            printf("  - No book with ID %s in %s\n", bid, BOOKS_FILE);
        if (!*m)
            printf("  - No member with ID %s in %s\n", mid, MEMBERS_FILE);
        return -2;
    }
    return 0;
}

/* Signs a record and puts it in the pending pool (saved to disk). */
static int add_pending(App *a, const Book *bk, const char *member_id, const char *member_name,
                       const char *action, int reward)
{
    Block rec;
    if (record_create(&rec, a->priv, time(NULL), bk->book_id, bk->title, member_id, member_name,
                      action, reward) != 0)
        return -1;
    if (pending_add(&a->pool, &rec) != 0)
        return -1;
    if (pending_save(&a->pool, PENDING_FILE) != 0) {
        pending_pop_back(&a->pool);
        printf("ERROR: Could not save the pending pool. Nothing was added.\n");
        return -1;
    }
    return 0;
}

static int pending_conflict(const App *a, const char *book_id)
{
    if (pending_has_book(&a->pool, book_id)) {
        printf("ERROR: %s already has an unconfirmed record in the pending pool.\n"
               "       Mine the pending pool (option 5) before recording another action for it.\n", book_id);
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------ menu actions */

static int do_borrow(App *a)
{
    const Book *bk;
    const Member *m;
    char bid[ID_LEN], mid[ID_LEN], when[32];

    printf("\n--- Borrow a book ---\n");
    if (!require_write(a))
        return 0;
    int rc = read_book_and_member(a, &bk, &m, bid, mid);
    if (rc != 0)
        return rc == -1 ? -1 : 0;
    if (pending_conflict(a, bid))
        return 0;
    const Block *loan = chain_active_loan(&a->chain, bid);
    if (loan) {
        format_time(loan->timestamp, when, sizeof when);
        printf("ERROR: %s (\"%s\") is already on loan to %s (%s) since %s.\n", bid, bk->title,
               loan->member_id, loan->member_name, when);
        return 0;
    }
    if (add_pending(a, bk, m->member_id, m->full_name, "BORROWED", 0) == 0) {
        printf("PENDING: %s borrowed by %s (\"%s\" -> %s)\n", bid, mid, bk->title, m->full_name);
        printf("  Signed and added to the pending pool (%zu waiting). Not confirmed until mined.\n",
               a->pool.count);
        printf("  A borrow creates no token transaction.\n");
    }
    return 0;
}

static int do_return(App *a)
{
    const Book *bk;
    const Member *m;
    char bid[ID_LEN], mid[ID_LEN], held_txt[48];

    printf("\n--- Return a book ---\n");
    if (!require_write(a))
        return 0;
    int rc = read_book_and_member(a, &bk, &m, bid, mid);
    if (rc != 0)
        return rc == -1 ? -1 : 0;
    if (pending_conflict(a, bid))
        return 0;
    const Block *loan = chain_active_loan(&a->chain, bid);
    if (!loan) {
        printf("ERROR: No confirmed BORROWED record for %s (never borrowed, already returned,\n"
               "       or the borrow is still waiting to be mined).\n", bid);
        return 0;
    }
    if (strcmp(loan->member_id, mid) != 0) {
        printf("ERROR: %s was borrowed by %s (%s), not %s. Only the borrower can return it.\n", bid,
               loan->member_id, loan->member_name, mid);
        return 0;
    }

    long held = (long)(time(NULL) - loan->timestamp);
    int late = chain_flagged_overdue(&a->chain, bid) || held > a->loan_period;
    int reward = late ? REWARD_LATE : REWARD_ON_TIME;
    format_duration(held, held_txt, sizeof held_txt);

    if (add_pending(a, bk, m->member_id, m->full_name, "RETURNED", reward) == 0) {
        const Block *rec = &a->pool.items[a->pool.count - 1];
        printf("PENDING: %s returned by %s after %s -> %s\n", bid, mid, held_txt,
               late ? "LATE" : "ON TIME");
        printf("  Reward transaction created: %d coins to %s (%d coin fee, %d credited after mining)\n",
               reward, mid, TX_FEE, reward - TX_FEE);
        printf("  Tx ID: %s\n", rec->tx_id);
        printf("  Added to the pending pool (%zu waiting). The balance updates only after mining.\n",
               a->pool.count);
    }
    return 0;
}

static void do_overdue(App *a)
{
    int flagged = 0;
    char limit[48];
    time_t now = time(NULL);

    printf("\n--- Check for overdue loans ---\n");
    if (!require_write(a))
        return;
    format_duration(a->loan_period, limit, sizeof limit);
    printf("Loan period: %s\n", limit);
    for (size_t i = 0; i < a->books.count; i++) {
        const Book *bk = &a->books.items[i];
        const Block *loan = chain_active_loan(&a->chain, bk->book_id);
        if (!loan || chain_flagged_overdue(&a->chain, bk->book_id) || pending_has_book(&a->pool, bk->book_id))
            continue;
        long held = (long)(now - loan->timestamp);
        if (held <= a->loan_period)
            continue;
        char mid[ID_LEN], name[50];
        safe_copy(mid, sizeof mid, loan->member_id);
        safe_copy(name, sizeof name, loan->member_name);
        if (add_pending(a, bk, mid, name, "OVERDUE", 0) != 0)
            return;
        printf("FLAGGED: %s held by %s (%s) for %ld s -> OVERDUE record added to the pending pool.\n",
               bk->book_id, mid, name, held);
        printf("  No reward transaction is created because the book has not been returned.\n");
        flagged++;
    }
    if (!flagged)
        printf("No new overdue loans.\n");
}

/* Called by the mining code for each newly confirmed block. */
static int on_block_confirmed(const Block *b, void *ctx)
{
    App *a = ctx;
    if (chain_save(&a->chain, CHAIN_FILE) != 0 || pending_save(&a->pool, PENDING_FILE) != 0)
        return -1;
    if (ledger_apply_reward(&a->ledger, b) != 0)
        return -1;
    printf("  CONFIRMED block #%d: %s %s by %s", b->index, b->book_id, b->action, b->member_id);
    if (b->token_reward > 0)
        printf(" -> %s credited %d coin(s) (reward %d - fee %d). Balance now %ld.\n", b->member_id,
               b->token_reward - TX_FEE, b->token_reward, TX_FEE, ledger_balance(&a->ledger, b->member_id));
    else
        printf(" (no token transaction)\n");
    if (a->ledger.model == MODEL_UTXO)
        utxo_print_set(&a->ledger.utxo);
    return 0;
}

static int do_mine(App *a)
{
    char buf[32], miner[32];
    long choice, n;
    int rc;

    printf("\n--- Mine the pending pool ---\n");
    if (!require_write(a))
        return 0;
    printf("Pending blocks: %zu | Difficulty: %d\n", a->pool.count, a->difficulty);
    if (a->pool.count == 0)
        printf("Note: the pool is empty. Solo and pool mining will have nothing to do, and\n"
               "cloud mining will charge rent while earning nothing.\n");
    printf("  1. Solo mining\n  2. Pool mining\n  3. Cloud mining\n");
    if ((rc = prompt_long("Mining method: ", 1, 3, &choice)) != 0)
        return rc == -1 ? -1 : 0;

    MiningContext mc = { &a->chain, &a->pool, a->difficulty, on_block_confirmed, a, &a->miners, &a->carry_fees };
    if (choice == 1) {
        rc = read_line("Miner ID (e.g. SOLO-1): ", buf, sizeof buf);
        if (rc == -1)
            return -1;
        trim(buf);
        str_upper(buf);
        safe_copy(miner, sizeof miner, (rc == 0 && is_valid_id(buf, 20)) ? buf : "SOLO-1");
        mine_solo(&mc, miner);
    } else if (choice == 2) {
        if ((rc = prompt_long("Number of miners in the pool (2-8): ", 2, 8, &n)) != 0)
            return rc == -1 ? -1 : 0;
        mine_pool(&mc, (int)n);
    } else {
        rc = read_line("Renter name (e.g. CLOUD-USER): ", buf, sizeof buf);
        if (rc == -1)
            return -1;
        trim(buf);
        str_upper(buf);
        safe_copy(miner, sizeof miner, (rc == 0 && is_valid_id(buf, 20)) ? buf : "CLOUD-USER");
        if ((rc = prompt_long("Rental duration in rounds (1-5): ", 1, CLOUD_MAX_ROUNDS, &n)) != 0)
            return rc == -1 ? -1 : 0;
        mine_cloud(&mc, miner, (int)n);
    }
    if (a->ledger.model == MODEL_ACCOUNT)
        account_print_balances(&a->ledger.acct);
    return 0;
}

static void do_balances(App *a)
{
    printf("\n--- Member token balances (%s model) ---\n", ledger_model_name(a->ledger.model));
    if (a->ledger.model == MODEL_UTXO) {
        printf("  %-8s %-24s %s\n", "Member", "Name", "Balance (sum of UTXOs)");
        for (size_t i = 0; i < a->members.count; i++)
            printf("  %-8s %-24s %ld\n", a->members.items[i].member_id, a->members.items[i].full_name,
                   ledger_balance(&a->ledger, a->members.items[i].member_id));
    }
    ledger_print(&a->ledger);
    if (a->carry_fees)
        printf("  Transfer fees waiting for the next miner: %ld coin(s)\n", a->carry_fees);
    miners_print(&a->miners);
}

static int do_transfer(App *a)
{
    char from[ID_LEN], to[ID_LEN], prompt[96];
    long amount, nonce = -1;
    int rc;

    printf("\n--- Transfer tokens between members (%s model, fee %d coin) ---\n",
           ledger_model_name(a->ledger.model), TX_FEE);
    if (!require_write(a))
        return 0;
    if ((rc = prompt_id("From member ID : ", from, sizeof from)) != 0)
        return rc == -1 ? -1 : 0;
    if ((rc = prompt_id("To member ID   : ", to, sizeof to)) != 0)
        return rc == -1 ? -1 : 0;
    if (!find_member(&a->members, from) || !find_member(&a->members, to)) {
        printf("ERROR: Book or Member not found (both members must be in %s).\n", MEMBERS_FILE);
        return 0;
    }
    if ((rc = prompt_long("Amount (coins) : ", 1, 1000000, &amount)) != 0)
        return rc == -1 ? -1 : 0;
    if (a->ledger.model == MODEL_ACCOUNT) {
        Account *acc = account_find(&a->ledger.acct, from);
        snprintf(prompt, sizeof prompt, "Nonce (%s's next nonce is %lu): ", from, acc ? acc->nonce : 0UL);
        if ((rc = prompt_long(prompt, 0, 1000000000L, &nonce)) != 0)
            return rc == -1 ? -1 : 0;
    }
    if (ledger_transfer(&a->ledger, from, to, amount, nonce, time(NULL), 1, 1) == 0) {
        a->carry_fees += TX_FEE;
        printf("  The %d coin fee goes to whoever mines next.\n", TX_FEE);
        if (a->ledger.model == MODEL_UTXO)
            utxo_print_set(&a->ledger.utxo);
    }
    return 0;
}

static int do_history(App *a)
{
    char mid[ID_LEN];
    int rc = prompt_id("Member ID: ", mid, sizeof mid);
    if (rc != 0)
        return rc == -1 ? -1 : 0;
    if (!find_member(&a->members, mid)) {
        printf("ERROR: Book or Member not found (no member %s).\n", mid);
        return 0;
    }
    ledger_history(&a->ledger, mid);
    return 0;
}

static int do_set_difficulty(App *a)
{
    long d;
    printf("\n--- Set mining difficulty ---\n");
    if (!a->is_librarian) {
        printf("ACCESS DENIED: Only the librarian can change the difficulty.\n");
        return 0;
    }
    printf("Current difficulty: %d. Higher = more leading zeros = more hash attempts.\n", a->difficulty);
    int rc = prompt_long("New difficulty (1-4): ", MIN_DIFFICULTY, MAX_DIFFICULTY, &d);
    if (rc != 0)
        return rc == -1 ? -1 : 0;
    a->difficulty = (int)d;
    printf("Difficulty set to %d. New blocks must have a hash starting with %d zero(s).\n", a->difficulty,
           a->difficulty);
    return 0;
}

static int do_double_spend(App *a)
{
    char from[ID_LEN], to[ID_LEN];
    int rc;
    if (a->ledger.model != MODEL_UTXO) {
        printf("\nThe double-spend test is for the UTXO model. In the account model,\n"
               "replays are blocked by the nonce: try option 9 with an old nonce.\n");
        return 0;
    }
    if ((rc = prompt_id("Member who will try to double spend: ", from, sizeof from)) != 0)
        return rc == -1 ? -1 : 0;
    if ((rc = prompt_id("Member receiving the first payment : ", to, sizeof to)) != 0)
        return rc == -1 ? -1 : 0;
    if (!find_member(&a->members, from) || !find_member(&a->members, to)) {
        printf("ERROR: Book or Member not found.\n");
        return 0;
    }
    utxo_double_spend_demo(&a->ledger.utxo, from, to);
    return 0;
}

static void do_status(const App *a)
{
    char when[32];
    printf("\nBOOK STATUS (confirmed chain + pending pool)\n");
    for (size_t i = 0; i < a->books.count; i++) {
        const Book *bk = &a->books.items[i];
        const Block *loan = chain_active_loan(&a->chain, bk->book_id);
        const char *pend = pending_has_book(&a->pool, bk->book_id) ? "  [PENDING RECORD]" : "";
        if (!loan) {
            printf("  %-6s %-30s AVAILABLE%s\n", bk->book_id, bk->title, pend);
            continue;
        }
        format_time(loan->timestamp, when, sizeof when);
        int late = chain_flagged_overdue(&a->chain, bk->book_id) ||
                   (time(NULL) - loan->timestamp) > a->loan_period;
        printf("  %-6s %-30s ON LOAN to %s since %s%s%s\n", bk->book_id, bk->title, loan->member_id, when,
               late ? "  [OVERDUE]" : "", pend);
    }
}

static int do_tamper_demo(const App *a)
{
    char prompt[80], prefix[HASH_PREFIX_MAX];
    Blockchain copy;
    long k, mode;
    int rc;

    printf("\n--- Tamper detection demo (runs on a COPY of the chain) ---\n");
    if (a->chain.count < 2) {
        printf("Mine at least one lending block first so there's a record to tamper with.\n");
        return 0;
    }
    snprintf(prompt, sizeof prompt, "Block to tamper with (1-%zu): ", a->chain.count - 1);
    if ((rc = prompt_long(prompt, 1, (long)a->chain.count - 1, &k)) != 0)
        return rc == -1 ? -1 : 0;
    printf("  1. Naive: edit the record only\n");
    printf("  2. Determined: edit the record, then REDO the proof-of-work for every later block\n");
    if ((rc = prompt_long("Attack type: ", 1, 2, &mode)) != 0)
        return rc == -1 ? -1 : 0;
    if (chain_copy(&copy, &a->chain) != 0) {
        printf("ERROR: Out of memory.\n");
        return 0;
    }

    Block *t = &copy.blocks[k];
    char old_member[ID_LEN];
    safe_copy(old_member, sizeof old_member, t->member_id);
    /* steal the record: credit it to a different member */
    safe_copy(t->member_id, sizeof t->member_id, strcmp(old_member, "ALU005") ? "ALU005" : "ALU004");
    printf("\nAttacker changed block #%ld (%s %s): member %s -> %s\n", k, t->book_id, t->action, old_member,
           t->member_id);

    if (mode == 2) {
        unsigned long total = 0;
        for (size_t i = (size_t)k; i < copy.count; i++) {
            Block *b = &copy.blocks[i];
            if (i > (size_t)k)
                memcpy(b->previous_hash, copy.blocks[i - 1].hash, HASH_HEX_LEN);
            int plen = block_hash_prefix(b, prefix, sizeof prefix);
            for (unsigned long n = 0;; n++) {
                total++;
                if (pow_attempt(b, prefix, plen, n))
                    break;
            }
        }
        printf("Attacker re-mined blocks #%ld to #%zu: %lu hash attempts of extra work.\n", k, copy.count - 1,
               total);
    }
    printf("\nRunning validation on the tampered copy...\n");
    chain_validate(&copy, a->pub, 1);
    if (mode == 1)
        printf("\nResult: the hash no longer matches, the proof-of-work is broken and the signature fails.\n");
    else
        printf("\nResult: hashes, links and proof-of-work all pass after the extra work, but the\n"
               "librarian's signature still fails. Redoing the mining cannot fix a forged record.\n");
    chain_free(&copy);
    printf("The real chain (memory and %s) is untouched.\n", CHAIN_FILE);
    return 0;
}

/* ----------------------------------------------------------------- startup */

static void usage(const char *prog)
{
    printf("Usage: %s [--model utxo|account] [--difficulty 1-4]\n", prog);
    printf("  --model       token model for this session (asks if not given)\n");
    printf("  --difficulty  leading zeros required by proof-of-work (default %d)\n", DEFAULT_DIFFICULTY);
    printf("Environment: LOAN_PERIOD_SECONDS=n  shortens the loan period for testing.\n");
}

/* Returns 0 ok, 1 = exit cleanly (help), -1 = bad arguments. */
static int parse_args(int argc, char **argv, LedgerModel *model, int *difficulty)
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 1;
        } else if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "utxo") == 0)
                *model = MODEL_UTXO;
            else if (strcmp(argv[i], "account") == 0)
                *model = MODEL_ACCOUNT;
            else {
                fprintf(stderr, "ERROR: --model must be 'utxo' or 'account'.\n");
                return -1;
            }
        } else if (strcmp(argv[i], "--difficulty") == 0 && i + 1 < argc) {
            char *end;
            long d = strtol(argv[++i], &end, 10);
            if (*end != '\0' || d < MIN_DIFFICULTY || d > MAX_DIFFICULTY) {
                fprintf(stderr, "ERROR: --difficulty must be between %d and %d.\n", MIN_DIFFICULTY, MAX_DIFFICULTY);
                return -1;
            }
            *difficulty = (int)d;
        } else {
            fprintf(stderr, "ERROR: Unknown argument '%s'.\n", argv[i]);
            usage(argv[0]);
            return -1;
        }
    }
    return 0;
}

static int first_run(App *a)
{
    char pass[PASSWORD_MAX];
    if (access(CHAIN_FILE, F_OK) == 0) {
        fprintf(stderr, "ERROR: %s exists but there is no librarian account. Run 'make reset'.\n", CHAIN_FILE);
        return -1;
    }
    if (auth_setup(a->user, sizeof a->user, pass, sizeof pass) != 0)
        return -1;
    printf("Generating ECDSA P-256 key pair...\n");
    a->priv = generate_keypair();
    int rc = (a->priv && save_keypair(a->priv, PRIV_KEY_FILE, PUB_KEY_FILE, pass) == 0) ? 0 : -1;
    OPENSSL_cleanse(pass, sizeof pass);
    if (rc != 0) {
        unlink(AUTH_FILE);
        return -1;
    }
    printf("[OK] Keys saved: %s (AES-256 encrypted, mode 600) and %s\n", PRIV_KEY_FILE, PUB_KEY_FILE);
    a->is_librarian = 1;
    return 0;
}

static int login(App *a)
{
    char pass[PASSWORD_MAX];
    long choice;
    int rc;

    printf("\nSign in:\n  1. Librarian login (full access)\n  2. Guest (read-only)\n");
    while ((rc = prompt_long("Choice: ", 1, 2, &choice)) != 0)
        if (rc == -1)
            return -1;
    if (choice == 2) {
        printf("[OK] Guest session: you can view and validate, but not change anything.\n");
        safe_copy(a->user, sizeof a->user, "guest");
        return 0;
    }
    if (auth_login(a->user, sizeof a->user, pass, sizeof pass) != 0)
        return -1;
    a->priv = load_private_key(PRIV_KEY_FILE, pass);
    OPENSSL_cleanse(pass, sizeof pass);
    if (!a->priv) {
        fprintf(stderr, "ERROR: Could not unlock %s with this password.\n", PRIV_KEY_FILE);
        return -1;
    }
    printf("[OK] Signing key unlocked.\n");
    a->is_librarian = 1;
    return 0;
}

static int choose_model(LedgerModel *model)
{
    long choice;
    int rc;
    printf("\nChoose the token transaction model for this session:\n");
    printf("  1. UTXO model (coins are unspent outputs)\n");
    printf("  2. Account-based model (each member has a balance and a nonce)\n");
    while ((rc = prompt_long("Model: ", 1, 2, &choice)) != 0)
        if (rc == -1)
            return -1;
    *model = choice == 1 ? MODEL_UTXO : MODEL_ACCOUNT;
    return 0;
}

/* Drops pending records that are already on the chain (e.g. after a crash mid-save). */
static void dedupe_pending(App *a)
{
    size_t removed = 0;
    for (size_t i = 0; i < a->pool.count;) {
        int dup = 0;
        for (size_t j = 1; j < a->chain.count && !dup; j++)
            dup = a->chain.blocks[j].sig_len == a->pool.items[i].sig_len &&
                  memcmp(a->chain.blocks[j].signature, a->pool.items[i].signature, a->pool.items[i].sig_len) == 0;
        if (dup) {
            memmove(&a->pool.items[i], &a->pool.items[i + 1], (a->pool.count - i - 1) * sizeof *a->pool.items);
            a->pool.count--;
            removed++;
        } else {
            i++;
        }
    }
    if (removed) {
        printf("NOTE: removed %zu pending record(s) that were already confirmed.\n", removed);
        pending_save(&a->pool, PENDING_FILE);
    }
}

static int load_state(App *a, int is_first_run)
{
    int rc = chain_load(&a->chain, CHAIN_FILE);
    if (rc < 0) {
        fprintf(stderr, "ERROR: %s could not be parsed. It may be corrupted or tampered with.\n", CHAIN_FILE);
        return -1;
    }
    if (rc == 1) {
        if (!a->is_librarian) {
            printf("No %s yet. A librarian must log in to create the chain.\n", CHAIN_FILE);
            a->chain_ok = 1;
            return 0;
        }
        if (!is_first_run)
            printf("WARNING: %s not found. Starting a new chain.\n", CHAIN_FILE);
        printf("Mining the genesis block (difficulty %d)...\n", a->difficulty);
        if (chain_create_genesis(&a->chain, a->priv, a->difficulty) != 0 || chain_save(&a->chain, CHAIN_FILE) != 0)
            return -1;
        printf("[OK] Genesis block mined: nonce %lu, hash %.20s...\n", a->chain.blocks[0].nonce,
               a->chain.blocks[0].hash);
    } else {
        printf("[OK] Loaded %zu confirmed block(s) from %s\n", a->chain.count, CHAIN_FILE);
    }

    if (pending_load(&a->pool, PENDING_FILE, a->pub) != 0) {
        fprintf(stderr, "ERROR: %s could not be loaded. Fix or remove it and try again.\n", PENDING_FILE);
        return -1;
    }
    dedupe_pending(a);
    printf("[OK] Pending pool: %zu unconfirmed record(s)\n", a->pool.count);

    printf("Startup integrity check: ");
    fflush(stdout);
    a->chain_ok = (chain_validate(&a->chain, a->pub, 0) == 0);
    if (!a->chain_ok)
        printf("WARNING: Write operations are disabled because the chain is not valid.\n");
    return 0;
}

static void print_menu(const App *a)
{
    const char *lock = a->is_librarian ? "" : "  [librarian]";
    printf("\n==================== LIBRARY LENDING CHAIN ====================\n");
    printf(" User: %-12s Model: %-13s Difficulty: %d\n", a->is_librarian ? a->user : "GUEST",
           ledger_model_name(a->ledger.model), a->difficulty);
    printf(" Confirmed blocks: %-4zu Pending: %-4zu Chain: %s\n", a->chain.count, a->pool.count,
           a->chain_ok ? "VALID" : "INVALID");
    printf("---------------------------------------------------------------\n");
    printf("  1. Borrow a book%s\n", lock);
    printf("  2. Return a book%s\n", lock);
    printf("  3. Flag overdue loans%s\n", lock);
    printf("  4. View pending pool\n");
    printf("  5. Mine pending pool (solo / pool / cloud)%s\n", lock);
    printf("  6. View confirmed records\n");
    printf("  7. Validate chain\n");
    printf("  8. Token balances, UTXO set and miner earnings\n");
    printf("  9. Transfer tokens between members%s\n", lock);
    printf(" 10. Transaction history for a member\n");
    printf(" 11. Set mining difficulty (1-4)%s\n", lock);
    printf(" 12. Double-spend test (UTXO)\n");
    printf(" 13. Book status\n");
    printf(" 14. View registries\n");
    printf(" 15. Tamper detection demo\n");
    printf(" 16. Difficulty benchmark\n");
    printf("  0. Exit\n");
}

int main(int argc, char **argv)
{
    App app;
    LedgerModel model = 0;
    int exit_code = 1;

    memset(&app, 0, sizeof app);
    chain_init(&app.chain);
    pending_init(&app.pool);
    miners_init(&app.miners);
    app.difficulty = DEFAULT_DIFFICULTY;
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    int arg_rc = parse_args(argc, argv, &model, &app.difficulty);
    if (arg_rc != 0)
        return arg_rc == 1 ? 0 : 1;

    printf("===============================================================\n");
    printf("   Blockchain Library Lending Tracker: Tokens and Mining\n");
    printf("===============================================================\n");
    printf("Loading registries...\n");
    if (load_books(BOOKS_FILE, &app.books) != 0 || load_members(MEMBERS_FILE, &app.members) != 0) {
        fprintf(stderr, "Cannot continue without valid %s and %s.\n", BOOKS_FILE, MEMBERS_FILE);
        goto out;
    }
    app.loan_period = get_loan_period();

    int is_first_run = !auth_exists();
    if ((is_first_run ? first_run(&app) : login(&app)) != 0)
        goto out;
    app.pub = load_public_key(PUB_KEY_FILE);
    if (!app.pub || load_state(&app, is_first_run) != 0)
        goto out;

    if (!model && choose_model(&model) != 0)
        goto out;
    if (ledger_init(&app.ledger, model, &app.members) != 0 ||
        ledger_rebuild(&app.ledger, &app.chain, TXLOG_FILE) != 0) {
        fprintf(stderr, "ERROR: Could not build the %s ledger.\n", ledger_model_name(model));
        goto out;
    }
    printf("[OK] %s ledger rebuilt from the confirmed chain and %s\n", ledger_model_name(model), TXLOG_FILE);

    for (;;) {
        long choice;
        print_menu(&app);
        int rc = prompt_long("Choose an option: ", 0, 16, &choice);
        if (rc == -1)
            break;
        if (rc != 0)
            continue;
        int eof = 0;
        switch (choice) {
        case 1:  eof = do_borrow(&app) == -1; break;
        case 2:  eof = do_return(&app) == -1; break;
        case 3:  do_overdue(&app); break;
        case 4:  pending_print(&app.pool, app.pub); break;
        case 5:  eof = do_mine(&app) == -1; break;
        case 6:  chain_print(&app.chain, app.pub); break;
        case 7:  app.chain_ok = (chain_validate(&app.chain, app.pub, 1) == 0); break;
        case 8:  do_balances(&app); break;
        case 9:  eof = do_transfer(&app) == -1; break;
        case 10: eof = do_history(&app) == -1; break;
        case 11: eof = do_set_difficulty(&app) == -1; break;
        case 12: eof = do_double_spend(&app) == -1; break;
        case 13: do_status(&app); break;
        case 14: print_books(&app.books); print_members(&app.members); break;
        case 15: eof = do_tamper_demo(&app) == -1; break;
        case 16: difficulty_benchmark(10); break;
        case 0:  printf("Goodbye. Chain saved in %s, pending pool in %s.\n", CHAIN_FILE, PENDING_FILE);
                 exit_code = 0; goto out;
        }
        if (eof)
            break;
    }
    exit_code = 0;

out:
    if (model)
        ledger_free(&app.ledger);
    EVP_PKEY_free(app.priv);
    EVP_PKEY_free(app.pub);
    chain_free(&app.chain);
    pending_free(&app.pool);
    miners_free(&app.miners);
    free_books(&app.books);
    free_members(&app.members);
    return exit_code;
}
