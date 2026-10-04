# Blockchain Library Lending Tracker: Tokens and Mining (Formative 2)

This extends the Formative 1 lending tracker. Returning a book now earns the
member tokens, and every lending record has to be **mined** (confirmed with
proof-of-work) before it joins the chain.

## How it works

1. **Borrow, return or flag overdue.** The librarian's action is signed and put
   in the **pending pool**. It is not on the chain yet.
2. **Token reward.** A return creates a reward transaction:
   - on time: **10 coins**
   - late: **5 coins**
   - overdue and not returned: **no transaction**

   A fixed **1-coin fee** is taken, so the member receives 9 or 4.
3. **Mining.** A miner takes the pending records in order, links each one to the
   chain, and changes the nonce until the SHA-256 hash starts with enough zeros
   (the difficulty). Only then is the block confirmed.
4. **Balance update.** When a RETURNED block is confirmed, the reward is
   credited under the chosen transaction model.

## Requirements

- Linux or WSL (tested on Ubuntu 24.04)
- GCC and Make
- OpenSSL development library

```bash
sudo apt update
sudo apt install -y build-essential libssl-dev
```

## Build and run

```bash
make
./library_chain
```

Run it from the project folder so it finds `books.txt` and `members.txt`.
On the first run you create the librarian account. After that, log in as the
librarian (full access) or as a guest (view only).

## Choosing the transaction model

The model applies to the whole session. Pick it on the command line:

```bash
./library_chain --model utxo
./library_chain --model account
```

If you leave it out, the program asks at start-up.

| | UTXO model | Account model |
|---|---|---|
| Balance | Sum of unspent outputs you own | Stored number per member |
| Spending | Consumes whole outputs, change comes back as a new output | Debit sender, credit recipient |
| Replay / double spend | A spent output no longer exists | Each transfer must use the next nonce |
| Extra views | Full UTXO set after every confirmed block | Per-member transaction history (linked list) |

## Setting the mining difficulty

Difficulty is the number of leading `0` characters the block hash needs (1 to 4, default 2).

```bash
./library_chain --difficulty 3
```

It can also be changed during a session with menu option 11. Option 16 runs a
benchmark showing how many attempts each difficulty needs.

## Testing the mining simulations

Menu option 5 mines the pending pool:

| Method | What happens |
|---|---|
| Solo | One miner confirms every pending block, shows attempts per block, and gets the full reward (50 per block + fees) |
| Pool | 2 to 8 miners with random hash rates work together; 2% pool fee; rewards shared by attempts |
| Cloud | Rent 600 attempts/round for 1 to 5 rounds at 20 coins/round, minus 10% maintenance; warns if unprofitable |

A quick way to see everything:

```bash
make reset
./library_chain --model utxo
# 1  borrow BK001 / ALU001
# 5  mine -> 1 (solo)
# 2  return BK001 / ALU001      (on time, 10-coin reward goes to pending)
# 5  mine -> 2 (pool, 4 miners)
# 8  balances and UTXO set
# 5  mine -> 3 (cloud, 3 rounds)   with nothing pending, this shows an unprofitable rental
```

To test late returns and overdue loans quickly, shorten the loan period:

```bash
LOAN_PERIOD_SECONDS=30 ./library_chain --model utxo
```

## Automated tests

```bash
make test
```

Runs 48 checks in a temporary folder, covering the pending pool, all three
mining methods, both token models, fees and change, double spending, nonces,
insufficient balances, unprofitable cloud rentals, access control and tamper
detection.

## Start fresh

```bash
make reset
```

Deletes the chain, pending pool, transfer log, keys and librarian account.

## Files

| File | Purpose |
|---|---|
| `books.txt`, `members.txt` | Book and member registries |
| `chain.dat` | Confirmed (mined) blocks |
| `pending.dat` | Signed records waiting to be mined |
| `transactions.dat` | Confirmed member-to-member transfers |
| `librarian.dat`, `private_key.pem`, `public_key.pem` | Login and signing keys (not committed) |

## Project structure

```
src/
  common.h          Structs and constants (rewards, fees, difficulty, mining settings)
  main.c            Menu, lending actions, start-up, session model choice
  blockchain.c/.h   Signing, proof-of-work hashing, validation, saving and loading
  pending.c/.h      Pending pool of unconfirmed records
  mining.c/.h       Solo, pool and cloud mining, difficulty benchmark
  utxo.c/.h         UTXO model: inputs, outputs, fees, change, double-spend checks
  account.c/.h      Account model: balances, nonces, linked-list history
  ledger.c/.h       Common interface over both models, transfer log
  crypto_utils.c/.h SHA-256 and ECDSA via OpenSSL
  auth.c/.h         Librarian login
  registry.c/.h     books.txt and members.txt
  util.c/.h         Input helpers
tests/run_tests.sh  Automated tests
```

## Design choices and assumptions

- Records are **signed when the event happens** (by the librarian) and
  **hashed with proof-of-work when mined** (by a miner). Miners don't need the
  librarian's key, and a forged record fails its signature even if it is re-mined.
- Each lending record becomes one block. Mining the pool confirms the records in
  the order they were created.
- A book can only have one unconfirmed record at a time, and a return needs a
  **confirmed** borrow first.
- The 1-coin fee on each reward and transfer goes to the miner of the next block.
- Member-to-member transfers are checked and applied immediately and saved to
  `transactions.dat`. Only lending records go through the pending pool, as the
  brief describes.
- Balances are rebuilt at start-up from the confirmed chain plus the transfer
  log, so either model can be chosen each session.
- Miner earnings are shown per session and are separate from member balances.
