#!/usr/bin/env bash
# Automated tests for the Formative 2 lending tracker (tokens + mining).
# Runs in a temporary folder so your real data is never touched.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/library_chain"
PASS=0
FAIL=0
PW='S3curePass!'
LOGIN="1\nadmin\n$PW\n"

check() {   # check "name" "expected text" "$output"
    if grep -qF -- "$2" <<<"$3"; then
        echo "PASS: $1"; PASS=$((PASS + 1))
    else
        echo "FAIL: $1   (expected to see: $2)"; FAIL=$((FAIL + 1))
    fi
}
run() { printf "$1" | "$BIN" "${@:2}" 2>&1; }

[ -x "$BIN" ] || { echo "Build first with: make"; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "== Registries and arguments =="
out=$(run "")
check "missing books.txt is rejected" "Cannot open books.txt" "$out"
cp "$ROOT/books.txt" .; : > members.txt
out=$(run "")
check "empty members.txt is rejected" "members.txt is empty" "$out"
cp "$ROOT/members.txt" .
out=$(run "" --difficulty 7)
check "difficulty outside 1-4 is rejected" "must be between 1 and 4" "$out"
out=$(run "" --model banana)
check "unknown model is rejected" "must be 'utxo' or 'account'" "$out"

echo "== Pending pool and solo mining (UTXO model) =="
out=$(run "admin\n$PW\n$PW\n1\nBK001\nALU001\n1\nBK002\nALU002\n1\nBK001\nALU003\n2\nBK001\nALU001\n1\nBK999\nALU001\n4\n0\n" --model utxo)
check "genesis block is mined" "Genesis block mined" "$out"
check "borrow goes to the pending pool" "PENDING: BK001 borrowed by ALU001" "$out"
check "unconfirmed record blocks a second action" "already has an unconfirmed record" "$out"
check "return before the borrow is mined is refused" "Mine the pending pool (option 5)" "$out"
check "unknown IDs are rejected" "ERROR: Book or Member not found" "$out"
check "pending pool lists unconfirmed records" "PENDING POOL (2 unconfirmed)" "$out"
out=$(run "${LOGIN}4\n0\n" --model utxo)
check "pending pool survives a restart" "Pending pool: 2 unconfirmed" "$out"
out=$(run "${LOGIN}5\n1\nSOLO-1\n7\n0\n" --model utxo)
check "solo mining reports hash attempts" "found after" "$out"
check "solo mining summary" "SOLO MINING SUMMARY" "$out"
check "solo miner gets the full reward" "all paid to SOLO-1" "$out"
check "borrow blocks create no transaction" "(no token transaction)" "$out"
check "mined chain validates with proof-of-work" "CHAIN VALID" "$out"

echo "== On-time return, reward and UTXO transfers =="
out=$(run "${LOGIN}2\nBK001\nALU001\n8\n5\n2\n3\n8\n0\n" --model utxo)
check "on-time return creates a 10-coin reward" "Reward transaction created: 10 coins" "$out"
check "balance not updated before mining" "ALU001   John Doe                 0" "$out"
check "pool mining shows the sharing table" "POOL REWARD SHARING" "$out"
check "pool fee of 2% is deducted" "Pool fee (2%)" "$out"
check "member credited reward minus fee" "ALU001 credited 9 coin(s)" "$out"
check "UTXO set shown after confirmation" "UTXO SET (1 unspent output(s))" "$out"
out=$(run "${LOGIN}9\nALU001\nALU003\n20\n9\nALU001\nALU003\n3\n12\nALU001\nALU002\n8\n0\n" --model utxo)
check "insufficient inputs are rejected" "INSUFFICIENT INPUTS" "$out"
check "valid transfer is accepted" "ACCEPTED: ALU001 sent 3 coin(s) to ALU003" "$out"
check "change output returned to sender" "5 coin(s) -> ALU001  (change)" "$out"
check "double spend is rejected" "REJECTED: DOUBLE SPEND" "$out"

echo "== Late return, overdue (no transaction) and cloud mining =="
out=$(run "${LOGIN}1\nBK003\nALU003\n5\n1\nSOLO-1\n0\n" --model utxo)
sleep 2
out=$(LOAN_PERIOD_SECONDS=1 run "${LOGIN}3\n5\n1\nSOLO-1\n2\nBK003\nALU003\n5\n3\nRENTER\n2\n0\n" --model utxo)
check "overdue loan creates no transaction" "No reward transaction is created" "$out"
check "late return earns 5 coins" "LATE" "$out"
check "late reward is 5" "Reward transaction created: 5 coins" "$out"
check "cloud mining summary" "CLOUD MINING SUMMARY (2 round(s))" "$out"
check "cloud mining shows net profit" "Net profit" "$out"
out=$(run "${LOGIN}5\n3\nRENTER\n2\n0\n" --model utxo --difficulty 4)
check "unprofitable rental gives a warning" "WARNING: rental is UNPROFITABLE" "$out"

echo "== Account-based model =="
out=$(run "${LOGIN}8\n9\nALU001\nALU002\n1\n5\n9\nALU001\nALU002\n1\n0\n9\nALU001\nALU002\n1\n1\n9\nALU002\nALU001\n50\n0\n10\nALU001\n0\n" --model account)
check "balances rebuilt from chain and log" "| ALU001   |       5 |     1 |" "$out"
check "incorrect nonce is rejected" "INCORRECT NONCE" "$out"
check "reused nonce is rejected" "REUSED NONCE" "$out"
check "correct nonce is accepted" "ACCEPTED: ALU001 sent 1 coin(s) to ALU002 (fee 1, nonce 1)" "$out"
check "insufficient balance is rejected" "INSUFFICIENT BALANCE" "$out"
check "history is printed per member" "TRANSACTION HISTORY for ALU001" "$out"
check "history lists the reward from LIBRARY" "LIBRARY   ALU001" "$out"

echo "== Access control, benchmark and tampering =="
out=$(run "2\n1\n5\n9\n16\n0\n" --model utxo)
check "guest cannot borrow, mine or transfer" "ACCESS DENIED" "$out"
check "difficulty benchmark runs" "DIFFICULTY BENCHMARK" "$out"
out=$(run "2\n15\n1\n1\n15\n1\n2\n0\n" --model utxo)
check "naive tamper breaks proof-of-work" "PROOF-OF-WORK FAILED" "$out"
check "re-mining attacker still fails the signature" "INVALID SIGNATURE" "$out"
check "attacker's extra work is reported" "hash attempts of extra work" "$out"
cp chain.dat chain.bak
sed -i '0,/|BORROWED|/s//|RETURNED|/' chain.dat
out=$(run "2\n7\n0\n" --model utxo)
check "edited chain.dat is detected" "CHAIN INVALID" "$out"
check "edited block fails its checks" "HASH MISMATCH" "$out"
out=$(run "${LOGIN}1\n0\n" --model utxo)
check "writes blocked on an invalid chain" "Write operations are disabled" "$out"
cp chain.bak chain.dat
out=$(run "${LOGIN}1\nBK005\nALU005\n0\n" --model utxo)
sed -i 's/Aline Uwase/Mallory X/' pending.dat
out=$(run "2\n0\n" --model utxo)
check "tampered pending pool is refused" "pending pool was tampered with" "$out"

echo
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
