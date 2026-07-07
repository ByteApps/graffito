#!/usr/bin/env bash
# M4 gate: hermetic end-to-end proof of the app pipeline against a local
# bitcoind -regtest, INCLUDING the app↔Prime interop matrix — both cores
# run as host binaries in this one script.
#
#   app role   = app-core/examples/cli.rs   (identity from APP_KEY)
#   prime role = prime-chain-notes' notes_cli (identity from NOTES_APP_SEED)
#   chain role = prime-chain-notes/companion/server.py --regtest
#                (mempool-shaped API, manages its own throwaway bitcoind,
#                 auto-mines on POST /tx and /faucet)
#
# Requires the prime workspace layout: ../prime-chain-notes as a sibling.
# Run inside the SDK nix shell (cargo): see CLAUDE.md.
set -euo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; NC=$'\033[0m'
pass() { echo "${GRN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*"; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PRIME="$(cd "$REPO/../prime-chain-notes" && pwd)" || fail "needs ../prime-chain-notes"
WORK="${E2E_WORK:-$(mktemp -d /tmp/chain-notes-app-e2e.XXXXXX)}"
PORT="${E2E_PORT:-18791}"
BASE="http://127.0.0.1:$PORT/regtest/api"

echo "== build both host binaries =="
( cd "$REPO" && cargo build -q -p app-core --example cli )
APP="$REPO/target/debug/examples/cli"
( cd "$PRIME" && cargo build -q -p notes-core --example notes_cli )
NOTES="$PRIME/target/debug/examples/notes_cli"

echo "== start companion server + managed regtest node =="
python3 "$PRIME/companion/server.py" "$PORT" --regtest >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 1 60); do
    curl -sf "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break
    sleep 1
done
curl -sf "http://127.0.0.1:$PORT/api/health" >/dev/null || fail "server did not come up (see $WORK/server.log)"

# App identity: a BIP-39 mnemonic exercises the flagship import format.
export APP_KEY="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
A_ADDR="$("$APP" address regtest)"
[[ "$A_ADDR" == bcrt1p* ]] || fail "app address not taproot: $A_ADDR"
pass "app address $A_ADDR"

# Prime identity (notes_cli's fixed test-seed default).
unset NOTES_APP_SEED
P_ADDR="$("$NOTES" address regtest)"
[[ "$P_ADDR" == bcrt1p* ]] || fail "prime address not taproot: $P_ADDR"
pass "prime address $P_ADDR"

echo "== fund both identities =="
curl -sf -X POST "$BASE/faucet" -d "{\"address\":\"$A_ADDR\",\"amount\":0.001}" >/dev/null
curl -sf -X POST "$BASE/faucet" -d "{\"address\":\"$P_ADDR\",\"amount\":0.001}" >/dev/null
curl -sf -X POST "$BASE/mine?blocks=100" >/dev/null   # mature coinbase for later mining fees

STORE="$WORK/app-store.json"
"$APP" init "$STORE" regtest | grep -q "kind=mnemonic" || fail "init"
"$APP" scan "$STORE" "$BASE" | tee "$WORK/scan1" | grep -q "balance=100000" || fail "funding scan: $(cat "$WORK/scan1")"
pass "funded + scanned (100000 sats)"

echo "== self-notes: public, then private CHAINED on unconfirmed change =="
"$APP" compose "$STORE" "$BASE" public 1.0 "hello public from app" | grep -q broadcast=ok || fail "compose public"
"$APP" compose "$STORE" "$BASE" private 1.0 "hello private from app" | grep -q broadcast=ok || fail "compose private (chained)"
"$APP" scan "$STORE" "$BASE" >/dev/null
"$APP" notes "$STORE" | tee "$WORK/notes1" | grep -q "status=confirmed .*text=hello public from app" || fail "public note confirmed"
grep -q "private=true .*text=hello private from app" "$WORK/notes1" || fail "private note confirmed"
pass "both self-notes confirmed (change chaining worked)"

echo "== wipe recovery: fresh store, bare key, full rescan =="
STORE2="$WORK/app-store-recovered.json"
"$APP" init "$STORE2" regtest >/dev/null
"$APP" scan "$STORE2" "$BASE" >/dev/null
"$APP" notes "$STORE2" | tee "$WORK/notes2" | grep -q "text=hello private from app" || fail "private text not recovered from chain"
grep -q "text=hello public from app" "$WORK/notes2" || fail "public text not recovered"
[[ "$(grep -c '^note ' "$WORK/notes2")" == 2 ]] || fail "expected exactly 2 recovered notes"
pass "wipe recovery: private + public notes rebuilt from chain + key alone"

echo "== external funding (PSBT): build → sign (sim HW) → finalize → broadcast =="
# The shim genesis-rescans each newly-watched address, so touch the minimum:
# gap 0 = only index 0 per chain (the funded coin is at 0/0). Run here — while
# the chain is small — after wipe-recovery so its note count is unaffected.
export CN_FUND_GAP=0
FUND_SEED="1111111111111111111111111111111111111111111111111111111111111111"
IFS=$'\t' read -r F_DESC F_XPRV F_ADDR <<<"$("$APP" fund-keygen regtest "$FUND_SEED")"
[[ -n "$F_ADDR" ]] || fail "fund-keygen produced no address"
curl -sf -X POST "$BASE/faucet" -d "{\"address\":\"$F_ADDR\",\"amount\":0.002}" >/dev/null
curl -sf -X POST "$BASE/mine?blocks=1" >/dev/null
# App identity AUTHORS a directed-private note to prime; the FUNDING wallet pays.
PSBT="$("$APP" fund-build "$BASE" regtest "$F_DESC" private 2.0 "funded by cold storage" "$P_ADDR" 2>"$WORK/fb.log")"
grep -q "fund-build txid=" "$WORK/fb.log" || fail "fund-build: $(cat "$WORK/fb.log")"
SIGNED="$("$APP" fund-sign "$PSBT" "$F_XPRV" 2>"$WORK/fs.log")"
grep -q "inputs_signed=[1-9]" "$WORK/fs.log" || fail "fund-sign signed no inputs: $(cat "$WORK/fs.log")"
FTXID="$("$APP" fund-finalize "$BASE" regtest "$SIGNED" 2>"$WORK/ff.log")"
grep -q "broadcast=ok" "$WORK/ff.log" || fail "fund-finalize: $(cat "$WORK/ff.log")"
pass "external-funded directed note built+signed+finalized+broadcast (txid=$FTXID)"

# Prime decrypts it via the candidate-key path: the author key is not the
# spending input (the funder) but the dust-to-self output — and it is attributed
# to the app identity, not the funder.
"$APP" bundle "$P_ADDR" regtest "$BASE" "$WORK/prime2.json" >/dev/null
"$NOTES" scan "$WORK/prime2.json" >"$WORK/prime2-scan.json"
jq -e --arg from "$A_ADDR" \
    '.[] | select(.received and .private and .from == $from and .text == "funded by cold storage")' \
    "$WORK/prime2-scan.json" >/dev/null \
    || fail "prime did not decrypt externally-funded note: $(cat "$WORK/prime2-scan.json")"
pass "prime decrypted externally-funded note via candidate key, attributed to the app identity"

echo "== app → prime: directed PRIVATE note =="
"$APP" compose "$STORE" "$BASE" private 1.0 "psst prime, from the app" "$P_ADDR" | grep -q broadcast=ok || fail "directed compose"
"$APP" bundle "$P_ADDR" regtest "$BASE" "$WORK/prime.json" >/dev/null
"$NOTES" scan "$WORK/prime.json" >"$WORK/prime-scan.json"
jq -e --arg from "$A_ADDR" \
    '.[] | select(.received and .private and .from == $from and .text == "psst prime, from the app")' \
    "$WORK/prime-scan.json" >/dev/null || fail "prime did not decrypt the app's directed note: $(cat "$WORK/prime-scan.json")"
pass "app → prime directed private: received, attributed, decrypted by prime-core"

echo "== prime → app: directed PRIVATE reply =="
"$NOTES" send "$WORK/prime.json" "$A_ADDR" private 1.0 100000 "hello app, from the prime" >"$WORK/prime-send.json"
RAW="$(jq -r .raw_hex "$WORK/prime-send.json")"
curl -sf -X POST "$BASE/tx" --data-binary "$RAW" >/dev/null || fail "broadcast prime reply"
"$APP" scan "$STORE" "$BASE" >/dev/null
"$APP" notes "$STORE" | tee "$WORK/notes3" | \
    grep -q "received=true from=$P_ADDR .*text=hello app, from the prime" || fail "app did not decrypt prime's directed note: $(cat "$WORK/notes3")"
pass "prime → app directed private: received, attributed, decrypted by app-core"

echo
pass "M4 interop matrix + external funding complete (work dir: $WORK)"
