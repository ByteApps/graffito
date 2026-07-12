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

echo "== recovery-seeds interop: a Prime bip86 seed's 24 words import identically =="
# The whole point of PLAN-chain-notes-seed-rotation.md, proven across the
# two ACTUAL host binaries: the device derives a rotatable BIP-39 phrase
# from its app seed (notes_cli seed-words) and a bip86 notebook address
# (seed-address); feeding those SAME words to the app's normal mnemonic
# import (APP_KEY) must land on the byte-identical address for every
# (seed, account, index) — funds + notes + ECDH all recover from the
# words alone. (The in-process key-level proof is app-core's
# prime_recovery_seed_words_import_identically.)
R_SEED="d074c6f28bb0d891fd30dd6ff6f5face8ea6d209c7b81684babc34e8446d379a"
for combo in "0 0 0" "0 1 2" "1 0 0"; do
    read -r s a i <<<"$combo"
    R_WORDS="$(NOTES_APP_SEED=$R_SEED "$NOTES" seed-words "$s")"
    DEV_ADDR="$(NOTES_APP_SEED=$R_SEED "$NOTES" seed-address regtest "$s" "$a" "$i")"
    APP_ADDR="$(APP_KEY="$R_WORDS" APP_ACCOUNT="$a" APP_INDEX="$i" "$APP" address regtest)"
    [[ "$DEV_ADDR" == "$APP_ADDR" ]] \
        || fail "recovery interop s$s a$a i$i: device $DEV_ADDR != app $APP_ADDR"
done
pass "device seed words → app import: byte-identical addresses across seed/account/index"

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

# External funding (PSBT): the app builds an unsigned tx paid by a watch-only
# funding wallet, an "external wallet" (here: the funding xprv) signs it, the app
# finalizes + broadcasts, and prime decrypts the note — proven for BOTH funding
# address types the feature supports (P2TR and P2WPKH / segwit v0).
#
# The shim genesis-rescans each newly-watched address, so touch the minimum:
# gap 0 = only index 0 per chain (the funded coin is at 0/0). Run here — while
# the chain is small — after wipe-recovery so its note count is unaffected.
export CN_FUND_GAP=0
external_funding() { # <tr|wpkh> <seed-hex> <note-text>
    local kind="$1" seed="$2" text="$3"
    echo "== external funding [$kind]: build → sign (external wallet) → finalize → broadcast =="
    local F_DESC F_XPRV F_ADDR PSBT SIGNED FTXID
    IFS=$'\t' read -r F_DESC F_XPRV F_ADDR <<<"$("$APP" fund-keygen regtest "$seed" "$kind")"
    [[ -n "$F_ADDR" ]] || fail "[$kind] fund-keygen produced no address"
    case "$kind" in
        tr) [[ "$F_ADDR" == bcrt1p* ]] || fail "[$kind] funding addr not taproot: $F_ADDR" ;;
        wpkh) [[ "$F_ADDR" == bcrt1q* ]] || fail "[$kind] funding addr not segwit v0: $F_ADDR" ;;
    esac
    curl -sf -X POST "$BASE/faucet" -d "{\"address\":\"$F_ADDR\",\"amount\":0.002}" >/dev/null
    curl -sf -X POST "$BASE/mine?blocks=1" >/dev/null
    # App identity AUTHORS a directed-private note to prime; the funding wallet pays.
    PSBT="$("$APP" fund-build "$BASE" regtest "$F_DESC" private 2.0 "$text" "$P_ADDR" 2>"$WORK/fb-$kind.log")"
    grep -q "fund-build txid=" "$WORK/fb-$kind.log" || fail "[$kind] fund-build: $(cat "$WORK/fb-$kind.log")"
    SIGNED="$("$APP" fund-sign "$PSBT" "$F_XPRV" 2>"$WORK/fs-$kind.log")"
    grep -q "inputs_signed=[1-9]" "$WORK/fs-$kind.log" \
        || fail "[$kind] fund-sign signed no inputs: $(cat "$WORK/fs-$kind.log")"
    FTXID="$("$APP" fund-finalize "$BASE" regtest "$SIGNED" 2>"$WORK/ff-$kind.log")"
    grep -q "broadcast=ok" "$WORK/ff-$kind.log" || fail "[$kind] fund-finalize: $(cat "$WORK/ff-$kind.log")"
    pass "[$kind] external-funded directed note built+signed+finalized+broadcast (txid=$FTXID)"

    # Prime decrypts it via the candidate-key path: the author key is not the
    # spending input (the funder) but the dust-to-self output — and it is
    # attributed to the app identity, not the funder.
    "$APP" bundle "$P_ADDR" regtest "$BASE" "$WORK/prime-$kind.json" >/dev/null
    "$NOTES" scan "$WORK/prime-$kind.json" >"$WORK/prime-$kind-scan.json"
    jq -e --arg from "$A_ADDR" --arg text "$text" \
        '.[] | select(.received and .private and .from == $from and .text == $text)' \
        "$WORK/prime-$kind-scan.json" >/dev/null \
        || fail "[$kind] prime did not decrypt externally-funded note: $(cat "$WORK/prime-$kind-scan.json")"
    pass "[$kind] prime decrypted externally-funded note via candidate key, attributed to the app identity"
}
external_funding tr 1111111111111111111111111111111111111111111111111111111111111111 "funded by cold storage"
external_funding wpkh 2222222222222222222222222222222222222222222222222222222222222222 "funded by a segwit wallet"

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

echo "== prime → app NOTEBOOK 1 (rev 3: receive index 0/1, own enc key) =="
# A second notebook of the SAME app seed/account is receive index 1 — its
# address AND note-encryption key differ from notebook 0's (frozen rule
# derives from the leaf). Prime sends it a directed private note; only the
# index-1 identity can decrypt it.
NB1_ADDR="$(APP_INDEX=1 "$APP" address regtest)"
[ "$NB1_ADDR" != "$A_ADDR" ] || fail "notebook 1 address equals notebook 0"
NB1_STORE="$WORK/app-nb1.json"
APP_INDEX=1 "$APP" init "$NB1_STORE" regtest >/dev/null
# Refresh prime's ledger first — its previous send's inputs are gone.
"$APP" bundle "$P_ADDR" regtest "$BASE" "$WORK/prime.json" >/dev/null
"$NOTES" scan "$WORK/prime.json" >/dev/null
"$NOTES" send "$WORK/prime.json" "$NB1_ADDR" private 1.0 100000 "hello notebook one" >"$WORK/prime-send-nb1.json"
RAW="$(jq -r .raw_hex "$WORK/prime-send-nb1.json")"
curl -s -X POST "$BASE/tx" --data-binary "$RAW" >"$WORK/nb1-broadcast" || true
grep -qi error "$WORK/nb1-broadcast" && fail "broadcast prime → nb1: $(cat "$WORK/nb1-broadcast")"
APP_INDEX=1 "$APP" scan "$NB1_STORE" "$BASE" >/dev/null
APP_INDEX=1 "$APP" notes "$NB1_STORE" | tee "$WORK/notes-nb1" | \
    grep -q "received=true from=$P_ADDR .*text=hello notebook one" || fail "notebook 1 did not decrypt its directed note: $(cat "$WORK/notes-nb1")"
# Notebook 0 must NOT see the body (different leaf, different enc key —
# and a different address entirely, so it never even scans that tx).
"$APP" scan "$STORE" "$BASE" >/dev/null
"$APP" notes "$STORE" | grep -q "text=hello notebook one" && fail "notebook 0 leaked notebook 1's note"
pass "prime → app notebook 1 (index 0/1): decrypted by its own leaf key only"

echo
pass "interop matrix + external funding (P2TR + P2WPKH) complete (work dir: $WORK)"
