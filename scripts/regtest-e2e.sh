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
#
# --core-rpc (opt-in, PLAN-chain-notes-app-core-rpc.md unit U8): runs the
# IDENTICAL legs against a REAL `bitcoind -regtest` this script starts and
# manages itself — NO companion shim in the loop at all. The app's base
# becomes a `bitcoind+http://` URL (`app_core::chain::AnyTransport`'s Core
# backend, U2/U3), and the two harness-only conveniences server.py's
# /regtest/api/mine and /regtest/api/faucet provide are replaced with
# direct `bitcoin-cli` calls — the app itself speaks ONLY Core RPC in this
# mode, which is the whole point of the unit: proving the app needs no
# shim. The default (no-arg) mode is byte-identical to before this unit.
set -euo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; NC=$'\033[0m'
pass() { echo "${GRN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*"; exit 1; }

CORE_RPC=0
if [[ "${1:-}" == "--core-rpc" ]]; then
    CORE_RPC=1
fi

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PRIME="$(cd "$REPO/../prime-chain-notes" && pwd)" || fail "needs ../prime-chain-notes"
WORK="${E2E_WORK:-$(mktemp -d /tmp/chain-notes-app-e2e.XXXXXX)}"
PORT="${E2E_PORT:-18791}"

echo "== build both host binaries =="
( cd "$REPO" && cargo build -q -p app-core --example cli )
APP="$REPO/target/debug/examples/cli"
( cd "$PRIME" && cargo build -q -p notes-core --example notes_cli )
NOTES="$PRIME/target/debug/examples/notes_cli"

# ---------------------------------------------------------------------------
# Backend setup: Esplora (server.py-managed regtest, default) or Core RPC
# (a throwaway bitcoind THIS script starts/stops directly, no shim).
#
# Both branches define the same four harness verbs the rest of the script
# calls: `mine_blocks N`, `faucet ADDR BTC`, `broadcast_raw HEX FAILMSG`,
# `broadcast_raw_check HEX OUTFILE`. These are TEST-HARNESS conveniences —
# server.py exposes the first two as HTTP routes and auto-mines on the last
# two; the app itself never calls any of them. In --core-rpc mode every one
# of the four is a direct `bitcoin-cli` call, and mining is EXPLICIT after
# every broadcast (Core mode's transport deliberately does not auto-mine —
# see chain.rs's `CoreRpcTransport::post_text` doc comment — so this script
# must do what server.py's POST /tx handler used to do for it).
if [[ "$CORE_RPC" == 1 ]]; then
    echo "== start our OWN regtest bitcoind (no companion shim — Core RPC mode) =="
    CORE_PORT="${E2E_CORE_PORT:-$((19000 + ($$ % 3000)))}"
    export CORE_RPC_USER="cnrpcuser"
    export CORE_RPC_PASS="cnrpcpass-$$"
    CORE_DATADIR="$(mktemp -d /tmp/chain-notes-app-core-rpc.XXXXXX)"
    # rpcuser/rpcpassword/rpcport are network-specific settings and MUST
    # live under a [regtest] section (bitcoind refuses otherwise —
    # verified in app-core/tests/core_rpc_conformance.rs's start_node()).
    # Basic auth, deliberately NOT cookie auth: cookie files aren't
    # readable from iOS (plan §2.4), so this genuinely exercises the auth
    # path the app itself uses. txindex=1 + fallbackfee=0.0001 mirror
    # server.py's managed-node config (companion/server.py:80-102).
    cat > "$CORE_DATADIR/bitcoin.conf" <<CONF
regtest=1
server=1
txindex=1
fallbackfee=0.0001

[regtest]
rpcuser=$CORE_RPC_USER
rpcpassword=$CORE_RPC_PASS
rpcport=$CORE_PORT
CONF
    bitcoind -regtest -datadir="$CORE_DATADIR" -daemon=0 >"$WORK/bitcoind.log" 2>&1 &
    BITCOIND_PID=$!

    core_cli() { bitcoin-cli -regtest -datadir="$CORE_DATADIR" -rpcuser="$CORE_RPC_USER" -rpcpassword="$CORE_RPC_PASS" -rpcport="$CORE_PORT" "$@"; }
    miner_cli() { core_cli -rpcwallet=miner "$@"; }

    cleanup() {
        if [[ -n "${BITCOIND_PID:-}" ]]; then
            core_cli stop >/dev/null 2>&1 || true
            for _ in $(seq 1 20); do
                kill -0 "$BITCOIND_PID" 2>/dev/null || break
                sleep 0.5
            done
            kill "$BITCOIND_PID" 2>/dev/null || true
            wait "$BITCOIND_PID" 2>/dev/null || true
        fi
        [[ -n "${CORE_DATADIR:-}" ]] && rm -rf "$CORE_DATADIR"
    }
    trap cleanup EXIT

    for _ in $(seq 1 60); do
        core_cli getblockchaininfo >/dev/null 2>&1 && break
        sleep 0.5
    done
    core_cli getblockchaininfo >/dev/null 2>&1 || fail "bitcoind did not come up (see $WORK/bitcoind.log, datadir $CORE_DATADIR)"

    # `mine_blocks`/`faucet` are needed immediately (initial maturity), so
    # define them before first use.
    mine_blocks() { # n
        local n="$1" addr
        addr="$(miner_cli getnewaddress)"
        miner_cli generatetoaddress "$n" "$addr" >/dev/null
        # bitcoind's wallet block-processing is ASYNC (validation-interface
        # callbacks drain on the scheduler thread after generatetoaddress
        # returns) — without this sync, a listunspent/getrawtransaction
        # served right after can answer from the PRE-block view. Same
        # hazard server.py's mine() and the U3 conformance suite's
        # Node::generate() both guard against.
        core_cli syncwithvalidationinterfacequeue >/dev/null 2>&1 || true
    }
    faucet() { # addr amount_btc
        miner_cli sendtoaddress "$1" "$2" >/dev/null
        mine_blocks 1
    }
    broadcast_raw() { # hex failmsg
        core_cli sendrawtransaction "$1" >/dev/null || fail "$2"
        mine_blocks 1
    }
    broadcast_raw_check() { # hex outfile — never fails the script; writes
                             # the txid (success) or bitcoind's error text
                             # (rejection, contains "error") to outfile,
                             # mirroring curl -s's "print the body either
                             # way" behavior against server.py.
        local hex="$1" outfile="$2" out
        if out="$(core_cli sendrawtransaction "$hex" 2>&1)"; then
            printf '%s' "$out" > "$outfile"
            mine_blocks 1
        else
            printf '%s' "$out" > "$outfile"
        fi
    }

    core_cli createwallet miner >/dev/null
    mine_blocks 101   # mature coinbase, mirrors server.py's start_managed_node
    echo "bitcoind up (datadir $CORE_DATADIR, port $CORE_PORT), 101 blocks mined"

    BASE="bitcoind+http://127.0.0.1:$CORE_PORT"
else
    BASE="http://127.0.0.1:$PORT/regtest/api"

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

    mine_blocks() { curl -sf -X POST "$BASE/mine?blocks=$1" >/dev/null; }
    faucet() { curl -sf -X POST "$BASE/faucet" -d "{\"address\":\"$1\",\"amount\":$2}" >/dev/null; }
    broadcast_raw() { curl -sf -X POST "$BASE/tx" --data-binary "$1" >/dev/null || fail "$2"; }
    broadcast_raw_check() { curl -s -X POST "$BASE/tx" --data-binary "$1" >"$2" || true; }
fi

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
faucet "$A_ADDR" 0.001
faucet "$P_ADDR" 0.001
mine_blocks 100   # mature coinbase for later mining fees

STORE="$WORK/app-store.json"
"$APP" init "$STORE" regtest | grep -q "kind=mnemonic" || fail "init"
"$APP" scan "$STORE" "$BASE" | tee "$WORK/scan1" | grep -q "balance=100000" || fail "funding scan: $(cat "$WORK/scan1")"
pass "funded + scanned (100000 sats)"

echo "== self-notes: public, then private CHAINED on unconfirmed change =="
"$APP" compose "$STORE" "$BASE" public 1.0 "hello public from app" | grep -q broadcast=ok || fail "compose public"
"$APP" compose "$STORE" "$BASE" private 1.0 "hello private from app" | grep -q broadcast=ok || fail "compose private (chained)"
# Core mode does not auto-mine on broadcast, so mine ONCE here — AFTER both
# composes, never between them — so the private tx's build genuinely spent
# the public tx's still-unconfirmed change (app-core's local Store ledger
# tracks that pending output the instant it signs, before any scan/mine),
# and only the follow-up scan below needs both confirmed.
if [[ "$CORE_RPC" == 1 ]]; then mine_blocks 1; fi
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
    faucet "$F_ADDR" 0.002
    mine_blocks 1
    # App identity AUTHORS a directed-private note to prime; the funding wallet pays.
    PSBT="$("$APP" fund-build "$BASE" regtest "$F_DESC" private 2.0 "$text" "$P_ADDR" 2>"$WORK/fb-$kind.log")"
    grep -q "fund-build txid=" "$WORK/fb-$kind.log" || fail "[$kind] fund-build: $(cat "$WORK/fb-$kind.log")"
    SIGNED="$("$APP" fund-sign "$PSBT" "$F_XPRV" 2>"$WORK/fs-$kind.log")"
    grep -q "inputs_signed=[1-9]" "$WORK/fs-$kind.log" \
        || fail "[$kind] fund-sign signed no inputs: $(cat "$WORK/fs-$kind.log")"
    FTXID="$("$APP" fund-finalize "$BASE" regtest "$SIGNED" 2>"$WORK/ff-$kind.log")"
    grep -q "broadcast=ok" "$WORK/ff-$kind.log" || fail "[$kind] fund-finalize: $(cat "$WORK/ff-$kind.log")"
    if [[ "$CORE_RPC" == 1 ]]; then mine_blocks 1; fi
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
if [[ "$CORE_RPC" == 1 ]]; then mine_blocks 1; fi
"$APP" bundle "$P_ADDR" regtest "$BASE" "$WORK/prime.json" >/dev/null
"$NOTES" scan "$WORK/prime.json" >"$WORK/prime-scan.json"
jq -e --arg from "$A_ADDR" \
    '.[] | select(.received and .private and .from == $from and .text == "psst prime, from the app")' \
    "$WORK/prime-scan.json" >/dev/null || fail "prime did not decrypt the app's directed note: $(cat "$WORK/prime-scan.json")"
pass "app → prime directed private: received, attributed, decrypted by prime-core"

echo "== prime → app: directed PRIVATE reply =="
"$NOTES" send "$WORK/prime.json" "$A_ADDR" private 1.0 100000 "hello app, from the prime" >"$WORK/prime-send.json"
RAW="$(jq -r .raw_hex "$WORK/prime-send.json")"
broadcast_raw "$RAW" "broadcast prime reply"
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
broadcast_raw_check "$RAW" "$WORK/nb1-broadcast"
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

# ---------------------------------------------------------------------------
# Funding-unification M4: the INTERNAL spending wallet (BIP-84 of the same
# seed, signed fully in-app — see ../PLAN-chain-notes-funding-unification.md).
# A dedicated identity (own mnemonic, own store) so its notebook stays
# dust-only and the balance/utxo assertions below aren't polluted by the
# self/directed notes composed against $STORE above.
#
# gap=0 (still exported from the external-funding block above) would only
# ever probe receive/change index 0 — wrong here, since these legs hand out
# MULTIPLE spending-wallet addresses over time. A small nonzero gap keeps the
# regtest shim's per-address genesis-rescan cost down while still reaching
# every index actually used.
export CN_FUND_GAP=2
FU_KEY="zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
FU_STORE="$WORK/fu-store.json"
export APP_KEY="$FU_KEY"
"$APP" init "$FU_STORE" regtest | grep -q "kind=mnemonic" || fail "fu: init"
FU_ADDR="$("$APP" address regtest)"
[[ "$FU_ADDR" == bcrt1p* ]] || fail "fu: notebook address not taproot: $FU_ADDR"
pass "fu: dedicated funding-unification identity $FU_ADDR (notebook stays dust-only)"

echo "== fu leg 1: funded self-note (public) — self-spk-SET marks it OWN =="
SPEND_ADDR1="$("$APP" spending-address "$FU_STORE" regtest | tail -1)"
[[ "$SPEND_ADDR1" == bcrt1q* ]] || fail "fu leg1: spending address not segwit v0: $SPEND_ADDR1"
faucet "$SPEND_ADDR1" 0.0005
mine_blocks 1
"$APP" note-spend-funded "$FU_STORE" "$BASE" public 2.0 "funded self note" \
    | tee "$WORK/fu-leg1.log" | grep -q "broadcast=ok" || fail "fu leg1: note-spend-funded: $(cat "$WORK/fu-leg1.log")"
if [[ "$CORE_RPC" == 1 ]]; then mine_blocks 1; fi
pass "fu leg1: funded self-note composed + signed + broadcast entirely in-app via the spending wallet"

"$APP" scan "$FU_STORE" "$BASE" >/dev/null
"$APP" notes "$FU_STORE" | tee "$WORK/fu-notes1" \
    | grep -q "private=false directed=false received=false from=- to=- text=funded self note" \
    || fail "fu leg1: funded self-note did not scan back as OWN: $(cat "$WORK/fu-notes1")"
pass "fu leg1: a fresh scan classifies the spending-wallet-funded note as OWN (self-spk SET, not the old notebook-spk-only rule)"

echo "== fu leg 2: funded directed-private note → prime =="
SPEND_ADDR2="$("$APP" spending-address "$FU_STORE" regtest | tail -1)"
[ "$SPEND_ADDR2" != "$SPEND_ADDR1" ] || fail "fu leg2: spending wallet reused a receive address"
faucet "$SPEND_ADDR2" 0.0005
mine_blocks 1
"$APP" note-spend-funded "$FU_STORE" "$BASE" private 2.0 "funded directed note" "$P_ADDR" \
    | tee "$WORK/fu-leg2.log" | grep -q "broadcast=ok" || fail "fu leg2: note-spend-funded: $(cat "$WORK/fu-leg2.log")"
if [[ "$CORE_RPC" == 1 ]]; then mine_blocks 1; fi
pass "fu leg2: funded directed-private note composed + signed + broadcast entirely in-app via the spending wallet"

"$APP" scan "$FU_STORE" "$BASE" >/dev/null
"$APP" notes "$FU_STORE" | tee "$WORK/fu-notes2" \
    | grep -q "private=true directed=true received=false from=- to=$P_ADDR text=funded directed note" \
    || fail "fu leg2: sender's own scan did not re-read its funded directed note: $(cat "$WORK/fu-notes2")"
pass "fu leg2: the sender's own scan re-reads its funded directed-private note (self-spk SET, own dust-output recipient key)"

echo "== fu leg 4: device-side interop — prime's scanner doesn't know the spending branch =="
# Prime (device role) scans with only a SINGLETON notebook spk — the
# funding-unification scanner generalization is opt-in, and a device that
# never passes a self-spk set gets exactly the pre-M0 behavior. It cannot
# see the spending-wallet input, so it falls to the pays-notebook+PNTE
# RECEIVED path and decrypts via the candidate-key walk (the dust-to-self
# output, a taproot address) — same mechanism the external-funding legs
# above already proved, now exercised for the INTERNAL kind.
"$APP" bundle "$P_ADDR" regtest "$BASE" "$WORK/fu-prime-bundle.json" >/dev/null
"$NOTES" scan "$WORK/fu-prime-bundle.json" >"$WORK/fu-prime-scan.json"
jq -e --arg from "$FU_ADDR" --arg text "funded directed note" \
    '.[] | select(.received and .private and .from == $from and .text == $text)' \
    "$WORK/fu-prime-scan.json" >/dev/null \
    || fail "fu leg4: prime did not decrypt the spending-wallet-funded directed note: $(cat "$WORK/fu-prime-scan.json")"
jq -e --arg text "funded directed note" '[.[] | select(.text == $text)] | length == 1' \
    "$WORK/fu-prime-scan.json" >/dev/null \
    || fail "fu leg4: note vanished or duplicated in prime's scan: $(cat "$WORK/fu-prime-scan.json")"
pass "fu leg4: prime's scanner (singleton spk) neither drops the note nor calls it its own — received, attributed to the app identity, not the funder"

echo "== fu leg 5: dust accumulation — two funded notes leave two 330-sat dust coins on the notebook =="
"$APP" scan "$FU_STORE" "$BASE" | tee "$WORK/fu-scan-dust" | grep -q "balance=660" \
    || fail "fu leg5: expected 660 sats (2x330 dust-to-self) on the notebook: $(cat "$WORK/fu-scan-dust")"
pass "fu leg5: notebook balance accounts for both dust-to-self outputs"

echo "== fu leg 5b: the EXISTING consolidate (sweep-to-self) path sweeps the accumulated dust =="
"$APP" sweep "$FU_STORE" "$BASE" "$FU_ADDR" 1.0 \
    | tee "$WORK/fu-consolidate.log" | grep -q "^cli: sweep txid=" \
    || fail "fu leg5b: dust consolidate: $(cat "$WORK/fu-consolidate.log")"
if [[ "$CORE_RPC" == 1 ]]; then mine_blocks 1; fi
"$APP" scan "$FU_STORE" "$BASE" | tee "$WORK/fu-scan-post-consolidate" >/dev/null
FU_BAL_POST="$(grep -o 'balance=[0-9]*' "$WORK/fu-scan-post-consolidate" | cut -d= -f2)"
[[ "$FU_BAL_POST" -gt 0 && "$FU_BAL_POST" -lt 660 ]] \
    || fail "fu leg5b: post-consolidate balance unexpected: $FU_BAL_POST (want 0 < n < 660)"
pass "fu leg5b: the two dust coins merged into one via the notebook's existing sweep/consolidate flow (balance $FU_BAL_POST sats after fee, no new mechanism)"

echo "== fu leg 3: words-only recovery re-labels the funded self-note OWN, with NO local state =="
# "Wipe the app's data dir": a brand-new work directory means a brand-new
# notebooks index path too (it's keyed off APP_KEY's fingerprint + this
# store's directory) — nothing survives except the SAME mnemonic. Discovery
# re-derives the spending branch's used addresses from chain data alone,
# proving the recovery property the whole self-spk-SET rule exists for.
FU_RECOVERY_DIR="$WORK/fu-recovery"
mkdir -p "$FU_RECOVERY_DIR"
FU_STORE3="$FU_RECOVERY_DIR/fu-store.json"
"$APP" init "$FU_STORE3" regtest >/dev/null
"$APP" spending-discover "$FU_STORE3" "$BASE" 3 \
    | tee "$WORK/fu-discover.log" | grep -q "^cli: spending-discover found=" \
    || fail "fu leg3: spending-discover: $(cat "$WORK/fu-discover.log")"
FU_FOUND="$(grep -o 'found=[0-9]*' "$WORK/fu-discover.log" | cut -d= -f2)"
[[ "$FU_FOUND" -ge 2 ]] || fail "fu leg3: expected discovery to find both used receive addresses (leg1 + leg2), got found=$FU_FOUND"
"$APP" scan "$FU_STORE3" "$BASE" >/dev/null
"$APP" notes "$FU_STORE3" | tee "$WORK/fu-notes3" \
    | grep -q "private=false directed=false received=false from=- to=- text=funded self note" \
    || fail "fu leg3: words-only recovery did not re-label the funded self-note OWN: $(cat "$WORK/fu-notes3")"
pass "fu leg3: words-only recovery (fresh store + fresh notebooks index, same mnemonic) re-derives the spending branch via gap discovery and re-labels the funded note OWN"

echo
pass "funding-unification M4: internal spending wallet e2e (funded self-note, funded directed-private, words-only recovery re-labeling, device-side interop, dust accumulation + consolidate) complete (work dir: $WORK)"

# ---------------------------------------------------------------------------
# multi-all-paths M0: multi-recipient directed notes through the SPENDING-
# WALLET-funded path (`build_funding_psbt_multi` / `on_spending_compose_send`
# in the app) — the CLI-level substitute the plan sanctioned for this leg
# (driving the full simtap UI would additionally need enabling spending in
# Settings + faucet-funding a derived spending address before compose even
# starts; the notebook-funded multi-recipient path already has a full simtap
# leg in ui-automation/tests/chain-notes-app-multi-recipient.sh). A FRESH
# dedicated identity + store, exactly like the "fu" legs above, so this
# never perturbs their exact balance/count assertions.
echo "== multi leg: spending-wallet-funded note to 3 recipients =="
MFU_KEY="legal winner thank year wave sausage worth useful legal winner thank yellow"
MFU_STORE="$WORK/mfu-store.json"
export APP_KEY="$MFU_KEY"
"$APP" init "$MFU_STORE" regtest | grep -q "kind=mnemonic" || fail "multi-fu: init"
MFU_SPEND_ADDR="$("$APP" spending-address "$MFU_STORE" regtest | tail -1)"
[[ "$MFU_SPEND_ADDR" == bcrt1q* ]] || fail "multi-fu: spending address not segwit v0: $MFU_SPEND_ADDR"
faucet "$MFU_SPEND_ADDR" 0.0006
mine_blocks 1

# Three throwaway taproot recipients (any valid 32-byte hex key — none of
# them need to sign anything, just be valid taproot regtest addresses).
M_R1="$(APP_KEY=1111111111111111111111111111111111111111111111111111111111111111 "$APP" address regtest)"
M_R2="$(APP_KEY=2222222222222222222222222222222222222222222222222222222222222222 "$APP" address regtest)"
M_R3="$(APP_KEY=3333333333333333333333333333333333333333333333333333333333333333 "$APP" address regtest)"
export APP_KEY="$MFU_KEY"
"$APP" note-spend-funded-multi "$MFU_STORE" "$BASE" public 2.0 500 "multi-recipient spending-wallet note" \
    "$M_R1" "$M_R2" "$M_R3" \
    | tee "$WORK/multi-fu-leg.log" | grep -q "recipients=3 sent_to_recipient=1500 .*broadcast=ok" \
    || fail "multi leg: note-spend-funded-multi: $(cat "$WORK/multi-fu-leg.log")"
if [[ "$CORE_RPC" == 1 ]]; then mine_blocks 1; fi
pass "multi leg: 3-recipient spending-wallet-funded note (uniform 500-sat gift, 1500 sats total) composed + signed + broadcast entirely in-app"

# Each recipient decrypts/decodes its own copy of the PUBLIC multi-recipient
# note independently (FLAG_MULTI body is plaintext for a public note — any
# holder of a recipient dust output can read it, same as any other public
# note; the multi-recipient framing only changes ownership/addressing, not
# visibility).
for rk in 1111111111111111111111111111111111111111111111111111111111111111 \
          2222222222222222222222222222222222222222222222222222222222222222 \
          3333333333333333333333333333333333333333333333333333333333333333; do
    R_STORE="$WORK/multi-recip-$rk.json"
    APP_KEY="$rk" "$APP" init "$R_STORE" regtest >/dev/null
    APP_KEY="$rk" "$APP" scan "$R_STORE" "$BASE" >/dev/null
    APP_KEY="$rk" "$APP" notes "$R_STORE" | tee "$WORK/multi-recip-notes-$rk" \
        | grep -q "received=true .*text=multi-recipient spending-wallet note" \
        || fail "multi leg: recipient $rk did not receive the multi-recipient note: $(cat "$WORK/multi-recip-notes-$rk")"
done
pass "multi leg: all three recipients independently scan + read the multi-recipient public note"

if [[ "$CORE_RPC" == 1 ]]; then
    echo
    pass "Core RPC mode (--core-rpc): every leg above ran against a real bitcoind with NO companion shim in the loop"
fi
