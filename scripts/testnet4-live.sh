#!/usr/bin/env bash
# Targeted LIVE testnet4 pass for the Bitcoin Core RPC backend
# (PLAN-chain-notes-app-core-rpc.md) — the validation regtest structurally
# cannot provide: a real, synced, non-pruned node on a real network, over
# an SSH tunnel to a remote Pi (this is NOT Esplora — see the tunnel's
# port table; this script only ever speaks Core JSON-RPC, matching the
# app's own `bitcoind+http://` transport).
#
# Requires (never read from argv, never printed/logged):
#   CORE_RPC_USER / CORE_RPC_PASS   — the SAME env vars examples/cli.rs
#                                      already reads for Core RPC auth.
# Base defaults to the tunnel's forwarded testnet4 RPC port; override with
# E2E_T4_HOST / E2E_T4_PORT.
#
# FUNDS RULES (hard limits — see the task brief this script was written
# for): total spend this whole task <= 50,000 sats excluding the sweep-back;
# funding source is the gift-wallet address; leftovers sweep back to it;
# NEVER touch the two live App-Review addresses; NEVER touch mainnet; low
# fee rate (1-2 sat/vB). This script enforces the amount cap itself
# (FUND_SATS below) and refuses to run if it's set above the remaining
# budget.
#
# Design note (history, kept for context): step 2 below USED TO fail with a
# clear BUG banner rather than proceed to fund/compose/broadcast, because
# `CoreRpcTransport::ensure_address_watched` (app-core/src/chain.rs)
# unconditionally re-imported every queried address with `timestamp: 0` (a
# full genesis rescan) with no check for an already-imported descriptor, on
# EVERY fresh transport instance, while `CoreRpcTransport::new`'s `reqwest`
# client had a HARDCODED 30-second total timeout — far shorter than the
# ~340s (~5.7 min) a genesis rescan of testnet4 (146,369+ blocks) actually
# takes server-side. That bug is now FIXED (see `ensure_address_watched`'s
# own doc comment in app-core/src/chain.rs — node-truth idempotence via
# `getaddressinfo`/`ismine`, a process-global watch cache, and a
# minutes-long `RESCAN_TIMEOUT` reserved for the one time an import is
# genuinely needed): step 2 now completes in ~8s against this exact node,
# and steps 3-5 below are exercised live on every run. If step 2 ever
# observe it complete inside CHAIN_TOUCH_TIMEOUT and this script will
# proceed automatically to fund/compose/broadcast/scan/sweep — nothing
# here needs to change.
set -uo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; NC=$'\033[0m'
pass() { echo "${GRN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*"; }
bug()  { echo "${YEL}BUG ${NC} $*"; }

: "${CORE_RPC_USER:?testnet4-live.sh needs CORE_RPC_USER in the environment}"
: "${CORE_RPC_PASS:?testnet4-live.sh needs CORE_RPC_PASS in the environment}"
export CORE_RPC_USER CORE_RPC_PASS

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${E2E_WORK:-$(mktemp -d /tmp/chain-notes-app-t4-live.XXXXXX)}"
T4_HOST="${E2E_T4_HOST:-127.0.0.1}"
T4_PORT="${E2E_T4_PORT:-48332}"
BASE="bitcoind+http://$T4_HOST:$T4_PORT"

# Hard cap enforced HERE too, independent of the task brief: this script
# will refuse to broadcast anything spending more than this many sats
# (excludes the sweep-back, which returns funds rather than spending them).
FUND_SATS="${E2E_T4_FUND_SATS:-20000}"
FUND_ADDR="${E2E_T4_FUND_ADDR:-tb1q2ylq48ne37ng9clds23xjcrxp8hmn707j5vpyk}"
# Never touch these — quoted in the live App Store review notes.
FORBIDDEN_ADDRS=(
    "tb1pev690svkjfgl86ps4ptv47tuuclgg9ajdkexg43rctq0msr6692qr6zksz"
    "tb1pgm6v3lpp38f9msgs7vllcq68ep25qf8f7592zlsrffsh5tdl4eks6mhr0e"
)
if [[ " ${FORBIDDEN_ADDRS[*]} " == *" $FUND_ADDR "* ]]; then
    fail "refusing to run: FUND_ADDR is one of the forbidden App-Review addresses"
    exit 2
fi
if (( FUND_SATS > 50000 )); then
    fail "refusing to run: FUND_SATS=$FUND_SATS exceeds the task's 50,000-sat total-spend cap"
    exit 2
fi

echo "== build app-core cli =="
( cd "$REPO" && cargo build -q -p app-core --example cli )
APP="$REPO/target/debug/examples/cli"

PASS_N=0
FAIL_N=0

# Portable timeout wrapper (no GNU `timeout`/`gtimeout` on this Mac):
# kills the child after $1 seconds, returns the child's exit code
# otherwise. Used defensively — the app's own reqwest client already
# self-bounds around 30s (see the file header) — so this is a backstop,
# not the primary bound.
with_timeout() { # secs cmd...
    local secs="$1"; shift
    "$@" &
    local pid=$!
    # The watcher must NOT inherit this function's stdout: under command
    # substitution ($(with_timeout ...)), a background job that keeps the
    # pipe's write end open makes the WHOLE capture block until the
    # watcher exits too, even after $pid has long since finished — so the
    # caller would see the full $secs elapse regardless of how fast the
    # real command returned.
    ( sleep "$secs" 2>/dev/null; kill -9 "$pid" 2>/dev/null ) >/dev/null 2>&1 &
    local watcher=$!
    local rc=0
    wait "$pid" 2>/dev/null || rc=$?
    kill "$watcher" 2>/dev/null
    wait "$watcher" 2>/dev/null
    return "$rc"
}

echo
echo "== step 1: preflight against the real, synced, non-pruned testnet4 node =="
PREFLIGHT_OUT="$(with_timeout 40 "$APP" preflight "$BASE" testnet4 2>"$WORK/preflight.err")"
PREFLIGHT_RC=$?
echo "$PREFLIGHT_OUT"
if [[ $PREFLIGHT_RC -ne 0 ]]; then
    fail "preflight call itself failed/timed out: $(cat "$WORK/preflight.err")"
    FAIL_N=$((FAIL_N+1))
else
    PRUNED="$(grep -o 'pruned=[a-z]*' <<<"$PREFLIGHT_OUT" | cut -d= -f2)"
    TXINDEX="$(grep -o 'txindex=[a-z]*' <<<"$PREFLIGHT_OUT" | cut -d= -f2)"
    IBD="$(grep -o 'ibd=[a-z]*' <<<"$PREFLIGHT_OUT" | cut -d= -f2)"
    TIP="$(grep -o 'tip=[0-9]*' <<<"$PREFLIGHT_OUT" | cut -d= -f2)"
    if [[ "$PRUNED" == "false" && "$TXINDEX" == "true" && "$IBD" == "false" && "${TIP:-0}" -ge 146369 ]]; then
        pass "preflight: pruned=false txindex=true ibd=false tip=$TIP (real, synced, non-pruned testnet4 node)"
        PASS_N=$((PASS_N+1))
    else
        fail "preflight reported an unhealthy/unexpected node: $PREFLIGHT_OUT"
        FAIL_N=$((FAIL_N+1))
    fi
fi

echo
echo "== step 2: chain-touch probe (prerequisite for fund/compose/scan/sweep) =="
# A throwaway, well-known BIP-39 test vector (used elsewhere in this repo's
# own e2e suites too) — never funded unless this probe succeeds, so there
# is nothing sensitive about it being public.
export APP_KEY="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SIM_ADDR="$("$APP" address testnet4)"
echo "sim identity address: $SIM_ADDR"
# CHAIN_TOUCH_TIMEOUT is deliberately generous — well beyond the ~8s this
# now measures against the real node — so a slow-but-eventually-successful
# call still counts as success rather than a flaky failure.
CHAIN_TOUCH_TIMEOUT=65
T0=$(date +%s)
BUNDLE_OUT="$(with_timeout "$CHAIN_TOUCH_TIMEOUT" "$APP" bundle "$SIM_ADDR" testnet4 "$BASE" - 2>"$WORK/bundle.err")"
BUNDLE_RC=$?
T1=$(date +%s)
echo "chain-touch attempt took $((T1-T0))s, exit=$BUNDLE_RC"

if [[ $BUNDLE_RC -eq 0 ]]; then
    pass "chain-touch: address watch + scan completed in $((T1-T0))s — proceeding to fund/compose/scan/sweep"
    PASS_N=$((PASS_N+1))
    CAN_PROCEED=1
else
    bug "chain-touch: ensure_address_watched (app-core/src/chain.rs) failed/timed out against the real testnet4 node"
    echo "  --- evidence (stderr tail) ---"
    tail -10 "$WORK/bundle.err" | sed 's/^/  /'
    echo "  ------------------------------"
    bug "This used to be an EXPECTED failure (a genesis-rescan/client-timeout bug, see the file header's"
    bug "history note) but that bug is fixed and this step normally passes in ~8s — a failure here now is"
    bug "a genuine, unexpected regression or a live-node/network problem, not the historical bug."
    fail "chain-touch probe did not complete within ${CHAIN_TOUCH_TIMEOUT}s — see evidence above"
    FAIL_N=$((FAIL_N+1))
    CAN_PROCEED=0
fi

if [[ "${CAN_PROCEED:-0}" != 1 ]]; then
    echo
    echo "== STOPPING before fund/compose/scan/sweep =="
    echo "No testnet4 funds were moved. FUND_ADDR ($FUND_ADDR) balance is untouched."
    echo "This is a STOP-and-report per the task's own instructions — not a harness failure to paper over."
    echo
    echo "Summary: $PASS_N PASS, $FAIL_N FAIL (steps 3-5 SKIPPED — blocked by the app-core bug above)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Steps 3-5: fund the sim identity from the gift wallet, compose+broadcast
# ONE note through the Core RPC backend, scan it back, sweep leftovers to
# the gift-wallet address. Step 2 just proved the backend can watch/scan an
# address against this real node in seconds, so this is now reachable.
#
# Node-RPC helper (separate from the app's own CLI — funding FROM the
# gift wallet is plumbing, not something the app itself does): talks
# straight to bitcoind over the tunnel with the SAME CORE_RPC_USER/
# CORE_RPC_PASS the app-core CLI reads. `-stdin` is used for the ONE call
# that would otherwise put the gift-wallet WIF on argv/`ps` — every other
# call is fine as flags, same as the rest of this script.
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
RPC_ARGS=(-rpcconnect="$T4_HOST" -rpcport="$T4_PORT" -rpcuser="$CORE_RPC_USER" -rpcpassword="$CORE_RPC_PASS")
if ! command -v "$BITCOIN_CLI" >/dev/null 2>&1; then
    fail "bitcoin-cli not found on PATH — needed to fund the sim identity from the gift wallet"
    FAIL_N=$((FAIL_N+1))
    echo
    echo "Summary: $PASS_N PASS, $FAIL_N FAIL"
    exit 1
fi

STEP345_OK=1

echo
echo "== step 3: fund the sim identity ($SIM_ADDR) from the gift wallet =="
# The WIF lives in a project the user explicitly approved reading from
# (never argv, never printed/logged — same discipline as CORE_RPC_USER/PASS).
GIFT_WIF_FILE="${E2E_GIFT_WIF_FILE:-/Users/sal/Projects/Gifts/bitcoin-gift-wallet/.claude/settings.local.json}"
FUND_WIF=""
if [[ ! -r "$GIFT_WIF_FILE" ]]; then
    fail "gift-wallet WIF file not readable: $GIFT_WIF_FILE"
    FAIL_N=$((FAIL_N+1))
    STEP345_OK=0
else
    FUND_WIF="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['env']['TESTNET4_WIF'])" "$GIFT_WIF_FILE" 2>/dev/null)"
    if [[ -z "$FUND_WIF" ]]; then
        fail "could not read TESTNET4_WIF from $GIFT_WIF_FILE"
        FAIL_N=$((FAIL_N+1))
        STEP345_OK=0
    fi
fi

FUND_TXID=""
if [[ "$STEP345_OK" == 1 ]]; then
    # Read-only, UTXO-set-index based (no wallet import, no rescan — see
    # the FORBIDDEN_ADDRS comment above on why `addr()` vs `rawtr()` output
    # shapes matter when eyeballing a scantxoutset result).
    SCAN_OUT="$("$BITCOIN_CLI" "${RPC_ARGS[@]}" scantxoutset start "[\"addr($FUND_ADDR)\"]" 2>"$WORK/scan.err")"
    if [[ -z "$SCAN_OUT" ]]; then
        fail "scantxoutset against the gift-wallet address failed: $(cat "$WORK/scan.err")"
        FAIL_N=$((FAIL_N+1))
        STEP345_OK=0
    else
        echo "$SCAN_OUT" > "$WORK/giftwallet-scan.json"
        TOTAL_SATS="$(python3 -c "import json; d=json.load(open('$WORK/giftwallet-scan.json')); print(round(d.get('total_amount',0)*1e8))")"
        echo "gift wallet confirmed balance: ${TOTAL_SATS} sats across $(python3 -c "import json; print(len(json.load(open('$WORK/giftwallet-scan.json'))['unspents']))") UTXOs"
        # Pick the largest candidate whose outpoint is not ALREADY spent by
        # something sitting in the mempool (a prior run of this same
        # script, e.g.) — `gettxout` defaults to including the mempool
        # view, so a null result here means "don't touch, already in
        # flight" rather than a genuine double-spend attempt.
        CAND="$(python3 -c "
import json
d = json.load(open('$WORK/giftwallet-scan.json'))
u = sorted(d['unspents'], key=lambda x: -x['amount'])
for c in u:
    print(c['txid'], c['vout'], round(c['amount']*1e8))
")"
        FUND_UTXO_TXID=""
        FUND_UTXO_VOUT=""
        FUND_UTXO_SATS=""
        while read -r cand_txid cand_vout cand_sats; do
            [[ -z "$cand_txid" ]] && continue
            LIVE="$("$BITCOIN_CLI" "${RPC_ARGS[@]}" gettxout "$cand_txid" "$cand_vout" 2>/dev/null)"
            if [[ -n "$LIVE" && "$LIVE" != "null" ]]; then
                FUND_UTXO_TXID="$cand_txid"; FUND_UTXO_VOUT="$cand_vout"; FUND_UTXO_SATS="$cand_sats"
                break
            fi
        done <<< "$CAND"
        if [[ -z "$FUND_UTXO_TXID" ]]; then
            fail "no usable (not already mempool-spent) gift-wallet UTXO found"
            FAIL_N=$((FAIL_N+1))
            STEP345_OK=0
        else
            FEE1_SATS=300
            CHANGE1_SATS=$((FUND_UTXO_SATS - FUND_SATS - FEE1_SATS))
            if (( CHANGE1_SATS < 1000 )); then
                fail "selected gift-wallet UTXO too small ($FUND_UTXO_SATS sats) to fund $FUND_SATS sats + fee + change"
                FAIL_N=$((FAIL_N+1))
                STEP345_OK=0
            else
                FUND_BTC="$(python3 -c "print(format($FUND_SATS/1e8, '.8f'))")"
                CHANGE1_BTC="$(python3 -c "print(format($CHANGE1_SATS/1e8, '.8f'))")"
                RAW="$("$BITCOIN_CLI" "${RPC_ARGS[@]}" createrawtransaction \
                    "[{\"txid\":\"$FUND_UTXO_TXID\",\"vout\":$FUND_UTXO_VOUT,\"sequence\":4294967293}]" \
                    "{\"$SIM_ADDR\":$FUND_BTC,\"$FUND_ADDR\":$CHANGE1_BTC}" 2>"$WORK/craw.err")"
                if [[ -z "$RAW" ]]; then
                    fail "createrawtransaction (funding) failed: $(cat "$WORK/craw.err")"
                    FAIL_N=$((FAIL_N+1))
                    STEP345_OK=0
                else
                    # -stdin keeps the WIF off argv/`ps` — the one place in
                    # this script that ever touches it.
                    SIGNED_JSON="$(printf '%s\n%s\n' "$RAW" "[\"$FUND_WIF\"]" | "$BITCOIN_CLI" "${RPC_ARGS[@]}" -stdin signrawtransactionwithkey 2>"$WORK/sign.err")"
                    FUND_WIF=""  # scrub from the shell's memory the instant it's no longer needed
                    COMPLETE="$(echo "$SIGNED_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('complete', False))" 2>/dev/null)"
                    if [[ "$COMPLETE" != "True" ]]; then
                        fail "signrawtransactionwithkey (funding) did not complete: $(cat "$WORK/sign.err") $SIGNED_JSON"
                        FAIL_N=$((FAIL_N+1))
                        STEP345_OK=0
                    else
                        SIGNED_HEX="$(echo "$SIGNED_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['hex'])")"
                        FUND_TXID="$("$BITCOIN_CLI" "${RPC_ARGS[@]}" sendrawtransaction "$SIGNED_HEX" 2>"$WORK/send.err")"
                        if [[ -z "$FUND_TXID" ]]; then
                            fail "sendrawtransaction (funding) failed: $(cat "$WORK/send.err")"
                            FAIL_N=$((FAIL_N+1))
                            STEP345_OK=0
                        else
                            MP="$("$BITCOIN_CLI" "${RPC_ARGS[@]}" getmempoolentry "$FUND_TXID" 2>/dev/null)"
                            if [[ -z "$MP" ]]; then
                                fail "funding txid $FUND_TXID broadcast but not found in mempool"
                                FAIL_N=$((FAIL_N+1))
                                STEP345_OK=0
                            else
                                pass "[MEMPOOL-ONLY] funding txid=$FUND_TXID sent ${FUND_SATS} sats to sim identity, fee=${FEE1_SATS} sats, change ${CHANGE1_SATS} sats back to gift wallet"
                                PASS_N=$((PASS_N+1))
                            fi
                        fi
                    fi
                fi
            fi
        fi
    fi
fi
FUND_WIF=""  # belt and braces

STORE="$WORK/sim-store.json"
COMPOSE_TXID=""
NOTE_ID=""
NOTE_TEXT="chain-notes-app testnet4-live-pass: real note through the Core RPC backend ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
if [[ "$STEP345_OK" == 1 ]]; then
    echo
    echo "== step 4: compose + broadcast ONE note through the Core RPC backend =="
    "$APP" init "$STORE" testnet4 >/dev/null
    SCAN1_OUT="$(with_timeout "$CHAIN_TOUCH_TIMEOUT" "$APP" scan "$STORE" "$BASE" 2>"$WORK/scan1.err")"
    echo "$SCAN1_OUT" | grep '^cli:'
    if ! echo "$SCAN1_OUT" | grep -q "balance=$FUND_SATS\|balance=[1-9]"; then
        fail "post-fund scan did not see the funded (mempool) coin: $SCAN1_OUT / $(cat "$WORK/scan1.err")"
        FAIL_N=$((FAIL_N+1))
        STEP345_OK=0
    else
        pass "[MEMPOOL-ONLY] scan sees the funded coin at the sim identity's address before any confirmation"
        PASS_N=$((PASS_N+1))
        COMPOSE_OUT="$(with_timeout "$CHAIN_TOUCH_TIMEOUT" "$APP" compose "$STORE" "$BASE" public 2 "$NOTE_TEXT" 2>"$WORK/compose.err")"
        echo "$COMPOSE_OUT" | grep '^cli:'
        if ! echo "$COMPOSE_OUT" | grep -q 'broadcast=ok'; then
            fail "compose (note broadcast via Core RPC) failed: $COMPOSE_OUT / $(cat "$WORK/compose.err")"
            FAIL_N=$((FAIL_N+1))
            STEP345_OK=0
        else
            COMPOSE_LINE="$(echo "$COMPOSE_OUT" | grep '^cli: compose')"
            # Exact field extraction (NOT a substring grep for 'id=' —
            # that also matches inside 'txid=' and 'vsize=' has no 'id' but
            # 'txid=' does, so a naive `grep -o 'id=[0-9a-f]*'` double-hits
            # and corrupts NOTE_ID with the txid appended). The line has a
            # fixed shape: "cli: compose id=<hex8> txid=<hex64> fee=<n>
            # vsize=<n> to=<addr|self> private=<bool> broadcast=ok".
            NOTE_ID="$(echo "$COMPOSE_LINE" | awk '{print $3}' | cut -d= -f2)"
            COMPOSE_TXID="$(echo "$COMPOSE_LINE" | awk '{print $4}' | cut -d= -f2)"
            MP="$("$BITCOIN_CLI" "${RPC_ARGS[@]}" getmempoolentry "$COMPOSE_TXID" 2>/dev/null)"
            if [[ -z "$MP" ]]; then
                fail "compose txid $COMPOSE_TXID broadcast but not found in mempool"
                FAIL_N=$((FAIL_N+1))
                STEP345_OK=0
            else
                pass "[MEMPOOL-ONLY] compose+broadcast through Core RPC ok: id=$NOTE_ID txid=$COMPOSE_TXID"
                PASS_N=$((PASS_N+1))
            fi
        fi
    fi
fi

if [[ "$STEP345_OK" == 1 ]]; then
    echo
    echo "== step 5: scan it back, assert it reads correctly, then sweep leftovers =="
    # Re-scan the SAME store (persistence) — but the stronger proof is a
    # COMPLETELY FRESH store/scan below: that one can only know about this
    # note by decoding it straight off the chain via Core RPC, not from
    # anything compose recorded locally.
    "$APP" scan "$STORE" "$BASE" >/dev/null 2>"$WORK/scan2.err"
    STORE_FRESH="$WORK/sim-store-fresh.json"
    "$APP" init "$STORE_FRESH" testnet4 >/dev/null
    SCAN_FRESH_OUT="$(with_timeout "$CHAIN_TOUCH_TIMEOUT" "$APP" scan "$STORE_FRESH" "$BASE" 2>"$WORK/scan-fresh.err")"
    echo "$SCAN_FRESH_OUT" | grep '^cli:'
    NOTES_OUT="$("$APP" notes "$STORE_FRESH")"
    echo "$NOTES_OUT"
    EXPECTED_LINE="id=$NOTE_ID"
    if ! echo "$NOTES_OUT" | grep -q "$EXPECTED_LINE" || ! echo "$NOTES_OUT" | grep -qF "$NOTE_TEXT"; then
        fail "fresh independent scan did not read back note id=$NOTE_ID with the exact composed text"
        FAIL_N=$((FAIL_N+1))
        STEP345_OK=0
    else
        pass "[MEMPOOL-ONLY] fresh independent scan decoded note id=$NOTE_ID with byte-exact text straight off the chain via Core RPC"
        PASS_N=$((PASS_N+1))

        SWEEP_OUT="$(with_timeout "$CHAIN_TOUCH_TIMEOUT" "$APP" sweep "$STORE" "$BASE" "$FUND_ADDR" 2 2>"$WORK/sweep.err")"
        echo "$SWEEP_OUT" | grep '^cli:'
        if ! echo "$SWEEP_OUT" | grep -q '^cli: sweep txid='; then
            fail "sweep back to the gift wallet failed: $SWEEP_OUT / $(cat "$WORK/sweep.err")"
            FAIL_N=$((FAIL_N+1))
        else
            SWEEP_TXID="$(echo "$SWEEP_OUT" | grep -o 'txid=[0-9a-f]*' | cut -d= -f2)"
            SWEEP_VALUE="$(echo "$SWEEP_OUT" | grep -o 'value=[0-9]*' | cut -d= -f2)"
            SWEEP_FEE="$(echo "$SWEEP_OUT" | grep -o 'fee=[0-9]*' | cut -d= -f2)"
            MP="$("$BITCOIN_CLI" "${RPC_ARGS[@]}" getmempoolentry "$SWEEP_TXID" 2>/dev/null)"
            if [[ -z "$MP" ]]; then
                fail "sweep txid $SWEEP_TXID broadcast but not found in mempool"
                FAIL_N=$((FAIL_N+1))
            else
                pass "[MEMPOOL-ONLY] swept ${SWEEP_VALUE} sats (fee ${SWEEP_FEE}) back to the gift wallet, txid=$SWEEP_TXID"
                PASS_N=$((PASS_N+1))
                echo
                echo "== accounting (fees only — everything else returns via the sweep) =="
                echo "  fund tx fee:    ${FEE1_SATS:-?} sats"
                echo "  compose tx fee: $(echo "$COMPOSE_LINE" | grep -o 'fee=[0-9]*' | cut -d= -f2 | head -1) sats"
                echo "  sweep tx fee:   ${SWEEP_FEE} sats"
                echo "  (all three txs are MEMPOOL-ONLY as of this run — testnet4 confirms in ~10 min;"
                echo "   this script deliberately does not wait for a block, per the task's own instructions)"
            fi
        fi
    fi
fi

echo
if [[ "$FAIL_N" -eq 0 ]]; then
    echo "Summary: $PASS_N PASS, $FAIL_N FAIL — steps 1-5 all green (mempool-only for the funding/compose/sweep txids — see [MEMPOOL-ONLY] lines above)"
    exit 0
else
    echo "Summary: $PASS_N PASS, $FAIL_N FAIL"
    exit 1
fi
