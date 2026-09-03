#!/usr/bin/env bash
# M4 gate: hermetic-as-possible end-to-end proof of the app pipeline,
# INCLUDING the app↔Prime interop matrix — both cores run as host binaries
# in this one script.
#
#   app role   = app-core/examples/cli.rs   (identity from APP_KEY)
#   prime role = notes-core's notes_cli (identity from NOTES_APP_SEED)
#   chain role = the shared PERSISTENT node described below
#
# PLAN-one-regtest-node.md (prime workspace root): there is only ONE
# regtest node — the Raspberry Pi's persistent, shared one — and this
# script never spawns bitcoind itself, in any mode. Two independent
# choices, orthogonal to each other:
#
#   BACKEND  --esplora (default) | --core-rpc
#            HOW THE APP talks to the chain. Esplora goes through
#            ../prime-graffito/companion/server.py, a mempool.space-
#            shaped shim pointed at the real node (`AnyTransport::Esplora`
#            on the app side). --core-rpc has the app speak Bitcoin Core
#            JSON-RPC directly (`AnyTransport::Core`, a
#            `bitcoind+http://` base) — no shim in the loop at all.
#
#   NETWORK  --network regtest (default) | testnet4
#            WHICH chain. You cannot mine on-demand on testnet4 — see
#            "Two verbs, not one" below.
#
#   --dry-run   Exercises argument parsing, connectivity, preflight (Core
#            RPC backend), and identity derivation + the recovery-seed
#            interop check — then stops, before any funding/broadcast leg
#            is even attempted. Every broadcasting verb (mine_n/faucet/
#            broadcast_raw/broadcast_raw_check/settle/confirm) is also
#            overridden to a hard no-op that only logs what it would have
#            sent, as a second layer of defense — but the real guarantee is
#            that the script exits before "== fund both identities ==" ever
#            runs, so nothing downstream can race a kill signal into a live
#            broadcast the way an ad hoc kill-on-log-match attempt did on
#            2026-08-02. On testnet4, `faucet`'s lazy WIF read (see below)
#            is never reached in dry-run mode at all.
#
# Contract (PLAN-one-regtest-node.md "The shared contract" — this is a
# PUBLIC repo, so these are read from the ENVIRONMENT ONLY, never a flag,
# never printed, never sourced from ../private/):
#   CN_NETWORK     regtest | testnet4           (default: regtest)
#   CN_NODE_HOST    RPC host                     (default: 127.0.0.1)
#   CN_NODE_PORT    RPC port                      (default: 18443 / 48332)
#   CORE_RPC_USER / CORE_RPC_PASS   RPC credentials — REQUIRED, no default.
# In the prime workspace, `ui-automation/node-env.sh <net> <cmd>...` decrypts
# the Pi's creds and execs a command with all five exported — e.g.:
#   ui-automation/node-env.sh testnet4 bash graffito/scripts/regtest-e2e.sh --network testnet4
# Both an already-open SSH tunnel (127.0.0.1) and a direct tailnet address
# work identically — this script never assumes which.
#
# Precondition: `cargo` must already be on PATH before running the
# node-env.sh line above (e.g. `export PATH="$HOME/.cargo/bin:$PATH"`) —
# node-env.sh only sets the credential/node contract, it does not touch
# PATH, so a bare invocation through it dies with `cargo: command not
# found`.
#
# Two verbs, not one (the redesign's core idea — see the plan doc):
#   settle  <txid>   "make the chain reflect this tx." Regtest: mine 1 +
#                     syncwithvalidationinterfacequeue. Testnet4: the
#                     broadcast having succeeded already IS the observable
#                     (a light poll for belt-and-braces). Most former
#                     `mine_blocks 1` call sites are this — the app treats
#                     unconfirmed coins as spendable and visible.
#   confirm <txid>   "this must be IN A BLOCK." Regtest: mine 1 (same op as
#                     settle there). Testnet4: poll getrawtransaction until
#                     confirmations>=1, bounded by CN_CONFIRM_TIMEOUT
#                     (default 1800s) — a REAL wait for a REAL block; a
#                     timeout FAILS. Exactly one leg in this script needs
#                     it (see the self-notes section) — everything else
#                     only needed the coin to be visible to a scan, not
#                     confirmed, and stays a settle.
# `faucet`/`broadcast_raw`/`broadcast_raw_check` keep their names and
# original semantics; their bodies differ per network+backend below.
#
# Funding (PLAN-one-regtest-node.md "Funding, per network"):
#   regtest    the Pi's `testwallet` (~14,096 BTC spendable, Core-RPC
#              backend only — spend FROM it, never create/load/rename/
#              reset it, it is not ours). Esplora-backend regtest funding
#              goes through server.py's OWN `/node/api/faucet`, which
#              manages its own dedicated wallet (never testwallet either
#              — see server.py's module docstring).
#   testnet4   the gift-wallet FUND_WIF, the same way
#              scripts/testnet4-live.sh already does (never printed/
#              logged). Regardless of BACKEND, funding+harness settle/
#              confirm always talk DIRECTLY to the node over Core RPC —
#              the harness's own chain access is independent of which
#              transport the APP UNDER TEST is using. Sequential funding
#              legs chain their own unconfirmed change locally (scantxoutset
#              only sees the CONFIRMED utxo set, so a second faucet call in
#              the same run must not re-query it). Leftovers are swept back
#              to the gift-wallet address at the end (see the testnet4
#              cleanup section) — this is real money, kept deliberately
#              small (see the FUND_*_BTC defaults) and never printed.
#   Every chain-touching identity in this script is randomized PER RUN
#   (account index + two funding seeds + the prime identity's seed) on
#   BOTH networks — the node/chain persist across runs, so fixed test
#   mnemonics would make every absolute "balance=N"/"exactly N notes"
#   assertion flaky against accumulated history. This generalizes what
#   the old `--pi-regtest` flag already proved out.
#   **Testnet4 spending is opt-in, not automatic.** Merely running this
#   script with --network testnet4 must NEVER acquire spending authority
#   over the gift wallet on its own — that is exactly how an interrupted
#   dry-run test became a live broadcast on 2026-08-02. `faucet`'s
#   internal `t4_fund_init` requires `E2E_ALLOW_TESTNET4_SPEND=1` in the
#   environment and reads `TESTNET4_WIF` out of `$GIFT_WIF_FILE` lazily,
#   on the FIRST actual funding call — never at setup time, never
#   speculatively, and never at all in --dry-run mode.
#
# Pending-state legs (PLAN-one-regtest-node.md "Skips must be loud"): any
# leg whose correctness genuinely depends on ON-DEMAND block production
# (not just chain visibility) is regtest-only. This script has exactly one
# such leg (the self-notes "status=confirmed" assertion below); it's
# gated behind `require_regtest`, which prints a loud `SKIP <leg>
# (regtest-only: <why>)`, counts it, and the final summary line reports
# `N PASS · M SKIP` with every skipped leg named. The testnet4 fallback
# path for that leg reports its reduced check via plain `echo`, never
# `pass` — a leg that skipped part of its assertion must not ALSO claim a
# full PASS credit; it's represented exactly once, as the SKIP.
#
# The rescan trap (PLAN-one-regtest-node.md "A rescan BLOCKS the whole
# wallet"): `importdescriptors` at `timestamp: 0` is a genesis rescan and
# BLOCKS every other RPC on that wallet (error -4) until it finishes —
# free on a short chain, fatal on testnet4, and dangerous on ANY shared
# node since another consumer's import can start one underneath this
# script at any moment (app-core and server.py both use the SAME
# `graffito-watch` wallet on the node). Three rules, all implemented
# here: (1) `pre_watch_fresh` registers this run's fresh addresses in that
# wallet at a RECENT timestamp (not 0) before app-core/server.py's own
# lazy per-address import would otherwise fall back to genesis — this
# run's identities are provably fresh, so genesis buys nothing; (2)
# `wait_for_wallet_scan` polls `getwalletinfo`'s `scanning` field before
# proceeding; (3) `core_cli` itself retries "-4 Wallet is currently
# rescanning" with backoff as a safety net for every direct RPC call this
# script makes (it cannot protect the APP's OWN internal RPC calls, which
# are app-core's responsibility).
#
# `examples/cli.rs` stdout is DATA (PSBTs/addresses/JSON this script
# captures via `$(...)`). Diagnostics are `eprintln!` only — see the repo
# CLAUDE.md's "CLI stdout is DATA" note.
set -euo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; NC=$'\033[0m'
PASS_N=0
SKIP_N=0
SKIPPED_LEGS=()
pass() { PASS_N=$((PASS_N+1)); echo "${GRN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*"; exit 1; }
# `err` is for helpers that callers invoke via `$(...)` (faucet,
# t4_fund_init) — their stdout is CAPTURED by the caller, so a `fail`-style
# message written to stdout would silently vanish into the captured
# variable instead of ever reaching the terminal. `set -e` still aborts
# the script the instant such a command substitution's assignment sees a
# nonzero exit status (standard bash errexit behavior for `x=$(cmd)`), so
# writing the message to stderr is enough to keep it visible.
err() { echo "${RED}FAIL${NC} $*" >&2; exit 1; }

BACKEND="esplora"
NETWORK="${CN_NETWORK:-regtest}"
DRY_RUN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --core-rpc) BACKEND="core-rpc"; shift ;;
        --network) NETWORK="${2:?--network requires regtest|testnet4}"; shift 2 ;;
        --network=*) NETWORK="${1#--network=}"; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        *) fail "unknown arg $1: usage: $0 [--core-rpc] [--network regtest|testnet4] [--dry-run]" ;;
    esac
done
case "$NETWORK" in
    regtest|testnet4) ;;
    *) fail "unknown network '$NETWORK' (want regtest|testnet4)" ;;
esac
export CN_NETWORK="$NETWORK"

case "$NETWORK" in
    regtest) DEFAULT_NODE_PORT=18443; TAP_HRP="bcrt1p"; SEG_HRP="bcrt1q" ;;
    testnet4) DEFAULT_NODE_PORT=48332; TAP_HRP="tb1p"; SEG_HRP="tb1q" ;;
esac
CN_NODE_HOST="${CN_NODE_HOST:-127.0.0.1}"
CN_NODE_PORT="${CN_NODE_PORT:-$DEFAULT_NODE_PORT}"
: "${CORE_RPC_USER:?regtest-e2e.sh needs CORE_RPC_USER in the environment (see ui-automation/node-env.sh in the prime workspace)}"
: "${CORE_RPC_PASS:?regtest-e2e.sh needs CORE_RPC_PASS in the environment (see ui-automation/node-env.sh in the prime workspace)}"
export CN_NODE_HOST CN_NODE_PORT CORE_RPC_USER CORE_RPC_PASS
CN_CONFIRM_TIMEOUT="${CN_CONFIRM_TIMEOUT:-1800}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PRIME="$(cd "$REPO/../prime-graffito" && pwd)" || fail "needs ../prime-graffito"
WORK="${E2E_WORK:-$(mktemp -d /tmp/graffito-e2e.XXXXXX)}"

echo "== build both host binaries =="
( cd "$REPO" && cargo build -q -p app-core --example cli )
APP="$REPO/target/debug/examples/cli"
( cd "$REPO" && cargo build -q -p notes-core --example notes_cli )
NOTES="$REPO/target/debug/examples/notes_cli"

# The harness's OWN direct node access — used for connectivity checks and
# (on testnet4, and on regtest in --core-rpc mode) for mining/funding.
# Independent of BACKEND: the app under test may still talk through
# server.py even while THIS script reaches the node directly. Retries
# "-4 Wallet is currently rescanning" with backoff (the rescan trap's rule
# 3, a safety net since the node/wallet are shared with every other
# consumer) — stdout/stderr are captured SEPARATELY (via a temp file for
# stderr) so a warning on stderr from a successful call can never corrupt
# a JSON result callers parse from stdout.
core_cli() {
    local tries=0 max=8 delay=2 out err rc errfile
    errfile="$(mktemp "${TMPDIR:-/tmp}/core_cli_err.XXXXXX")"
    while :; do
        out="$(bitcoin-cli "-$NETWORK" -rpcconnect="$CN_NODE_HOST" -rpcport="$CN_NODE_PORT" \
            -rpcuser="$CORE_RPC_USER" -rpcpassword="$CORE_RPC_PASS" "$@" 2>"$errfile")"
        rc=$?
        if [[ $rc -eq 0 ]]; then
            rm -f "$errfile"
            printf '%s' "$out"
            return 0
        fi
        err="$(cat "$errfile" 2>/dev/null)"
        if [[ "$err" == *"Wallet is currently rescanning"* && $tries -lt $max ]]; then
            tries=$((tries+1))
            echo "core_cli: wallet rescanning, retry $tries/$max in ${delay}s ($*)" >&2
            sleep "$delay"
            delay=$(( delay < 30 ? delay * 2 : 30 ))
            continue
        fi
        echo "$err" >&2
        rm -f "$errfile"
        return "$rc"
    done
}
# The node's own funded wallet — the faucet source, and where regtest coins
# go back to (FAUCET.md). Same one-liner ui-automation/node-suite-lib.sh
# defines; this script cannot source that library (it lives in the private
# workspace and this repo is public), so it carries its own copy. It was
# MISSING until 2026-08-04, and `e2e_fund_return`'s only regtest destination
# was `miner_cli getnewaddress` — an undefined command, so `dest` came back
# empty and the whole return path printed "no destination — skipping" and did
# nothing, on every regtest run there has ever been.
miner_cli() { core_cli -rpcwallet=testwallet "$@"; }

core_cli getblockchaininfo >/dev/null 2>&1 \
    || fail "cannot reach the $NETWORK node at $CN_NODE_HOST:$CN_NODE_PORT (tunnel/tailnet up? credentials correct?)"
TIP_BEFORE="$(core_cli getblockcount)"
echo "$NETWORK node reachable at $CN_NODE_HOST:$CN_NODE_PORT, tip=$TIP_BEFORE (persistent chain — untouched, no reset/wipe/reindex)"

# --- The rescan trap: shared infrastructure (rules 1 + 2) ------------------
# Registering an address BEFORE server.py lazily imports it makes its
# `ensure_address_watched`/getaddressinfo check see it as already known and
# skip the per-address `timestamp: 0` fallback entirely.
#
# The wallet is PER RUN, and that is the whole point. A rescan costs
# O(blocks x descriptors), so a long-lived shared watch wallet gets
# monotonically slower as every run imports more addresses into it: measured
# 2026-08-04 on the shared `graffito-watch`, one `timestamp: 0` import
# took **130 seconds** (630 txs, hundreds of descriptors) against **0.5s**
# for the identical import into a fresh wallet on the same chain. At 130s
# the app's own 30s HTTP timeout fires first, which is exactly how this
# suite died at the external-funding leg: `fund-keygen` mints an address
# mid-run that nothing could have pre-registered, so it paid full price.
#
# Exported so the server.py this script launches uses the same wallet
# (server.py reads CN_WATCH_WALLET, defaulting to `graffito-watch`).
# NOTE this only covers the Esplora path: in --core-rpc mode the app talks
# to the node directly and uses app-core's own WATCH_WALLET constant, which
# is correct for production (a real user has one wallet, holding only their
# own addresses) but means pre-registration here is invisible to it.
CN_WATCH_WALLET="cn-e2e-$$-$(date +%s)"
export CN_WATCH_WALLET
RUN_START_TS=$(( $(date +%s) - 3600 ))  # 1h buffer for clock skew — NOT 0
# Every address this suite touches is created DURING the run, so nothing it
# scans can have history older than RUN_START_TS. Telling server.py that
# turns each lazily-imported address from a genesis rescan (146,900 blocks on
# testnet4, minutes — well past the app's 30s HTTP timeout) into a no-op.
# Pre-registering addresses one at a time does not work here: the app derives
# them dynamically, so the first one nobody enumerated still pays full price.
export CN_IMPORT_TIMESTAMP="$RUN_START_TS"

# The per-run watch wallet holds no keys and no funds (disable_private_keys),
# so there is nothing to sweep — but unload it so repeated runs don't pile up
# loaded wallets on the shared node. Best effort: never fail a run over it.
# ONE EXIT trap for the whole script. bash REPLACES an EXIT trap rather than
# chaining, so three separate `trap ... EXIT` registrations meant only the
# last one ever ran: `trap 'unset FUND_WIF' EXIT` inside the testnet4 funding
# path silently disabled the server.py kill, leaking the shim on every
# funded run. Everything that must happen on exit goes in here.
# Addresses this run funded, by which identity owns them. Registered as they
# are funded so the EXIT trap can give the coins back — the shell counterpart
# of the RAII guard in app-core's conformance suite.
E2E_APP_FUNDED=()
E2E_PRIME_FUNDED=()
# Stores whose BIP-84 SPENDING wallet was funded. These are NOT coverable by
# e2e_sweep_app_addr: that sweeps a notebook's taproot utxos, while spending
# coins live on a separate m/84' branch with its own keys, so they used to be
# stranded on every run (the recorded fund-return gap). Each entry is
# "<store-path>|<APP_KEY>|<APP_ACCOUNT>" — the key travels with the store
# because these suites use several identities and the shell must sweep each
# with the right one.
E2E_SPENDING_FUNDED=()

# Sweep one app-identity address back. Deliberately builds the store from
# `scantxoutset` rather than `cli scan`: a scan makes app-core import the
# identity's ranged descriptors at timestamp 0, i.e. a genesis rescan
# (146,900 blocks on testnet4) that outlives any sane cleanup budget.
# scantxoutset needs no wallet and no import at all.
e2e_sweep_app_addr() { # addr|key dest
    local entry="$1" dest="$2" addr key utxos store
    addr="${entry%%|*}"
    key="${entry#*|}"
    [[ "$key" == "$addr" ]] && key="${APP_KEY:-}"    # legacy entry with no key
    utxos="$(core_cli scantxoutset start "[\"addr($addr)\"]" 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(json.dumps([{'txid':u['txid'],'vout':u['vout'],'value':int(u['amount']*1e8),
                   'height':u.get('height'),'pending_spend':False} for u in d.get('unspents',[])]))
" 2>/dev/null)" || { echo "e2e_fund_return: app scan FAILED for ${addr:0:16}... (coins may be stranded)" >&2; return 0; }
    # Account for every registered identity out loud. A silent "nothing here"
    # is indistinguishable from a broken return path, which is precisely how
    # an undefined miner_cli disabled this entire function unnoticed.
    if [[ -z "$utxos" || "$utxos" == "[]" ]]; then
        echo "e2e_fund_return: app address ${addr:0:16}... already empty (nothing to return)" >&2
        return 0
    fi
    store="$(mktemp "${TMPDIR:-/tmp}/e2e-return.XXXXXX")"
    APP_KEY="$key" "$APP" init "$store" "$NETWORK" >/dev/null 2>&1 || { echo "e2e_fund_return: app init FAILED for ${addr:0:16}..." >&2; rm -f "$store"; return 0; }
    python3 -c "
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d['utxos']=json.loads(sys.argv[2]); json.dump(d,open(p,'w'))
" "$store" "$utxos" 2>/dev/null || { rm -f "$store"; return 0; }
    if APP_KEY="$key" "$APP" sweep "$store" "$BASE" "$dest" 2.0 >/dev/null 2>&1; then
        echo "e2e_fund_return: swept app address ${addr:0:16}... back to $dest" >&2
    else
        echo "e2e_fund_return: app sweep skipped for ${addr:0:16}... (empty/dust)" >&2
    fi
    rm -f "$store"
}

e2e_sweep_prime_addr() { # addr dest
    local addr="$1" dest="$2" bundle
    bundle="$(mktemp "${TMPDIR:-/tmp}/e2e-return-b.XXXXXX")"
    if "$APP" bundle "$addr" "$NETWORK" "$BASE" "$bundle" >/dev/null 2>&1 \
       && "$NOTES" sweep "$bundle" "$NETWORK" "$dest" 2.0 >/dev/null 2>&1; then
        echo "e2e_fund_return: swept prime address ${addr:0:16}... back to $dest" >&2
    else
        echo "e2e_fund_return: prime sweep skipped for ${addr:0:16}... (empty/dust/unreachable)" >&2
    fi
    rm -f "$bundle"
}

# Sweep a store's BIP-84 spending wallet back. Unlike the two above this
# cannot work from an address list: spending coins are spread across a gap-
# walked branch, so the sweep discovers them live (`cli spending-sweep`, which
# scans and then uses the SAME mixed builder the UI's wallet sweep does).
e2e_sweep_spending() { # store|key|account dest
    local entry="$1" dest="$2" store key acct out
    store="${entry%%|*}"; entry="${entry#*|}"
    key="${entry%%|*}"; acct="${entry##*|}"
    [[ -r "$store" ]] || return 0
    if out="$(APP_KEY="$key" APP_ACCOUNT="$acct" "$APP" spending-sweep "$store" "$BASE" "$dest" 2.0 2>&1)"; then
        echo "e2e_fund_return: spending wallet -> $(echo "$out" | grep -o 'utxos=[0-9]* value=[0-9]*' | head -1)" >&2
    else
        echo "e2e_fund_return: spending sweep skipped for $(basename "$store") (empty/dust/unreachable)" >&2
    fi
}

# Give every funded coin back, on success AND on failure. Best-effort
# throughout: a cleanup problem must never mask the real result.
e2e_fund_return() {
    [[ "$DRY_RUN" == 1 ]] && return 0
    [[ ${#E2E_APP_FUNDED[@]} -eq 0 && ${#E2E_PRIME_FUNDED[@]} -eq 0 \
       && ${#E2E_SPENDING_FUNDED[@]} -eq 0 ]] && return 0
    local dest a
    if [[ "$NETWORK" == regtest ]]; then
        dest="$(miner_cli getnewaddress 2>/dev/null)"
    else
        dest="$FUND_ADDR"        # back to the gift wallet it came from
    fi
    # LOUD, not quiet. This exact branch silently swallowed the entire regtest
    # return path for as long as it has existed, because `miner_cli` was
    # undefined and an empty dest reads the same as "nothing to do". On a
    # chain at its supply ceiling a skipped return is lost coins, so say so.
    if [[ -z "$dest" ]]; then
        echo "e2e_fund_return: WARNING no destination on $NETWORK — ${#E2E_APP_FUNDED[@]} app + ${#E2E_PRIME_FUNDED[@]} prime + ${#E2E_SPENDING_FUNDED[@]} spending identity(ies) will NOT be returned" >&2
        return 0
    fi
    # Spending wallets FIRST: their sweep needs server.py alive and is the leg
    # most likely to hold real value (the fu legs fund it repeatedly).
    for a in ${E2E_SPENDING_FUNDED[@]+"${E2E_SPENDING_FUNDED[@]}"}; do e2e_sweep_spending "$a" "$dest" || true; done
    for a in ${E2E_APP_FUNDED[@]+"${E2E_APP_FUNDED[@]}"}; do e2e_sweep_app_addr "$a" "$dest" || true; done
    for a in ${E2E_PRIME_FUNDED[@]+"${E2E_PRIME_FUNDED[@]}"}; do e2e_sweep_prime_addr "$a" "$dest" || true; done
}

e2e_cleanup() {
    # BEFORE killing server.py: in esplora mode $BASE points at it, and the
    # sweeps need it alive.
    e2e_fund_return || true
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    unset FUND_WIF
    # The per-run watch wallet holds no keys and no funds
    # (disable_private_keys), so there is nothing to sweep — just unload it so
    # repeated runs don't pile up loaded wallets. Best effort, never fatal.
    core_cli unloadwallet "$CN_WATCH_WALLET" >/dev/null 2>&1 || true
}
trap e2e_cleanup EXIT

ensure_cn_watch_wallet() {
    core_cli createwallet "$CN_WATCH_WALLET" true true >/dev/null 2>&1 \
        || core_cli loadwallet "$CN_WATCH_WALLET" >/dev/null 2>&1 || true
}

wait_for_wallet_scan() { # rule 2 — poll getwalletinfo.scanning to false
    local i info scanning
    for i in $(seq 1 240); do   # up to 240 * 5s = 20 min ceiling
        info="$(core_cli -rpcwallet="$CN_WATCH_WALLET" getwalletinfo 2>/dev/null)" || return 0
        scanning="$(python3 -c "import json,sys; d=json.load(sys.stdin); print('1' if d.get('scanning') else '0')" <<<"$info" 2>/dev/null || echo 0)"
        [[ "$scanning" == 0 ]] && return 0
        sleep 5
    done
    echo "wait_for_wallet_scan: still scanning after 20 minutes, giving up" >&2
    return 1
}

pre_watch_descriptor() { # desc — register a RANGED descriptor, not one address.
    # `fund-build`'s scan_funding walks the funding descriptor's whole address
    # window, so registering only index 0 leaves every other derived address
    # unknown — and the first one the app touches pays a genesis rescan
    # (146,900 blocks on testnet4, well past the app's 30s HTTP timeout).
    # One ranged import covers the entire window; this is the same shape
    # app-core uses for its own identity (open_client_watched).
    # Best-effort, exactly like pre_watch_fresh: the app's slow per-address
    # fallback still yields a CORRECT run, just a much slower one.
    local desc="$1" checksummed import_json
    [[ -z "$desc" ]] && return 0
    if [[ "$DRY_RUN" == 1 ]]; then
        echo "[DRY-RUN] would pre-watch descriptor: $desc" >&2
        return 0
    fi
    wait_for_wallet_scan || true
    ensure_cn_watch_wallet
    checksummed="$(core_cli getdescriptorinfo "$desc" 2>/dev/null \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['descriptor'])" 2>/dev/null)" || return 0
    [[ -n "$checksummed" ]] || return 0
    import_json="$(python3 -c "
import json,sys
print(json.dumps([{'desc': sys.argv[1], 'timestamp': int(sys.argv[2]), 'range': [0, 50]}]))
" "$checksummed" "$RUN_START_TS")" || return 0
    core_cli -rpcwallet="$CN_WATCH_WALLET" importdescriptors "$import_json" >/dev/null 2>&1 || true
    wait_for_wallet_scan || true
}

pre_watch_fresh() { # addr... — rule 1: no-op for any address the shared
                     # watch wallet already knows; imports the rest at
                     # THIS RUN's start time (never genesis) in one batched
                     # call. Best-effort: on failure the app's own slower
                     # per-address fallback still makes the run correct,
                     # just slower, so this never aborts the script.
    [[ $# -eq 0 ]] && return 0
    if [[ "$DRY_RUN" == 1 ]]; then
        echo "[DRY-RUN] would pre-watch: $*" >&2
        return 0
    fi
    wait_for_wallet_scan || true   # don't layer an import on an in-flight rescan
    ensure_cn_watch_wallet
    local addr new=() entries=() info ismine desc
    for addr in "$@"; do
        info="$(core_cli -rpcwallet="$CN_WATCH_WALLET" getaddressinfo "$addr" 2>/dev/null)" || info="{}"
        ismine="$(python3 -c "import json,sys; d=json.load(sys.stdin); print('1' if (d.get('ismine') or d.get('iswatchonly')) else '0')" <<<"$info" 2>/dev/null || echo 0)"
        [[ "$ismine" == 1 ]] || new+=("$addr")
    done
    [[ ${#new[@]} -eq 0 ]] && return 0
    for addr in "${new[@]}"; do
        desc="$(core_cli getdescriptorinfo "addr($addr)" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['descriptor'])" 2>/dev/null)" || continue
        [[ -n "$desc" ]] && entries+=("{\"desc\":\"$desc\",\"timestamp\":$RUN_START_TS}")
    done
    [[ ${#entries[@]} -eq 0 ]] && return 0
    local import_json
    import_json="[$(IFS=,; echo "${entries[*]}")]"
    core_cli -rpcwallet="$CN_WATCH_WALLET" importdescriptors "$import_json" >/dev/null 2>&1 || true
    wait_for_wallet_scan || true
}

# ---------------------------------------------------------------------------
# Backend setup: how the APP under test reaches the chain.
if [[ "$BACKEND" == esplora ]]; then
    PORT="${E2E_PORT:-18791}"
    echo "== start companion server (Esplora shim) -> $NETWORK node =="
    python3 "$PRIME/companion/server.py" "$PORT" --node "$CN_NODE_HOST:$CN_NODE_PORT" --network "$NETWORK" \
        >"$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    # server.py is killed by e2e_cleanup (the single EXIT trap above).
    for _ in $(seq 1 60); do
        curl -sf "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break
        sleep 1
    done
    HEALTH="$(curl -sf "http://127.0.0.1:$PORT/api/health")" || fail "server did not come up (see $WORK/server.log)"
    python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('network')=='$NETWORK', d" <<<"$HEALTH" \
        || fail "server health reports an unexpected network: $HEALTH"
    BASE="http://127.0.0.1:$PORT/node/api"
else
    echo "== Core RPC backend: app talks directly to the $NETWORK node, no shim =="
    BASE="bitcoind+http://$CN_NODE_HOST:$CN_NODE_PORT"
fi

# Preflight (Core RPC backend only — the app's `preflight` subcommand only
# understands a `bitcoind+http(s)://` base, and panics on an Esplora one):
# a read-only health check (pruned/txindex/IBD/wallet-scanning/tip),
# reported as a warning and never gating — mirrors testnet4-live.sh's
# preflight step. Also the app-level confirmation that the wallet this
# script is about to touch isn't ALREADY mid-rescan from another consumer.
if [[ "$BACKEND" == core-rpc ]]; then
    PREFLIGHT_OUT="$("$APP" preflight "$BASE" "$NETWORK" 2>&1)" || echo "preflight call failed (non-fatal): $PREFLIGHT_OUT" >&2
    echo "$PREFLIGHT_OUT"
fi

# True only when the APP's own broadcasts get auto-confirmed server-side
# with no action from this script (server.py mines 1 block inside its own
# POST /node/api/tx handler, but ONLY on regtest — see its module
# docstring). Every other combination needs an explicit settle/confirm
# call after a broadcast this script didn't itself perform.
NEEDS_EXPLICIT_SETTLE=1
[[ "$BACKEND" == esplora && "$NETWORK" == regtest ]] && NEEDS_EXPLICIT_SETTLE=0

# ---------------------------------------------------------------------------
# The four harness verbs (settle/confirm/faucet/broadcast_raw[_check]),
# plus require_regtest. Regtest and testnet4 get genuinely different
# implementations per "Two verbs, not one" above.
if [[ "$NETWORK" == regtest ]]; then
    require_regtest() { return 0; }  # nothing is skipped on regtest itself

    if [[ "$BACKEND" == esplora ]]; then
        mine_n() { curl -sf -X POST "$BASE/mine?blocks=$1" >/dev/null; }
        faucet() { # addr amount_btc -> echoes txid
            local resp
            resp="$(curl -sf -X POST "$BASE/faucet" -d "{\"address\":\"$1\",\"amount\":$2}")" \
                || err "faucet $1 failed"
            python3 -c "import json,sys; print(json.load(sys.stdin)['txid'])" <<<"$resp"
        }
        broadcast_raw() { curl -sf -X POST "$BASE/tx" --data-binary "$1" >/dev/null || fail "$2"; }
        broadcast_raw_check() { curl -s -X POST "$BASE/tx" --data-binary "$1" >"$2" || true; }
    else
        core_miner_cli() { core_cli -rpcwallet=testwallet "$@"; }
        # The node's OWN pre-existing funded wallet — we spend FROM it but
        # never create, load, rename, or reset it. It is not ours.
        core_miner_cli getwalletinfo >/dev/null 2>&1 \
            || fail "testwallet is not loaded on the $NETWORK node — this script does not load/create it"
        mine_n() { # n — bitcoind's wallet block-processing is ASYNC
                   # (validation-interface callbacks drain on the scheduler
                   # thread after generatetoaddress returns) — without the
                   # drain, a query served right after can answer from the
                   # PRE-block view.
            local n="$1" addr
            addr="$(core_miner_cli getnewaddress)"
            core_miner_cli generatetoaddress "$n" "$addr" >/dev/null
            core_cli syncwithvalidationinterfacequeue >/dev/null 2>&1 || true
        }
        faucet() { core_miner_cli sendtoaddress "$1" "$2"; }  # echoes txid
        broadcast_raw() { core_cli sendrawtransaction "$1" >/dev/null || fail "$2"; mine_n 1; }
        broadcast_raw_check() {
            local hex="$1" outfile="$2" out
            if out="$(core_cli sendrawtransaction "$hex" 2>&1)"; then
                printf '%s' "$out" > "$outfile"
                mine_n 1
            else
                printf '%s' "$out" > "$outfile"
            fi
        }
    fi
    # Regtest doesn't distinguish "visible" from "in a block" — mining one
    # block does both, so settle and confirm are the same operation here.
    settle() { mine_n 1; }
    confirm() { mine_n 1; }
else
    require_regtest() { # leg-name [why] -> loud SKIP, returns 1
        local name="$1" why="${2:-needs on-demand block production, unavailable on testnet4}"
        echo "SKIP $name (regtest-only: $why)"
        SKIP_N=$((SKIP_N+1))
        SKIPPED_LEGS+=("$name")
        return 1
    }
    settle() { # txid — the node already knows about it the instant
               # broadcast/faucet returned successfully (that IS the
               # observable on testnet4); this is a short confirmatory
               # poll, not a real wait.
        local txid="$1" i
        for i in $(seq 1 10); do
            core_cli getrawtransaction "$txid" >/dev/null 2>&1 && return 0
            sleep 1
        done
        fail "settle: node never saw txid $txid"
    }
    confirm() { # txid — genuinely wait for a real block (testnet4 blocks
                # land roughly every ~10 min), bounded by CN_CONFIRM_TIMEOUT.
        local txid="$1" start now conf
        start="$(date +%s)"
        while :; do
            conf="$(core_cli getrawtransaction "$txid" true 2>/dev/null \
                | python3 -c "import json,sys; print(json.load(sys.stdin).get('confirmations',0))" 2>/dev/null || echo 0)"
            [[ "${conf:-0}" -ge 1 ]] && return 0
            now="$(date +%s)"
            (( now - start >= CN_CONFIRM_TIMEOUT )) && fail "confirm: txid $txid did not confirm within ${CN_CONFIRM_TIMEOUT}s"
            sleep 15
        done
    }
    if [[ "$BACKEND" == esplora ]]; then
        broadcast_raw() {
            local out
            out="$(curl -sf -X POST "$BASE/tx" --data-binary "$1")" || fail "$2"
            settle "$out"
        }
        broadcast_raw_check() {
            local hex="$1" outfile="$2" out
            out="$(curl -s -X POST "$BASE/tx" --data-binary "$hex")" || true
            printf '%s' "$out" > "$outfile"
            [[ "$out" =~ ^[0-9a-f]{64}$ ]] && settle "$out"
            return 0
        }
    else
        broadcast_raw() {
            local txid
            txid="$(core_cli sendrawtransaction "$1")" || fail "$2"
            settle "$txid"
        }
        broadcast_raw_check() {
            local hex="$1" outfile="$2" out
            if out="$(core_cli sendrawtransaction "$hex" 2>&1)"; then
                printf '%s' "$out" > "$outfile"
                settle "$out"
            else
                printf '%s' "$out" > "$outfile"
            fi
        }
    fi

    # --- testnet4 funding: the gift wallet, chained by hand ------------
    # scantxoutset only sees the CONFIRMED utxo set, so a second faucet
    # call this run cannot re-query it to find the first call's change —
    # it isn't confirmed yet. T4_FUND_UTXO_* tracks the current spendable
    # outpoint locally across calls, exactly like a real wallet would.
    #
    # THE CHAIN STATE LIVES IN A FILE, NOT A SHELL VARIABLE, and it must
    # stay that way. Every faucet call site is `$(faucet …)` — a command
    # substitution, i.e. a SUBSHELL — because faucet echoes the txid. A
    # variable assigned at the end of faucet therefore dies with that
    # subshell and never reaches the next call, so the chaining above was
    # dead code from the start: each call fell back to scantxoutset and
    # spent FRESH CONFIRMED outputs. That silently turned "needs one
    # confirmed utxo" into "needs one per funding leg", which is why a
    # testnet4 run had never once completed — it exhausted the confirmed
    # set around the sixth leg and failed with "no usable UTXO" while the
    # wallet still held ~900k sats in unconfirmed change. Diagnosed
    # 2026-08-04 after a run that mined zero blocks start to finish.
    T4_FUND_STATE="$WORK/t4-fund-state"
    FUND_ADDR="${E2E_T4_FUND_ADDR:-tb1q2ylq48ne37ng9clds23xjcrxp8hmn707j5vpyk}"
    FORBIDDEN_ADDRS=(
        "tb1pev690svkjfgl86ps4ptv47tuuclgg9ajdkexg43rctq0msr6692qr6zksz"
        "tb1pgm6v3lpp38f9msgs7vllcq68ep25qf8f7592zlsrffsh5tdl4eks6mhr0e"
    )
    if [[ " ${FORBIDDEN_ADDRS[*]} " == *" $FUND_ADDR "* ]]; then
        fail "refusing to run: FUND_ADDR is one of the forbidden App-Review addresses"
    fi
    # GIFT_WIF_FILE is only a PATH here — never read until a funding leg is
    # actually about to run (see t4_fund_init below). Merely running this
    # script on --network testnet4 must not, by itself, acquire spending
    # authority over the gift wallet.
    GIFT_WIF_FILE="${E2E_GIFT_WIF_FILE:-}"   # no default: public repo, no machine-specific path

    # The input SET this run funds from (JSON array for createrawtransaction),
    # and how much it holds. Combining inputs is what lets a run start while a
    # previous run's change is still unconfirmed.
    T4_FUND_INPUTS=""; T4_FUND_UTXO_SATS=""
    # Enough for this suite's several ~20k fundings plus fees, gathered once
    # up front so later faucet calls just chain off the change.
    T4_FUND_TARGET_SATS="${E2E_T4_FUND_TARGET_SATS:-120000}"
    t4_fund_init() {
        [[ -n "$T4_FUND_INPUTS" ]] && return 0
        # Spending real testnet4 funds requires an explicit, out-of-band
        # grant. A dry-run test that raced past its own kill signal turned
        # "run the script on testnet4" into "spend the gift wallet" on
        # 2026-08-02 — this gate is the direct fix, and the WIF is read
        # HERE, lazily, on the first ACTUAL funding call, never earlier.
        if [[ "${E2E_ALLOW_TESTNET4_SPEND:-}" != 1 ]]; then
            err "refusing to spend: set E2E_ALLOW_TESTNET4_SPEND=1 to authorize this run to read the gift-wallet WIF and broadcast real testnet4 funding transactions (currently unset or not '1')"
        fi
        if [[ -z "${FUND_WIF:-}" ]]; then
            [[ -n "$GIFT_WIF_FILE" ]] || err "set E2E_GIFT_WIF_FILE to the JSON file holding the gift-wallet TESTNET4_WIF"
            [[ -r "$GIFT_WIF_FILE" ]] || err "gift-wallet WIF file not readable: $GIFT_WIF_FILE"
            FUND_WIF="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['env']['TESTNET4_WIF'])" "$GIFT_WIF_FILE")"
            [[ -n "$FUND_WIF" ]] || err "could not read TESTNET4_WIF from $GIFT_WIF_FILE"
            # FUND_WIF is unset by e2e_cleanup (the single EXIT trap above).
            # NB it is re-read on EVERY faucet call, because each one is its
            # own subshell and cannot see a sibling's assignment — the same
            # reason the input chain lives in a file.
        fi

        # Resume the chain a previous faucet call left behind. Re-VALIDATE it
        # against the node rather than trusting the file: gettxout (mempool
        # included by default) answers "still unspent?" for an UNCONFIRMED
        # change output, which is exactly the thing scantxoutset cannot see.
        # A stale or spent outpoint just falls through to a fresh scan.
        #
        # THIS MUST STAY BELOW THE AUTH GATE AND THE WIF READ. Sitting above
        # them, its early return skipped both: the spend authorization stopped
        # being checked per call, and faucet #2 onward built transactions with
        # an EMPTY signing key (bitcoin-cli answered with its usage text, which
        # the script reported as the misleading "sign failed").
        if [[ -s "$T4_FUND_STATE" ]]; then
            local s_txid s_vout s_sats s_live
            IFS=$'\t' read -r s_txid s_vout s_sats < "$T4_FUND_STATE" || true
            if [[ -n "${s_txid:-}" && -n "${s_vout:-}" && -n "${s_sats:-}" ]]; then
                s_live="$(core_cli gettxout "$s_txid" "$s_vout" 2>/dev/null || true)"
                if [[ -n "$s_live" && "$s_live" != "null" ]]; then
                    T4_FUND_INPUTS="[{\"txid\":\"$s_txid\",\"vout\":$s_vout,\"sequence\":4294967293}]"
                    T4_FUND_UTXO_SATS="$s_sats"
                    return 0
                fi
                echo "t4_fund_init: chained outpoint ${s_txid:0:12}...:$s_vout is gone, rescanning" >&2
            fi
        fi
        local scan cand mem_cand txid vout sats live
        scan="$(core_cli scantxoutset start "[\"addr($FUND_ADDR)\"]")" || err "gift-wallet scantxoutset failed"
        cand="$(python3 -c "
import json, sys
d = json.load(sys.stdin)
u = sorted(d.get('unspents', []), key=lambda x: -x['amount'])
for c in u:
    print(c['txid'], c['vout'], round(c['amount'] * 1e8))
" <<<"$scan")"
        # TESTNET4 IS A LIVE CHAIN WE DO NOT CONTROL, so a block may be 10
        # minutes away or an hour, and a run that can only spend CONFIRMED
        # coins is hostage to that. scantxoutset is confirmed-only by
        # definition, so a previous run's change — frequently the entire
        # value of the wallet — is invisible to it. Add the mempool as a
        # candidate source: unconfirmed outputs paying FUND_ADDR are just as
        # spendable (the chain below already relies on exactly that), and it
        # is what makes a cold start possible while every confirmed output
        # sits spent in the mempool. Verified 2026-08-04: a run failed at
        # "no usable UTXO" with 0 live confirmed outputs and 842,333 sats of
        # its own change waiting in the mempool.
        mem_cand=""
        local mp_ids mp_n id raw
        mp_ids="$(core_cli getrawmempool 2>/dev/null || true)"
        if [[ -n "$mp_ids" ]]; then
            mp_n="$(python3 -c "import json,sys; print(len(json.load(sys.stdin)))" <<<"$mp_ids" 2>/dev/null || echo 0)"
            # Bounded: one RPC per mempool tx. Testnet4's mempool is normally
            # tens of txs; refuse to grind through a flood rather than hang.
            if (( mp_n > 0 && mp_n <= 3000 )); then
                for id in $(python3 -c "
import json,sys
for t in json.load(sys.stdin): print(t)
" <<<"$mp_ids" 2>/dev/null); do
                    raw="$(core_cli getrawtransaction "$id" true 2>/dev/null || true)"
                    [[ -z "$raw" ]] && continue
                    mem_cand="$mem_cand$(python3 -c "
import json, sys
d = json.load(sys.stdin)
for o in d.get('vout', []):
    if (o.get('scriptPubKey') or {}).get('address') == '$FUND_ADDR':
        print(d['txid'], o['n'], round(o['value'] * 1e8))
" <<<"$raw" 2>/dev/null)
"
                done
            elif (( mp_n > 3000 )); then
                echo "t4_fund_init: mempool has $mp_n txs — skipping the unconfirmed sweep this run" >&2
            fi
        fi
        # Confirmed first (cheapest to reason about), then unconfirmed; the
        # accumulate loop below sorts out liveness and sufficiency either way.
        cand="$(printf '%s\n%s\n' "$cand" "$mem_cand" | awk 'NF' | sort -u -k1,2)"
        # COMBINE utxos rather than demanding a single big one, and note that
        # `gettxout` is the liveness oracle for BOTH sources: it includes the
        # mempool by default, so it accepts an unconfirmed output that is
        # still unspent and rejects a confirmed one that is already spent
        # there. That is precisely the distinction scantxoutset cannot make,
        # and reading a confirmed-but-mempool-spent output as available is
        # what made a run fail after five successful funding legs.
        local acc_total=0 acc_inputs=""
        while read -r txid vout sats; do
            [[ -z "$txid" ]] && continue
            live="$(core_cli gettxout "$txid" "$vout" 2>/dev/null)"
            [[ -n "$live" && "$live" != "null" ]] || continue
            acc_inputs="$acc_inputs{\"txid\":\"$txid\",\"vout\":$vout,\"sequence\":4294967293},"
            acc_total=$(( acc_total + sats ))
            if (( acc_total >= T4_FUND_TARGET_SATS )); then
                T4_FUND_INPUTS="[${acc_inputs%,}]"
                T4_FUND_UTXO_SATS="$acc_total"
                return 0
            fi
        done <<<"$cand"
        if [[ -n "$acc_inputs" ]]; then
            # Everything live, still short of target: proceed anyway and let
            # the per-faucet arithmetic below fail with the real numbers.
            T4_FUND_INPUTS="[${acc_inputs%,}]"
            T4_FUND_UTXO_SATS="$acc_total"
            return 0
        fi
        err "no usable (unspent, not mempool-conflicted) gift-wallet UTXO found for $FUND_ADDR"
    }
    faucet() { # addr amount_btc -> echoes txid
        local addr="$1" amt_btc="$2" amt_sats fee_sats change_sats amt_fmt change_fmt raw signed complete hex txid change_vout
        t4_fund_init
        amt_sats="$(python3 -c "print(round($amt_btc*1e8))")"
        # Fee must cover EVERY input we are spending, not just one.
        local n_in
        n_in="$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])))" "$T4_FUND_INPUTS")"
        fee_sats=$(( 200 + n_in * 120 ))
        change_sats=$(( T4_FUND_UTXO_SATS - amt_sats - fee_sats ))
        (( change_sats >= 1000 )) || err "faucet $addr: gift-wallet utxo too small (${T4_FUND_UTXO_SATS} sats) for ${amt_sats}+fee"
        amt_fmt="$(python3 -c "print(format($amt_sats/1e8,'.8f'))")"
        change_fmt="$(python3 -c "print(format($change_sats/1e8,'.8f'))")"
        raw="$(core_cli createrawtransaction \
            "$T4_FUND_INPUTS" \
            "{\"$addr\":$amt_fmt,\"$FUND_ADDR\":$change_fmt}")" || err "faucet $addr: createrawtransaction failed"
        # Assert the key BEFORE signing: with FUND_WIF empty, bitcoin-cli
        # answers with its usage text and the failure reads as "sign failed",
        # which points at the transaction instead of at the missing key.
        [[ -n "${FUND_WIF:-}" ]] || err "faucet $addr: no signing key in scope (t4_fund_init must run, and must not return before reading the WIF)"
        signed="$(printf '%s\n%s\n' "$raw" "[\"$FUND_WIF\"]" | core_cli -stdin signrawtransactionwithkey)" \
            || err "faucet $addr: sign failed"
        complete="$(python3 -c "import json,sys; print(json.load(sys.stdin).get('complete', False))" <<<"$signed")"
        [[ "$complete" == "True" ]] || err "faucet $addr: signrawtransactionwithkey incomplete"
        hex="$(python3 -c "import json,sys; print(json.load(sys.stdin)['hex'])" <<<"$signed")"
        txid="$(core_cli sendrawtransaction "$hex")" || err "faucet $addr: broadcast failed"
        change_vout="$(core_cli decoderawtransaction "$hex" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for o in d['vout']:
    a = (o.get('scriptPubKey') or {}).get('address')
    if a == '$FUND_ADDR':
        print(o['n']); break
")"
        # Chain the next faucet off this tx's change: one input from here on.
        # Through the FILE — this function always runs in a command-substitution
        # subshell (see T4_FUND_STATE above), so these two assignments are only
        # good for the rest of THIS call; the file is what the next one reads.
        T4_FUND_INPUTS="[{\"txid\":\"$txid\",\"vout\":$change_vout,\"sequence\":4294967293}]"
        T4_FUND_UTXO_SATS="$change_sats"
        [[ -n "$change_vout" ]] \
            && printf '%s\t%s\t%s\n' "$txid" "$change_vout" "$change_sats" > "$T4_FUND_STATE"
        echo "$txid"
    }
fi

# --dry-run: override every broadcasting verb to a hard no-op that only
# logs what it would have sent — defense in depth. The real guarantee is
# structural: the script exits (see below, right after identity
# derivation) before ANY of these would actually be called, so this
# override existing is a belt-and-braces backstop, not the load-bearing
# safety mechanism.
if [[ "$DRY_RUN" == 1 ]]; then
    mine_n() { echo "[DRY-RUN] would mine $1 block(s) on $NETWORK" >&2; }
    faucet() { # addr amount_btc -> echoes a fake (all-zero) txid; never
               # touches the network, never reads FUND_WIF.
        echo "[DRY-RUN] would fund $1 with $2 BTC" >&2
        printf '%064d' 0
    }
    broadcast_raw() { echo "[DRY-RUN] would broadcast raw tx (${#1} hex chars) [$2]" >&2; }
    broadcast_raw_check() {
        echo "[DRY-RUN] would broadcast raw tx (${#1} hex chars) -> $2" >&2
        printf '%064d' 0 > "$2"
    }
    settle() { echo "[DRY-RUN] would settle txid ${1:-<none>}" >&2; }
    confirm() { echo "[DRY-RUN] would confirm (wait for a block) txid ${1:-<none>}" >&2; }
fi

# Funding amounts. Regtest coins are worthless (testwallet has ~14,096
# BTC) so the original generous amounts are kept unchanged. Testnet4 is
# REAL money from the gift wallet — deliberately small, env-overridable
# for a coordinator to tune before a live run.
if [[ "$NETWORK" == regtest ]]; then
    FUND_MAIN_BTC="0.001"
    FUND_EXTERNAL_BTC="0.002"
    FUND_FU_BTC="0.0005"
    FUND_MULTI_BTC="0.0006"
else
    FUND_MAIN_BTC="${E2E_T4_FUND_MAIN_BTC:-0.0002}"          # 20,000 sats
    FUND_EXTERNAL_BTC="${E2E_T4_FUND_EXTERNAL_BTC:-0.00008}" # 8,000 sats
    FUND_FU_BTC="${E2E_T4_FUND_FU_BTC:-0.00005}"             # 5,000 sats
    FUND_MULTI_BTC="${E2E_T4_FUND_MULTI_BTC:-0.00006}"       # 6,000 sats
fi
FUND_MAIN_SATS="$(python3 -c "print(round($FUND_MAIN_BTC*1e8))")"

# ---------------------------------------------------------------------------
# Every chain-touching identity gets a fresh, never-before-seen derivation
# this run — both networks persist across runs, so fixed test mnemonics
# would make every absolute assertion below flaky (accumulated balance/
# note-text history from earlier runs against the same addresses).
RUN_ACCOUNT="${E2E_ACCOUNT:-$(( $(date +%s) % 1000000 ))}"
export APP_ACCOUNT="$RUN_ACCOUNT"
RUN_FUND_SEED_TR="${E2E_FUND_SEED_TR:-$(openssl rand -hex 32)}"
RUN_FUND_SEED_WPKH="${E2E_FUND_SEED_WPKH:-$(openssl rand -hex 32)}"
# The prime identity (notes_cli) also needs a fresh seed every run — several
# assertions below check "exactly one note with THIS exact text", which a
# fixed P_ADDR would violate on a second run against the shared chain.
RUN_PRIME_SEED="${E2E_PRIME_SEED:-$(openssl rand -hex 32)}"
export NOTES_APP_SEED="$RUN_PRIME_SEED"
echo "run identity: backend=$BACKEND network=$NETWORK APP_ACCOUNT=$RUN_ACCOUNT (fresh — never reused against the shared chain)"
# Log the prime seed too. It is throwaway per-run test material, and without
# it a crashed run's prime-side funds are UNRECOVERABLE: four aborted
# testnet4 runs stranded 60,000 sats permanently that way, while the app side
# survived only because APP_ACCOUNT happened to be printed. The fund-return
# below is the real fix; this is the recovery path when that cannot run.
echo "run identity: NOTES_APP_SEED=$RUN_PRIME_SEED (throwaway, logged so an aborted run stays recoverable)"

# App identity: a BIP-39 mnemonic exercises the flagship import format.
export APP_KEY="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
A_ADDR="$("$APP" address "$NETWORK")"
[[ "$A_ADDR" == "$TAP_HRP"* ]] || fail "app address not taproot: $A_ADDR"
pre_watch_fresh "$A_ADDR"
E2E_APP_FUNDED+=("$A_ADDR|$APP_KEY")   # addr|key — give it back on exit.
# The KEY travels with the address because later legs `export APP_KEY` to
# other identities (fu, multi), so by the time the EXIT trap runs the
# ambient APP_KEY is NOT this address's owner. Sweeping with it would
# derive the wrong key and fail as a quiet "skipped".
pass "app address $A_ADDR"

P_ADDR="$("$NOTES" address "$NETWORK")"
[[ "$P_ADDR" == "$TAP_HRP"* ]] || fail "prime address not taproot: $P_ADDR"
pre_watch_fresh "$P_ADDR"
E2E_PRIME_FUNDED+=("$P_ADDR")   # give it back on exit (e2e_fund_return)
pass "prime address $P_ADDR"

echo "== recovery-seeds interop: a Prime bip86 seed's 24 words import identically =="
# The whole point of PLAN-chain-notes-seed-rotation.md, proven across the
# two ACTUAL host binaries: the device derives a rotatable BIP-39 phrase
# from its app seed (notes_cli seed-words) and a bip86 notebook address
# (seed-address); feeding those SAME words to the app's normal mnemonic
# import (APP_KEY) must land on the byte-identical address for every
# (seed, account, index) — funds + notes + ECDH all recover from the
# words alone. (The in-process key-level proof is app-core's
# prime_recovery_seed_words_import_identically.) Pure derivation — no
# chain interaction, unaffected by network/backend.
R_SEED="d074c6f28bb0d891fd30dd6ff6f5face8ea6d209c7b81684babc34e8446d379a"
for combo in "0 0 0" "0 1 2" "1 0 0"; do
    read -r s a i <<<"$combo"
    R_WORDS="$(NOTES_APP_SEED=$R_SEED "$NOTES" seed-words "$s")"
    DEV_ADDR="$(NOTES_APP_SEED=$R_SEED "$NOTES" seed-address "$NETWORK" "$s" "$a" "$i")"
    APP_ADDR="$(APP_KEY="$R_WORDS" APP_ACCOUNT="$a" APP_INDEX="$i" "$APP" address "$NETWORK")"
    [[ "$DEV_ADDR" == "$APP_ADDR" ]] \
        || fail "recovery interop s$s a$a i$i: device $DEV_ADDR != app $APP_ADDR"
done
pass "device seed words → app import: byte-identical addresses across seed/account/index"

if [[ "$DRY_RUN" == 1 ]]; then
    echo
    pass "dry-run: argument parsing + connectivity + preflight + identity derivation all exercised; stopping here — no funding/broadcast leg was attempted (backend=$BACKEND network=$NETWORK)"
    echo
    echo "Summary: $PASS_N PASS · $SKIP_N SKIP"
    exit 0
fi

echo "== fund both identities =="
FUND_A_TXID="$(faucet "$A_ADDR" "$FUND_MAIN_BTC")"
FUND_P_TXID="$(faucet "$P_ADDR" "$FUND_MAIN_BTC")"
# One settle, not a height margin. Faucet coins are already mature (they
# come from testwallet, not a fresh coinbase — FAUCET.md), and nothing
# downstream asks for more than confirmations>=1, so the old `mine_n 100`
# bought nothing while burning 100 blocks of a chain that has ~10,000 sats
# left to mine ever. Both funding txs are in the mempool together, so on
# regtest the first settle already confirms both and the second just adds a
# harmless second block — worth staying branch-free for, at 2 blocks instead
# of 100. On testnet4 each settle is the per-txid visibility wait it has to be.
settle "$FUND_A_TXID"
settle "$FUND_P_TXID"

STORE="$WORK/app-store.json"
"$APP" init "$STORE" "$NETWORK" | grep -q "kind=mnemonic" || fail "init"
"$APP" scan "$STORE" "$BASE" | tee "$WORK/scan1" | grep -q "balance=$FUND_MAIN_SATS" || fail "funding scan: $(cat "$WORK/scan1")"
pass "funded + scanned ($FUND_MAIN_SATS sats)"

echo "== self-notes: public, then private CHAINED on unconfirmed change =="
PUB_OUT="$("$APP" compose "$STORE" "$BASE" public 1.0 "hello public from app")"
echo "$PUB_OUT" | grep -q broadcast=ok || fail "compose public"
PRIV_OUT="$("$APP" compose "$STORE" "$BASE" private 1.0 "hello private from app")"
echo "$PRIV_OUT" | grep -q broadcast=ok || fail "compose private (chained)"
PRIV_TXID="$(echo "$PRIV_OUT" | grep -oE 'txid=[0-9a-f]+' | head -1 | cut -d= -f2)"
# The ONE genuinely regtest-only leg in this script: the assertion below
# hardcodes "status=confirmed", which needs an actual block — on testnet4
# that means a real ~10-minute wait for on-demand mining that doesn't
# exist there (PLAN-one-regtest-node.md's "pending→confirmed" skip
# category). Everything ELSE in this script only ever needed the tx
# visible to a scan (settle), never actually confirmed.
if require_regtest "self-notes: confirmed-status assertion (needs on-demand mining)"; then
    confirm "$PRIV_TXID"
    "$APP" scan "$STORE" "$BASE" >/dev/null
    "$APP" notes "$STORE" | tee "$WORK/notes1" | grep -q "status=confirmed .*text=hello public from app" || fail "public note confirmed"
    grep -q "status=confirmed .*private=true .*text=hello private from app" "$WORK/notes1" || fail "private note confirmed"
    pass "both self-notes confirmed (change chaining worked)"
else
    settle "$PRIV_TXID"
    "$APP" scan "$STORE" "$BASE" >/dev/null
    "$APP" notes "$STORE" | tee "$WORK/notes1" | grep -q "text=hello public from app" || fail "public note present"
    grep -q "private=true .*text=hello private from app" "$WORK/notes1" || fail "private note present"
    # NOT `pass` — this leg already recorded its ONE outcome as the SKIP
    # above (require_regtest). Claiming a plain PASS here too would be the
    # exact silent-green failure mode: a leg that skipped part of its
    # assertion must not ALSO claim full credit.
    echo "both self-notes present (change chaining worked) — recorded as SKIP above, not PASS, since the confirmed-status assertion did not run"
fi

echo "== wipe recovery: fresh store, bare key, full rescan =="
STORE2="$WORK/app-store-recovered.json"
"$APP" init "$STORE2" "$NETWORK" >/dev/null
"$APP" scan "$STORE2" "$BASE" >/dev/null
"$APP" notes "$STORE2" | tee "$WORK/notes2" | grep -q "text=hello private from app" || fail "private text not recovered from chain"
grep -q "text=hello public from app" "$WORK/notes2" || fail "public text not recovered"
[[ "$(grep -c '^note ' "$WORK/notes2")" == 2 ]] || fail "expected exactly 2 recovered notes"
pass "wipe recovery: private + public notes rebuilt from chain + key alone"

# External funding (PSBT): the app builds an unsigned tx paid by a watch-only
# funding wallet, an "external wallet" (here: the funding xprv) signs it, the app
# finalizes + broadcasts, and prime decrypts the note — proven for BOTH funding
# address types the feature supports (P2TR and P2WPKH / segwit v0).
export CN_FUND_GAP=0
external_funding() { # <tr|wpkh> <seed-hex> <note-text>
    local kind="$1" seed="$2" text="$3"
    echo "== external funding [$kind]: build → sign (external wallet) → finalize → broadcast =="
    local F_DESC F_XPRV F_ADDR PSBT SIGNED FTXID FUND_TXID
    IFS=$'\t' read -r F_DESC F_XPRV F_ADDR <<<"$("$APP" fund-keygen "$NETWORK" "$seed" "$kind")"
    [[ -n "$F_ADDR" ]] || fail "[$kind] fund-keygen produced no address"
    case "$kind" in
        tr) [[ "$F_ADDR" == "$TAP_HRP"* ]] || fail "[$kind] funding addr not taproot: $F_ADDR" ;;
        wpkh) [[ "$F_ADDR" == "$SEG_HRP"* ]] || fail "[$kind] funding addr not segwit v0: $F_ADDR" ;;
    esac
    # `fund-keygen` mints this address DURING the run, so no earlier
    # pre-registration could have covered it — and an unregistered address is
    # exactly what costs a genesis rescan (146,900 blocks on testnet4; the
    # app's 30s HTTP timeout loses that race and the leg dies with a bare
    # Transport error). Register it before anything queries it. It was
    # generated moments ago, so it provably has no history before this run.
    # Register the funding descriptor's whole RANGE, not just $F_ADDR:
    # scan_funding walks the window, and one unregistered address in it costs
    # a genesis rescan that outlives the app's HTTP timeout.
    pre_watch_descriptor "$F_DESC"
    pre_watch_fresh "$F_ADDR"
    FUND_TXID="$(faucet "$F_ADDR" "$FUND_EXTERNAL_BTC")"
    settle "$FUND_TXID"
    PSBT="$("$APP" fund-build "$BASE" "$NETWORK" "$F_DESC" private 2.0 "$text" "$P_ADDR" 2>"$WORK/fb-$kind.log")"
    grep -q "fund-build txid=" "$WORK/fb-$kind.log" || fail "[$kind] fund-build: $(cat "$WORK/fb-$kind.log")"
    SIGNED="$("$APP" fund-sign "$PSBT" "$F_XPRV" 2>"$WORK/fs-$kind.log")"
    grep -q "inputs_signed=[1-9]" "$WORK/fs-$kind.log" \
        || fail "[$kind] fund-sign signed no inputs: $(cat "$WORK/fs-$kind.log")"
    FTXID="$("$APP" fund-finalize "$BASE" "$NETWORK" "$SIGNED" 2>"$WORK/ff-$kind.log")"
    grep -q "broadcast=ok" "$WORK/ff-$kind.log" || fail "[$kind] fund-finalize: $(cat "$WORK/ff-$kind.log")"
    [[ "$NEEDS_EXPLICIT_SETTLE" == 1 ]] && settle "$FTXID"
    pass "[$kind] external-funded directed note built+signed+finalized+broadcast (txid=$FTXID)"

    # Prime decrypts it via the candidate-key path: the author key is not the
    # spending input (the funder) but the dust-to-self output — and it is
    # attributed to the app identity, not the funder.
    "$APP" bundle "$P_ADDR" "$NETWORK" "$BASE" "$WORK/prime-$kind.json" >/dev/null
    "$NOTES" scan "$WORK/prime-$kind.json" >"$WORK/prime-$kind-scan.json"
    jq -e --arg from "$A_ADDR" --arg text "$text" \
        '.[] | select(.received and .private and .from == $from and .text == $text)' \
        "$WORK/prime-$kind-scan.json" >/dev/null \
        || fail "[$kind] prime did not decrypt externally-funded note: $(cat "$WORK/prime-$kind-scan.json")"
    pass "[$kind] prime decrypted externally-funded note via candidate key, attributed to the app identity"
}
external_funding tr "$RUN_FUND_SEED_TR" "funded by cold storage"
external_funding wpkh "$RUN_FUND_SEED_WPKH" "funded by a segwit wallet"

echo "== app → prime: directed PRIVATE note =="
DIRECTED_OUT="$("$APP" compose "$STORE" "$BASE" private 1.0 "psst prime, from the app" "$P_ADDR")"
echo "$DIRECTED_OUT" | grep -q broadcast=ok || fail "directed compose"
DIRECTED_TXID="$(echo "$DIRECTED_OUT" | grep -oE 'txid=[0-9a-f]+' | head -1 | cut -d= -f2)"
[[ "$NEEDS_EXPLICIT_SETTLE" == 1 ]] && settle "$DIRECTED_TXID"
"$APP" bundle "$P_ADDR" "$NETWORK" "$BASE" "$WORK/prime.json" >/dev/null
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
NB1_ADDR="$(APP_INDEX=1 "$APP" address "$NETWORK")"
[ "$NB1_ADDR" != "$A_ADDR" ] || fail "notebook 1 address equals notebook 0"
pre_watch_fresh "$NB1_ADDR"
NB1_STORE="$WORK/app-nb1.json"
APP_INDEX=1 "$APP" init "$NB1_STORE" "$NETWORK" >/dev/null
# Refresh prime's ledger first — its previous send's inputs are gone.
"$APP" bundle "$P_ADDR" "$NETWORK" "$BASE" "$WORK/prime.json" >/dev/null
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
export CN_FUND_GAP=2
FU_KEY="zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
FU_STORE="$WORK/fu-store.json"
export APP_KEY="$FU_KEY"
"$APP" init "$FU_STORE" "$NETWORK" | grep -q "kind=mnemonic" || fail "fu: init"
FU_ADDR="$("$APP" address "$NETWORK")"
[[ "$FU_ADDR" == "$TAP_HRP"* ]] || fail "fu: notebook address not taproot: $FU_ADDR"
pre_watch_fresh "$FU_ADDR"
pass "fu: dedicated funding-unification identity $FU_ADDR (notebook stays dust-only)"

echo "== fu leg 1: funded self-note (public) — self-spk-SET marks it OWN =="
SPEND_ADDR1="$("$APP" spending-address "$FU_STORE" "$NETWORK" | tail -1)"
[[ "$SPEND_ADDR1" == "$SEG_HRP"* ]] || fail "fu leg1: spending address not segwit v0: $SPEND_ADDR1"
pre_watch_fresh "$SPEND_ADDR1"
FU1_FUND_TXID="$(faucet "$SPEND_ADDR1" "$FUND_FU_BTC")"
# Register ONCE per store: spending-sweep discovers every coin on the branch
# by scanning, so a second entry would just re-sweep an emptied wallet.
E2E_SPENDING_FUNDED+=("$FU_STORE|$FU_KEY|${APP_ACCOUNT:-0}")
settle "$FU1_FUND_TXID"
FU1_LOG="$("$APP" note-spend-funded "$FU_STORE" "$BASE" public 2.0 "funded self note")"
echo "$FU1_LOG" | tee "$WORK/fu-leg1.log" | grep -q "broadcast=ok" || fail "fu leg1: note-spend-funded: $FU1_LOG"
FU1_TXID="$(echo "$FU1_LOG" | grep -oE 'txid=[0-9a-f]+' | head -1 | cut -d= -f2)"
[[ "$NEEDS_EXPLICIT_SETTLE" == 1 ]] && settle "$FU1_TXID"
pass "fu leg1: funded self-note composed + signed + broadcast entirely in-app via the spending wallet"

"$APP" scan "$FU_STORE" "$BASE" >/dev/null
"$APP" notes "$FU_STORE" | tee "$WORK/fu-notes1" \
    | grep -q "private=false directed=false received=false from=- to=- text=funded self note" \
    || fail "fu leg1: funded self-note did not scan back as OWN: $(cat "$WORK/fu-notes1")"
pass "fu leg1: a fresh scan classifies the spending-wallet-funded note as OWN (self-spk SET, not the old notebook-spk-only rule)"

echo "== fu leg 2: funded directed-private note → prime =="
SPEND_ADDR2="$("$APP" spending-address "$FU_STORE" "$NETWORK" | tail -1)"
[ "$SPEND_ADDR2" != "$SPEND_ADDR1" ] || fail "fu leg2: spending wallet reused a receive address"
pre_watch_fresh "$SPEND_ADDR2"
FU2_FUND_TXID="$(faucet "$SPEND_ADDR2" "$FUND_FU_BTC")"
settle "$FU2_FUND_TXID"
FU2_LOG="$("$APP" note-spend-funded "$FU_STORE" "$BASE" private 2.0 "funded directed note" "$P_ADDR")"
echo "$FU2_LOG" | tee "$WORK/fu-leg2.log" | grep -q "broadcast=ok" || fail "fu leg2: note-spend-funded: $FU2_LOG"
FU2_TXID="$(echo "$FU2_LOG" | grep -oE 'txid=[0-9a-f]+' | head -1 | cut -d= -f2)"
[[ "$NEEDS_EXPLICIT_SETTLE" == 1 ]] && settle "$FU2_TXID"
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
"$APP" bundle "$P_ADDR" "$NETWORK" "$BASE" "$WORK/fu-prime-bundle.json" >/dev/null
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
FU_CONSOL_OUT="$("$APP" sweep "$FU_STORE" "$BASE" "$FU_ADDR" 1.0)"
echo "$FU_CONSOL_OUT" | tee "$WORK/fu-consolidate.log" | grep -q "^cli: sweep txid=" \
    || fail "fu leg5b: dust consolidate: $FU_CONSOL_OUT"
FU_CONSOL_TXID="$(echo "$FU_CONSOL_OUT" | grep -oE 'txid=[0-9a-f]+' | head -1 | cut -d= -f2)"
[[ "$NEEDS_EXPLICIT_SETTLE" == 1 ]] && settle "$FU_CONSOL_TXID"
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
"$APP" init "$FU_STORE3" "$NETWORK" >/dev/null
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
# in the app) — the CLI-level substitute the plan sanctioned for this leg. A
# FRESH dedicated identity + store, exactly like the "fu" legs above, so this
# never perturbs their exact balance/count assertions.
echo "== multi leg: spending-wallet-funded note to 3 recipients =="
MFU_KEY="legal winner thank year wave sausage worth useful legal winner thank yellow"
MFU_STORE="$WORK/mfu-store.json"
export APP_KEY="$MFU_KEY"
"$APP" init "$MFU_STORE" "$NETWORK" | grep -q "kind=mnemonic" || fail "multi-fu: init"
MFU_SPEND_ADDR="$("$APP" spending-address "$MFU_STORE" "$NETWORK" | tail -1)"
[[ "$MFU_SPEND_ADDR" == "$SEG_HRP"* ]] || fail "multi-fu: spending address not segwit v0: $MFU_SPEND_ADDR"
pre_watch_fresh "$MFU_SPEND_ADDR"
MULTI_FUND_TXID="$(faucet "$MFU_SPEND_ADDR" "$FUND_MULTI_BTC")"
E2E_SPENDING_FUNDED+=("$MFU_STORE|$MFU_KEY|${APP_ACCOUNT:-0}")
settle "$MULTI_FUND_TXID"

# Three throwaway taproot recipients (any valid 32-byte hex key — none of
# them need to sign anything, just be valid taproot addresses).
M_R1="$(APP_KEY=1111111111111111111111111111111111111111111111111111111111111111 "$APP" address "$NETWORK")"
M_R2="$(APP_KEY=2222222222222222222222222222222222222222222222222222222222222222 "$APP" address "$NETWORK")"
M_R3="$(APP_KEY=3333333333333333333333333333333333333333333333333333333333333333 "$APP" address "$NETWORK")"
pre_watch_fresh "$M_R1" "$M_R2" "$M_R3"
export APP_KEY="$MFU_KEY"
MULTI_OUT="$("$APP" note-spend-funded-multi "$MFU_STORE" "$BASE" public 2.0 500 "multi-recipient spending-wallet note" \
    "$M_R1" "$M_R2" "$M_R3")"
echo "$MULTI_OUT" | tee "$WORK/multi-fu-leg.log" | grep -q "recipients=3 sent_to_recipient=1500 .*broadcast=ok" \
    || fail "multi leg: note-spend-funded-multi: $MULTI_OUT"
MULTI_TXID="$(echo "$MULTI_OUT" | grep -oE 'txid=[0-9a-f]+' | head -1 | cut -d= -f2)"
[[ "$NEEDS_EXPLICIT_SETTLE" == 1 ]] && settle "$MULTI_TXID"
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
    APP_KEY="$rk" "$APP" init "$R_STORE" "$NETWORK" >/dev/null
    APP_KEY="$rk" "$APP" scan "$R_STORE" "$BASE" >/dev/null
    APP_KEY="$rk" "$APP" notes "$R_STORE" | tee "$WORK/multi-recip-notes-$rk" \
        | grep -q "received=true .*text=multi-recipient spending-wallet note" \
        || fail "multi leg: recipient $rk did not receive the multi-recipient note: $(cat "$WORK/multi-recip-notes-$rk")"
done
pass "multi leg: all three recipients independently scan + read the multi-recipient public note"

# ---------------------------------------------------------------------------
# testnet4 cleanup: sweep leftovers back to the gift-wallet address. This is
# real money — best-effort (a store at/near zero balance is expected to
# "fail" harmlessly here, e.g. FU_STORE after leg5b's consolidate).
if [[ "$NETWORK" == testnet4 ]]; then
    echo
    echo "== testnet4 cleanup: sweep leftovers back to the gift wallet ($FUND_ADDR) =="
    SWEEP_OUT="$("$APP" sweep "$STORE" "$BASE" "$FUND_ADDR" 1.0 2>&1 || true)"
    if echo "$SWEEP_OUT" | grep -q "^cli: sweep txid="; then
        pass "swept app identity ($A_ADDR) leftovers back to the gift wallet"
    else
        echo "note: app identity sweep-back skipped/failed (balance may be dust-only): $SWEEP_OUT"
    fi

    # The prime identity has no single "sweep and broadcast" cli verb —
    # build + broadcast it the same way the app<->prime interop legs above
    # do (notes_cli only builds the raw tx; this script broadcasts it).
    if "$APP" bundle "$P_ADDR" "$NETWORK" "$BASE" "$WORK/prime-final.json" >/dev/null 2>&1; then
        PRIME_SWEEP_OUT="$("$NOTES" sweep "$WORK/prime-final.json" "$NETWORK" "$FUND_ADDR" 1.0 2>&1 || true)"
        PRIME_SWEEP_HEX="$(python3 -c "import json,sys; print(json.load(sys.stdin).get('raw_hex',''))" <<<"$PRIME_SWEEP_OUT" 2>/dev/null || true)"
        if [[ -n "$PRIME_SWEEP_HEX" ]]; then
            if broadcast_raw "$PRIME_SWEEP_HEX" "prime sweep-back broadcast" 2>/dev/null; then
                pass "swept prime identity ($P_ADDR) leftovers back to the gift wallet"
            else
                echo "note: prime identity sweep-back broadcast failed"
            fi
        else
            echo "note: prime identity sweep-back skipped (no spendable balance, or build failed): $PRIME_SWEEP_OUT"
        fi
    fi

    for pair in "spending-wallet notebook ($FU_ADDR):$FU_STORE" "multi-recipient funder:$MFU_STORE"; do
        label="${pair%%:*}"; s_store="${pair#*:}"
        SW_OUT="$("$APP" sweep "$s_store" "$BASE" "$FUND_ADDR" 1.0 2>&1 || true)"
        if echo "$SW_OUT" | grep -q "^cli: sweep txid="; then
            pass "swept $label leftovers back to the gift wallet"
        else
            echo "note: $label sweep-back skipped/failed (balance may be dust-only or zero): $SW_OUT"
        fi
    done

    echo "note: the two external-funding ephemeral wallets (tr/wpkh, ~$FUND_EXTERNAL_BTC BTC funded each) and the"
    echo "      three multi-recipient throwaway addresses are NOT swept back by this script — their leftover"
    echo "      change/dust stays on testnet4. Amounts are deliberately small (see FUND_EXTERNAL_BTC) to bound"
    echo "      this known gap; a future unit could add a recovery sweep if that dust needs reclaiming."
fi

TIP_AFTER="$(core_cli getblockcount)"
echo
pass "regtest-e2e complete: backend=$BACKEND network=$NETWORK tip $TIP_BEFORE -> $TIP_AFTER (node never reset/wiped/reindexed)"

echo
echo "Summary: $PASS_N PASS · $SKIP_N SKIP"
if [[ "$SKIP_N" -gt 0 ]]; then
    echo "Skipped legs (regtest-only):"
    for leg in "${SKIPPED_LEGS[@]}"; do
        echo "  - $leg"
    done
fi
