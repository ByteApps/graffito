#!/usr/bin/env bash
# regtest-spending-self-notes.sh — e2e for the spending-funded-self-notes fix
# (../../PLAN-chain-notes-app-spending-self-notes.md).
#
# Reproduces the REPORTED scenario end to end against a real bitcoind:
# a note composed by this identity but paid for entirely from its SPENDING
# wallet (BIP-84 P2WPKH, no notebook input) must scan back as OWN — even on a
# FRESH store with no recorded spending-address snapshot, i.e. after a
# reinstall + seed restore, which is exactly when the pre-fix build filed it
# as `received` with no resolvable sender and bucketed it under "unknown".
#
# Legs:
#   1. compose a spending-funded public self-note; scan in the SAME store →
#      OWN (regression: this already worked pre-fix via the recorded-`used`
#      snapshot).
#   2. RESTORE: a brand-new store for the SAME seed in a directory with NO
#      notebooks index (so the spending snapshot is empty — the reinstall
#      case) → must STILL scan as OWN, purely from the derived spending
#      window (Unit A). This is the leg that FAILS pre-fix.
#   3. PRUNE (Unit B): inject a stale `received`/no-sender twin of that note
#      into the restored store (what a pre-fix scan would have left behind),
#      rescan, and assert it is gone — leaving exactly one OWN note and no
#      "unknown"-sender record.
#
# Talks to the ONE shared node — the Pi's persistent regtest chain, never a
# local throwaway bitcoind (PLAN-one-regtest-node.md). Run it through the
# workspace wrapper so CN_NETWORK/CN_NODE_HOST/CN_NODE_PORT/CORE_RPC_USER/
# CORE_RPC_PASS reach it:
#   ui-automation/node-env.sh regtest graffito/scripts/regtest-spending-self-notes.sh
# Regtest-only by construction — every leg needs POST .../faucet and
# .../mine, both 409 on testnet4 (the plan's "two verbs, not one"); a
# CN_NETWORK naming anything else makes this script print a loud SKIP and
# exit instead of quietly proving less. Each run also derives a fresh
# APP_ACCOUNT so its notebook/spending addresses are brand new on the
# shared chain (the Pi's chain is never wiped/reset; this script only ever
# touches server.py's own chain-notes-watch/chain-notes-miner wallets, not
# the Pi's testwallet). Never prints a credential value.
set -euo pipefail
GRN=$'\033[32m'; RED=$'\033[31m'; NC=$'\033[0m'
pass() { echo "${GRN}PASS${NC} $*"; }
fail() { echo "${RED}FAIL${NC} $*"; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PRIME_ROOT="$(cd "$REPO/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
PORT=18801
BASE="http://127.0.0.1:$PORT/regtest/api"
WORK="$(mktemp -d)"
APP="$REPO/target/debug/examples/cli"

NET="${CN_NETWORK:-regtest}"
if [[ "$NET" != "regtest" ]]; then
    echo "SKIP regtest-spending-self-notes (regtest-only: every leg needs POST"
    echo "  .../faucet and .../mine, both 409 on $NET — see PLAN-one-regtest-node.md"
    echo "  'two verbs, not one')"
    echo "0 PASS · 1 SKIP"
    exit 0
fi

( cd "$REPO" && cargo build -q -p app-core --example cli )
# server.py reads CN_NETWORK/CN_NODE_HOST/CN_NODE_PORT/CORE_RPC_USER/
# CORE_RPC_PASS straight from the environment (no --regtest/--datadir —
# those are gone; see companion/server.py's module docstring).
python3 "$PRIME_ROOT/prime-chain-notes/companion/server.py" $PORT >/dev/null 2>&1 &
SRV=$!
cleanup() { kill $SRV 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break; sleep 1; done
curl -sf "http://127.0.0.1:$PORT/api/health" >/dev/null || fail "server did not come up"

# A dedicated identity so the notebook itself stays coin-free: every note
# below is funded ONLY by the spending wallet (no notebook input at all),
# which is precisely the shape that produced "unknown". APP_ACCOUNT is
# randomized per run (same technique as regtest-e2e.sh's --pi-regtest
# mode): the Pi's regtest is shared and persistent, so a fixed account
# would accumulate on-chain notes across runs and break the exact
# note-count assertions below (leg2/leg3 expect exactly one note).
export APP_KEY="zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
export APP_ACCOUNT="${E2E_ACCOUNT:-$(( ($(date +%s%N) + $$) % 900000000 ))}"
echo "APP_ACCOUNT=$APP_ACCOUNT (fresh this run — never reused against the shared chain)"
export CN_FUND_GAP=2
mkdir -p "$WORK/orig"
STORE="$WORK/orig/store.json"
"$APP" init "$STORE" regtest | grep -q "kind=mnemonic" || fail "init"
NB_ADDR="$("$APP" address regtest)"
[[ "$NB_ADDR" == bcrt1p* ]] || fail "notebook address not taproot: $NB_ADDR"

# ---- leg 1: compose a spending-funded self-note, scan in the same store ----
SPEND_ADDR="$("$APP" spending-address "$STORE" regtest | tail -1)"
[[ "$SPEND_ADDR" == bcrt1q* ]] || fail "spending address not segwit v0: $SPEND_ADDR"
curl -sf -X POST "$BASE/faucet" -d "{\"address\":\"$SPEND_ADDR\",\"amount\":0.0005}" >/dev/null
curl -sf -X POST "$BASE/mine?blocks=1" >/dev/null
NOTE_TEXT="spending funded self note"
"$APP" note-spend-funded "$STORE" "$BASE" public 2.0 "$NOTE_TEXT" \
    | tee "$WORK/compose.log" | grep -q "broadcast=ok" || fail "note-spend-funded: $(cat "$WORK/compose.log")"
curl -sf -X POST "$BASE/mine?blocks=1" >/dev/null
"$APP" scan "$STORE" "$BASE" >/dev/null
"$APP" notes "$STORE" | tee "$WORK/notes-orig" \
    | grep -q "received=false .*text=$NOTE_TEXT" \
    || fail "leg1: not OWN in the composing store: $(cat "$WORK/notes-orig")"
pass "leg1: spending-funded note scans as OWN in the composing store"

# ---- leg 2: RESTORE — fresh store, same seed, NO spending snapshot --------
# A separate directory means `spending_index_path` finds no notebooks-*.json,
# so `store.spending` stays empty — byte-for-byte the reinstall+restore state
# where the recorded-`used` list can't vouch for the funding address.
mkdir -p "$WORK/restored"
STORE2="$WORK/restored/store.json"
"$APP" init "$STORE2" regtest | grep -q "kind=mnemonic" || fail "restore init"
[ ! -f "$WORK/restored/notebooks-regtest-"*.json ] 2>/dev/null || fail "restored dir must have no notebooks index"
"$APP" scan "$STORE2" "$BASE" >/dev/null
"$APP" notes "$STORE2" | tee "$WORK/notes-restored" \
    | grep -q "received=false .*text=$NOTE_TEXT" \
    || fail "leg2 (THE FIX): restored store filed the note as received/unknown: $(cat "$WORK/notes-restored")"
grep -q "received=true" "$WORK/notes-restored" \
    && fail "leg2: a received twin exists in the restored store: $(cat "$WORK/notes-restored")"
pass "leg2 (THE FIX): a fresh restore classifies the spending-funded note as OWN — no 'unknown' bucket"

# ---- leg 3: Unit B — a stale received twin from a pre-fix scan is pruned ---
python3 - "$STORE2" <<'PY'
import json, sys
p = sys.argv[1]
s = json.load(open(p))
own = [n for n in s["notes"] if not n.get("received")]
assert own, "expected an own note to clone"
twin = dict(own[0])
twin["received"] = True     # what a pre-fix scan stored...
twin["sender"] = None       # ...with no resolvable taproot sender → "unknown"
s["notes"].append(twin)
json.dump(s, open(p, "w"), indent=2)
print(f"injected stale received twin for note {twin['note_id']}")
PY
"$APP" notes "$STORE2" | grep -q "received=true" || fail "leg3: twin injection did not take"
"$APP" scan "$STORE2" "$BASE" >/dev/null
"$APP" notes "$STORE2" | tee "$WORK/notes-pruned" | grep -q "received=true" \
    && fail "leg3: stale received twin survived the rescan: $(cat "$WORK/notes-pruned")"
[ "$(grep -c "^note id=" "$WORK/notes-pruned")" = "1" ] \
    || fail "leg3: expected exactly one note after the prune: $(cat "$WORK/notes-pruned")"
grep -q "received=false .*text=$NOTE_TEXT" "$WORK/notes-pruned" \
    || fail "leg3: the surviving note is not the OWN one: $(cat "$WORK/notes-pruned")"
pass "leg3 (Unit B): the stale received/'unknown' twin is pruned, leaving one OWN note"

echo "${GRN}ALL PASS${NC} — spending-funded self-notes classify as OWN across a restore, and stale twins heal."
echo "3 PASS · 0 SKIP"
exit 0
