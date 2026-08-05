//! U3 conformance suite (`PLAN-chain-notes-app-core-rpc.md` §3 step 3):
//! replays the SAME backend-agnostic contract battery `chain_contract.rs`
//! runs against `EsploraFake` (U1), this time against the workspace's ONE
//! shared regtest node (`PLAN-one-regtest-node.md`) through
//! `ChainClient<AnyTransport>`'s Core RPC backend (U3).
//!
//! **This suite no longer spawns its own `bitcoind`.** It connects to the
//! shared node over the "one regtest node" contract:
//!
//!   | env var | meaning | default |
//!   |---|---|---|
//!   | `CN_NETWORK` | `regtest` \| `testnet4` | `regtest` |
//!   | `CN_NODE_HOST` | RPC host | `127.0.0.1` |
//!   | `CN_NODE_PORT` | RPC port | 18443 / 48332 by network |
//!   | `CORE_RPC_USER` / `CORE_RPC_PASS` | credentials | none — required |
//!
//! Get real values by running (from the `prime` workspace root)
//! `ui-automation/node-env.sh <network> cargo test -p app-core --test
//! core_rpc_conformance -- --nocapture --test-threads=1`, or export the vars
//! yourself. The node is reached through Sal's SSH tunnel — bring it up with
//! `ssh -f -N -o ExitOnForwardFailure=yes -L 18443:127.0.0.1:18443
//! satoshi@raspberrypi.local` (regtest) if it isn't already. **Absence of a
//! reachable node or credentials is a HARD FAILURE with fix instructions,
//! never a silent skip** — a missing/broken node used to make this whole
//! suite report a false green in well under a second; see the
//! `silent-green-test-hazards` memory. A genuine run against the real node
//! takes on the order of a minute; a sub-second "pass" means something is
//! wrong, not that the suite is fast.
//!
//! **The chain is shared, persistent, and not ours — and coinbase funding
//! is FINISHED, not merely degraded.** Regtest halves every 150 blocks
//! (`50 × 150 × 2` = a 15,000 BTC total supply cap); the shared node passed
//! height 4300 in mid-2026 with 27+ halvings behind it, the subsidy is 18
//! sats (below the 330-sat P2TR dust limit), and only a few thousand more
//! sats will EVER be mineable across every future block combined. Directly
//! mining a coinbase reward to a fresh test address — this file's ORIGINAL
//! funding strategy — permanently strands that reward the instant the
//! address is discarded (nothing will ever load that throwaway wallet
//! again): 58 such wallets once accumulated 505 BTC of dead coin this way,
//! 3.4% of the chain's entire supply, and the 100-block coinbase-maturity
//! padding that pattern needed was the single biggest driver of the
//! chain's own growth — the funding strategy caused its own extinction.
//!
//! **Every fixture-building test now funds itself from a [`Faucet`] —
//! `testwallet` (the node owner's wallet, holding essentially all of the
//! chain's ~15,000 BTC final supply) spent from via `sendtoaddress`/`send`,
//! NEVER created/loaded/renamed/reset — and every throwaway wallet this
//! suite creates (a faucet, or a `sender` signing wallet) is wrapped in a
//! [`WalletGuard`]/[`Faucet`] RAII guard that sweeps its balance back to a
//! fresh `testwallet` address via `sendall` on `Drop`, success OR test
//! failure** (the guard is held for the FIXTURE's whole lifetime, not
//! unloaded at the bottom of a function, precisely so it still fires if an
//! assertion panics partway through — proven directly by
//! `core_rpc_wallet_guard_returns_funds_even_on_panic`). Mining is used
//! ONLY to confirm an already-broadcast tx now, never to fund one — every
//! confirm block's reward goes to a FRESH `testwallet` address, so even
//! that stays fully recovered rather than stranded on a throwaway sink. A
//! wallet holding only a sub-dust leftover fails `sendall` with -6 ("Total
//! value of UTXO pool too low") — expected, and swallowed by the guard, not
//! a bug (fee genuinely exceeds the dust). Any throwaway wallet still gets
//! a per-run-random name so repeated runs never collide; each is also
//! `unloadwallet`d (best effort) once its guard fires, so nothing piles up
//! loaded on the shared node forever. Tests that build a fixture by mining
//! confirm blocks are regtest-only by construction (there is no way to
//! mine on testnet4) and fail loudly, via [`require_regtest`], if pointed
//! at any other network.
//!
//! **Four tests that used to need a differently-configured (or
//! differently-clocked) node are RESTRUCTURED, not `#[ignore]`d**, against
//! `common::mock_rpc` — a local-only bitcoind-JSON-RPC-shaped HTTP stub
//! (NOT bitcoind, NOT the shared node; see its own doc comment). What each
//! of them actually verifies is how `CoreRpcTransport` INTERPRETS an RPC
//! response or WHAT it SENDS on the wire, not anything that genuinely needs
//! a real pruned/no-txindex/clock-skewed node:
//! `core_rpc_preflight_reports_pruned_node` and
//! `core_rpc_preflight_reports_missing_txindex` feed `preflight()` a
//! synthetic `getblockchaininfo`/`getindexinfo` body instead of starting a
//! node with different flags;
//! `core_rpc_notfound_requires_txindex_not_just_rpc_code_minus5` is now a
//! TABLE-DRIVEN battery over synthetic `txindex`/IBD/mempool/RPC-error
//! combinations (the shared node always runs `txindex=1`, so the negative
//! cases can no longer come from a real node at all); and
//! `core_rpc_ranged_import_sends_the_caller_birthday_not_zero` (renamed
//! from `core_rpc_birthday_excludes_history_before_a_late_timestamp`)
//! captures the exact `importdescriptors` request bitcoind would receive
//! and asserts the caller's birthday is on it verbatim, instead of relying
//! on a real rescan to prove exclusion — which needed `setmocktime`, global
//! state on the shared node this suite has no business touching. See each
//! test's doc comment for the specific reasoning and what changed.
//!
//! Two traps this file exists to avoid (see the plan's U3 brief):
//!
//! 1. `assert_chain_contract`'s broadcast leg needs a GENUINELY SIGNED tx
//!    against a real backend (`Scenario::broadcast_probe`, this unit's
//!    addition to `common/mod.rs`) — an unsigned spend (fine against
//!    `EsploraFake`, which never validates scripts) gets rejected by a
//!    real node's script validation. This suite builds that probe tx via
//!    `bitcoind`'s own wallet (`send` with `add_to_wallet: false` — signed,
//!    but neither broadcast nor known to the node yet) and hands it to
//!    `Scenario::broadcast_probe`.
//! 2. The `chain_contract.rs` scenarios are built from UNSIGNED synthetic
//!    transactions and are not broadcastable — this file builds its OWN
//!    chain state directly on the node and describes what it did as a
//!    `Scenario`, cross-checked against `bitcoind`'s own `getrawtransaction`
//!    reporting rather than this driver's own bookkeeping (empirically
//!    verified live against bitcoind v30.2.0 while writing this, not
//!    guessed from docs alone — see the prevout-fallback note below).
//!
//! A THIRD, non-obvious trap this file avoids on its own — and the one the
//! faucet redesign above had to answer empirically before it could be
//! safe: a shared funder's own accumulated coin-selection history is NOT
//! something this driver fully tracks, and `Scenario::all_addresses()`
//! pulls in every address that appears as an input's resolved prevout — so
//! if `testwallet` (or any address it touches) ever leaked into a recorded
//! tx's vin, its FULL real history (visible to the live node, ~14,919 BTC
//! and untold prior operations, but not represented in this file's
//! hand-built `Scenario`) would silently desync from what
//! `assert_chain_contract` expects. **The prevout-depth question this
//! migration answered live**: does `Scenario::all_addresses()`/
//! `assert_chain_contract` follow a prevout more than one hop? No — it only
//! ever inspects the vin of a tx THIS FILE ITSELF chose to record, never
//! walks further back into THAT tx's own inputs. So a ONE-HOP funder is
//! provably safe to hide, and [`Faucet`] is built to stay exactly one hop:
//! `testwallet` funds a throwaway faucet wallet's addresses (never
//! recorded), each of which pays a single test address in FULL — no change,
//! `subtract_fee_from_outputs` — so it never appears as a vout anywhere
//! either. `hide_vin` then clears that ONE recorded tx's `vin` before it
//! joins the `Scenario`, keeping the faucet address (and `testwallet`
//! behind it) out of `all_addresses()` entirely — not merely inconvenient
//! to desync, but structurally unreachable. This is the SAME choice as
//! option (a) over option (b) in `PLAN-one-regtest-node.md`'s design
//! writeup: scoping the contract assertion down to "addresses this file
//! itself funded" (option b) would have removed the concern too, but at
//! the cost of the "complete real history" property `assert_chain_contract`
//! otherwise proves for every address it touches — the one-hop faucet gets
//! to keep that property AND avoid the trap. Every test address here is
//! therefore still single-purpose and its complete real history is exactly
//! what this file records: a "funder" address (the faucet, or a confirm-
//! mining `testwallet` address) either (a) never appears in any RECORDED
//! tx at all, or (b) has its own faucet-funding tx recorded too — WITH ITS
//! `vin` HIDDEN — alongside whatever it later spends (`addr_note`, the
//! `mempool_funder` relay, both of which keep their REAL vin since it
//! correctly references another already-tracked test address, not the
//! faucet).
//!
//! Note on vin representation: no genuinely coinbase tx is EVER recorded
//! into this file's `Scenario` anymore (every faucet-fund/mining split
//! goes to `testwallet`/faucet addresses that are never converted to a
//! `ScenarioTx` at all — see the funding-model paragraphs above), so the
//! ORIGINAL reason this file needed to represent a coinbase input's
//! nonexistent prevout (`getrawtransaction`'s vin entry carries a
//! `"coinbase"` hex field instead of `txid`/`vout`/`prevout`) as an EMPTY
//! `ScenarioTx.vin` no longer applies. The SAME empty-`vin` representation
//! is still produced today, deliberately, by `hide_vin`/
//! `build_scenario_tx` for every faucet-funded tx — a genuine, non-coinbase
//! spend whose real vin is simply not recorded (see the THIRD trap above).
//! Either way the shape is behaviorally identical to a `None`-prevout entry
//! for every pure address-matching computation in `common/mod.rs` (none of
//! them ever match a nonexistent prevout address), and it's what keeps
//! `assert_chain_contract`'s ONE vin-COUNT-sensitive check (`fetch_tx_io`,
//! which only ever inspects the FIRST tx with a non-empty `vin`) landing on
//! a real spend (`addr_note`'s own legs) instead of a faucet-funding tx.

mod common;

use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use app_core::chain::{AnyTransport, ChainClient, TxLookupStatus, WatchDescriptor};
use app_core::funding::FundingSource;
use app_core::identity::{parse_key_material, realize, realize_change};
use app_core::keyexport::export_formats;
use app_core::notes_core::Network;
use app_core::spending;

use common::{assert_chain_contract, Scenario, ScenarioIn, ScenarioOut, ScenarioTx, ScenarioWallet};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn sats(btc: f64) -> u64 {
    (btc * 1e8).round() as u64
}

fn btc_str(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

fn pay_output(address: &str, sats: u64) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert(address.to_string(), serde_json::Value::String(btc_str(sats)));
    serde_json::Value::Object(map)
}

fn data_output(payload: &[u8]) -> serde_json::Value {
    serde_json::json!({"data": hex::encode(payload)})
}

// ---------------------------------------------------------------------
// The shared-node contract (PLAN-one-regtest-node.md, "the shared
// contract"). No suite invents its own — this is it.
// ---------------------------------------------------------------------

/// Connection details for the ONE shared regtest/testnet4 node, read from
/// the environment. Credentials carry no default: their absence is a HARD
/// FAILURE (via [`node_env`]'s panic), never a silent skip. `Clone` so a
/// [`Node`] can be cheaply duplicated into a [`WalletGuard`]/[`Faucet`]
/// that outlives the function that opened the original connection (an RAII
/// guard can't borrow `&Node` from a sibling field of the SAME struct it
/// lives in — see `ConformanceFixture`).
#[derive(Clone)]
struct NodeEnv {
    network: String,
    host: String,
    port: u16,
    user: String,
    pass: String,
}

fn node_env() -> NodeEnv {
    let network = std::env::var("CN_NETWORK").unwrap_or_else(|_| "regtest".to_string());
    if network != "regtest" && network != "testnet4" {
        panic!(
            "CN_NETWORK={network:?} is not one of \"regtest\"/\"testnet4\" — see the shared contract \
             table in PLAN-one-regtest-node.md."
        );
    }
    let host = std::env::var("CN_NODE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let default_port: u16 = if network == "testnet4" { 48332 } else { 18443 };
    let port = match std::env::var("CN_NODE_PORT") {
        Ok(p) => p.parse::<u16>().unwrap_or_else(|_| panic!("CN_NODE_PORT={p:?} is not a valid port number")),
        Err(_) => default_port,
    };
    let user = std::env::var("CORE_RPC_USER").unwrap_or_else(|_| {
        panic!(
            "CORE_RPC_USER is not set. This suite talks to the ONE shared {network} node — it never \
             spawns its own bitcoind (PLAN-one-regtest-node.md). Fix: export CN_NETWORK, CN_NODE_HOST, \
             CN_NODE_PORT, CORE_RPC_USER, CORE_RPC_PASS yourself (or run through the workspace wrapper \
             `ui-automation/node-env.sh {network} cargo test -p app-core ...` once it exists), and make \
             sure the SSH tunnel is up: `ssh -f -N -o ExitOnForwardFailure=yes -L {default_port}:\
             127.0.0.1:{default_port} satoshi@raspberrypi.local`."
        )
    });
    let pass = std::env::var("CORE_RPC_PASS").unwrap_or_else(|_| {
        panic!("CORE_RPC_PASS is not set — see the CORE_RPC_USER panic message above for the full fix.")
    });
    // A per-run watch wallet is REQUIRED against the shared node, and its
    // absence is a hard failure for the same reason missing credentials are:
    // the alternative is quietly doing the wrong thing. Without it the code
    // under test creates and imports into the PRODUCTION `chain-notes-watch`
    // wallet, which every run then grows — it reached 642 txs / 404
    // descriptors that way, and since a rescan is O(blocks x descriptors)
    // under the wallet lock, a `timestamp: 0` import cost ~130s against ~0.5s
    // into a fresh wallet, with every other suite queued behind it.
    //
    // Set by the environment rather than by the suite: `std::env::set_var`
    // from inside a multi-threaded test process races every concurrent reader
    // of the environment, and this transport reads the variable on each RPC.
    if std::env::var("CN_WATCH_WALLET").map(|v| v.trim().is_empty()).unwrap_or(true) {
        panic!(
            "CN_WATCH_WALLET is not set. This suite drives the PRODUCTION Core transport, so without \
             a per-run wallet name it creates and bloats the shared `chain-notes-watch` wallet on the \
             {network} node (PLAN-one-regtest-node.md, \"Two things now grow\"). Fix: export a unique \
             name first, e.g. `export CN_WATCH_WALLET=\"cn-conf-$$-$(date +%s)\"`, alongside the \
             CN_NETWORK/CN_NODE_* and CORE_RPC_* variables."
        );
    }
    NodeEnv { network, host, port, user, pass }
}

/// The watch wallet this run's assertions must target — the same name the code
/// under test resolves (`CoreRpcTransport::WATCH_WALLET_ENV`). Asserting
/// against a hardcoded "chain-notes-watch" while the transport wrote somewhere
/// else would check an empty wallet and pass for the wrong reason.
fn watch_wallet() -> String {
    std::env::var("CN_WATCH_WALLET")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "chain-notes-watch".to_string())
}

fn network_of(env: &NodeEnv) -> Network {
    match env.network.as_str() {
        "regtest" => Network::Regtest,
        "testnet4" => Network::Testnet4,
        other => panic!("unsupported CN_NETWORK={other:?}"),
    }
}

/// Fails loudly (never silently skips) when the configured network isn't
/// regtest. Every fixture-building test in this file mines blocks to set up
/// its scenario, and there is no testnet4 equivalent — you cannot mine
/// there (`PLAN-one-regtest-node.md`'s hard constraint).
fn require_regtest(test_name: &str, env: &NodeEnv) {
    assert_eq!(
        env.network, "regtest",
        "{test_name} is regtest-only: it mines blocks to build its fixture, and there is no testnet4 \
         equivalent (mining isn't possible there). Set CN_NETWORK=regtest (the default) — got \
         CN_NETWORK={:?}.",
        env.network
    );
}

/// A connection to the shared node this suite talks to — never a locally
/// spawned process. `Node::connect` is the only constructor; it fails
/// loudly if the node can't be reached or the reported chain doesn't match
/// what was asked for. `Clone` (both fields are — `reqwest::blocking::
/// Client` is `Arc`-backed, cheap to duplicate) so [`WalletGuard`]/
/// [`Faucet`] can own their own handle to the same node instead of
/// borrowing one with a lifetime.
#[derive(Clone)]
struct Node {
    env: NodeEnv,
    client: reqwest::blocking::Client,
}

impl Node {
    fn base(&self) -> String {
        format!("http://{}:{}", self.env.host, self.env.port)
    }

    /// The `bitcoind+http://user:pass@host:port` URL for the real node —
    /// kept ONLY as a manual-debugging escape hatch (bypasses
    /// `common::count_proxy::CountingProxy`); every test in this file now
    /// routes its transport-under-test through the counting proxy instead,
    /// which is why nothing here calls this. **Never print or embed this
    /// string in a panic/assert message** — it carries the real shared
    /// node's credentials (`chain-notes-app` is a PUBLIC repo).
    #[allow(dead_code)]
    fn core_rpc_url(&self) -> String {
        format!("bitcoind+http://{}:{}@{}:{}", self.env.user, self.env.pass, self.env.host, self.env.port)
    }

    fn try_rpc(&self, wallet: Option<&str>, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let url = match wallet {
            Some(w) => format!("{}/wallet/{w}", self.base()),
            None => self.base(),
        };
        let resp = self
            .client
            .post(&url)
            .basic_auth(&self.env.user, Some(&self.env.pass))
            .json(&serde_json::json!({"jsonrpc": "1.0", "id": "setup", "method": method, "params": params}))
            .send()
            .map_err(|e| e.to_string())?;
        let text = resp.text().map_err(|e| e.to_string())?;
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| format!("non-JSON response: {text}"))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            return Err(err.to_string());
        }
        Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }

    fn rpc(&self, wallet: Option<&str>, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.try_rpc(wallet, method, params).unwrap_or_else(|e| panic!("setup rpc {method} failed: {e}"))
    }

    /// Connect to the shared node and verify it answers AND reports the
    /// chain we asked for — never a 60s "boot" retry loop (this node is
    /// already running; if it's unreachable, that's a tunnel/creds problem,
    /// not a startup race), just a short tolerance for a transient blip
    /// over the SSH tunnel before failing loudly with fix instructions.
    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.try_rpc(None, "getblockchaininfo", serde_json::json!([])) {
                Ok(v) => {
                    let chain = v.get("chain").and_then(|c| c.as_str()).unwrap_or("?").to_string();
                    let expected = if self.env.network == "testnet4" { "testnet4" } else { "regtest" };
                    assert_eq!(
                        chain, expected,
                        "connected to a node at {}:{} but it reports chain={chain:?}, not {expected:?} — \
                         the tunnel/CN_NODE_HOST/CN_NODE_PORT is pointed at the wrong node",
                        self.env.host, self.env.port
                    );
                    return;
                }
                Err(e) => {
                    if Instant::now() >= deadline {
                        panic!(
                            "cannot reach the shared {} node at {}:{} after 10s: {e}\n\
                             Fix: bring up the SSH tunnel — `ssh -f -N -o ExitOnForwardFailure=yes \
                             -L {port}:127.0.0.1:{port} satoshi@raspberrypi.local` — and confirm \
                             CN_NODE_HOST/CN_NODE_PORT/CORE_RPC_USER/CORE_RPC_PASS are correct for the \
                             {} node (PLAN-one-regtest-node.md's shared contract). This suite never \
                             spawns its own bitcoind, so there is no local fallback.",
                            self.env.network, self.env.host, self.env.port, self.env.network,
                            port = self.env.port,
                        );
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }

    /// Mine `n` blocks, coinbase paid directly to `address`. Follows with a
    /// BEST-EFFORT `syncwithvalidationinterfacequeue` — bitcoind's wallet
    /// block-processing is ASYNC (validation-interface callbacks drain on
    /// the scheduler thread AFTER `generatetoaddress` returns), so a
    /// `listunspent`/`gettransaction` served immediately after a mine can
    /// answer from the PRE-block view. Same hazard, same fix, as
    /// `companion/server.py`'s `mine()` (verified live while writing this
    /// suite, not merely inherited from that comment).
    fn generate(&self, n: u64, address: &str) {
        self.rpc(None, "generatetoaddress", serde_json::json!([n, address]));
        let _ = self.try_rpc(None, "syncwithvalidationinterfacequeue", serde_json::json!([]));
    }

    fn fresh_addr(&self, wallet: &str) -> String {
        self.rpc(Some(wallet), "getnewaddress", serde_json::json!(["", "bech32m"]))
            .as_str()
            .expect("getnewaddress: not a string")
            .to_string()
    }

    /// The SOLE utxo at `address` right now — panics if there isn't
    /// exactly one, which is the point: every address in this suite is
    /// single-purpose enough that "how many coins does it have at this
    /// checkpoint" is always a known, asserted quantity.
    fn sole_utxo(&self, wallet: &str, address: &str) -> (String, u32, u64) {
        let v = self.rpc(Some(wallet), "listunspent", serde_json::json!([0, 9_999_999, [address]]));
        let arr = v.as_array().expect("listunspent: not an array");
        assert_eq!(arr.len(), 1, "expected exactly one utxo at {address}, got {arr:?}");
        let u = &arr[0];
        (
            u["txid"].as_str().expect("utxo txid").to_string(),
            u["vout"].as_u64().expect("utxo vout") as u32,
            u["amount"].as_f64().map(sats).expect("utxo amount"),
        )
    }

    fn tip_height(&self) -> u64 {
        self.rpc(None, "getblockcount", serde_json::json!([])).as_u64().expect("getblockcount: not a number")
    }

    /// Best-effort cleanup for a throwaway signing wallet THIS RUN created
    /// (never `testwallet`, never `chain-notes-watch` — production state
    /// this suite doesn't own). Doesn't delete wallet files on the node,
    /// just unloads it so repeated runs don't leave an ever-growing pile of
    /// loaded wallets on a shared, persistent node.
    fn unload_wallet(&self, name: &str) {
        let _ = self.try_rpc(None, "unloadwallet", serde_json::json!([name]));
    }
}

/// Connect to the shared node named by the environment (the "one regtest
/// node" contract) — the sole replacement for the old `start_node()`, which
/// used to spawn a throwaway local `bitcoind`. No local process is ever
/// started by this suite anymore.
fn connect_node() -> Node {
    let env = node_env();
    let node = Node { client: reqwest::blocking::Client::builder().timeout(Duration::from_secs(30)).build().unwrap(), env };
    node.wait_ready();
    node
}

/// Waits (bounded) for the shared node's `chain-notes-watch` wallet to
/// finish any IN-PROGRESS rescan before this test starts touching it.
/// Purely test-harness courtesy for a genuinely observed hazard on the
/// shared, multi-consumer node (`PLAN-one-regtest-node.md`): bitcoind
/// refuses ANY concurrent operation on a wallet mid-rescan (RPC code -4,
/// "Wallet is currently rescanning. Abort existing rescan or wait.")  — and
/// on a node other agents/suites/the real app may be touching at the same
/// moment, SOMEONE ELSE'S rescan can already be running the instant this
/// test makes its very first touch of `chain-notes-watch`. Observed live
/// (2026-08-02): four tests in one run each hit -4 on their FIRST touch of
/// the wallet, and a direct `getwalletinfo` moments after that run ended
/// showed `scanning: false` — i.e. genuinely external, transient
/// contention (from a concurrently-running sibling suite/unit against this
/// same Pi node), not anything this suite's own logic caused.
///
/// This is NOT "retry and hope a race resolves in our favor" — it waits
/// for an OBSERVABLE, well-defined condition (`getwalletinfo().scanning`)
/// before letting the test proceed with its own deterministic operations,
/// the same courtesy bitcoind's own error message asks for ("wait").
/// Best-effort: if the wallet doesn't exist yet (nothing has imported into
/// it this session), `getwalletinfo` errors and this treats that as
/// "nothing to wait for" and returns immediately. Bounded at 5 minutes —
/// past that, something is genuinely stuck and the test should fail
/// loudly on its own next real RPC call rather than hang here forever.
fn wait_for_watch_wallet_idle(node: &Node) {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let info = match node.try_rpc(Some(&watch_wallet()), "getwalletinfo", serde_json::json!([])) {
            Ok(v) => v,
            Err(_) => return, // wallet doesn't exist yet — nothing to wait for
        };
        let scanning = match info.get("scanning") {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::Object(_)) => true,
            _ => false,
        };
        if !scanning {
            return;
        }
        if Instant::now() >= deadline {
            eprintln!("cb: test-harness gave up waiting for chain-notes-watch to finish rescanning after 300s");
            return;
        }
        eprintln!("cb: test-harness waiting for a concurrent chain-notes-watch rescan to clear (shared node)");
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// U5 measurement addition (`regtest-hides-cost-bugs` memory: assert on
/// call counts, not elapsed time — a per-operation genesis rescan shipped
/// in build 52 because a 118-block regtest made it free and elapsed time
/// never caught it). Prints ONE line per real-node test: wall-clock
/// elapsed AND, from `proxy` (a [`common::count_proxy::CountingProxy`]
/// sitting between the transport-under-test and the real node), the exact
/// per-RPC-method call counts the CODE UNDER TEST issued — independent of
/// chain height, node latency, or how long any individual call took. This
/// is the chain-length-independent signal; the elapsed time is printed
/// alongside it only for human context, never as a pass/fail signal.
fn report_timing(name: &str, t0: Instant, proxy: &common::count_proxy::CountingProxy) {
    let mut counts: Vec<(String, u32)> = proxy.snapshot().into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    eprintln!(
        "TIMING {name}: {:?} elapsed, {} total RPC calls via proxy, breakdown={counts:?}",
        t0.elapsed(),
        proxy.total()
    );
}

/// Per-run-unique name for a throwaway signing wallet THIS test creates on
/// the shared node — never reused across runs (the node is persistent, so a
/// fixed name would collide with a previous run's leftovers or a
/// concurrently running instance of this same suite).
static WALLET_SEQ: AtomicU32 = AtomicU32::new(0);

fn unique_wallet_name(role: &str) -> String {
    let seq = WALLET_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    format!("cn-test-{role}-{}-{nanos}-{seq}", std::process::id())
}

// ---------------------------------------------------------------------
// Faucet funding (`PLAN-one-regtest-node.md`'s "value must circulate, not
// be mined" fix). See the module doc's "Fixture funding" section for the
// full design writeup — this is the mechanism.
// ---------------------------------------------------------------------

/// How much every faucet-issued single-purpose coin carries. Comfortably
/// above dust (~330 sats for a P2TR output) after paying a 5 sat/vB fee
/// through up to two further hops (`addr_note`'s phase-2/phase-3 spends),
/// and utterly negligible against `testwallet`'s ~14,919 BTC balance.
const FAUCET_FUND_SATS: u64 = 50_000;

/// Best-effort: sweep whatever `wallet` still holds back to a FRESH
/// `testwallet` address via `sendall`, then unload it. Called from every
/// throwaway wallet's `Drop` (`WalletGuard`, `Faucet`) — **must never
/// panic**, because a panic during unwind ABORTS THE PROCESS (Rust only
/// runs `Drop`s during a panic if nothing ELSE panics on the way out),
/// which would destroy the very test failure this cleanup exists to run
/// alongside. Every fallible step here is swallowed, logged at most.
///
/// A wallet holding only a sub-dust leftover (or nothing at all — every
/// `Faucet`-issued coin is fully drained by `Faucet::fund`'s
/// `subtract_fee_from_outputs`, so its wallet is normally already empty
/// by the time this runs) fails `sendall` with -6 "Total value of UTXO
/// pool too low to pay for transaction" — EXPECTED, verified live against
/// the real shared node while designing this, and not a bug: the fee
/// would genuinely exceed the value being swept.
fn sweep_wallet_to_testwallet(node: &Node, wallet: &str) {
    let dest = match node.try_rpc(Some("testwallet"), "getnewaddress", serde_json::json!(["", "bech32m"])) {
        Ok(v) => v.as_str().map(str::to_string),
        Err(e) => {
            eprintln!("cb: wallet-guard[{wallet}] could not get a testwallet return address: {e}");
            None
        }
    };
    if let Some(dest) = dest {
        // sendall's recipients argument is a BARE array of addresses
        // (`["addr"]`), never `{"addr": amount}` — verified live: the
        // object shape is for PARTIAL sendall (a mix of fixed-amount and
        // remainder recipients), and passing one address as a bare
        // string means "send it everything".
        match node.try_rpc(Some(wallet), "sendall", serde_json::json!([[dest], serde_json::Value::Null, "unset", 5, {}])) {
            Ok(v) => eprintln!("cb: wallet-guard[{wallet}] swept funds back to testwallet: {v}"),
            Err(e) => eprintln!(
                "cb: wallet-guard[{wallet}] sweep skipped (expected for an empty/dust-only wallet): {e}"
            ),
        }
    }
    let _ = node.try_rpc(None, "unloadwallet", serde_json::json!([wallet]));
}

/// RAII guard for a throwaway SIGNING wallet (a `sender`-role wallet this
/// suite created — NEVER `testwallet`/`chain-notes-watch`, production
/// state this suite doesn't own): on `Drop`, sweeps its balance back to
/// `testwallet` and unloads it — success OR failure. Rust's default test
/// profile is `panic = "unwind"` (verified: neither this repo's
/// `Cargo.toml` nor its `.cargo/config.toml` sets `panic = "abort"` for
/// any profile, so an assertion failure unwinds the stack instead of
/// aborting the process), and `Drop` runs during unwind exactly like it
/// does on a normal return — that is the entire point of holding this
/// guard for the FULL lifetime of a test's fixture, not just calling an
/// unload at the bottom of the function. Proven directly by
/// `core_rpc_wallet_guard_returns_funds_even_on_panic` below.
struct WalletGuard {
    node: Node,
    name: String,
}

impl WalletGuard {
    fn new(node: &Node, name: impl Into<String>) -> Self {
        WalletGuard { node: node.clone(), name: name.into() }
    }
}

impl Drop for WalletGuard {
    fn drop(&mut self) {
        sweep_wallet_to_testwallet(&self.node, &self.name);
    }
}

/// A per-fixture-build, ONE-HOP faucet: `n` freshly generated single-use
/// addresses in their own throwaway wallet, each funded with
/// [`FAUCET_FUND_SATS`] from `testwallet` in ONE combined `send` (never
/// recorded into any `Scenario`, exactly like the coinbase-maturity
/// padding it replaces — see the module doc). Constructing it also mines
/// ONE confirm block (reward to a FRESH `testwallet` address, so nothing
/// is ever stranded) so all `n` coins are simultaneously spendable with
/// zero unconfirmed-ancestor limit to worry about — the shared node's
/// default `-limitdescendantcount=25` would otherwise cap how many of
/// these can be spent onward while the split tx itself is still
/// unconfirmed. `fund(i, dest)` then spends faucet address `i`'s ENTIRE
/// balance (minus fee, `subtract_fee_from_outputs`, an explicit `inputs`
/// entry, NO change) onward to `dest` — the exact no-change single-hop
/// shape this file's `mempool_funder`/broadcast-probe legs already use
/// live — and returns the resulting tx's own txid (left in the mempool;
/// the caller mines its own confirm block, exactly matching this file's
/// existing phase-by-phase confirm rhythm).
///
/// **Why one hop, never `testwallet` directly** (the prevout-depth
/// question this migration had to answer empirically — see the module
/// doc's "Fixture funding" section): a funding tx's REAL `vin` carries
/// its funder's address as prevout. Recording that verbatim would drag
/// whoever paid for the fixture into `Scenario::all_addresses()` — and
/// `testwallet`'s own real history (~14,919 BTC, uncounted prior
/// operations on a node this suite doesn't administer) can never be
/// represented by this file's hand-built bookkeeping; this is Trap 3 the
/// module doc already documents for a shared miner address, and it
/// applies identically to a shared FUNDER address. A faucet address makes
/// hiding that safe rather than merely convenient: because every payout
/// drains it to EXACTLY zero (no change output is ever produced), it
/// never appears as a vout anywhere either, so clearing `vin` on the one
/// tx that references it (`hide_funder`) is airtight — there is no SECOND
/// tx anywhere that could still expose it.
struct Faucet {
    node: Node,
    wallet: String,
    addrs: Vec<String>,
}

impl Faucet {
    /// Builds `n` faucet addresses and funds all of them in one shared
    /// `testwallet` send + one confirm block.
    fn new(node: &Node, n: usize) -> Self {
        let wallet = unique_wallet_name("faucet");
        node.rpc(None, "createwallet", serde_json::json!([wallet]));
        let addrs: Vec<String> = (0..n).map(|_| node.fresh_addr(&wallet)).collect();

        let mut outputs = serde_json::Map::new();
        for a in &addrs {
            outputs.insert(a.clone(), serde_json::Value::String(btc_str(FAUCET_FUND_SATS)));
        }
        node.rpc(
            Some("testwallet"),
            "send",
            serde_json::json!([serde_json::Value::Object(outputs), serde_json::Value::Null, "unset", 5, {}]),
        );

        node.generate(1, &node.fresh_addr("testwallet"));

        Faucet { node: node.clone(), wallet, addrs }
    }

    /// Fund address index `i`'s ENTIRE balance (minus fee) onward to
    /// `dest`, no change. Returns the funding tx's own txid — a mempool
    /// tx the caller confirms in its own time, mirroring how every other
    /// funding step in this file already works.
    fn fund(&self, i: usize, dest: &str) -> String {
        let addr = &self.addrs[i];
        let (txid, vout, amount) = self.node.sole_utxo(&self.wallet, addr);
        let result = self.node.rpc(
            Some(&self.wallet),
            "send",
            serde_json::json!([
                [pay_output(dest, amount)],
                serde_json::Value::Null,
                "unset",
                5,
                {"inputs": [{"txid": txid, "vout": vout}], "subtract_fee_from_outputs": [0]},
            ]),
        );
        result["txid"].as_str().expect("send: no txid").to_string()
    }
}

impl Drop for Faucet {
    fn drop(&mut self) {
        sweep_wallet_to_testwallet(&self.node, &self.wallet);
    }
}

/// A per-run-random BIP-32 account number for deriving HD (notebook/
/// spending) addresses from [`TEST_MNEMONIC`]. **Load-bearing on a shared,
/// persistent node**: `TEST_MNEMONIC` is a well-known PUBLIC BIP-39 test
/// vector reused across this whole codebase's test suites (host tests,
/// other e2e harnesses, quite possibly a concurrently-running sibling unit
/// of this very migration) — every one of them that fixes `account = 0`
/// derives the EXACT SAME addresses, and against a throwaway local node
/// that never mattered. Against the ONE shared node it means two
/// completely unrelated test runs can fund the identical taproot address
/// at different chain heights, which is precisely what happened the first
/// time this suite ran here: `client.utxos()` (real node truth) showed TWO
/// coinbases at account-0/index-0 while this run's own `Scenario` only
/// recorded the one IT mined. Randomizing the account index (the
/// `regtest-e2e.sh --pi-regtest` technique — see
/// `PLAN-one-regtest-node.md`'s "Assertions become deltas" section) makes
/// every HD-derived address in this run unique across all of history, past
/// and future, without touching how `TEST_MNEMONIC` itself is used.
static ACCOUNT_SEQ: AtomicU32 = AtomicU32::new(0);

fn random_account() -> u32 {
    let seq = ACCOUNT_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() as u32;
    let pid = std::process::id();
    // Never 0 (every OTHER consumer of this public mnemonic defaults to
    // account 0) and comfortably under the hardened-derivation ceiling
    // (2^31).
    1 + ((nanos ^ pid.wrapping_mul(2_654_435_761) ^ seq.wrapping_mul(40_503)) % 1_000_000)
}

/// Serializes every `#[test]` in this file against each other. Unlike the
/// old local-node version of this suite (where each test owned its own
/// throwaway `bitcoind` process and this lock only existed to avoid
/// resource contention between them), this now guards CORRECTNESS: every
/// test shares the SAME shared node and, more specifically, the SAME
/// production `chain-notes-watch` wallet the code under test creates
/// lazily — two tests racing on it concurrently (cargo's default
/// `#[test]` parallelism) could see each other's descriptor imports
/// mid-assertion. Recovers from a poisoned lock (an earlier test panicking)
/// so one failure doesn't cascade into every other test failing on the lock
/// instead of its own assertions.
static NODE_LOCK: Mutex<()> = Mutex::new(());

fn serialize_nodes() -> std::sync::MutexGuard<'static, ()> {
    NODE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Maps ONE txid into a [`ScenarioTx`] from `bitcoind`'s own
/// `getrawtransaction` reporting — never from this driver's own
/// bookkeeping (Trap 2). Mirrors (independently — this is the TEST's own
/// re-derivation, not a call into the library code under test)
/// `CoreRpcTransport::esplora_tx_json`'s prevout-fallback: a MEMPOOL tx's
/// vin can come back with NO `prevout` at all (verified live — "omitted
/// if block undo data is not available" applies to an unconfirmed input
/// even though its parent tx is perfectly well known), resolved here by
/// fetching the parent tx directly, exactly like the transport under test
/// does server-side.
fn build_scenario_tx(node: &Node, txid: &str, tip: u64) -> ScenarioTx {
    let raw = node.rpc(None, "getrawtransaction", serde_json::json!([txid, 2]));
    let confirmations = raw.get("confirmations").and_then(|c| c.as_u64()).unwrap_or(0);
    let confirmed_height =
        if confirmations > 0 { Some(tip.saturating_sub(confirmations).saturating_add(1)) } else { None };
    let hex = raw["hex"].as_str().expect("getrawtransaction: no hex").to_string();

    let mut vin = Vec::new();
    for i in raw["vin"].as_array().cloned().unwrap_or_default() {
        // A coinbase input has neither `txid` nor `vout` — see the module
        // doc's "Note on vin representation". Skipped entirely.
        let (Some(prev_txid), Some(prev_vout)) =
            (i.get("txid").and_then(|t| t.as_str()), i.get("vout").and_then(|v| v.as_u64()))
        else {
            continue;
        };
        let (prevout_address, prevout_value) = match i.get("prevout").filter(|p| !p.is_null()) {
            Some(p) => (
                p["scriptPubKey"]["address"].as_str().map(str::to_string),
                p["value"].as_f64().map(sats).unwrap_or(0),
            ),
            None => {
                let parent = node.rpc(None, "getrawtransaction", serde_json::json!([prev_txid, 1]));
                let o = &parent["vout"][prev_vout as usize];
                (o["scriptPubKey"]["address"].as_str().map(str::to_string), o["value"].as_f64().map(sats).unwrap_or(0))
            }
        };
        vin.push(ScenarioIn {
            prev_txid: prev_txid.to_string(),
            prev_vout: prev_vout as u32,
            prevout_address,
            prevout_value,
        });
    }

    let mut vout = Vec::new();
    for o in raw["vout"].as_array().cloned().unwrap_or_default() {
        let spk = &o["scriptPubKey"];
        let is_op_return = spk["type"].as_str() == Some("nulldata");
        let address = spk["address"].as_str().map(str::to_string);
        let script_hex = spk["hex"].as_str().expect("vout: no script hex").to_string();
        let value = o["value"].as_f64().map(sats).unwrap_or(0);
        vout.push(ScenarioOut { address, value, script_hex, is_op_return });
    }

    ScenarioTx { txid: txid.to_string(), hex, confirmed_height, vin, vout }
}

/// `listdescriptors` on the transport-under-test's watch wallet, parsed
/// into (desc-without-checksum, range-end) pairs. This exists to prove
/// the MECHANISM under test, not just `assert_chain_contract`'s
/// externally-observable PASS: a reviewer's mutation test that forces
/// `ranged_lookup_or_widen` to always return `Ok(false)` (disabling the
/// ranged path entirely) still passes the whole battery — the U3
/// per-address fallback silently produces an identical answer — so an
/// assertion on RESULTS alone cannot tell the two implementations apart.
/// This CAN: a ranged family's `desc` is `tr(...)`/`wpkh(...)` with a
/// wildcard; the per-address fallback's is literally `addr(<address>)`.
/// Must be called against `"chain-notes-watch"`, matching
/// `CoreRpcTransport::WATCH_WALLET` (private to app-core, so this test
/// hardcodes the string it must match).
fn watch_wallet_descriptors(node: &Node) -> Vec<(String, u32)> {
    let v = node.rpc(Some(&watch_wallet()), "listdescriptors", serde_json::json!([]));
    v["descriptors"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|d| {
            let desc = d["desc"].as_str().unwrap_or("").split('#').next().unwrap_or("").to_string();
            let end = d["range"][1].as_u64().unwrap_or(0) as u32;
            (desc, end)
        })
        .collect()
}

/// Every address currently imported as its OWN `addr(<address>)`
/// descriptor — the sole observable signature of the U3 per-address
/// fallback path. Zero entries here for an address that belongs to a
/// configured ranged family is the thing a mutation disabling ranged
/// lookup cannot fake.
fn addr_import_addresses(node: &Node) -> Vec<String> {
    watch_wallet_descriptors(node)
        .into_iter()
        .filter_map(|(desc, _)| desc.strip_prefix("addr(").and_then(|s| s.strip_suffix(')')).map(str::to_string))
        .collect()
}

/// The `xpub`/`tpub` token inside a descriptor string — used to match a
/// ranged descriptor's `listdescriptors` entries against the ORIGINAL
/// multipath string this suite configured. Two things make an exact
/// string comparison against the original descriptor wrong (verified
/// live): bitcoind SPLITS a `<0;1>` multipath import into two separate
/// single-path `listdescriptors` entries (`.../0/*)` and `.../1/*)`), and
/// it NORMALIZES the hardened-path marker (`'` in, `h` out). The xpub
/// itself is untouched by either, so it's the one thing safe to match on.
fn xpub_of(descriptor: &str) -> &str {
    descriptor
        .split(['(', ')', '[', ']', '/'])
        .find(|s| s.starts_with("xpub") || s.starts_with("tpub"))
        .unwrap_or_else(|| panic!("descriptor carries no xpub/tpub: {descriptor}"))
}

/// Everything the ranged-descriptor conformance tests (U4 test 1) need: a
/// running node with the SAME 43-tx scenario `core_rpc_conformance` (U3)
/// exercises, already built — factored out of that test so a SECOND test
/// can configure `watch_descriptors` before `assert_chain_contract` runs
/// against an otherwise-identical transport, proving the two paths are
/// observationally identical (plan §3 step, U4 test 1). Each caller gets
/// its OWN connection and its OWN uniquely-named throwaway signing wallet
/// (guarded by `_sender_guard`, which sweeps it back to `testwallet` on
/// `Drop` — success OR failure) — cargo runs this binary's tests in
/// parallel threads of the SAME process, so two independent fixtures
/// built at once must never share a wallet name.
struct ConformanceFixture {
    node: Node,
    scenario: Scenario,
    network: Network,
    /// RAII cleanup for the throwaway signing wallet this fixture
    /// created. Held for the fixture's WHOLE lifetime (not just unloaded
    /// at the bottom of a test function) so it still fires if
    /// `assert_chain_contract` itself panics — see `WalletGuard`'s doc
    /// comment.
    _sender_guard: WalletGuard,
    /// The account-0 notebook's `tr(...)` multipath descriptor — the exact
    /// string `export_formats` produces for a real caller.
    notebook_descriptor: String,
    /// The account-0 spending wallet's `wpkh(...)` multipath descriptor —
    /// the exact string `spending::funding_descriptor` produces.
    spending_descriptor: String,
}

fn build_conformance_fixture() -> ConformanceFixture {
    let node = connect_node();
    wait_for_watch_wallet_idle(&node);

    // The throwaway signing wallet holds every test address's private key
    // (so it can sign the spend-with-change / OP_RETURN-note / broadcast-
    // probe legs). The watch-only "chain-notes-watch" wallet is created
    // LAZILY by the CoreRpcTransport under test, never here. Guarded from
    // this point on — a panic anywhere below (fixture building OR the
    // caller's own `assert_chain_contract` run) still sweeps it back to
    // `testwallet`.
    let sender = unique_wallet_name("sender");
    node.rpc(None, "createwallet", serde_json::json!([sender]));
    let sender_guard = WalletGuard::new(&node, sender.clone());

    let addr_a = node.fresh_addr(&sender);
    let addr_note = node.fresh_addr(&sender);
    let mempool_funder = node.fresh_addr(&sender);
    let addr_probe_src = node.fresh_addr(&sender);
    let addr_pager = node.fresh_addr(&sender);
    let ext_recipient = node.fresh_addr(&sender);
    // Confirm-mining target and the broadcast-probe's own destination —
    // a FRESH `testwallet` address (never a throwaway sink this suite
    // would otherwise strand): every coinbase reward this fixture mines
    // is a pure settle/confirm step, never a funding one, so it belongs
    // to the node owner, not to an address nothing will ever sweep.
    let testwallet_confirm_addr = node.fresh_addr("testwallet");

    let network = Network::Regtest;
    let material = parse_key_material(TEST_MNEMONIC, network).expect("valid mnemonic");
    let account = random_account();
    let gap = 3u32;
    let used_receive = vec![0u32, 2u32]; // a hole at index 1
    let used_change = vec![0u32];
    let used_spending_receive = vec![0u32, 1u32];
    let used_spending_change = vec![0u32];

    let addr_recv0 = realize(&material, network, account, 0).unwrap().address;
    let addr_recv2 = realize(&material, network, account, 2).unwrap().address;
    let addr_chg0 = realize_change(&material, network, account, 0).unwrap().address;
    let spending_src = spending::funding_source(&material, network, account).unwrap();
    let addr_sprecv0 = spending_src.derive(0, 0).unwrap().address;
    let addr_sprecv1 = spending_src.derive(0, 1).unwrap().address;
    let addr_spchg0 = spending_src.derive(1, 0).unwrap().address;

    let mut txids: Vec<String> = Vec::new();
    // Every txid whose RECORDED `vin` must be forced empty — see
    // `Faucet`'s doc comment ("Why one hop, never testwallet directly").
    // Populated only by faucet-funded legs; the addr_note/mempool_funder
    // spends below keep their REAL vin (it correctly references another
    // TRACKED test address, not the faucet).
    let mut hide_vin: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    // ---- Phase 1: one faucet coin straight to each single-use address
    // (the funding-source isolation the module doc explains), plus 30 on
    // addr_pager (>25-tx pagination) — all drawn from the SAME `Faucet`
    // (`testwallet` -> 40 one-shot addresses -> these 40 test addresses),
    // replacing the old direct-coinbase funding + 100-block maturity
    // padding: a faucet coin is an ordinary spend, never a coinbase, so it
    // needs no maturity wait at all. ----
    let faucet_main_addrs = [
        &addr_a,
        &addr_note,
        &mempool_funder,
        &addr_probe_src,
        &addr_recv0,
        &addr_recv2,
        &addr_chg0,
        &addr_sprecv0,
        &addr_sprecv1,
        &addr_spchg0,
    ];
    let pager_n = 30usize;
    let faucet = Faucet::new(&node, faucet_main_addrs.len() + pager_n);
    for (i, addr) in faucet_main_addrs.iter().enumerate() {
        let txid = faucet.fund(i, addr);
        hide_vin.insert(txid.clone());
        txids.push(txid);
    }
    for i in 0..pager_n {
        let txid = faucet.fund(faucet_main_addrs.len() + i, &addr_pager);
        hide_vin.insert(txid.clone());
        txids.push(txid);
    }
    node.generate(1, &testwallet_confirm_addr);

    // ---- Phase 2: addr_note spend-with-change — input = its funding
    // coin, one paying output to a fresh one-shot address, change back to
    // addr_note itself (verified live pattern: explicit `inputs` +
    // `change_address`). ----
    let (note_txid0, note_vout0, note_amount0) = node.sole_utxo(&sender, &addr_note);
    let pay_amount = note_amount0 / 2;
    let spend_result = node.rpc(
        Some(&sender),
        "send",
        serde_json::json!([
            [pay_output(&ext_recipient, pay_amount)],
            serde_json::Value::Null,
            "unset",
            5,
            {"inputs": [{"txid": note_txid0, "vout": note_vout0}], "change_address": addr_note},
        ]),
    );
    txids.push(spend_result["txid"].as_str().expect("send: no txid").to_string());
    node.generate(1, &testwallet_confirm_addr);

    // ---- Phase 3: addr_note's self-authored OP_RETURN note — spends the
    // change coin from phase 2, an OP_RETURN-only output list with NO
    // separate paying output means the ENTIRE remainder becomes change
    // back to addr_note (verified live: exactly 2 outputs result). ----
    let (note_txid1, note_vout1, _) = node.sole_utxo(&sender, &addr_note);
    let note_result = node.rpc(
        Some(&sender),
        "send",
        serde_json::json!([
            [data_output(b"hello from the core-rpc conformance suite")],
            serde_json::Value::Null,
            "unset",
            5,
            {"inputs": [{"txid": note_txid1, "vout": note_vout1}], "change_address": addr_note},
        ]),
    );
    txids.push(note_result["txid"].as_str().expect("send: no txid").to_string());
    node.generate(1, &testwallet_confirm_addr);

    // ---- Phase 4 (Trap 1): the genuinely SIGNED broadcast-probe tx.
    // `add_to_wallet: false` returns signed hex WITHOUT touching the
    // wallet or the mempool — the transport-under-test's `broadcast()`
    // call is this tx's very first appearance on the node. Deliberately
    // NOT pushed into `txids` — it's asserted only via
    // `Scenario::broadcast_probe`. Pays back to a fresh testwallet
    // address (never a stranded sink) once actually broadcast. ----
    let (probe_in_txid, probe_in_vout, probe_in_amount) = node.sole_utxo(&sender, &addr_probe_src);
    let probe_result = node.rpc(
        Some(&sender),
        "send",
        serde_json::json!([
            [pay_output(&testwallet_confirm_addr, probe_in_amount)],
            serde_json::Value::Null,
            "unset",
            5,
            {
                "inputs": [{"txid": probe_in_txid, "vout": probe_in_vout}],
                "subtract_fee_from_outputs": [0],
                "add_to_wallet": false,
            },
        ]),
    );
    let probe_hex = probe_result["hex"].as_str().expect("send: no hex").to_string();
    let probe_txid = probe_result["txid"].as_str().expect("send: no txid").to_string();

    // ---- Phase 5 (LAST — must be the final chain mutation): addr_a's
    // second, genuinely UNCONFIRMED coin, relayed in FULL from
    // `mempool_funder` (whose own complete history is now exactly its two
    // recorded txs). Never mined — this is the scenario's mempool leg. ----
    let (mf_txid, mf_vout, mf_amount) = node.sole_utxo(&sender, &mempool_funder);
    let mempool_result = node.rpc(
        Some(&sender),
        "send",
        serde_json::json!([
            [pay_output(&addr_a, mf_amount)],
            serde_json::Value::Null,
            "unset",
            5,
            {"inputs": [{"txid": mf_txid, "vout": mf_vout}], "subtract_fee_from_outputs": [0]},
        ]),
    );
    txids.push(mempool_result["txid"].as_str().expect("send: no txid").to_string());

    let tip = node.tip_height();

    let scenario_txs: Vec<ScenarioTx> = txids
        .iter()
        .map(|t| {
            let mut st = build_scenario_tx(&node, t, tip);
            if hide_vin.contains(t) {
                st.vin.clear();
            }
            st
        })
        .collect();

    let notebook_descriptor = export_formats(TEST_MNEMONIC, network, account, 0)
        .expect("export_formats")
        .descriptor
        .expect("mnemonic yields a tr() descriptor");
    let notebook_watch =
        FundingSource::parse(&notebook_descriptor, network).expect("parse notebook watch descriptor");
    let spending_descriptor =
        spending::funding_descriptor(&material, network, account).expect("spending descriptor string");

    let wallet = ScenarioWallet {
        material,
        notebook_watch,
        spending: spending_src,
        account,
        gap,
        used_receive,
        used_change,
        used_spending_receive,
        used_spending_change,
    };

    let scenario = Scenario {
        network,
        tip_height: tip,
        txs: scenario_txs,
        wallet: Some(wallet),
        broadcast_probe: Some((probe_hex, probe_txid)),
    };

    // `faucet` is dropped here (end of scope) — by now every one of its
    // coins has been drained to exactly zero by `fund`'s
    // `subtract_fee_from_outputs`, so its own `Drop` sweep is expected to
    // no-op (rule 4: tolerate an uneconomical/empty sweep).
    ConformanceFixture { node, scenario, network, _sender_guard: sender_guard, notebook_descriptor, spending_descriptor }
}

#[test]
fn core_rpc_conformance() {
    let _guard = serialize_nodes();
    require_regtest("core_rpc_conformance", &node_env());

    let fx = build_conformance_fixture();
    let node = &fx.node;
    let scenario = &fx.scenario;
    let tip = scenario.tip_height;

    let t0 = Instant::now();
    let proxy =
        common::count_proxy::CountingProxy::start(node.env.host.clone(), node.env.port, node.env.user.clone(), node.env.pass.clone());
    let base = proxy.base_url();
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, fx.network);

    assert_chain_contract(&client, scenario);

    // Explicit, standalone demonstration of the plan's §2.1 requirement
    // (also exercised implicitly inside `assert_chain_contract`'s own
    // `tx_lookup_status` leg): a genuinely unknown txid on a synced,
    // txindex=1 node maps to NotFound, never Unknown.
    let unknown_txid = "ff".repeat(32);
    assert_eq!(client.tx_lookup_status(&unknown_txid), TxLookupStatus::NotFound, "unknown txid must be NotFound");

    // U4 preflight, exercised against this suite's own healthy (synced,
    // txindex=1, unpruned) node as the positive-case companion to the
    // dedicated pruned/no-txindex tests below. `transport` is already
    // moved into `client` by now, so this opens a SECOND connection to the
    // SAME already-running node — `preflight` is Core-specific (not part
    // of the `Transport` trait), harmless to call from a fresh instance.
    match AnyTransport::new(&base, None).expect("construct a second Core RPC transport for preflight") {
        AnyTransport::Core(core) => {
            let status = core.preflight().expect("preflight");
            assert!(!status.pruned, "the shared node is never pruned");
            assert!(status.txindex, "the shared node runs with txindex=1");
            // NEVER an exact tip-height equality (PLAN-one-regtest-node.md)
            // — `tip` was captured back when the fixture finished building,
            // and everything `assert_chain_contract` just did in between
            // gave the shared node's automine plenty of wall-clock time to
            // mine another block underneath this test. Only forward
            // movement is a bug (a block cannot un-mine itself).
            assert!(
                status.tip_height >= tip,
                "preflight tip_height must be >= the fixture's own recorded tip (a shared node only \
                 ever advances): preflight={}, fixture={tip}",
                status.tip_height
            );
            // The watch wallet DOES exist by now (every route above
            // touched it), so scanning info must be reportable, not absent.
            assert!(status.wallet_scanning.is_some(), "watch wallet exists — scanning info must be Some");
        }
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    }

    // `fx`'s `_sender_guard` sweeps the throwaway signing wallet back to
    // testwallet on Drop (end of this function, success OR panic) — no
    // explicit unload call needed here anymore.
    report_timing("core_rpc_conformance", t0, &proxy);
    eprintln!("core_rpc_conformance: PASS ({} scenario txs, tip={tip})", scenario.txs.len());
}

/// U4 test 1 (`../../PLAN-chain-notes-app-core-rpc.md` §3 step, "Ranged
/// import works"): the SAME 43-tx scenario `core_rpc_conformance` builds,
/// this time with the notebook's `tr(...)` chain and the spending wallet's
/// `wpkh(...)` chain configured as RANGED descriptor families
/// (`CoreRpcTransport::watch_descriptors`) BEFORE `assert_chain_contract`
/// runs — every address `assert_chain_contract`'s wallet legs touch
/// (receive/change/spending-receive/spending-change, all account 0) is
/// covered by one of these two families, so this run never falls back to
/// the U3 per-address `addr()` path for them (the ad-hoc scenario
/// addresses — `addr_a`, `addr_note`, the pager, the probe/mempool
/// legs — belong to neither family and still go through that fallback,
/// exactly as before). A PASS here is the "observationally identical"
/// requirement: nothing about what the client sees may differ by backend
/// wiring choice.
#[test]
fn core_rpc_conformance_ranged_descriptors() {
    let _guard = serialize_nodes();
    require_regtest("core_rpc_conformance_ranged_descriptors", &node_env());

    let fx = build_conformance_fixture();
    let node = &fx.node;

    let t0 = Instant::now();
    let proxy =
        common::count_proxy::CountingProxy::start(node.env.host.clone(), node.env.port, node.env.user.clone(), node.env.pass.clone());
    let base = proxy.base_url();
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    match &transport {
        AnyTransport::Core(core) => core
            .watch_descriptors(vec![
                WatchDescriptor {
                    descriptor: fx.notebook_descriptor.clone(),
                    network: fx.network,
                    timestamp: 0,
                    range_end: 10,
                },
                WatchDescriptor {
                    descriptor: fx.spending_descriptor.clone(),
                    network: fx.network,
                    timestamp: 0,
                    range_end: 10,
                },
            ])
            .expect("configure ranged descriptors"),
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    }

    let client = ChainClient::new(transport, fx.network);
    assert_chain_contract(&client, &fx.scenario);

    // Prove the MECHANISM, not just the result — a mutation that forces
    // `ranged_lookup_or_widen` to always return `Ok(false)` (disabling
    // the ranged path entirely) still passes the `assert_chain_contract`
    // run above via the U3 per-address fallback, which produces an
    // identical answer. That is caught here instead.
    let descriptors = watch_wallet_descriptors(node);
    let notebook_xpub = xpub_of(&fx.notebook_descriptor);
    let spending_xpub = xpub_of(&fx.spending_descriptor);
    // bitcoind splits a `<0;1>` multipath import into two SEPARATE
    // single-path `listdescriptors` entries — verified live — so this
    // checks for both chains individually by xpub + type + chain suffix,
    // never an exact string match against the original multipath text.
    let has_ranged_chain = |xpub: &str, prefix: &str, chain_suffix: &str| {
        descriptors
            .iter()
            .any(|(d, end)| d.starts_with(prefix) && d.contains(xpub) && d.ends_with(chain_suffix) && *end >= 10)
    };
    assert!(
        has_ranged_chain(notebook_xpub, "tr(", "/0/*)") && has_ranged_chain(notebook_xpub, "tr(", "/1/*)"),
        "expected the notebook's ranged tr() descriptor imported on BOTH chains with range >= 10 — got {descriptors:?}"
    );
    assert!(
        has_ranged_chain(spending_xpub, "wpkh(", "/0/*)") && has_ranged_chain(spending_xpub, "wpkh(", "/1/*)"),
        "expected the spending wallet's ranged wpkh() descriptor imported on BOTH chains with range >= 10 — got {descriptors:?}"
    );
    // None of the specific addresses covered by those two ranged families
    // may ALSO have been imported as their own `addr(...)` descriptor —
    // that would mean the per-address fallback did the work instead.
    // (The scenario's ad-hoc addresses — addr_a, addr_note, the pager,
    // the probe/mempool legs — belong to neither family and legitimately
    // DO show up as `addr(...)` entries; this only asserts about the
    // notebook/spending-derived ones.)
    let wallet = fx.scenario.wallet.as_ref().expect("scenario carries a wallet");
    let ranged_addrs = [
        wallet.notebook_watch.derive(0, 0).unwrap().address,
        wallet.notebook_watch.derive(0, 2).unwrap().address,
        wallet.notebook_watch.derive(1, 0).unwrap().address,
        wallet.spending.derive(0, 0).unwrap().address,
        wallet.spending.derive(0, 1).unwrap().address,
        wallet.spending.derive(1, 0).unwrap().address,
    ];
    let addr_imports = addr_import_addresses(node);
    for a in &ranged_addrs {
        assert!(
            !addr_imports.contains(a),
            "{a} belongs to a configured ranged family — it must NEVER be individually \
             imported as its own addr() descriptor (found addr() imports: {addr_imports:?})"
        );
    }

    // `fx`'s `_sender_guard` sweeps the throwaway signing wallet back to
    // testwallet on Drop — no explicit unload call needed here anymore.
    report_timing("core_rpc_conformance_ranged_descriptors", t0, &proxy);
    eprintln!(
        "core_rpc_conformance_ranged_descriptors: PASS ({} scenario txs, tip={}, {} watch-wallet \
         descriptors, 0 addr() imports among the {} ranged-covered addresses)",
        fx.scenario.txs.len(),
        fx.scenario.tip_height,
        descriptors.len(),
        ranged_addrs.len(),
    );
}

/// U4 test 2 ("Range widening"): a notebook receive-chain address well
/// PAST a descriptor's configured `range_end` still gets found — the
/// transport widens (re-imports the SAME descriptor with a bigger range,
/// `CoreRpcTransport::ranged_lookup_or_widen`) instead of ever falling back
/// to the U3 per-address `addr()` path for an address that genuinely
/// belongs to a configured family.
#[test]
fn core_rpc_range_widening_finds_address_beyond_initial_range() {
    let _guard = serialize_nodes();
    require_regtest("core_rpc_range_widening_finds_address_beyond_initial_range", &node_env());

    let node = connect_node();
    wait_for_watch_wallet_idle(&node);

    let network = Network::Regtest;
    let material = parse_key_material(TEST_MNEMONIC, network).expect("valid mnemonic");
    let account = random_account();

    let descriptor = export_formats(TEST_MNEMONIC, network, account, 0)
        .expect("export_formats")
        .descriptor
        .expect("mnemonic yields a tr() descriptor");
    // `far_index` is on the RECEIVE chain (chain 0) — bitcoind splits the
    // `<0;1>` multipath import into two separate `listdescriptors`
    // entries, so this looks up the chain-0 one specifically (by xpub +
    // type + "/0/*)" suffix, never an exact string match against the
    // original multipath text — see `xpub_of`'s doc comment).
    let descriptor_xpub = xpub_of(&descriptor).to_string();
    let find_receive_chain_end = |descs: &[(String, u32)]| -> Option<u32> {
        descs
            .iter()
            .find(|(d, _)| d.starts_with("tr(") && d.contains(&descriptor_xpub) && d.ends_with("/0/*)"))
            .map(|(_, end)| *end)
    };
    // Configured range only covers 0..=900 — bitcoind pads any requested
    // span under 1000 indices up to a minimum of 999 (verified live), so
    // the range this ACTUALLY imports at is [0, 999]. `far_index` is
    // chosen past THAT padded ceiling too (not just past 900) so a
    // widened re-import is observable as a genuine, unambiguous GROWTH in
    // `listdescriptors`' reported range — not masked by bitcoind's own
    // padding — while staying comfortably inside `CoreRpcTransport`'s
    // widen search ceiling (`WIDEN_CHUNK * MAX_WIDEN_CHUNKS` = 1000
    // indices beyond this transport's OWN `imported_end` bookkeeping,
    // which tracks the REQUESTED 900, not bitcoind's padded 999).
    let far_index = 1050u32;
    let addr_far = realize(&material, network, account, far_index).unwrap().address;

    // No Scenario/all_addresses() tracking happens in this test (it only
    // ever calls `client.address_stats` directly), so there's nothing to
    // hide here — a one-address Faucet funds+confirms addr_far in a
    // single hop; its wallet (guaranteed empty afterward — `fund` drains
    // it to zero) is swept on Drop at the end of this function.
    let faucet = Faucet::new(&node, 1);
    let funding_txid = faucet.fund(0, &addr_far);
    node.generate(1, &node.fresh_addr("testwallet"));
    let tip = node.tip_height();

    let t0 = Instant::now();
    let proxy =
        common::count_proxy::CountingProxy::start(node.env.host.clone(), node.env.port, node.env.user.clone(), node.env.pass.clone());
    let base = proxy.base_url();
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    match &transport {
        AnyTransport::Core(core) => core
            .watch_descriptors(vec![WatchDescriptor {
                descriptor: descriptor.clone(),
                network,
                timestamp: 0,
                range_end: 900,
            }])
            .expect("configure ranged descriptor"),
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    }

    let range_before = find_receive_chain_end(&watch_wallet_descriptors(&node))
        .expect("the notebook descriptor must already be imported before any address is queried");

    let client = ChainClient::new(transport, network);
    // The whole point: BEFORE any widening this address is outside the
    // imported range, yet the client still finds its coin — proving the
    // transport widened internally on the cache miss rather than reporting
    // a genuinely-owned address as unused.
    let stats = client.address_stats(&addr_far).expect("address_stats");
    assert_eq!(
        stats.chain_tx_count, 1,
        "the far-index ({far_index}) coinbase (txid {funding_txid}) must be found after widening"
    );

    // Prove the MECHANISM, not just the result — a mutation that forces
    // `ranged_lookup_or_widen` to always return `Ok(false)` still finds
    // this coin (via the U3 per-address `addr()` fallback), which would
    // make the `chain_tx_count == 1` assertion above pass for the WRONG
    // reason. Two independent, bitcoind-observable signals catch that:
    // the descriptor's imported range must have genuinely grown, and
    // `addr_far` must never have been imported as its own descriptor.
    let after = watch_wallet_descriptors(&node);
    let range_after = find_receive_chain_end(&after);
    assert!(
        range_after.is_some_and(|end| end > range_before),
        "widening must have grown the descriptor's imported range on bitcoind \
         (before={range_before}, after={range_after:?}, all descriptors={after:?})"
    );
    let addr_imports = addr_import_addresses(&node);
    assert!(
        !addr_imports.contains(&addr_far),
        "addr_far ({addr_far}) must be covered by the WIDENED ranged descriptor, \
         not imported as its own addr() descriptor (found: {addr_imports:?})"
    );

    report_timing("core_rpc_range_widening_finds_address_beyond_initial_range", t0, &proxy);
    eprintln!(
        "core_rpc_range_widening_finds_address_beyond_initial_range: PASS \
         (index={far_index}, tip={tip}, range {range_before} -> {range_after:?})"
    );
}

/// U7 test ("wiring reachability" —
/// `../../PLAN-chain-notes-app-core-rpc.md` §2.2's "ranged descriptor
/// import" finally gets a production caller). Every ranged-descriptor test
/// ABOVE this one calls `CoreRpcTransport::watch_descriptors` DIRECTLY —
/// which is exactly why the bug this unit fixes shipped in the first
/// place: `grep -rn watch_descriptors src/ app-core/ examples/` found only
/// this crate's own tests, never a production call site, so the app always
/// paid for one genesis-rescan `importdescriptors` PER ADDRESS instead of
/// one per descriptor family. A test that configures `watch_descriptors`
/// itself can never catch a regression where the WIRING (not the mechanism)
/// breaks again.
///
/// This test instead drives the actual PRODUCTION entry point: builds and
/// runs `examples/cli.rs` as a REAL SUBPROCESS (the same binary
/// `scripts/regtest-e2e.sh` drives — `../../CLAUDE.md`'s "examples/cli.rs
/// stdout is DATA" rule applies here too, so this only ever reads stdout
/// for the documented `cli: scan …` line and treats stderr as diagnostics),
/// calling `scan` — the CLI's mirror of `src/lib.rs`'s `refresh`/
/// `refresh_async`, both of which now go through `open_client_watched`
/// (`src/lib.rs`) / `open_client_watched` (`examples/cli.rs`) instead of
/// plain `open_client`. No test code here ever calls `watch_descriptors`
/// — if either production wiring point is reverted to plain `open_client`,
/// this test fails: `listdescriptors` would show these addresses individually
/// imported as `addr(...)` entries instead of covered by a ranged family.
///
/// Two SEPARATE subprocess invocations (`scan` for notebook index 0, then
/// index 2 — a different address of the SAME family, mirroring
/// `build_conformance_fixture`'s `used_receive = [0, 2]` gap) prove the
/// O(families)-not-O(addresses) shape end to end: each process computes its
/// OWN fresh `identity_watch_descriptors`/`watch_descriptors` call (no
/// cross-process cache is possible, or intended — see `open_client_watched`'s
/// doc comment in both `src/lib.rs` and `examples/cli.rs`), yet the SECOND
/// invocation's node-truth idempotence check
/// (`CoreRpcTransport::ranged_family_imported_end`, this unit's
/// `listdescriptors`-based counterpart to the U6 per-address
/// `getaddressinfo` check) means the watch wallet ends up with the SAME two
/// `listdescriptors` entries after both runs as after the first — not four,
/// and never a growing `addr(...)` entry per address scanned.
///
/// **Env passing note**: the shared node's real `CORE_RPC_USER`/
/// `CORE_RPC_PASS` end up embedded in the `bitcoind+http://user:pass@…`
/// argument handed to the `cli` subprocess (same calling convention
/// `scripts/regtest-e2e.sh --core-rpc` already uses) — that argument is
/// visible via `ps` to other LOCAL users on this machine for the
/// subprocess's lifetime. That was harmless when the credentials were
/// per-run throwaway values; it is a real, if minor, local exposure now
/// that they are the shared node's real credentials. `examples/cli.rs`
/// would need to grow env-var credential support to close this — noted as
/// a production-code follow-up, not fixed here (out of this unit's file
/// scope).
#[test]
fn core_rpc_cli_scan_wires_ranged_watch_descriptors() {
    let _guard = serialize_nodes();
    require_regtest("core_rpc_cli_scan_wires_ranged_watch_descriptors", &node_env());

    let node = connect_node();
    wait_for_watch_wallet_idle(&node);

    let network = Network::Regtest;
    let material = parse_key_material(TEST_MNEMONIC, network).expect("valid mnemonic");
    let account = random_account();

    // Fund two of the notebook's own receive addresses (indexes 0 and 2 —
    // a hole at 1, same shape `build_conformance_fixture` uses elsewhere in
    // this file) — both well within `RANGED_WATCH_INITIAL_RANGE_END`, so a
    // correctly-wired `scan` finds them via the ranged path without ever
    // widening.
    let addr0 = realize(&material, network, account, 0).unwrap().address;
    let addr2 = realize(&material, network, account, 2).unwrap().address;
    // Faucet-funded (`testwallet` -> 2 one-shot addresses -> addr0/addr2),
    // never coinbase — so unlike the old direct-coinbase version of this
    // test, NO maturity-wait padding is needed at all: a faucet coin is an
    // ordinary confirmed spend, immediately spendable and immediately
    // visible in `listunspent` the moment it's mined. This test never
    // builds a Scenario (only reads CLI stdout / listdescriptors), so no
    // vin-hiding is needed either. The faucet's own (guaranteed-empty)
    // wallet sweeps itself on Drop at the end of this function.
    let faucet = Faucet::new(&node, 2);
    faucet.fund(0, &addr0);
    faucet.fund(1, &addr2);
    node.generate(1, &node.fresh_addr("testwallet"));

    let t0 = Instant::now();
    let proxy =
        common::count_proxy::CountingProxy::start(node.env.host.clone(), node.env.port, node.env.user.clone(), node.env.pass.clone());
    let base = proxy.base_url();

    // Build the SAME `examples/cli.rs` binary the e2e scripts drive —
    // `scripts/regtest-e2e.sh`'s own recipe (`cargo build -q -p app-core
    // --example cli`, run from the repo root, one level up from
    // `CARGO_MANIFEST_DIR` = `app-core/`).
    let repo_root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("app-core has a parent dir");
    let build = Command::new(env!("CARGO"))
        .args(["build", "-q", "-p", "app-core", "--example", "cli"])
        .current_dir(repo_root)
        .status()
        .expect("run cargo build --example cli");
    assert!(build.success(), "cargo build -p app-core --example cli failed");
    let cli_bin = repo_root.join("target/debug/examples/cli");
    assert!(cli_bin.exists(), "expected the built cli binary at {cli_bin:?}");

    let store_path =
        std::env::temp_dir().join(format!("chain-notes-cli-scan-wiring-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&store_path);

    let run_cli = |args: &[&str], app_index: u32| -> std::process::Output {
        Command::new(&cli_bin)
            .args(args)
            .env("APP_KEY", TEST_MNEMONIC)
            .env("APP_ACCOUNT", account.to_string())
            .env("APP_INDEX", app_index.to_string())
            .output()
            .expect("run cli subprocess")
    };

    let init = run_cli(&["init", store_path.to_str().unwrap(), "regtest"], 0);
    assert!(init.status.success(), "cli init failed: {}", String::from_utf8_lossy(&init.stderr));

    // First `scan` — notebook index 0 (a fresh subprocess: no in-process
    // cache from `init` carries over).
    let scan0 = run_cli(&["scan", store_path.to_str().unwrap(), &base], 0);
    assert!(scan0.status.success(), "cli scan (index 0) failed: {}", String::from_utf8_lossy(&scan0.stderr));
    let scan0_stdout = String::from_utf8_lossy(&scan0.stdout);
    // The coinbase reward's exact sat figure isn't the point of this test
    // (that's what `core_rpc_conformance`'s scenario battery already
    // covers byte-for-byte) — just that the scan found SOME balance,
    // proving addr0's coinbase was genuinely seen (not silently missed by
    // a broken watch configuration reporting an empty, always-"success"
    // scan).
    assert!(
        !scan0_stdout.contains("balance=0 "),
        "expected the index-0 coinbase to be found via `cli: scan …`, got: {scan0_stdout}"
    );

    let after_first = watch_wallet_descriptors(&node);
    let notebook_descriptor = export_formats(TEST_MNEMONIC, network, account, 0)
        .expect("export_formats")
        .descriptor
        .expect("mnemonic yields a tr() descriptor");
    let spending_descriptor =
        spending::funding_descriptor(&material, network, account).expect("spending descriptor string");
    let notebook_xpub = xpub_of(&notebook_descriptor);
    let spending_xpub = xpub_of(&spending_descriptor);
    let has_ranged_chain = |descs: &[(String, u32)], xpub: &str, prefix: &str, chain_suffix: &str| {
        descs.iter().any(|(d, end)| {
            d.starts_with(prefix) && d.contains(xpub) && d.ends_with(chain_suffix) && *end >= 19
        })
    };
    assert!(
        has_ranged_chain(&after_first, notebook_xpub, "tr(", "/0/*)")
            && has_ranged_chain(&after_first, notebook_xpub, "tr(", "/1/*)"),
        "cli scan must configure the notebook's ranged tr() descriptor on BOTH chains — got {after_first:?}"
    );
    // The wiring covers the spending wallet too (`identity_watch_descriptors`
    // returns both families for hierarchical material) even though this
    // scan never looked up a spending address — proving the DERIVATION
    // side (not just "some ranged descriptor exists").
    assert!(
        has_ranged_chain(&after_first, spending_xpub, "wpkh(", "/0/*)")
            && has_ranged_chain(&after_first, spending_xpub, "wpkh(", "/1/*)"),
        "cli scan must ALSO configure the spending wallet's ranged wpkh() descriptor — got {after_first:?}"
    );
    let addr_imports_after_first = addr_import_addresses(&node);
    assert!(
        !addr_imports_after_first.contains(&addr0),
        "addr0 ({addr0}) belongs to the configured ranged family — it must never be individually \
         imported as its own addr() descriptor (found: {addr_imports_after_first:?})"
    );

    // Second `scan` — notebook index 2, a DIFFERENT address of the SAME
    // family, ANOTHER fresh subprocess (no cross-process cache).
    let scan2 = run_cli(&["scan", store_path.to_str().unwrap(), &base], 2);
    let _ = scan2; // index-2's own store isn't asserted on; the node side is what matters
    let after_second = watch_wallet_descriptors(&node);
    let addr_imports_after_second = addr_import_addresses(&node);
    assert!(
        !addr_imports_after_second.contains(&addr2),
        "addr2 ({addr2}) belongs to the configured ranged family — it must never be individually \
         imported as its own addr() descriptor (found: {addr_imports_after_second:?})"
    );
    // O(families), not O(addresses)/O(subprocess invocations): the SAME
    // descriptor entries the FIRST scan produced, byte-for-byte — not a
    // second (duplicate or wider) pair from the second subprocess's own
    // fresh `watch_descriptors` call, and no growth in the TOTAL count of
    // watch-wallet descriptors despite a second address (and a second,
    // fully independent process) now covered.
    assert_eq!(
        after_second, after_first,
        "a second `scan` (different address, fresh subprocess, same family) must find the family \
         ALREADY covered via listdescriptors idempotence — not re-import or grow it \
         (before={after_first:?}, after={after_second:?})"
    );

    // `faucet`'s Drop sweeps its (already-empty) wallet at the end of this
    // function — no `pad_wallet` exists anymore to unload.
    report_timing("core_rpc_cli_scan_wires_ranged_watch_descriptors", t0, &proxy);
    eprintln!(
        "core_rpc_cli_scan_wires_ranged_watch_descriptors: PASS (2 subprocess `cli scan` runs, \
         {} watch-wallet descriptors stable across both, 0 addr() imports for addr0/addr2)",
        after_first.len(),
    );
}

/// U4 test 3 ("Pruned node"), RESTRUCTURED for the "one regtest node"
/// migration (`PLAN-one-regtest-node.md`): the shared node is permanently
/// unpruned and not ours to restart with `-prune=550`, but what this test
/// actually verifies is `preflight()`'s INTERPRETATION of a
/// `getblockchaininfo` response — nothing about that needs a real pruned
/// node, only a controlled one. Driven against `common::mock_rpc`, a
/// local-only bitcoind-JSON-RPC-shaped stub (see its doc comment) scripted
/// with a synthetic `pruned: true, pruneheight: 550` body.
#[test]
fn core_rpc_preflight_reports_pruned_node() {
    let mock = common::mock_rpc::MockRpcServer::start();
    mock.set(
        "getblockchaininfo",
        common::mock_rpc::MockResponse::Ok(
            serde_json::json!({"pruned": true, "pruneheight": 550, "initialblockdownload": false, "blocks": 800}),
        ),
    );
    mock.set(
        "getindexinfo",
        common::mock_rpc::MockResponse::Ok(serde_json::json!({"txindex": {"synced": true, "best_block_height": 800}})),
    );
    mock.set(
        "getwalletinfo",
        common::mock_rpc::MockResponse::Err { code: -18, message: "Requested wallet does not exist or is not loaded".into() },
    );

    let transport = AnyTransport::new(&mock.base_url(), None).expect("construct Core RPC transport");
    let status = match &transport {
        AnyTransport::Core(core) => core.preflight().expect("preflight"),
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    };
    assert!(status.pruned, "a getblockchaininfo.pruned=true response must report pruned=true");
    assert_eq!(status.prune_height, Some(550), "pruneheight must be threaded through when pruned");

    eprintln!("core_rpc_preflight_reports_pruned_node: PASS (synthetic — status={status:?})");
}

/// U4 test 4 ("No txindex"), RESTRUCTURED the same way as the pruned test
/// above: a synthetic `getindexinfo` response carrying no `"txindex"` key
/// at all — real bitcoind's own shape for a node started without
/// `-txindex` — must report `txindex: false`.
#[test]
fn core_rpc_preflight_reports_missing_txindex() {
    let mock = common::mock_rpc::MockRpcServer::start();
    mock.set(
        "getblockchaininfo",
        common::mock_rpc::MockResponse::Ok(serde_json::json!({"pruned": false, "initialblockdownload": false, "blocks": 800})),
    );
    // No "txindex" key at all — bitcoind's real `getindexinfo` shape when
    // no index is enabled.
    mock.set("getindexinfo", common::mock_rpc::MockResponse::Ok(serde_json::json!({})));
    mock.set(
        "getwalletinfo",
        common::mock_rpc::MockResponse::Err { code: -18, message: "Requested wallet does not exist or is not loaded".into() },
    );

    let transport = AnyTransport::new(&mock.base_url(), None).expect("construct Core RPC transport");
    let status = match &transport {
        AnyTransport::Core(core) => core.preflight().expect("preflight"),
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    };
    assert!(!status.txindex, "an empty getindexinfo response (no txindex key) must report txindex=false");
    assert!(!status.pruned, "this synthetic node was never pruned");

    eprintln!("core_rpc_preflight_reports_missing_txindex: PASS (synthetic — status={status:?})");
}

/// U4 test 5 ("Birthday handling"), RESTRUCTURED per the coordinator's
/// review: the original version needed `setmocktime` to push the node's
/// clock hours ahead of "now" so a REAL block would clear bitcoind's
/// 2-hour rescan margin — global state on the shared, persistent node this
/// suite has no business touching. What the birthday plumbing actually
/// needs to prove is much narrower and needs no clock at all: that
/// `watch_descriptors` sends the CALLER'S OWN birthday on the wire to
/// `importdescriptors`, never silently substituting genesis (`timestamp:
/// 0`) for a known, non-zero value. Captured directly via
/// `common::mock_rpc::MockRpcServer::calls_for` — the exact request bitcoind
/// would receive, with no need for it to actually act on that timestamp.
#[test]
fn core_rpc_ranged_import_sends_the_caller_birthday_not_zero() {
    let mock = common::mock_rpc::MockRpcServer::start();
    mock.set("createwallet", common::mock_rpc::MockResponse::Ok(serde_json::json!({"name": "chain-notes-watch"})));
    // No descriptors configured yet on this fresh synthetic wallet —
    // `ranged_family_imported_end` must see nothing and fall through to a
    // real `import_ranged` call.
    mock.set("listdescriptors", common::mock_rpc::MockResponse::Ok(serde_json::json!({"descriptors": []})));
    mock.set(
        "getdescriptorinfo",
        common::mock_rpc::MockResponse::Ok(serde_json::json!({"checksum": "abcd1234"})),
    );
    mock.set("importdescriptors", common::mock_rpc::MockResponse::Ok(serde_json::json!([{"success": true}])));

    let network = Network::Regtest;
    let descriptor =
        export_formats(TEST_MNEMONIC, network, 0, 0).unwrap().descriptor.expect("tr() descriptor");
    // An arbitrary, deliberately non-round, non-zero unix timestamp —
    // chosen so it can't be confused with `0` by construction.
    let birthday: u64 = 1_700_000_000;

    let transport = AnyTransport::new(&mock.base_url(), None).expect("construct Core RPC transport");
    match &transport {
        AnyTransport::Core(core) => core
            .watch_descriptors(vec![WatchDescriptor { descriptor, network, timestamp: birthday, range_end: 2 }])
            .expect("configure ranged descriptor"),
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    }

    let sent = mock.calls_for("importdescriptors");
    assert_eq!(sent.len(), 1, "expected exactly one importdescriptors call, got {}: {sent:?}", sent.len());
    let items = sent[0][0].as_array().expect("importdescriptors params[0] must be an array of request objects");
    assert_eq!(items.len(), 1, "expected exactly one descriptor request in the batch: {items:?}");
    let ts = items[0].get("timestamp").and_then(|t| t.as_u64());
    assert_eq!(
        ts,
        Some(birthday),
        "the exact caller-supplied birthday must be sent on the wire to importdescriptors, \
         never silently substituted with 0/genesis — sent: {items:?}"
    );

    eprintln!("core_rpc_ranged_import_sends_the_caller_birthday_not_zero: PASS (birthday={birthday})");
}

/// U5 test 1 (plan §2.1, THE regression this unit exists to prevent), a
/// TABLE-DRIVEN battery over synthetic responses
/// (`common::mock_rpc::MockRpcServer`, RESTRUCTURED for the "one regtest
/// node" migration — the shared node always runs `txindex=1`, so the
/// negative cases below can no longer come from a real differently-
/// configured node, only from controlled inputs).
///
/// `TxLookupStatus::NotFound` may fire ONLY on POSITIVELY established
/// absence — txindex ∧ ¬IBD ∧ mempool-miss, from `established_absent`
/// (`app-core/src/chain.rs`) — because the RPC code for "genuinely doesn't
/// exist" (-5) is IDENTICAL to "this tx exists, confirmed, but I have no
/// way to look it up" on a node missing txindex, and to "haven't gotten
/// there yet" mid-IBD. Getting this wrong means the app declares a live,
/// on-chain transaction dropped — the single worst failure mode
/// `TxLookupStatus`'s own doc comment calls out, and a documented
/// invariant in this repo's CLAUDE.md.
fn synthetic_tx_lookup_status(
    txindex: bool,
    ibd: bool,
    mempool_present: bool,
    getrawtransaction: common::mock_rpc::MockResponse,
) -> TxLookupStatus {
    let mock = common::mock_rpc::MockRpcServer::start();
    mock.set("getblockcount", common::mock_rpc::MockResponse::Ok(serde_json::json!(800)));
    mock.set(
        "getblockchaininfo",
        common::mock_rpc::MockResponse::Ok(serde_json::json!({"pruned": false, "initialblockdownload": ibd, "blocks": 800})),
    );
    mock.set(
        "getindexinfo",
        common::mock_rpc::MockResponse::Ok(if txindex {
            serde_json::json!({"txindex": {"synced": true, "best_block_height": 800}})
        } else {
            serde_json::json!({})
        }),
    );
    mock.set(
        "getwalletinfo",
        common::mock_rpc::MockResponse::Err { code: -18, message: "Requested wallet does not exist or is not loaded".into() },
    );
    mock.set("getrawtransaction", getrawtransaction);
    mock.set(
        "getmempoolentry",
        if mempool_present {
            common::mock_rpc::MockResponse::Ok(serde_json::json!({"vsize": 200}))
        } else {
            common::mock_rpc::MockResponse::Err { code: -5, message: "Transaction not in mempool".into() }
        },
    );

    let transport = AnyTransport::new(&mock.base_url(), None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, Network::Regtest);
    client.tx_lookup_status(&"ff".repeat(32))
}

#[test]
fn core_rpc_notfound_requires_txindex_not_just_rpc_code_minus5() {
    let not_found = || common::mock_rpc::MockResponse::Err {
        code: -5,
        message: "No such mempool or blockchain transaction. Use gettransaction for wallet transactions.".into(),
    };

    // 1. Fully established absence: txindex present, not IBD, absent from
    //    the mempool too — THE positive case, must be NotFound.
    assert_eq!(
        synthetic_tx_lookup_status(true, false, false, not_found()),
        TxLookupStatus::NotFound,
        "txindex ∧ ¬IBD ∧ mempool-miss must be NotFound"
    );

    // 2. No txindex: the node genuinely cannot tell "gone" from "can't look
    //    up" — must NEVER read as NotFound. THE regression this test exists
    //    to prevent.
    assert_eq!(
        synthetic_tx_lookup_status(false, false, false, not_found()),
        TxLookupStatus::Unknown,
        "missing txindex must downgrade to Unknown, never NotFound"
    );

    // 3. In IBD: "not found yet" can just mean "haven't gotten there yet".
    assert_eq!(
        synthetic_tx_lookup_status(true, true, false, not_found()),
        TxLookupStatus::Unknown,
        "a node still in initial block download must downgrade to Unknown"
    );

    // 4. txindex present, not IBD, but the mempool check ITSELF says
    //    present — `established_absent`'s second, INDEPENDENT signal must
    //    be honored even though getrawtransaction alone said -5.
    assert_eq!(
        synthetic_tx_lookup_status(true, false, true, not_found()),
        TxLookupStatus::Unknown,
        "a mempool hit must block the NotFound verdict even when getrawtransaction itself returned -5"
    );

    // 5. A non-(-5) RPC error must never be read as absence either.
    assert_eq!(
        synthetic_tx_lookup_status(
            true,
            false,
            false,
            common::mock_rpc::MockResponse::Err { code: -1, message: "some other bitcoind error".into() }
        ),
        TxLookupStatus::Unknown,
        "a non-(-5) RPC error code must be Unknown, not NotFound"
    );

    // 6. Found, confirmed — the healthy positive case on the OTHER side of
    //    the table (getrawtransaction succeeds at all).
    assert_eq!(
        synthetic_tx_lookup_status(
            true,
            false,
            false,
            common::mock_rpc::MockResponse::Ok(serde_json::json!({"confirmations": 3}))
        ),
        TxLookupStatus::Found(true),
        "a genuinely confirmed tx must read Found(true)"
    );

    // 7. Found, still in the mempool (0/absent confirmations).
    assert_eq!(
        synthetic_tx_lookup_status(true, false, false, common::mock_rpc::MockResponse::Ok(serde_json::json!({}))),
        TxLookupStatus::Found(false),
        "a mempool (unconfirmed) tx must read Found(false)"
    );

    eprintln!("core_rpc_notfound_requires_txindex_not_just_rpc_code_minus5: PASS (synthetic table, 7 cases)");
}

/// Later unit (`PLAN-one-regtest-node.md`'s "Two things now grow without
/// bound" / the workspace CLAUDE.md's "Core has no per-address filter —
/// plan §2.2 flags the O(wallet) cost as a later-unit optimization"): a
/// `getrawtransaction`-result cache in `esplora_tx_json`
/// (`app_core::chain::TX_JSON_CACHE`, process-global, keyed by node +
/// txid) — proven with `common::mock_rpc` because the mechanism this test
/// verifies is exactly "did a SECOND call skip the RPC round trip", which
/// a mock's own `call_count` answers directly and deterministically,
/// unlike the real shared node (whose `getrawtransaction` count for a
/// fixed txid set can't be pinned to an exact number across runs).
///
/// This is the MUTATION test the cache's safety rule demands: caching a
/// transaction's `confirmed`/`status` shape is only safe once it can never
/// change again. The three-call sequence below is deliberately shaped to
/// catch BOTH wrong directions:
///
/// 1. First call — the tx is UNCONFIRMED. Must be a real RPC call (nothing
///    to hit yet), and the result must NOT be cached (a mutation that
///    cached unconditionally, on every result including pending ones,
///    would still pass call 1 by definition but fail call 2 below).
/// 2. Second call — the SAME txid has now CONFIRMED (the mock is
///    re-scripted between calls 1 and 2, simulating a block landing).
///    Must ALSO be a real RPC call (proving call 1's unconfirmed result
///    was genuinely never cached — a mutation that cached indiscriminately
///    would serve the STALE unconfirmed answer here, which is precisely
///    the "the app tells the user a live transaction was dropped" failure
///    mode this project treats as its worst) — the fresh confirmation
///    must be visible.
/// 3. Third call — same confirmed txid, mock left unchanged. Must be
///    served from cache: the `getrawtransaction` call count must NOT grow
///    a third time. A mutation that removed the cache entirely (or that
///    forgot to cache the confirmed branch) fails ONLY here, by regressing
///    the call count from 2 back up to 3 — this is the assertion that
///    proves the fix is doing anything at all, not just that it's safe.
#[test]
fn core_rpc_confirmed_tx_json_is_cached_but_a_pending_one_is_never_served_stale() {
    let mock = common::mock_rpc::MockRpcServer::start();
    let txid = "ab".repeat(32);
    let addr = "bcrt1pmockaddressfortxcachetest0000000000000000000000000000";

    mock.set("createwallet", common::mock_rpc::MockResponse::Ok(serde_json::json!({"name": "chain-notes-watch"})));
    mock.set("getaddressinfo", common::mock_rpc::MockResponse::Ok(serde_json::json!({"ismine": true})));
    mock.set("getblockcount", common::mock_rpc::MockResponse::Ok(serde_json::json!(800)));

    let vout = serde_json::json!([{
        "scriptPubKey": {"address": addr, "type": "witness_v1_taproot"},
        "value": 0.0001,
    }]);

    // Call 1: unconfirmed.
    mock.set(
        "listtransactions",
        common::mock_rpc::MockResponse::Ok(serde_json::json!([{"txid": txid, "confirmations": 0, "time": 1}])),
    );
    mock.set(
        "getrawtransaction",
        common::mock_rpc::MockResponse::Ok(serde_json::json!({"txid": txid, "confirmations": 0, "vin": [], "vout": vout})),
    );

    let transport = AnyTransport::new(&mock.base_url(), None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, Network::Regtest);

    let stats1 = client.address_stats(addr).expect("address_stats (unconfirmed)");
    assert_eq!(stats1.mempool_tx_count, 1, "the pending tx must be visible as mempool activity");
    assert_eq!(stats1.chain_tx_count, 0);
    assert_eq!(mock.call_count("getrawtransaction"), 1, "call 1 must be a genuine RPC round trip");

    // Call 2: the SAME txid has now confirmed — re-script both endpoints
    // the way a real node's answers would change once a block lands.
    mock.set(
        "listtransactions",
        common::mock_rpc::MockResponse::Ok(serde_json::json!([{"txid": txid, "confirmations": 6, "time": 1}])),
    );
    mock.set(
        "getrawtransaction",
        common::mock_rpc::MockResponse::Ok(serde_json::json!({"txid": txid, "confirmations": 6, "vin": [], "vout": vout})),
    );

    let stats2 = client.address_stats(addr).expect("address_stats (freshly confirmed)");
    assert_eq!(
        stats2.chain_tx_count, 1,
        "the fresh confirmation must be visible — a cache that served call 1's stale unconfirmed \
         result here would leave this at 0, exactly the 'live tx reads as dropped/pending forever' \
         failure this project treats as its worst"
    );
    assert_eq!(stats2.mempool_tx_count, 0);
    assert_eq!(
        mock.call_count("getrawtransaction"),
        2,
        "call 2 must ALSO be a genuine RPC round trip — proof call 1's unconfirmed result was never cached"
    );

    // Call 3: same confirmed txid, mock script unchanged — THIS is where
    // the cache must actually pay off.
    let stats3 = client.address_stats(addr).expect("address_stats (repeat, confirmed)");
    assert_eq!(stats3.chain_tx_count, 1);
    assert_eq!(stats3.mempool_tx_count, 0);
    assert_eq!(
        mock.call_count("getrawtransaction"),
        2,
        "call 3 must be served entirely from the confirmed-tx cache — a mutation that disabled \
         or bypassed TX_JSON_CACHE would regress this back to 3"
    );

    eprintln!(
        "core_rpc_confirmed_tx_json_is_cached_but_a_pending_one_is_never_served_stale: PASS \
         (3 address_stats calls, 2 real getrawtransaction round trips)"
    );
}

/// Companion to the cache test above: `app_core::chain::TX_JSON_CACHE_MAX_ENTRIES`
/// (exposed for tests via `core_rpc_tx_json_cache_max_entries`) is a HARD cap,
/// not a documented aspiration — an unbounded cache would trade the fixed
/// O(wallet-history) NETWORK cost this unit removes for an O(wallet-history)
/// MEMORY cost instead, on a platform (a phone) that can least afford it.
/// Drives ONE `address_stats` call against a synthetic wallet history of
/// `cap + 50` distinct, already-confirmed txids — comfortably past the
/// cap — and proves two things at once: the cache genuinely stops growing at
/// the documented ceiling (a mutation that dropped the `cache.len() <
/// TX_JSON_CACHE_MAX_ENTRIES` guard would let this regress unboundedly), and
/// the cap bounds MEMORY only, never correctness — every one of the `cap +
/// 50` txids must still be resolved via a real `getrawtransaction` call on
/// this first pass (nothing is silently skipped just because the cache is
/// full).
#[test]
fn core_rpc_tx_json_cache_is_bounded() {
    let mock = common::mock_rpc::MockRpcServer::start();
    let addr = "bcrt1pmockaddressforcachecaptest0000000000000000000000000000000";

    mock.set("createwallet", common::mock_rpc::MockResponse::Ok(serde_json::json!({"name": "chain-notes-watch"})));
    mock.set("getaddressinfo", common::mock_rpc::MockResponse::Ok(serde_json::json!({"ismine": true})));
    mock.set("getblockcount", common::mock_rpc::MockResponse::Ok(serde_json::json!(800)));
    // Every txid resolves to the SAME confirmed, empty-vin/vout body — the
    // mock scripts per METHOD, not per param, and content doesn't matter
    // here; only the DISTINCT txid strings (the cache key) do.
    mock.set(
        "getrawtransaction",
        common::mock_rpc::MockResponse::Ok(serde_json::json!({"confirmations": 6, "vin": [], "vout": []})),
    );

    let cap = app_core::chain::core_rpc_tx_json_cache_max_entries();
    let n = cap + 50;
    let entries: Vec<serde_json::Value> = (0..n)
        .map(|i| serde_json::json!({"txid": format!("{i:064x}"), "confirmations": 6, "time": 1}))
        .collect();
    mock.set("listtransactions", common::mock_rpc::MockResponse::Ok(serde_json::json!(entries)));

    let transport = AnyTransport::new(&mock.base_url(), None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, Network::Regtest);

    let before_len = app_core::chain::core_rpc_tx_json_cache_len();
    client.address_stats(addr).expect("address_stats over a large synthetic wallet history");
    let after_len = app_core::chain::core_rpc_tx_json_cache_len();

    assert!(
        after_len <= cap,
        "TX_JSON_CACHE must never exceed its documented cap of {cap} entries — landed at {after_len} \
         after offering {n} distinct confirmed txids"
    );
    assert!(
        after_len > before_len,
        "the cache must still have grown from this test's own activity (before={before_len}, after={after_len})"
    );
    assert_eq!(
        mock.call_count("getrawtransaction"),
        n,
        "the cap bounds MEMORY only — every one of the {n} distinct wallet-wide txids must still be \
         resolved via a real getrawtransaction call on this first pass, cap or no cap"
    );

    eprintln!(
        "core_rpc_tx_json_cache_is_bounded: PASS (cap={cap}, offered {n} distinct confirmed txids, \
         cache landed at {after_len} entries, before={before_len})"
    );
}

/// U5 test 2 (plan §2.1, "cache it; do not re-probe per call"): several
/// lookups of DIFFERENT unknown txids against the SAME transport instance
/// must trigger exactly ONE real `getblockchaininfo`/`getindexinfo` probe,
/// not one per lookup — proven via `CoreRpcTransport::preflight_probe_count`,
/// a counter incremented only by the raw uncached probe (per-INSTANCE, so
/// it starts at 0 for this test's own fresh transport regardless of what
/// any other test in this binary already did against the shared node).
/// A reviewer's mutation that made the absence check bypass the cache
/// would make this counter grow with every lookup instead of staying at 1.
#[test]
fn core_rpc_established_absence_caches_node_status_across_lookups() {
    let _guard = serialize_nodes();
    require_regtest("core_rpc_established_absence_caches_node_status_across_lookups", &node_env());

    let node = connect_node(); // txindex=1 (the shared node always is) — the positive case.
    wait_for_watch_wallet_idle(&node);
    let sender = unique_wallet_name("sender");
    node.rpc(None, "createwallet", serde_json::json!([sender]));
    let _sender_guard = WalletGuard::new(&node, sender.clone());
    let addr = node.fresh_addr(&sender);
    // Real (non-coinbase) chain activity funded from testwallet, not
    // mined — mining here is a pure settle/confirm step (1 block,
    // reward to a fresh testwallet address), never a funding one.
    node.rpc(Some("testwallet"), "sendtoaddress", serde_json::json!([addr, btc_str(FAUCET_FUND_SATS)]));
    node.generate(1, &node.fresh_addr("testwallet"));

    let t0 = Instant::now();
    let proxy =
        common::count_proxy::CountingProxy::start(node.env.host.clone(), node.env.port, node.env.user.clone(), node.env.pass.clone());
    let base = proxy.base_url();
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, Network::Regtest);

    for i in 0..5u8 {
        let txid = format!("{i:02x}{}", "ee".repeat(31));
        assert_eq!(
            client.tx_lookup_status(&txid),
            TxLookupStatus::NotFound,
            "each of these txids is genuinely unknown on this node"
        );
    }

    match &client.transport {
        AnyTransport::Core(core) => assert_eq!(
            core.preflight_probe_count(),
            1,
            "5 lookups must share ONE cached node-status probe, not re-probe per call"
        ),
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    }

    // `_sender_guard` sweeps `sender`'s balance back to testwallet on
    // Drop — no explicit unload call needed here anymore.
    report_timing("core_rpc_established_absence_caches_node_status_across_lookups", t0, &proxy);
    eprintln!("core_rpc_established_absence_caches_node_status_across_lookups: PASS");
}

/// U5 test 3 (plan §2.4, "the garbage-address silent-success path — make
/// it a decision, not an accident"): a syntactically invalid address reads
/// as "never used, no coins" — an explicit, documented decision (see
/// `CoreRpcTransport::ensure_address_watched`'s doc comment), not the
/// accident of a test fixture. This proves the decision is real and
/// stable against a live node: `getdescriptorinfo`/`listunspent` are never
/// handed the garbage string (which would itself error), and every
/// affected route answers with its empty shape instead of an `Error`.
///
/// Network-agnostic (no mining, no wallet, no fixture) — runs against
/// whatever network is configured, so no `require_regtest` guard.
#[test]
fn core_rpc_invalid_address_reads_as_never_used_not_error() {
    let _guard = serialize_nodes();
    let node = connect_node();
    wait_for_watch_wallet_idle(&node);
    let t0 = Instant::now();
    let proxy =
        common::count_proxy::CountingProxy::start(node.env.host.clone(), node.env.port, node.env.user.clone(), node.env.pass.clone());
    let base = proxy.base_url();
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, network_of(&node.env));

    let garbage = "not-a-real-bitcoin-address";
    let stats = client.address_stats(garbage).expect("address_stats must be Ok, not Err, for a garbage address");
    assert_eq!(stats.chain_tx_count, 0);
    assert_eq!(stats.mempool_tx_count, 0);
    let utxos = client.utxos(garbage).expect("utxos must be Ok, not Err, for a garbage address");
    assert!(utxos.is_empty());
    let history = client.full_history(garbage).expect("full_history must be Ok, not Err, for a garbage address");
    assert!(history.is_empty());

    report_timing("core_rpc_invalid_address_reads_as_never_used_not_error", t0, &proxy);
    eprintln!("core_rpc_invalid_address_reads_as_never_used_not_error: PASS");
}

/// U7: `/v1/fees/recommended` against the shared regtest node — the
/// "`estimatesmartfee` genuinely has nothing to estimate from" case the
/// plan calls out by name (a fresh regtest chain has coinbase-only blocks,
/// never a real fee market). On a FRESH local node that was always true;
/// on the shared, long-running Pi node it may or may not still be true
/// (cumulative fee-paying activity from every suite/person that has ever
/// used it could have given `estimatesmartfee` real data to work with) —
/// so this checks which case it's actually in and asserts accordingly,
/// rather than assuming: either way, `fee_rates()` must return sane,
/// correctly ORDERED tiers (fastest >= half_hour >= hour >= economy) whose
/// `minimum` reflects this node's OWN live `getmempoolinfo().mempoolminfee`
/// — that invariant holds regardless of whether the numbers came from the
/// fallback or from genuine fee-market data. The fallback-specific
/// "stays sane, nowhere near a spike rate" bound is only asserted in the
/// no-history case, since a real fee market's `fastest` estimate is
/// legitimately allowed to be whatever the mempool says.
#[test]
fn core_rpc_fee_route_falls_back_well_formed_on_a_node_with_no_fee_history() {
    let _guard = serialize_nodes();
    let node = connect_node();
    wait_for_watch_wallet_idle(&node);
    let t0 = Instant::now();
    let proxy =
        common::count_proxy::CountingProxy::start(node.env.host.clone(), node.env.port, node.env.user.clone(), node.env.pass.clone());
    let base = proxy.base_url();
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, network_of(&node.env));

    let estimate = node.rpc(None, "estimatesmartfee", serde_json::json!([1]));
    let has_real_estimate = estimate.get("feerate").is_some();

    let fees = client.fee_rates().expect("fee_rates");

    assert!(fees.fastest >= fees.half_hour, "fastest {} must be >= half_hour {}", fees.fastest, fees.half_hour);
    assert!(fees.half_hour >= fees.hour, "half_hour {} must be >= hour {}", fees.half_hour, fees.hour);
    assert!(fees.hour >= fees.economy, "hour {} must be >= economy {}", fees.hour, fees.economy);
    assert!(fees.economy >= 1.0, "economy fee must never be zero (or negative), got {}", fees.economy);

    // The node's own relay floor, read independently via `getmempoolinfo`
    // (never trusting this driver's own conversion helper — the whole
    // point is proving the ROUTE reads it from the live node).
    let mempool_info = node.rpc(None, "getmempoolinfo", serde_json::json!([]));
    let relay_min_btc_per_kvb =
        mempool_info.get("mempoolminfee").and_then(|v| v.as_f64()).expect("getmempoolinfo: no mempoolminfee");
    let relay_min_sat_vb = (relay_min_btc_per_kvb * 100_000.0).ceil().max(1.0);
    assert_eq!(
        fees.minimum, relay_min_sat_vb,
        "minimumFee must equal this node's own live relay minimum, not a hardcoded stand-in"
    );
    // Every tier must be AT LEAST the node's real relay floor — a composed
    // tx built at any tier's rate must never fall below what this node
    // will actually accept.
    assert!(fees.economy >= relay_min_sat_vb, "economy {} must be >= relay minimum {relay_min_sat_vb}", fees.economy);

    report_timing("core_rpc_fee_route_falls_back_well_formed_on_a_node_with_no_fee_history", t0, &proxy);
    if !has_real_estimate {
        assert!(
            fees.fastest < 1000.0,
            "fastest fallback must stay sane, nowhere near a real fee-spike rate: {}",
            fees.fastest
        );
        eprintln!(
            "core_rpc_fee_route_falls_back_well_formed_on_a_node_with_no_fee_history: PASS \
             (fees={fees:?}, relay_min_sat_vb={relay_min_sat_vb}, genuine no-fee-history fallback exercised)"
        );
    } else {
        eprintln!(
            "core_rpc_fee_route_falls_back_well_formed_on_a_node_with_no_fee_history: PASS \
             (fees={fees:?}, relay_min_sat_vb={relay_min_sat_vb}, shared node already had real fee \
             history — ordering/minimum-floor invariants checked, fallback-specific path not exercised \
             this run)"
        );
    }
}

/// `listdescriptors` on the transport-under-test's watch wallet, parsed
/// into (desc-without-checksum) -> raw `timestamp` — the ONE way to
/// observe, from OUTSIDE `CoreRpcTransport`, what timestamp an
/// `importdescriptors` call actually carried. bitcoind normalizes
/// `timestamp: 0` (genesis) to `1` internally (verified live against a
/// real testnet4 node, 2026-07-30: request 0, `listdescriptors` reports
/// back exactly `1`), while a real non-zero timestamp is echoed back
/// VERBATIM (same live check: request `now - 3600`, `listdescriptors`
/// reports back that exact value) — so `timestamp == 1` is a reliable,
/// live-verified signature of "this import genuinely requested a genesis
/// rescan", distinguishable from any real caller-supplied birthday.
fn watch_wallet_descriptor_timestamps(node: &Node) -> HashMap<String, u64> {
    let v = node.rpc(Some(&watch_wallet()), "listdescriptors", serde_json::json!([]));
    v["descriptors"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|d| {
            let desc = d["desc"].as_str().unwrap_or("").split('#').next().unwrap_or("").to_string();
            let ts = d["timestamp"].as_u64().unwrap_or(0);
            (desc, ts)
        })
        .collect()
}

/// U6 (`../../PLAN-chain-notes-app-core-rpc.md`, "unusable against a real
/// node" fix, 2026-07-30) — THE regression this unit exists to prevent.
///
/// The bug: `CoreRpcTransport::ensure_address_watched`'s `watched` cache
/// lives on the TRANSPORT INSTANCE, but `src/lib.rs` builds a fresh
/// `ChainClient`/`AnyTransport` (and therefore a fresh, empty
/// `CoreRpcTransport`) on nearly every real operation — `open_client`, 24
/// call sites, none of which persist a transport across calls. So that
/// cache was empty on essentially every real call, and every miss ran
/// `importdescriptors` with `timestamp: 0` (genesis) again. On regtest's
/// ~100-block chain that's free, which is exactly why nothing in this
/// suite ever caught it despite exercising the Core RPC backend
/// extensively; verified LIVE against a real, synced testnet4 node
/// (~146k blocks, 2026-07-30) that the SAME single call takes ~309s —
/// so in production every operation against a real chain either hung for
/// minutes or (with the transport's flat 30s timeout) simply failed,
/// while the orphaned rescan kept running on the node regardless. A
/// timing-based test would be flaky and chain-size dependent (fast on
/// regtest, slow on any real chain) — this one is neither: it counts the
/// real `importdescriptors` RPC calls via
/// [`app_core::chain::core_rpc_import_descriptors_call_count`] (a
/// process-global, test-visibility-only counter), which is entirely
/// independent of chain length and would have caught this bug on regtest
/// from day one. Now that regtest itself is a real, ever-growing shared
/// chain (`PLAN-one-regtest-node.md`), that independence matters even
/// more: a call-count assertion is exactly as meaningful at height 726 as
/// at height 72,600.
///
/// This test reproduces the SHAPE of the real bug directly: `N`
/// independently constructed transports (exactly what `open_client` does
/// on every operation), each querying the SAME address exactly once.
/// Fixed by three layers (see `ensure_address_watched`'s doc comment):
/// (1) idempotence checked AGAINST THE NODE (`getaddressinfo`'s `ismine`)
/// — stateless, survives the per-operation churn that defeats any
/// in-memory cache, and is what makes the VERY FIRST of these `N`
/// transports (which cannot possibly have a warm cache — this is a
/// brand-new address on the shared node) do the right thing; (2) a
/// process-global cache on top of that, purely so a repeat doesn't even
/// pay for the one cheap `getaddressinfo` round trip; (3) the import
/// itself, once genuinely needed, runs under a much longer timeout. A
/// mutation reverting this fix back to "always import on a per-instance
/// cache miss" (removing BOTH (1) and (2) — i.e. reverting the shape of
/// this unit's change) makes the asserted count go from 1 to `N`.
#[test]
fn core_rpc_import_is_idempotent_across_fresh_transports() {
    let _guard = serialize_nodes();
    require_regtest("core_rpc_import_is_idempotent_across_fresh_transports", &node_env());

    let node = connect_node();
    wait_for_watch_wallet_idle(&node);
    let sender = unique_wallet_name("sender");
    node.rpc(None, "createwallet", serde_json::json!([sender]));
    let _sender_guard = WalletGuard::new(&node, sender.clone());
    // A genuinely funded address — the point is the IMPORT count, but a
    // used address (rather than an empty one) is the more honest shape,
    // and doubles as a correctness check: every one of the N independent
    // lookups below must still see the SAME real funding tx. Funded from
    // testwallet (not mined directly) — the confirm block's reward goes
    // to a fresh testwallet address, so nothing here is stranded.
    let addr = node.fresh_addr(&sender);
    node.rpc(Some("testwallet"), "sendtoaddress", serde_json::json!([addr, btc_str(FAUCET_FUND_SATS)]));
    node.generate(1, &node.fresh_addr("testwallet"));

    let t0 = Instant::now();
    let proxy =
        common::count_proxy::CountingProxy::start(node.env.host.clone(), node.env.port, node.env.user.clone(), node.env.pass.clone());
    let base = proxy.base_url();

    // Baseline BEFORE this test's own activity — the counter is
    // process-global (shared with every other test in this binary), and
    // `serialize_nodes()` only serializes test BODIES against each other,
    // not this counter's lifetime, so a delta (not an absolute value) is
    // the only correct thing to assert.
    let before = app_core::chain::core_rpc_import_descriptors_call_count();

    const N: usize = 5;
    for i in 0..N {
        // A FRESH transport every iteration — exactly what `open_client`
        // does in `src/lib.rs` on every single network operation. Each
        // one's own per-instance `watched`/`invalid` caches start empty;
        // only the node itself (checked via `getaddressinfo`) and the
        // process-global cache can possibly make this cheap.
        let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
        let client = ChainClient::new(transport, Network::Regtest);
        let stats = client.address_stats(&addr).expect("address_stats");
        assert_eq!(
            stats.chain_tx_count, 1,
            "iteration {i}: the funding tx must be visible on EVERY independent lookup, \
             not just the first (an address the node has never heard of reads as unused)"
        );
    }

    let after = app_core::chain::core_rpc_import_descriptors_call_count();
    let import_calls = after - before;
    assert_eq!(
        import_calls, 1,
        "{N} independent operations against the SAME address (each building a fresh transport, \
         exactly like src/lib.rs's open_client) must import it into the watch wallet EXACTLY ONCE \
         — idempotent against the NODE, not process memory — but {import_calls} real importdescriptors \
         calls happened. This is the U6 regression: on a real (non-regtest) chain each extra call is a \
         genesis rescan measured in MINUTES, not a cheap no-op."
    );

    // Strengthens the count-based assertion: the ONE import that did
    // happen must be the deliberate, documented genesis case (see
    // `ensure_address_watched`'s doc comment on why `timestamp: 0` is
    // still correct for this address) — not some other, unexpected value
    // that would indicate a different code path fired.
    let timestamps = watch_wallet_descriptor_timestamps(&node);
    let addr_desc = format!("addr({addr})");
    assert_eq!(
        timestamps.get(&addr_desc).copied(),
        Some(1),
        "the address's own descriptor must show bitcoind's genesis-clamp value (1, from a \
         requested timestamp of 0) exactly — descriptors seen: {timestamps:?}"
    );

    // `_sender_guard` sweeps `sender`'s balance back to testwallet on
    // Drop — no explicit unload call needed here anymore.
    report_timing("core_rpc_import_is_idempotent_across_fresh_transports", t0, &proxy);
    eprintln!("core_rpc_import_is_idempotent_across_fresh_transports: PASS ({N} ops, {import_calls} import call)");
}

/// U6, companion to the idempotence test above: proves the RANGED path
/// (`CoreRpcTransport::watch_descriptors`/`import_ranged`, U4) never
/// silently substitutes `timestamp: 0` for a caller-supplied birthday —
/// i.e. that U6's changes (routing `import_ranged` through the same
/// `Self::import_descriptors` helper as the per-address fallback, for the
/// timeout fix) did not accidentally start defaulting its timestamp too.
/// Uses the SAME live-verified signature as the test above:
/// `listdescriptors` echoes a real non-zero timestamp back VERBATIM,
/// while `0` is normalized to bitcoind's internal `1` — so asserting the
/// ranged descriptor's reported timestamp equals the EXACT value passed
/// (not `1`) directly catches a regression that silently zeroed it.
#[test]
fn core_rpc_ranged_import_never_silently_defaults_timestamp_to_zero() {
    let _guard = serialize_nodes();
    require_regtest("core_rpc_ranged_import_never_silently_defaults_timestamp_to_zero", &node_env());

    let node = connect_node();
    wait_for_watch_wallet_idle(&node);
    let network = Network::Regtest;
    let material = parse_key_material(TEST_MNEMONIC, network).expect("valid mnemonic");
    let account = random_account();
    let descriptor =
        export_formats(TEST_MNEMONIC, network, account, 0).unwrap().descriptor.expect("tr() descriptor");
    let _ = &material; // only needed to derive `descriptor` above

    // An arbitrary, deliberately non-round, non-zero unix timestamp —
    // chosen so it can't be confused with `0` OR with bitcoind's
    // genesis-clamp value (`1`) by construction.
    let birthday: u64 = 1_700_000_000;

    let t0 = Instant::now();
    let proxy =
        common::count_proxy::CountingProxy::start(node.env.host.clone(), node.env.port, node.env.user.clone(), node.env.pass.clone());
    let base = proxy.base_url();
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    match &transport {
        AnyTransport::Core(core) => core
            .watch_descriptors(vec![WatchDescriptor { descriptor, network, timestamp: birthday, range_end: 2 }])
            .expect("configure ranged descriptor"),
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    }

    let timestamps = watch_wallet_descriptor_timestamps(&node);
    // Separate from the call-count question (`report_timing` below): the
    // WATCH WALLET ITSELF accumulates descriptors forever across every run
    // of this suite, every other unit's suite, and the real app — a single
    // `listdescriptors` response therefore grows in BYTES over time even
    // though it is always exactly one RPC call. Not a call-count defect,
    // but the same "grows without bound" family the coordinator flagged;
    // logging the count here is a cheap trend signal for future runs.
    eprintln!("cb: chain-notes-watch now carries {} total descriptor entries", timestamps.len());
    assert!(
        timestamps.values().any(|&ts| ts == birthday),
        "expected a descriptor carrying the exact caller-supplied birthday {birthday}, \
         got: {timestamps:?} — a `1` here would mean the ranged path silently substituted \
         a genesis (timestamp: 0) rescan for a KNOWN, non-zero birthday"
    );
    // NOTE: unlike the old locally-spawned-node version of this test, this
    // can no longer also assert "no descriptor anywhere carries the
    // genesis-clamp value `1`" — the shared `chain-notes-watch` wallet may
    // already carry OTHER descriptors (from earlier runs of this suite, or
    // other consumers of the shared node) imported at genesis. The
    // targeted assertion above (the caller-supplied birthday shows up
    // verbatim) is what this test actually needs to prove and is
    // unaffected by that.

    report_timing("core_rpc_ranged_import_never_silently_defaults_timestamp_to_zero", t0, &proxy);
    eprintln!("core_rpc_ranged_import_never_silently_defaults_timestamp_to_zero: PASS (birthday={birthday})");
}

/// The whole faucet/guard redesign above (`PLAN-one-regtest-node.md`'s
/// "value must circulate, not be mined" fix) rests on ONE claim: a
/// throwaway wallet's funds return to `testwallet` even when the test body
/// PANICS, not just on a clean return. An untested cleanup path is not a
/// cleanup path — this proves it directly rather than trusting the
/// reasoning in `WalletGuard`'s doc comment.
///
/// Funds a throwaway wallet from `testwallet`, constructs a `WalletGuard`
/// for it INSIDE a `catch_unwind` closure that then deliberately panics —
/// mirroring exactly how `ConformanceFixture`'s `_sender_guard` would be
/// dropped if `assert_chain_contract` panicked partway through a real
/// test. Rust only skips a scope's `Drop`s on unwind if the process itself
/// aborts (`panic = "abort"`); neither this repo's `Cargo.toml` nor its
/// `.cargo/config.toml` sets that for any profile (grepped while writing
/// this test), so the default `test`/`dev` profile unwinds — `Drop` runs
/// on the way out — and this test would FAIL (balance != 0) if that ever
/// changed. After the panic is caught, reload the wallet (best effort,
/// just to read its balance) and assert it's genuinely empty — the sweep
/// actually happened, not merely "didn't crash the process".
#[test]
fn core_rpc_wallet_guard_returns_funds_even_on_panic() {
    let _guard = serialize_nodes();
    let node = connect_node();

    let sender = unique_wallet_name("panic-guard-check");
    node.rpc(None, "createwallet", serde_json::json!([sender]));
    let addr = node.fresh_addr(&sender);
    node.rpc(Some("testwallet"), "sendtoaddress", serde_json::json!([addr, btc_str(FAUCET_FUND_SATS)]));
    node.generate(1, &node.fresh_addr("testwallet"));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = WalletGuard::new(&node, sender.clone());
        panic!(
            "deliberate — proving WalletGuard's Drop runs during unwind, not only on a clean return \
             (core_rpc_wallet_guard_returns_funds_even_on_panic)"
        );
    }));
    assert!(result.is_err(), "the inner closure was supposed to panic");

    // The guard's Drop already unloaded the wallet — reload it (best
    // effort) purely to read its balance back and confirm the sweep
    // genuinely happened, then leave it unloaded again.
    let _ = node.try_rpc(None, "loadwallet", serde_json::json!([sender]));
    let balances = node.rpc(Some(&sender), "getbalances", serde_json::json!([]));
    let confirmed = balances["mine"]["trusted"].as_f64().unwrap_or(-1.0);
    let pending = balances["mine"]["untrusted_pending"].as_f64().unwrap_or(-1.0);
    assert_eq!(
        confirmed, 0.0,
        "WalletGuard must have swept the wallet's confirmed balance back to testwallet during unwind, \
         got balances={balances:?}"
    );
    assert_eq!(pending, 0.0, "no pending balance should remain either, got balances={balances:?}");
    node.unload_wallet(&sender);

    eprintln!("core_rpc_wallet_guard_returns_funds_even_on_panic: PASS (Drop-on-panic sweep verified live)");
}
