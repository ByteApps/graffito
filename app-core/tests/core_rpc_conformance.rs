//! U3 conformance suite (`PLAN-chain-notes-app-core-rpc.md` §3 step 3):
//! replays the SAME backend-agnostic contract battery `chain_contract.rs`
//! runs against `EsploraFake` (U1), this time against a REAL `bitcoind
//! -regtest` through `ChainClient<AnyTransport>`'s Core RPC backend (U3).
//!
//! Skips gracefully (prints and returns — NOT a failure) when `bitcoind`
//! isn't on PATH, so this suite still passes on a machine without it.
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
//! A THIRD, non-obvious trap this file avoids on its own: every test
//! address here is funded by a coinbase reward paid DIRECTLY to it
//! (`generatetoaddress` targeting the address itself), never relayed
//! through a shared "miner" wallet address. A shared funder's own
//! accumulated coin-selection history is NOT something this driver fully
//! tracks, and `Scenario::all_addresses()` pulls in every address that
//! appears as an input's resolved prevout — so if a shared funder ever
//! leaked into a recorded tx's vin, its FULL real history (visible to the
//! live node, but not represented in this file's hand-built `Scenario`)
//! would silently desync from what `assert_chain_contract` expects. Every
//! address here is therefore single-purpose and its complete real history
//! is exactly what this file records: a "funder" address either (a) never
//! appears in any RECORDED tx (the 100-block maturity padding sink, the
//! probe's own destination) or (b) has its own coinbase-funding tx
//! recorded too, alongside whatever it later spends (`addr_note`, the
//! `mempool_funder` relay).
//!
//! Note on coinbase representation: a coinbase input has no real prevout
//! (`getrawtransaction`'s vin entry carries a `"coinbase"` hex field
//! instead of `txid`/`vout`/`prevout`) — this file represents every
//! coinbase-funded tx with an EMPTY `vin` in its `ScenarioTx`, which is
//! behaviorally identical to a `None`-prevout entry for every pure
//! address-matching computation in `common/mod.rs` (none of them ever
//! match a coinbase's nonexistent prevout address), and is what keeps
//! `assert_chain_contract`'s ONE vin-COUNT-sensitive check (`fetch_tx_io`,
//! which only ever inspects the FIRST tx with a non-empty `vin`) landing
//! on a real spend (`addr_note`'s own legs) instead of a coinbase tx.

mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use app_core::chain::{AnyTransport, ChainClient, NodeStatus, TxLookupStatus, WatchDescriptor};
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

/// True when a `bitcoind` executable exists on PATH. A pure filesystem
/// lookup — it deliberately does NOT execute anything.
///
/// This replaces a `Command::new("bitcoind").arg("-version").status()`
/// probe whose `Err(_) => false` / `!status.success() => false` arms were a
/// silent-green hazard. Every one of the six tests here calls this BEFORE
/// taking `NODE_LOCK`, so all six probes fire concurrently while other
/// nodes are still live; under that process pressure `bitcoind -version`
/// intermittently exits 1 even though the very same command exits 0 when
/// run by hand. The old code read that as "not installed" and returned
/// `ok` without running a thing — a deliberately-broken build was observed
/// passing all six in 0.56s where a real run takes ~60s, which is exactly
/// how a genuine regression ships behind a green suite.
///
/// Answering "is it on PATH" by *reading PATH* is both what the function
/// name claims and immune to load: no subprocess, no flake, no silent
/// pass. A node that is present but genuinely broken now surfaces where it
/// should — in `start_node`, which fails loudly.
fn bitcoind_on_path() -> bool {
    let Some(path) = std::env::var_os("PATH") else { return false };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join("bitcoind");
        std::fs::metadata(&candidate).map(|m| m.is_file()).unwrap_or(false)
    })
}

/// A throwaway `bitcoind -regtest` this suite starts, drives via raw
/// JSON-RPC (basic auth — same shape the transport-under-test uses, but a
/// SEPARATE client: this struct is test SETUP, never the code under test),
/// and tears down on drop — including on a test panic, since Rust unwinds
/// through `Drop` by default and this crate's test profile doesn't set
/// `panic = "abort"`.
struct Node {
    datadir: PathBuf,
    rpcuser: String,
    rpcpass: String,
    rpcport: u16,
    client: reqwest::blocking::Client,
    child: Option<Child>,
}

impl Node {
    fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpcport)
    }

    fn try_rpc(&self, wallet: Option<&str>, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
        let url = match wallet {
            Some(w) => format!("{}/wallet/{w}", self.base()),
            None => self.base(),
        };
        let resp = self
            .client
            .post(&url)
            .basic_auth(&self.rpcuser, Some(&self.rpcpass))
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

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if self.try_rpc(None, "getblockchaininfo", serde_json::json!([])).is_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "bitcoind did not become ready within 60s (datadir {:?})",
                self.datadir
            );
            std::thread::sleep(Duration::from_millis(300));
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

    /// Mine exactly ONE block, coinbase to `address`, and return that
    /// block's coinbase txid — read from the BLOCK itself (`getblock`
    /// verbosity 1), never from any wallet's `listunspent`. Load-bearing:
    /// several of this suite's funded addresses (the HD notebook/spending
    /// leaves) are never imported into ANY bitcoind wallet at all — only
    /// the transport-under-test's own `chain-notes-watch` wallet ever
    /// sees them — so a wallet-`listunspent`-based txid lookup would
    /// wrongly report them as coin-less even though the coinbase reward
    /// genuinely landed on-chain (verified live: this was the suite's
    /// first real failure while writing it).
    fn generate_single_capture(&self, address: &str) -> String {
        let hashes = self.rpc(None, "generatetoaddress", serde_json::json!([1, address]));
        let block_hash = hashes
            .as_array()
            .and_then(|a| a.first())
            .and_then(|h| h.as_str())
            .expect("generatetoaddress: no block hash")
            .to_string();
        let _ = self.try_rpc(None, "syncwithvalidationinterfacequeue", serde_json::json!([]));
        let block = self.rpc(None, "getblock", serde_json::json!([block_hash, 1]));
        block["tx"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|t| t.as_str())
            .expect("getblock: no coinbase txid")
            .to_string()
    }

    fn fresh_addr(&self) -> String {
        self.rpc(Some("sender"), "getnewaddress", serde_json::json!(["", "bech32m"]))
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

    fn utxo_txids(&self, wallet: &str, address: &str) -> Vec<String> {
        let v = self.rpc(Some(wallet), "listunspent", serde_json::json!([0, 9_999_999, [address]]));
        v.as_array()
            .expect("listunspent: not an array")
            .iter()
            .map(|u| u["txid"].as_str().expect("utxo txid").to_string())
            .collect()
    }

    fn tip_height(&self) -> u64 {
        self.rpc(None, "getblockcount", serde_json::json!([])).as_u64().expect("getblockcount: not a number")
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = self.try_rpc(None, "stop", serde_json::json!([]));
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

/// Distinguishes concurrently-running `#[test]` functions in this same
/// binary (cargo test runs them in parallel threads of ONE process) — the
/// original single-test suite derived its port/datadir from
/// `std::process::id()` alone, which is fine for exactly one node per
/// process but collides the instant a second test (U4's ranged/widening/
/// preflight suites) starts its own. Folded into both the port and the
/// datadir name so no two `Node`s this binary ever creates can collide.
static NODE_SEQ: AtomicU32 = AtomicU32::new(0);

/// Serializes every `#[test]` in this file to run ONE bitcoind at a time.
/// U4 added five more real-node tests alongside U3's original one; cargo's
/// default test-thread parallelism starts them all concurrently, and six
/// real regtest nodes competing for CPU on a loaded machine can starve
/// each other badly enough that `Node::wait_ready`'s 60s budget trips —
/// verified empirically while writing these tests (a `--test-threads=1`
/// run of the exact same suite is reliably green; the default parallel run
/// intermittently was not). That is a resource-contention flake, not a
/// correctness failure, so tests take this lock as their first action and
/// hold it for their whole body rather than risk it. Recovers from a
/// poisoned lock (an earlier test panicking) so one failure doesn't
/// cascade into every other test failing on the lock instead of its own
/// assertions.
static NODE_LOCK: Mutex<()> = Mutex::new(());

fn serialize_nodes() -> std::sync::MutexGuard<'static, ()> {
    NODE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn start_node() -> Node {
    start_node_with("txindex=1\n")
}

/// Same as [`start_node`] but with `extra_conf` appended to the (non-
/// `[regtest]`-sectioned) top of `bitcoin.conf` — used by the U4 preflight
/// tests to start a node WITHOUT `txindex=1` or WITH `-prune`-equivalent
/// settings, without duplicating the whole setup dance.
fn start_node_with(extra_conf: &str) -> Node {
    let seq = NODE_SEQ.fetch_add(1, Ordering::Relaxed);
    // Port derived from the process id (plus a per-node sequence offset,
    // so multiple `Node`s in one test binary never collide) to avoid
    // colliding with a real node (default regtest RPC is 18443) or a
    // concurrently-running one.
    let rpcport = 19000 + ((std::process::id().wrapping_add(seq.wrapping_mul(97))) % 3000) as u16;
    let rpcuser = "cnrpcuser".to_string();
    let rpcpass = format!("cnrpcpass-{}-{seq}", std::process::id());
    let datadir = std::env::temp_dir().join(format!("chain-notes-core-rpc-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&datadir); // stale leftover from a prior crashed run
    std::fs::create_dir_all(&datadir).expect("create bitcoind datadir");
    // `rpcuser`/`rpcpassword`/`rpcport` are network-specific settings and
    // MUST live under a `[regtest]` section (verified live: bitcoind
    // refuses to start otherwise — "Config setting for -rpcport only
    // applied on regtest network when in [regtest] section"). Basic auth,
    // deliberately NOT cookie auth (cookie files aren't readable from iOS
    // — plan §2.4) — so this exercises the real auth path.
    std::fs::write(
        datadir.join("bitcoin.conf"),
        format!(
            "regtest=1\nserver=1\nfallbackfee=0.0001\n{extra_conf}\n[regtest]\nrpcuser={rpcuser}\nrpcpassword={rpcpass}\nrpcport={rpcport}\n"
        ),
    )
    .expect("write bitcoin.conf");

    let child = Command::new("bitcoind")
        .arg("-regtest")
        .arg(format!("-datadir={}", datadir.display()))
        .arg("-daemon=0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn bitcoind");

    let node = Node {
        datadir,
        rpcuser,
        rpcpass,
        rpcport,
        client: reqwest::blocking::Client::builder().timeout(Duration::from_secs(30)).build().unwrap(),
        child: Some(child),
    };
    node.wait_ready();
    node
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
        // doc's "Note on coinbase representation". Skipped entirely.
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
    let v = node.rpc(Some("chain-notes-watch"), "listdescriptors", serde_json::json!([]));
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
/// its OWN fresh node (`Node` owns a live child process — it can't be
/// shared between two `#[test]` functions, and cargo runs this binary's
/// tests in parallel threads of the SAME process, so a second node is
/// unavoidable here regardless).
struct ConformanceFixture {
    node: Node,
    scenario: Scenario,
    network: Network,
    /// The account-0 notebook's `tr(...)` multipath descriptor — the exact
    /// string `export_formats` produces for a real caller.
    notebook_descriptor: String,
    /// The account-0 spending wallet's `wpkh(...)` multipath descriptor —
    /// the exact string `spending::funding_descriptor` produces.
    spending_descriptor: String,
}

fn build_conformance_fixture() -> ConformanceFixture {
    let node = start_node();

    // "sender" holds every test address's private key (so it can sign the
    // spend-with-change / OP_RETURN-note / broadcast-probe legs). The
    // watch-only "chain-notes-watch" wallet is created LAZILY by the
    // CoreRpcTransport under test, never here.
    node.rpc(None, "createwallet", serde_json::json!(["sender"]));

    let addr_a = node.fresh_addr();
    let addr_note = node.fresh_addr();
    let mempool_funder = node.fresh_addr();
    let addr_probe_src = node.fresh_addr();
    let addr_pager = node.fresh_addr();
    let ext_recipient = node.fresh_addr();
    let sink = node.fresh_addr(); // maturity padding + probe's own destination — NEVER recorded/queried

    let network = Network::Regtest;
    let material = parse_key_material(TEST_MNEMONIC, network).expect("valid mnemonic");
    let account = 0u32;
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

    // ---- Phase 1: one coinbase coin straight to each single-use address
    // (the funding-source isolation the module doc explains), plus 30 on
    // addr_pager (>25-tx pagination), then 100 blocks of maturity padding
    // to `sink` — never recorded, never queried. ----
    let single_coinbase_addrs = [
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
    for addr in single_coinbase_addrs {
        txids.push(node.generate_single_capture(addr));
    }
    node.generate(30, &addr_pager);
    node.generate(100, &sink);

    txids.extend(node.utxo_txids("sender", &addr_pager));

    // ---- Phase 2: addr_note spend-with-change — input = its funding
    // coin, one paying output to a fresh one-shot address, change back to
    // addr_note itself (verified live pattern: explicit `inputs` +
    // `change_address`). ----
    let (note_txid0, note_vout0, note_amount0) = node.sole_utxo("sender", &addr_note);
    let pay_amount = note_amount0 / 2;
    let spend_result = node.rpc(
        Some("sender"),
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
    node.generate(1, &sink);

    // ---- Phase 3: addr_note's self-authored OP_RETURN note — spends the
    // change coin from phase 2, an OP_RETURN-only output list with NO
    // separate paying output means the ENTIRE remainder becomes change
    // back to addr_note (verified live: exactly 2 outputs result). ----
    let (note_txid1, note_vout1, _) = node.sole_utxo("sender", &addr_note);
    let note_result = node.rpc(
        Some("sender"),
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
    node.generate(1, &sink);

    // ---- Phase 4 (Trap 1): the genuinely SIGNED broadcast-probe tx.
    // `add_to_wallet: false` returns signed hex WITHOUT touching the
    // wallet or the mempool — the transport-under-test's `broadcast()`
    // call is this tx's very first appearance on the node. Deliberately
    // NOT pushed into `txids` — it's asserted only via
    // `Scenario::broadcast_probe`. ----
    let (probe_in_txid, probe_in_vout, probe_in_amount) = node.sole_utxo("sender", &addr_probe_src);
    let probe_result = node.rpc(
        Some("sender"),
        "send",
        serde_json::json!([
            [pay_output(&sink, probe_in_amount)],
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
    let (mf_txid, mf_vout, mf_amount) = node.sole_utxo("sender", &mempool_funder);
    let mempool_result = node.rpc(
        Some("sender"),
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

    let scenario_txs: Vec<ScenarioTx> = txids.iter().map(|t| build_scenario_tx(&node, t, tip)).collect();

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

    ConformanceFixture { node, scenario, network, notebook_descriptor, spending_descriptor }
}

#[test]
fn core_rpc_conformance() {
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_conformance: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    let fx = build_conformance_fixture();
    let node = &fx.node;
    let scenario = &fx.scenario;
    let tip = scenario.tip_height;

    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
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
            assert!(!status.pruned, "this node is never pruned");
            assert!(status.txindex, "this node runs with txindex=1");
            assert_eq!(status.tip_height, tip);
            // The watch wallet DOES exist by now (every route above
            // touched it), so scanning info must be reportable, not absent.
            assert!(status.wallet_scanning.is_some(), "watch wallet exists — scanning info must be Some");
        }
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    }

    eprintln!(
        "core_rpc_conformance: PASS ({} scenario txs, tip={tip}, datadir {:?})",
        scenario.txs.len(),
        node.datadir
    );
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
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_conformance_ranged_descriptors: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    let fx = build_conformance_fixture();
    let node = &fx.node;

    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
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

    eprintln!(
        "core_rpc_conformance_ranged_descriptors: PASS ({} scenario txs, tip={}, {} watch-wallet \
         descriptors, 0 addr() imports among the {} ranged-covered addresses, datadir {:?})",
        fx.scenario.txs.len(),
        fx.scenario.tip_height,
        descriptors.len(),
        ranged_addrs.len(),
        node.datadir
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
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_range_widening_finds_address_beyond_initial_range: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    let node = start_node();
    node.rpc(None, "createwallet", serde_json::json!(["sender"]));

    let network = Network::Regtest;
    let material = parse_key_material(TEST_MNEMONIC, network).expect("valid mnemonic");
    let account = 0u32;

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

    let funding_txid = node.generate_single_capture(&addr_far);
    let tip = node.tip_height();

    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
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

    eprintln!(
        "core_rpc_range_widening_finds_address_beyond_initial_range: PASS \
         (index={far_index}, tip={tip}, range {range_before} -> {range_after:?}, datadir {:?})",
        node.datadir
    );
}

/// U4 test 3 ("Pruned node"): a throwaway `-prune=550` node reports
/// `pruned` (and SOME prune height) through `preflight()`. A pruned node
/// CANNOT rescan below its prune height at all (plan §2.2) — the UI (U6)
/// needs this reported so it can warn plainly rather than have the app
/// silently return partial history.
#[test]
fn core_rpc_preflight_reports_pruned_node() {
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_preflight_reports_pruned_node: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    // `-txindex` and `-prune` are mutually exclusive in bitcoind — this
    // node deliberately carries neither the default `start_node()` adds.
    let node = start_node_with("prune=550\n");
    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let core = match &transport {
        AnyTransport::Core(c) => c,
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    };

    let status: NodeStatus = core.preflight().expect("preflight");
    assert!(status.pruned, "a node started with -prune must report pruned=true");
    assert!(status.prune_height.is_some(), "a pruned node must report SOME prune height, even 0");

    eprintln!("core_rpc_preflight_reports_pruned_node: PASS (status={status:?}, datadir {:?})", node.datadir);
}

/// U4 test 4 ("No txindex"): a node started WITHOUT `-txindex` reports
/// `txindex: false` through `preflight()`. Without it, prevout lookup for
/// EXTERNAL parents fails, so sender attribution degrades (plan §2.3) —
/// the UI (U6) needs this reported rather than silently mis-attributing.
#[test]
fn core_rpc_preflight_reports_missing_txindex() {
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_preflight_reports_missing_txindex: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    let node = start_node_with(""); // plain node: no -txindex, no -prune
    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let core = match &transport {
        AnyTransport::Core(c) => c,
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    };

    let status: NodeStatus = core.preflight().expect("preflight");
    assert!(!status.txindex, "a node started without -txindex must report txindex=false");
    assert!(!status.pruned, "this node was never pruned");

    eprintln!("core_rpc_preflight_reports_missing_txindex: PASS (status={status:?}, datadir {:?})", node.datadir);
}

/// U4 test 5 ("Birthday handling"): a descriptor imported at a LATE
/// timestamp (well past a real funding tx's own block time) must NOT
/// report that earlier history — proving the birthday plumbing is honest
/// (an imported seed with no known birthday must degrade visibly, never
/// silently claim completeness — plan §2.2) rather than accidentally
/// complete. Two independent accounts of the SAME test mnemonic run side
/// by side against the SAME watch wallet: account 0 imported at timestamp
/// 0 (sees everything) is the control proving the harness itself is sound,
/// account 1 imported at a timestamp 4 hours past its own funding block is
/// the case under test.
///
/// **Load-bearing regtest gotcha, verified live (bitcoind v30.2.0) while
/// writing this test**: bitcoind's rescan-from-timestamp finds a starting
/// HEIGHT by locating the earliest block whose time is >= (timestamp minus
/// the documented 2-hour window). On a regtest chain freshly mined in the
/// same second, EVERY block's time is real "now" — so a timestamp set even
/// slightly in the FUTURE relative to the chain's actual tip has no
/// qualifying block to start from, and bitcoind's fallback is to scan
/// EVERYTHING, which would make this test pass for the wrong reason (or,
/// as first written, fail outright — it found the "excluded" tx anyway).
/// The fix: `setmocktime` the node forward past the intended import
/// timestamp and mine a few more blocks BEFORE importing, so the chain's
/// tip genuinely postdates the birthday and the exclusion is real.
#[test]
fn core_rpc_birthday_excludes_history_before_a_late_timestamp() {
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_birthday_excludes_history_before_a_late_timestamp: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    let node = start_node();
    node.rpc(None, "createwallet", serde_json::json!(["sender"]));
    let network = Network::Regtest;
    let material = parse_key_material(TEST_MNEMONIC, network).expect("valid mnemonic");

    let addr_full = realize(&material, network, 0, 0).unwrap().address;
    let desc_full =
        export_formats(TEST_MNEMONIC, network, 0, 0).unwrap().descriptor.expect("tr() descriptor");
    let addr_late = realize(&material, network, 1, 0).unwrap().address;
    let desc_late =
        export_formats(TEST_MNEMONIC, network, 1, 0).unwrap().descriptor.expect("tr() descriptor");

    node.generate_single_capture(&addr_full);
    let late_funding_txid = node.generate_single_capture(&addr_late);
    let funded_height = node.tip_height();
    let block_hash = node.rpc(None, "getblockhash", serde_json::json!([funded_height]));
    let block = node.rpc(None, "getblock", serde_json::json!([block_hash, 1]));
    let funded_time = block.get("time").and_then(|t| t.as_u64()).expect("block time");
    // bitcoind's own `importdescriptors` help text: blocks up to 2 HOURS
    // before the earliest timestamp are ALSO scanned — clear that margin
    // comfortably so this can't accidentally pass.
    let late_timestamp = funded_time + 4 * 3600;

    // Push the chain's actual tip time well past `late_timestamp` (see the
    // doc comment above) — otherwise bitcoind can't find a scan-start
    // height and conservatively scans everything, which would hide the
    // very bug this test exists to catch.
    node.rpc(None, "setmocktime", serde_json::json!([late_timestamp + 3600]));
    node.generate(5, &node.fresh_addr());

    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    match &transport {
        AnyTransport::Core(core) => core
            .watch_descriptors(vec![
                WatchDescriptor { descriptor: desc_full, network, timestamp: 0, range_end: 2 },
                WatchDescriptor { descriptor: desc_late, network, timestamp: late_timestamp, range_end: 2 },
            ])
            .expect("configure ranged descriptors"),
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    }

    let client = ChainClient::new(transport, network);

    let full_stats = client.address_stats(&addr_full).expect("address_stats (control)");
    assert_eq!(full_stats.chain_tx_count, 1, "a timestamp=0 import must see its own funding tx");

    let late_stats = client.address_stats(&addr_late).expect("address_stats (late birthday)");
    assert_eq!(
        late_stats.chain_tx_count, 0,
        "a late-birthday import reported history from BEFORE its birthday (funding txid {late_funding_txid}) \
         — that would be a silently-wrong wallet, not an honest gap"
    );

    eprintln!(
        "core_rpc_birthday_excludes_history_before_a_late_timestamp: PASS \
         (funded_time={funded_time}, late_timestamp={late_timestamp}, datadir {:?})",
        node.datadir
    );
}

/// U5 test 1 (plan §2.1, THE regression this unit exists to prevent): on a
/// node started WITHOUT `-txindex`, a genuinely unknown txid must map to
/// `TxLookupStatus::Unknown`, NEVER `NotFound` — the RPC code (-5) is
/// identical to the txindex=1 case (`core_rpc_conformance` above already
/// proves the POSITIVE case: NotFound on a healthy, synced, txindex=1
/// node), but without txindex bitcoind genuinely cannot tell "this tx
/// doesn't exist" apart from "this tx exists, confirmed, but I have no way
/// to look it up" — treating the two identically would make the app
/// declare a live, on-chain transaction dropped, which is the single worst
/// failure mode `TxLookupStatus`'s own doc comment calls out.
#[test]
fn core_rpc_notfound_requires_txindex_not_just_rpc_code_minus5() {
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_notfound_requires_txindex_not_just_rpc_code_minus5: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    // No `-txindex` (mirrors `core_rpc_preflight_reports_missing_txindex`).
    let node = start_node_with("");
    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, Network::Regtest);

    let unknown_txid = "ff".repeat(32);
    assert_eq!(
        client.tx_lookup_status(&unknown_txid),
        TxLookupStatus::Unknown,
        "a no-txindex node must NEVER report NotFound for an unresolvable txid — \
         that would read a live transaction as dropped"
    );

    // Same node, `fetch_tx_status`/`fetch_tx_hex` (the other two
    // `getrawtransaction`-backed routes) must degrade the SAME way — no
    // caller anywhere may see a bare "confirmed" verdict manufactured out
    // of an unresolved absence either.
    assert_eq!(
        client.fetch_tx_status(&unknown_txid),
        None,
        "fetch_tx_status must also read this as unknown, not confirmed/unconfirmed"
    );

    eprintln!(
        "core_rpc_notfound_requires_txindex_not_just_rpc_code_minus5: PASS (datadir {:?})",
        node.datadir
    );
}

/// U5 test 2 (plan §2.1, "cache it; do not re-probe per call"): several
/// lookups of DIFFERENT unknown txids against the SAME transport instance
/// must trigger exactly ONE real `getblockchaininfo`/`getindexinfo` probe,
/// not one per lookup — proven via `CoreRpcTransport::preflight_probe_count`,
/// a counter incremented only by the raw uncached probe. A reviewer's
/// mutation that made the absence check bypass the cache would make this
/// counter grow with every lookup instead of staying at 1.
#[test]
fn core_rpc_established_absence_caches_node_status_across_lookups() {
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_established_absence_caches_node_status_across_lookups: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    let node = start_node(); // txindex=1 — the positive case.
    // A brand-new regtest node's tip is still the genesis block (an
    // ancient timestamp), so `initialblockdownload` reports true until a
    // RECENT block exists — mine a few (system-clock timestamps, no
    // `setmocktime` needed, same as every other test here) so this test
    // exercises the "fully synced" case `established_absent` requires,
    // not an accidental IBD-driven `Unknown`.
    node.rpc(None, "createwallet", serde_json::json!(["sender"]));
    let addr = node.fresh_addr();
    node.generate(3, &addr);

    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, Network::Regtest);

    for i in 0..5u8 {
        let txid = format!("{i:02x}{}", "ee".repeat(31));
        assert_eq!(
            client.tx_lookup_status(&txid),
            TxLookupStatus::NotFound,
            "each of these txids is genuinely unknown on this fresh node"
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

    eprintln!(
        "core_rpc_established_absence_caches_node_status_across_lookups: PASS (datadir {:?})",
        node.datadir
    );
}

/// U5 test 3 (plan §2.4, "the garbage-address silent-success path — make
/// it a decision, not an accident"): a syntactically invalid address reads
/// as "never used, no coins" — an explicit, documented decision (see
/// `CoreRpcTransport::ensure_address_watched`'s doc comment), not the
/// accident of a test fixture. This proves the decision is real and
/// stable against a live node: `getdescriptorinfo`/`listunspent` are never
/// handed the garbage string (which would itself error), and every
/// affected route answers with its empty shape instead of an `Error`.
#[test]
fn core_rpc_invalid_address_reads_as_never_used_not_error() {
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_invalid_address_reads_as_never_used_not_error: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    let node = start_node();
    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, Network::Regtest);

    let garbage = "not-a-real-bitcoin-address";
    let stats = client.address_stats(garbage).expect("address_stats must be Ok, not Err, for a garbage address");
    assert_eq!(stats.chain_tx_count, 0);
    assert_eq!(stats.mempool_tx_count, 0);
    let utxos = client.utxos(garbage).expect("utxos must be Ok, not Err, for a garbage address");
    assert!(utxos.is_empty());
    let history = client.full_history(garbage).expect("full_history must be Ok, not Err, for a garbage address");
    assert!(history.is_empty());

    eprintln!("core_rpc_invalid_address_reads_as_never_used_not_error: PASS (datadir {:?})", node.datadir);
}

/// U7: `/v1/fees/recommended` against a REAL, freshly-started regtest node
/// — which is exactly the "`estimatesmartfee` genuinely has nothing to
/// estimate from" case the plan calls out by name (a brand-new regtest
/// chain has coinbase-only blocks, never a real fee market), so this
/// exercises the fallback path for real rather than merely asserting a
/// mock never called. A live assertion, not a "did it not crash" smoke
/// test: every tier must be present, non-zero, correctly ORDERED
/// (fastest >= half_hour >= hour >= economy — the U7 ordering invariant),
/// and `minimumFee` must reflect this node's OWN live
/// `getmempoolinfo().mempoolminfee` (a plain regtest node's default, 1
/// sat/vB) rather than a hardcoded stand-in.
#[test]
fn core_rpc_fee_route_falls_back_well_formed_on_a_node_with_no_fee_history() {
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_fee_route_falls_back_well_formed_on_a_node_with_no_fee_history: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    let node = start_node();
    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, Network::Regtest);

    // Independently confirm THIS node's `estimatesmartfee` really has
    // nothing to estimate from right now — if a future bitcoind version
    // ever changes that, this test should fail loudly here (with a clear
    // reason) rather than silently exercising the "happy path" instead of
    // the fallback path it claims to.
    let estimate = node.rpc(None, "estimatesmartfee", serde_json::json!([1]));
    assert!(
        estimate.get("feerate").is_none(),
        "expected a fresh regtest node to have no fee estimate yet, got {estimate:?}"
    );

    let fees = client.fee_rates().expect("fee_rates");

    assert!(fees.fastest >= fees.half_hour, "fastest {} must be >= half_hour {}", fees.fastest, fees.half_hour);
    assert!(fees.half_hour >= fees.hour, "half_hour {} must be >= hour {}", fees.half_hour, fees.hour);
    assert!(fees.hour >= fees.economy, "hour {} must be >= economy {}", fees.hour, fees.economy);
    assert!(fees.economy >= 1.0, "economy fee must never be zero (or negative), got {}", fees.economy);
    assert!(
        fees.fastest < 1000.0,
        "fastest fallback must stay sane, nowhere near a real fee-spike rate: {}",
        fees.fastest
    );

    // The node's own relay floor, read independently via `getmempoolinfo`
    // (never trusting this driver's own conversion helper — the whole
    // point is proving the ROUTE reads it from the live node) — a plain
    // regtest node with no mempool pressure reports the network default,
    // 0.00001 BTC/kvB = 1 sat/vB.
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

    eprintln!(
        "core_rpc_fee_route_falls_back_well_formed_on_a_node_with_no_fee_history: PASS \
         (fees={fees:?}, relay_min_sat_vb={relay_min_sat_vb}, datadir {:?})",
        node.datadir
    );
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
    let v = node.rpc(Some("chain-notes-watch"), "listdescriptors", serde_json::json!([]));
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
/// from day one.
///
/// This test reproduces the SHAPE of the real bug directly: `N`
/// independently constructed transports (exactly what `open_client` does
/// on every operation), each querying the SAME address exactly once.
/// Fixed by three layers (see `ensure_address_watched`'s doc comment):
/// (1) idempotence checked AGAINST THE NODE (`getaddressinfo`'s `ismine`)
/// — stateless, survives the per-operation churn that defeats any
/// in-memory cache, and is what makes the VERY FIRST of these `N`
/// transports (which cannot possibly have a warm cache — this is a
/// brand-new address on a brand-new node) do the right thing; (2) a
/// process-global cache on top of that, purely so a repeat doesn't even
/// pay for the one cheap `getaddressinfo` round trip; (3) the import
/// itself, once genuinely needed, runs under a much longer timeout. A
/// mutation reverting this fix back to "always import on a per-instance
/// cache miss" (removing BOTH (1) and (2) — i.e. reverting the shape of
/// this unit's change) makes the asserted count go from 1 to `N`.
#[test]
fn core_rpc_import_is_idempotent_across_fresh_transports() {
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_import_is_idempotent_across_fresh_transports: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    let node = start_node();
    node.rpc(None, "createwallet", serde_json::json!(["sender"]));
    // A genuinely funded address — the point is the IMPORT count, but a
    // used address (rather than an empty one) is the more honest shape,
    // and doubles as a correctness check: every one of the N independent
    // lookups below must still see the SAME real funding tx.
    let addr = node.fresh_addr();
    node.generate(1, &addr);

    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);

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

    eprintln!(
        "core_rpc_import_is_idempotent_across_fresh_transports: PASS \
         ({N} ops, {import_calls} import call, datadir {:?})",
        node.datadir
    );
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
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_ranged_import_never_silently_defaults_timestamp_to_zero: bitcoind not found on PATH");
        return;
    }
    let _guard = serialize_nodes();

    let node = start_node();
    let network = Network::Regtest;
    let material = parse_key_material(TEST_MNEMONIC, network).expect("valid mnemonic");
    let descriptor =
        export_formats(TEST_MNEMONIC, network, 0, 0).unwrap().descriptor.expect("tr() descriptor");
    let _ = &material; // only needed to derive `descriptor` above

    // An arbitrary, deliberately non-round, non-zero unix timestamp —
    // chosen so it can't be confused with `0` OR with bitcoind's
    // genesis-clamp value (`1`) by construction.
    let birthday: u64 = 1_700_000_000;

    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    match &transport {
        AnyTransport::Core(core) => core
            .watch_descriptors(vec![WatchDescriptor { descriptor, network, timestamp: birthday, range_end: 2 }])
            .expect("configure ranged descriptor"),
        AnyTransport::Esplora(_) => panic!("expected a Core transport for a bitcoind+ base"),
    }

    let timestamps = watch_wallet_descriptor_timestamps(&node);
    assert!(
        timestamps.values().any(|&ts| ts == birthday),
        "expected a descriptor carrying the exact caller-supplied birthday {birthday}, \
         got: {timestamps:?} — a `1` here would mean the ranged path silently substituted \
         a genesis (timestamp: 0) rescan for a KNOWN, non-zero birthday"
    );
    assert!(
        timestamps.values().all(|&ts| ts != 1),
        "no descriptor in a ranged-only scenario may show bitcoind's genesis-clamp value (1) — \
         every family here was configured with an explicit non-zero birthday: {timestamps:?}"
    );

    eprintln!(
        "core_rpc_ranged_import_never_silently_defaults_timestamp_to_zero: PASS \
         (birthday={birthday}, datadir {:?})",
        node.datadir
    );
}
