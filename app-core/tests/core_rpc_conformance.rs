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

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use app_core::chain::{AnyTransport, ChainClient, TxLookupStatus};
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

fn bitcoind_on_path() -> bool {
    match Command::new("bitcoind").arg("-version").stdout(Stdio::null()).stderr(Stdio::null()).status() {
        Ok(status) => status.success(),
        Err(_) => false,
    }
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

fn start_node() -> Node {
    // Port derived from the process id to avoid colliding with a real
    // node (default regtest RPC is 18443) or a concurrently-running one.
    let rpcport = 19000 + (std::process::id() % 3000) as u16;
    let rpcuser = "cnrpcuser".to_string();
    let rpcpass = format!("cnrpcpass-{}", std::process::id());
    let datadir = std::env::temp_dir().join(format!("chain-notes-core-rpc-{}", std::process::id()));
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
            "regtest=1\nserver=1\ntxindex=1\nfallbackfee=0.0001\n\n[regtest]\nrpcuser={rpcuser}\nrpcpassword={rpcpass}\nrpcport={rpcport}\n"
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

#[test]
fn core_rpc_conformance() {
    if !bitcoind_on_path() {
        eprintln!("SKIP core_rpc_conformance: bitcoind not found on PATH");
        return;
    }

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

    let descriptor = export_formats(TEST_MNEMONIC, network, account, 0)
        .expect("export_formats")
        .descriptor
        .expect("mnemonic yields a tr() descriptor");
    let notebook_watch = FundingSource::parse(&descriptor, network).expect("parse notebook watch descriptor");

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

    let base = format!("bitcoind+http://{}:{}@127.0.0.1:{}", node.rpcuser, node.rpcpass, node.rpcport);
    let transport = AnyTransport::new(&base, None).expect("construct Core RPC transport");
    let client = ChainClient::new(transport, network);

    assert_chain_contract(&client, &scenario);

    // Explicit, standalone demonstration of the plan's §2.1 requirement
    // (also exercised implicitly inside `assert_chain_contract`'s own
    // `tx_lookup_status` leg): a genuinely unknown txid on a synced,
    // txindex=1 node maps to NotFound, never Unknown.
    let unknown_txid = "ff".repeat(32);
    assert_eq!(client.tx_lookup_status(&unknown_txid), TxLookupStatus::NotFound, "unknown txid must be NotFound");

    eprintln!(
        "core_rpc_conformance: PASS ({} scenario txs, tip={tip}, datadir {:?})",
        scenario.txs.len(),
        node.datadir
    );
}
