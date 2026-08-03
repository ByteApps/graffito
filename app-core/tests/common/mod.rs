//! Backend-agnostic contract-testing helpers (PLAN-chain-notes-app-core-rpc.md
//! unit U1). Lives in a `common/` SUBDIRECTORY (not `common.rs`) precisely so
//! cargo does NOT treat it as its own test binary/crate — every other
//! `tests/*.rs` file pulls this in with `mod common;`.
//!
//! Three pieces:
//!   * [`Scenario`] — a plain, backend-agnostic description of chain state
//!     (a list of transactions with heights/confirmations), expressible both
//!     as canned Esplora JSON (today, via [`EsploraFake`]) and — later, by a
//!     different unit — as real state materialized on `bitcoind -regtest`.
//!     It also carries pure (no-transport) query helpers (`utxos_for`,
//!     `history_desc`, `stats_for`, …) that compute the SAME answers
//!     `ChainClient` should, straight from the scenario data — the ground
//!     truth [`assert_chain_contract`] checks a transport-under-test against.
//!   * [`EsploraFake`] — a `Transport` that serves a `Scenario` as correct
//!     Esplora JSON, so today's `ChainClient<EsploraFake>` battery locks in
//!     current behavior.
//!   * [`assert_chain_contract`] — the actual battery. Deliberately contains
//!     ZERO Esplora-specific assertions (no request-path or JSON checks —
//!     those live in `tests/esplora_paths.rs`) so it can be replayed
//!     verbatim, unmodified, against `ChainClient<CoreRpcTransport>` once
//!     that backend exists (U3).
//!
//! Transactions are REAL `bitcoin::Transaction` values (real taproot/segwit
//! addresses via the exact `notes_core::address`/`taproot` machinery the app
//! itself uses, real varint/consensus encoding, txid computed FROM the hex
//! via `Transaction::compute_txid()` — never hand-picked, so `fetch_tx_hex`
//! is a real round-trip and values always balance input ≥ output). Inputs
//! carry empty witnesses/scriptSigs — deliberately UNSIGNED: `EsploraFake`
//! never validates scripts (nothing here does), and real signing only
//! matters once a scenario is actually replayed against a live `bitcoind`
//! (a later unit) — see `PLAN-chain-notes-app-core-rpc.md` §3 step 3. Every
//! generated address is realized through `notes_core::address` /
//! `notes_core::taproot`, so it decodes, prefixes, and script-pubkey-encodes
//! exactly like a genuine on-chain address.

#![allow(dead_code)]

/// U5 (`PLAN-one-regtest-node.md`) addition: a local-only bitcoind-JSON-RPC
/// stub for driving `CoreRpcTransport`'s response-interpretation logic with
/// synthetic bodies a shared, persistent, not-ours node cannot be coerced
/// into producing on demand (pruned/no-txindex reporting, the NotFound
/// decision table, the ranged-import birthday timestamp). See its own doc
/// comment. Unrelated to the `Scenario`/`EsploraFake` machinery below.
pub mod mock_rpc;

/// U5 measurement addition: a forwarding, per-method-counting proxy for
/// distinguishing "this suite got slower because chain-length-independent
/// per-call latency accumulated" from "this suite got slower because it is
/// issuing MORE calls, or a call that costs more, as the shared chain/
/// wallet grow" — see its own doc comment.
pub mod count_proxy;

use std::cell::RefCell;
use std::collections::{BTreeSet, HashSet};
use std::str::FromStr;

use app_core::bitcoin::{
    absolute::LockTime, secp256k1::PublicKey, secp256k1::Secp256k1, secp256k1::SecretKey,
    transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use app_core::chain::{
    discover_indexes, discover_spending, scan_change_chain, scan_change_chain_watch, ChainClient,
    Transport, TxLookupStatus,
};
use app_core::funding::FundingSource;
use app_core::identity::KeyMaterial;
use app_core::keyexport::export_formats;
use app_core::notes_core::address::{
    address_to_script_pubkey, p2wpkh_address, taproot_address,
};
use app_core::notes_core::keys::{hash160, xonly_pubkey};
use app_core::notes_core::taproot::taproot_tweak_pubkey;
use app_core::notes_core::Network;
use app_core::Error;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------
// Scenario: plain, backend-agnostic chain-state description
// ---------------------------------------------------------------------

/// One transaction in a [`Scenario`], ordered oldest → newest within
/// `Scenario::txs`.
#[derive(Debug, Clone)]
pub struct ScenarioTx {
    pub txid: String,
    /// Raw tx hex — what `fetch_tx_hex` must return verbatim.
    pub hex: String,
    /// `Some(height)` for a confirmed tx, `None` for one still in the
    /// mempool.
    pub confirmed_height: Option<u64>,
    pub vin: Vec<ScenarioIn>,
    pub vout: Vec<ScenarioOut>,
}

impl ScenarioTx {
    pub fn touches(&self, address: &str) -> bool {
        self.vout.iter().any(|o| o.address.as_deref() == Some(address))
            || self.vin.iter().any(|i| i.prevout_address.as_deref() == Some(address))
    }
}

#[derive(Debug, Clone)]
pub struct ScenarioIn {
    pub prev_txid: String,
    pub prev_vout: u32,
    /// Esplora always inlines the prevout it resolved — real or synthetic
    /// (an "external" funding coin whose own parent tx isn't tracked by
    /// this scenario, e.g. a miner/faucet payout), exactly like a real
    /// indexer would for any known input.
    pub prevout_address: Option<String>,
    pub prevout_value: u64,
}

#[derive(Debug, Clone)]
pub struct ScenarioOut {
    /// `None` for an OP_RETURN output.
    pub address: Option<String>,
    pub value: u64,
    /// Raw scriptPubKey, hex.
    pub script_hex: String,
    pub is_op_return: bool,
}

/// Optional HD-wallet context so [`assert_chain_contract`] can also drive
/// the free scan functions (`discover_indexes`, `scan_change_chain`,
/// `scan_change_chain_watch`, `discover_spending`, `ChainClient::scan_funding`)
/// against addresses whose usage is known ahead of time. `used_*` lists are
/// deliberately allowed to contain gaps (holes) below their max — the walk
/// must skip over a hole and keep going, only stopping after `gap`
/// consecutive UNUSED indexes past the last used one.
pub struct ScenarioWallet {
    pub material: KeyMaterial,
    /// A ranged watch descriptor over the SAME BIP-86 notebook account as
    /// `material` — the watch-only sibling functions
    /// (`scan_change_chain_watch`) must see identical addresses/coins.
    pub notebook_watch: FundingSource,
    /// The BIP-84 spending-wallet branch of the same seed.
    pub spending: FundingSource,
    pub account: u32,
    pub gap: u32,
    /// BIP-86 notebook receive-chain (chain 0) indexes with on-chain
    /// history — what `discover_indexes` must return, in ascending order.
    pub used_receive: Vec<u32>,
    /// BIP-86 notebook change-chain (chain 1) indexes with on-chain
    /// history — what `scan_change_chain`/`scan_change_chain_watch` must
    /// each report a coin for, in ascending order.
    pub used_change: Vec<u32>,
    /// BIP-84 spending-wallet receive-chain indexes with history.
    pub used_spending_receive: Vec<u32>,
    /// BIP-84 spending-wallet change-chain indexes with history.
    pub used_spending_change: Vec<u32>,
}

pub struct Scenario {
    pub network: Network,
    pub tip_height: u64,
    /// Oldest → newest.
    pub txs: Vec<ScenarioTx>,
    pub wallet: Option<ScenarioWallet>,
    /// U3 (`PLAN-chain-notes-app-core-rpc.md`, "Trap 1"): a genuinely
    /// SIGNED `(raw hex, expected txid)` pair for the broadcast contract
    /// check, when the backend under test actually validates scripts (a
    /// real `bitcoind`). `EsploraFake` never validates scripts, so every
    /// existing `chain_contract.rs` scenario leaves this `None` and
    /// `assert_chain_contract` falls back to today's
    /// `build_unsigned_spend_hex` behavior, byte-identical to before this
    /// field existed. The Core RPC conformance suite is the one caller
    /// that sets it — its bitcoind driver signs a real spend with the
    /// node's own wallet.
    pub broadcast_probe: Option<(String, String)>,
}

impl Scenario {
    /// Every address appearing anywhere (an output destination, or an
    /// input's resolved prevout) across the whole scenario.
    pub fn all_addresses(&self) -> Vec<String> {
        let mut set = BTreeSet::new();
        for t in &self.txs {
            for o in &t.vout {
                if let Some(a) = &o.address {
                    set.insert(a.clone());
                }
            }
            for i in &t.vin {
                if let Some(a) = &i.prevout_address {
                    set.insert(a.clone());
                }
            }
        }
        set.into_iter().collect()
    }

    /// Every outpoint (txid, vout) referenced as an input anywhere in the
    /// scenario — spent, regardless of whether the spending tx itself is
    /// confirmed or still in the mempool (matching real esplora: a
    /// mempool-spent coin is unavailable too).
    fn spent_outpoints(&self) -> HashSet<(String, u32)> {
        self.txs.iter().flat_map(|t| t.vin.iter().map(|i| (i.prev_txid.clone(), i.prev_vout))).collect()
    }

    /// `address`'s history, newest-first: unconfirmed (mempool) txs first,
    /// then confirmed ones by descending height — same order real esplora's
    /// `/address/:a/txs` uses. Stable among ties (mirrors "insertion order,
    /// newest last" ⇒ reversed).
    pub fn history_desc(&self, address: &str) -> Vec<&ScenarioTx> {
        let mut v: Vec<&ScenarioTx> = self.txs.iter().filter(|t| t.touches(address)).collect();
        v.reverse();
        v.sort_by(|a, b| match (a.confirmed_height, b.confirmed_height) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(ha), Some(hb)) => hb.cmp(&ha),
        });
        v
    }

    /// `address`'s currently-unspent outputs: (txid, vout, value, height).
    /// A coin spent by ANY known tx (chain or mempool) is excluded.
    pub fn utxos_for(&self, address: &str) -> Vec<(String, u32, u64, Option<u64>)> {
        let spent = self.spent_outpoints();
        let mut out = Vec::new();
        for t in &self.txs {
            for (idx, o) in t.vout.iter().enumerate() {
                if o.address.as_deref() == Some(address) && !spent.contains(&(t.txid.clone(), idx as u32)) {
                    out.push((t.txid.clone(), idx as u32, o.value, t.confirmed_height));
                }
            }
        }
        out
    }

    /// Esplora `chain_stats`/`mempool_stats` shape, replicated purely from
    /// scenario data: (chain_tx_count, chain_funded, chain_spent,
    /// mempool_tx_count, mempool_funded, mempool_spent). `funded` sums every
    /// output value paid TO `address` in a bucket's txs; `spent` sums the
    /// value of `address`'s own outputs consumed by a bucket's txs (mirrors
    /// `companion/server.py`'s `esplora_tx`/`/address` handler, the working
    /// reference implementation this maps onto Core RPC).
    pub fn stats_for(&self, address: &str) -> (u64, u64, u64, u64, u64, u64) {
        let (mut ctc, mut cf, mut cs, mut mtc, mut mf, mut ms) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        for t in &self.txs {
            let mut funded = 0u64;
            let mut spent = 0u64;
            let mut touched = false;
            for o in &t.vout {
                if o.address.as_deref() == Some(address) {
                    funded += o.value;
                    touched = true;
                }
            }
            for i in &t.vin {
                if i.prevout_address.as_deref() == Some(address) {
                    spent += i.prevout_value;
                    touched = true;
                }
            }
            if !touched {
                continue;
            }
            if t.confirmed_height.is_some() {
                ctc += 1;
                cf += funded;
                cs += spent;
            } else {
                mtc += 1;
                mf += funded;
                ms += spent;
            }
        }
        (ctc, cf, cs, mtc, mf, ms)
    }
}

// ---------------------------------------------------------------------
// ScenarioBuilder: assembles real bitcoin::Transaction values
// ---------------------------------------------------------------------

/// Where a `ScenarioBuilder::add_tx` input's coin comes from.
pub enum InSpec {
    /// Spend output `vout` of a transaction already added to this builder.
    Prior { txid: String, vout: u32 },
    /// A coin from OUTSIDE the scenario's tracked history (a miner/faucet
    /// payout) — carries a genuine prevout address+value so the rendered
    /// vin looks exactly like a real indexer's, but its own parent tx is
    /// deliberately not represented (nothing in these tests ever looks it
    /// up by txid).
    External { address: String, value: u64 },
}

/// One `ScenarioBuilder::add_tx` output.
pub enum OutSpec {
    Pay { address: String, value: u64 },
    OpReturn { payload: Vec<u8> },
}

pub struct ScenarioBuilder {
    network: Network,
    tip_height: u64,
    txs: Vec<ScenarioTx>,
    wallet: Option<ScenarioWallet>,
    counter: u64,
}

/// Legacy-style OP_RETURN push encoding (matches
/// `notes_core::tx::op_return_payload`'s decoder exactly): `OP_RETURN` +
/// direct push (<=75) / OP_PUSHDATA1 (<=255) / OP_PUSHDATA2 (<=65535).
fn op_return_script(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x6a];
    let len = payload.len();
    if len <= 75 {
        v.push(len as u8);
    } else if len <= 255 {
        v.push(0x4c);
        v.push(len as u8);
    } else {
        v.push(0x4d);
        v.extend_from_slice(&(len as u16).to_le_bytes());
    }
    v.extend_from_slice(payload);
    v
}

impl ScenarioBuilder {
    pub fn new(network: Network, tip_height: u64) -> Self {
        ScenarioBuilder { network, tip_height, txs: Vec::new(), wallet: None, counter: 0 }
    }

    fn next_hash(&mut self, role: &str) -> [u8; 32] {
        self.counter += 1;
        let mut h = Sha256::new();
        h.update(b"chain-contract-scenario/");
        h.update(role.as_bytes());
        h.update(self.counter.to_le_bytes());
        h.finalize().into()
    }

    /// A fresh, genuine taproot address (key-path only, no script tree) —
    /// real `notes_core` BIP-341 tweak machinery, deterministic (hash-derived)
    /// secret key so tests are reproducible.
    pub fn taproot_addr(&mut self, role: &str) -> String {
        loop {
            let sk = self.next_hash(role);
            if let Ok((internal_x, _odd)) = xonly_pubkey(&sk) {
                if let Ok((output_x, _)) = taproot_tweak_pubkey(&internal_x, None) {
                    return taproot_address(self.network, &output_x);
                }
            }
            // internal_x/tweak land off-curve with negligible probability —
            // loop retries with the next counter-derived hash.
        }
    }

    /// A fresh, genuine P2WPKH address.
    pub fn wpkh_addr(&mut self, role: &str) -> String {
        let sk = self.next_hash(role);
        let secp = Secp256k1::new();
        let seckey = SecretKey::from_slice(&sk).expect("32-byte hash is a valid scalar w.h.p.");
        let pk = PublicKey::from_secret_key(&secp, &seckey);
        let hash = hash160(&pk.serialize());
        p2wpkh_address(self.network, &hash)
    }

    /// Add a transaction; returns its computed txid. Values are the
    /// caller's responsibility to balance (inputs ≥ outputs) — the plan's
    /// "no impossible states" constraint.
    pub fn add_tx(&mut self, ins: Vec<InSpec>, outs: Vec<OutSpec>, confirmed_height: Option<u64>) -> String {
        let mut scenario_ins = Vec::with_capacity(ins.len());
        let mut btc_ins = Vec::with_capacity(ins.len());
        for spec in ins {
            let (prev_txid, prev_vout, prevout_address, prevout_value) = match spec {
                InSpec::Prior { txid, vout } => {
                    let t = self.txs.iter().find(|t| t.txid == txid).expect("prior tx must already be added");
                    let o = t.vout.get(vout as usize).expect("prior vout must exist");
                    (txid, vout, o.address.clone(), o.value)
                }
                InSpec::External { address, value } => {
                    self.counter += 1;
                    let mut h = Sha256::new();
                    h.update(b"chain-contract-scenario/external-parent");
                    h.update(self.counter.to_le_bytes());
                    let txid: [u8; 32] = h.finalize().into();
                    (hex::encode(txid), 0u32, Some(address), value)
                }
            };
            btc_ins.push(TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(&prev_txid).expect("valid hex txid"),
                    vout: prev_vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            scenario_ins.push(ScenarioIn { prev_txid, prev_vout, prevout_address, prevout_value });
        }

        let mut scenario_outs = Vec::with_capacity(outs.len());
        let mut btc_outs = Vec::with_capacity(outs.len());
        for spec in outs {
            match spec {
                OutSpec::Pay { address, value } => {
                    let spk = address_to_script_pubkey(self.network, &address)
                        .expect("scenario address must be valid for its own network");
                    btc_outs.push(TxOut { value: Amount::from_sat(value), script_pubkey: ScriptBuf::from_bytes(spk.clone()) });
                    scenario_outs.push(ScenarioOut {
                        address: Some(address),
                        value,
                        script_hex: hex::encode(&spk),
                        is_op_return: false,
                    });
                }
                OutSpec::OpReturn { payload } => {
                    let spk = op_return_script(&payload);
                    btc_outs.push(TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::from_bytes(spk.clone()) });
                    scenario_outs.push(ScenarioOut { address: None, value: 0, script_hex: hex::encode(&spk), is_op_return: true });
                }
            }
        }

        let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: btc_ins, output: btc_outs };
        let txid = tx.compute_txid().to_string();
        let hex_str = app_core::bitcoin::consensus::encode::serialize_hex(&tx);
        self.txs.push(ScenarioTx { txid: txid.clone(), hex: hex_str, confirmed_height, vin: scenario_ins, vout: scenario_outs });
        txid
    }

    pub fn with_wallet(mut self, wallet: ScenarioWallet) -> Self {
        self.wallet = Some(wallet);
        self
    }

    pub fn build(self) -> Scenario {
        Scenario {
            network: self.network,
            tip_height: self.tip_height,
            txs: self.txs,
            wallet: self.wallet,
            // Every ScenarioBuilder-built scenario is made of UNSIGNED txs
            // (module doc above) — never broadcastable against a real
            // backend, so this always falls back to the old
            // build_unsigned_spend_hex path (harmless against
            // EsploraFake, which never validates scripts anyway).
            broadcast_probe: None,
        }
    }
}

/// Build a [`ScenarioWallet`] for `material` (a mnemonic) at `account`,
/// funding notebook receive/change indexes and BIP-84 spending indexes per
/// the `used_*` args (ascending, holes allowed) — one confirmed funding tx
/// per used index, into `builder`. `material_str` is the mnemonic's own
/// string form (needed to derive the notebook account's watch descriptor
/// via `keyexport::export_formats`).
pub fn attach_wallet(
    builder: &mut ScenarioBuilder,
    material_str: &str,
    network: Network,
    account: u32,
    gap: u32,
    used_receive: Vec<u32>,
    used_change: Vec<u32>,
    used_spending_receive: Vec<u32>,
    used_spending_change: Vec<u32>,
    tip_height: u64,
) -> ScenarioWallet {
    use app_core::identity::{parse_key_material, realize, realize_change};
    use app_core::spending;

    let material = parse_key_material(material_str, network).expect("valid mnemonic");
    let funder = builder.taproot_addr("funder");

    for &idx in &used_receive {
        let addr = realize(&material, network, account, idx).expect("realize notebook receive leaf").address;
        builder.add_tx(
            vec![InSpec::External { address: funder.clone(), value: 100_000 }],
            vec![OutSpec::Pay { address: addr, value: 50_000 }],
            Some(tip_height.saturating_sub(10)),
        );
    }
    for &idx in &used_change {
        let addr = realize_change(&material, network, account, idx).expect("realize notebook change leaf").address;
        builder.add_tx(
            vec![InSpec::External { address: funder.clone(), value: 100_000 }],
            vec![OutSpec::Pay { address: addr, value: 40_000 }],
            Some(tip_height.saturating_sub(9)),
        );
    }

    let spending_src = spending::funding_source(&material, network, account).expect("spending funding_source");
    for &idx in &used_spending_receive {
        let addr = spending_src.derive(0, idx).expect("derive spending receive leaf").address;
        builder.add_tx(
            vec![InSpec::External { address: funder.clone(), value: 100_000 }],
            vec![OutSpec::Pay { address: addr, value: 30_000 }],
            Some(tip_height.saturating_sub(8)),
        );
    }
    for &idx in &used_spending_change {
        let addr = spending_src.derive(1, idx).expect("derive spending change leaf").address;
        builder.add_tx(
            vec![InSpec::External { address: funder.clone(), value: 100_000 }],
            vec![OutSpec::Pay { address: addr, value: 20_000 }],
            Some(tip_height.saturating_sub(7)),
        );
    }

    let descriptor = export_formats(material_str, network, account, 0)
        .expect("export_formats")
        .descriptor
        .expect("mnemonic yields a tr() descriptor");
    let notebook_watch = FundingSource::parse(&descriptor, network).expect("parse notebook watch descriptor");

    ScenarioWallet {
        material,
        notebook_watch,
        spending: spending_src,
        account,
        gap,
        used_receive,
        used_change,
        used_spending_receive,
        used_spending_change,
    }
}

// ---------------------------------------------------------------------
// EsploraFake: serves a Scenario as correct Esplora JSON
// ---------------------------------------------------------------------

pub struct EsploraFake<'a> {
    pub scenario: &'a Scenario,
    pub requests: RefCell<Vec<String>>,
    pub posts: RefCell<Vec<(String, String)>>,
}

impl<'a> EsploraFake<'a> {
    pub fn new(scenario: &'a Scenario) -> Self {
        EsploraFake { scenario, requests: RefCell::new(Vec::new()), posts: RefCell::new(Vec::new()) }
    }

    /// Requested paths since the last call, in order — cleared. Lets a test
    /// assert one method's exact request sequence without earlier calls'
    /// paths leaking in.
    pub fn drain_requests(&self) -> Vec<String> {
        std::mem::take(&mut *self.requests.borrow_mut())
    }
}

fn confirmed_desc<'a>(sc: &'a Scenario, address: &str) -> Vec<&'a ScenarioTx> {
    sc.history_desc(address).into_iter().filter(|t| t.confirmed_height.is_some()).collect()
}

fn mempool_desc<'a>(sc: &'a Scenario, address: &str) -> Vec<&'a ScenarioTx> {
    sc.history_desc(address).into_iter().filter(|t| t.confirmed_height.is_none()).collect()
}

fn tx_json(t: &ScenarioTx) -> serde_json::Value {
    let vin: Vec<serde_json::Value> = t
        .vin
        .iter()
        .map(|i| {
            serde_json::json!({
                "txid": i.prev_txid,
                "vout": i.prev_vout,
                "prevout": {
                    "scriptpubkey_address": i.prevout_address,
                    "value": i.prevout_value,
                },
            })
        })
        .collect();
    let vout: Vec<serde_json::Value> = t
        .vout
        .iter()
        .map(|o| {
            let ty = if o.is_op_return {
                "op_return"
            } else if o.address.as_deref().map(is_taproot).unwrap_or(false) {
                "v1_p2tr"
            } else {
                "v0_p2wpkh"
            };
            serde_json::json!({
                "scriptpubkey": o.script_hex,
                "scriptpubkey_type": ty,
                "scriptpubkey_address": o.address,
                "value": o.value,
            })
        })
        .collect();
    let status = match t.confirmed_height {
        Some(h) => serde_json::json!({"confirmed": true, "block_height": h, "block_time": 1_700_000_000u64 + h}),
        None => serde_json::json!({"confirmed": false}),
    };
    serde_json::json!({"txid": t.txid, "vin": vin, "vout": vout, "status": status})
}

fn is_taproot(addr: &str) -> bool {
    addr.starts_with("bc1p") || addr.starts_with("tb1p") || addr.starts_with("bcrt1p")
}

fn addr_stats_json(sc: &Scenario, address: &str) -> String {
    let (ctc, cf, cs, mtc, mf, ms) = sc.stats_for(address);
    serde_json::json!({
        "chain_stats": {"tx_count": ctc, "funded_txo_sum": cf, "spent_txo_sum": cs},
        "mempool_stats": {"tx_count": mtc, "funded_txo_sum": mf, "spent_txo_sum": ms},
    })
    .to_string()
}

fn utxo_json(sc: &Scenario, address: &str) -> String {
    let items: Vec<serde_json::Value> = sc
        .utxos_for(address)
        .into_iter()
        .map(|(txid, vout, value, height)| match height {
            Some(h) => serde_json::json!({"txid": txid, "vout": vout, "value": value, "status": {"confirmed": true, "block_height": h}}),
            None => serde_json::json!({"txid": txid, "vout": vout, "value": value, "status": {"confirmed": false}}),
        })
        .collect();
    serde_json::to_string(&items).unwrap()
}

fn first_page_json(sc: &Scenario, address: &str) -> String {
    let mut items: Vec<serde_json::Value> = mempool_desc(sc, address).iter().map(|t| tx_json(t)).collect();
    items.extend(confirmed_desc(sc, address).into_iter().take(25).map(tx_json));
    serde_json::to_string(&items).unwrap()
}

fn chain_page_json(sc: &Scenario, address: &str, after_txid: &str) -> String {
    let confirmed = confirmed_desc(sc, address);
    let items: Vec<serde_json::Value> = match confirmed.iter().position(|t| t.txid == after_txid) {
        Some(i) => confirmed.iter().skip(i + 1).take(25).map(|t| tx_json(t)).collect(),
        None => Vec::new(),
    };
    serde_json::to_string(&items).unwrap()
}

fn route(sc: &Scenario, path: &str) -> Result<String, Error> {
    if path == "/blocks/tip/height" {
        return Ok(sc.tip_height.to_string());
    }
    if path == "/v1/fees/recommended" {
        return Ok(r#"{"fastestFee":3,"halfHourFee":2,"hourFee":1,"economyFee":1,"minimumFee":1}"#.into());
    }
    if path == "/v1/prices" {
        return Ok(r#"{"time":1700000000,"USD":65000.0}"#.into());
    }
    if let Some(rest) = path.strip_prefix("/address/") {
        let mut parts = rest.splitn(2, '/');
        let address = parts.next().unwrap_or("").to_string();
        return match parts.next() {
            None => Ok(addr_stats_json(sc, &address)),
            Some("utxo") => Ok(utxo_json(sc, &address)),
            Some("txs") => Ok(first_page_json(sc, &address)),
            Some(sub) if sub.starts_with("txs/chain/") => {
                Ok(chain_page_json(sc, &address, &sub["txs/chain/".len()..]))
            }
            Some(other) => Err(Error::Http(format!("404: no route /address/.../{other}"))),
        };
    }
    if let Some(rest) = path.strip_prefix("/tx/") {
        return if let Some(txid) = rest.strip_suffix("/hex") {
            match sc.txs.iter().find(|t| t.txid == txid) {
                Some(t) => Ok(t.hex.clone()),
                None => Err(Error::Http(format!("404: tx not found: {txid}"))),
            }
        } else {
            match sc.txs.iter().find(|t| t.txid == rest) {
                Some(t) => Ok(tx_json(t).to_string()),
                None => Err(Error::Http(format!("404: tx not found: {rest}"))),
            }
        };
    }
    Err(Error::Http(format!("404: no route for {path}")))
}

impl<'a> Transport for EsploraFake<'a> {
    fn get_text(&self, path: &str) -> Result<String, Error> {
        self.requests.borrow_mut().push(path.to_string());
        route(self.scenario, path)
    }

    fn post_text(&self, path: &str, body: String) -> Result<String, Error> {
        self.requests.borrow_mut().push(path.to_string());
        if path != "/tx" {
            return Err(Error::Http(format!("404: no POST route for {path}")));
        }
        let bytes = hex::decode(body.trim()).map_err(|_| Error::Http("400: raw tx must be hex".into()))?;
        let tx: Transaction = app_core::bitcoin::consensus::encode::deserialize(&bytes)
            .map_err(|e| Error::Http(format!("400: bad raw tx: {e}")))?;
        let txid = tx.compute_txid().to_string();
        self.posts.borrow_mut().push((path.to_string(), body));
        Ok(txid)
    }
}

/// Build an UNSIGNED (but structurally real) transaction spending
/// `(from_txid, from_vout)` — a coin actually present in the scenario —
/// to a fresh throwaway address, for the `broadcast` contract check.
/// Returns (raw hex, the txid a REAL backend would compute and echo back —
/// derived from the hex itself via `bitcoin`, never hand-picked).
pub fn build_unsigned_spend_hex(network: Network, from_txid: &str, from_vout: u32, from_value: u64) -> (String, String) {
    let mut h = Sha256::new();
    h.update(b"chain-contract-scenario/broadcast-dest");
    h.update(from_txid.as_bytes());
    h.update(from_vout.to_le_bytes());
    let sk: [u8; 32] = h.finalize().into();
    let (internal_x, _) = xonly_pubkey(&sk).expect("valid internal key");
    let (output_x, _) = taproot_tweak_pubkey(&internal_x, None).expect("valid tweak");
    let dest = taproot_address(network, &output_x);
    let spk = address_to_script_pubkey(network, &dest).expect("valid dest address");

    const FEE: u64 = 200;
    let value = from_value.saturating_sub(FEE).max(1);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid: Txid::from_str(from_txid).expect("valid txid"), vout: from_vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(value), script_pubkey: ScriptBuf::from_bytes(spk) }],
    };
    let txid = tx.compute_txid().to_string();
    (app_core::bitcoin::consensus::encode::serialize_hex(&tx), txid)
}

// ---------------------------------------------------------------------
// The contract battery
// ---------------------------------------------------------------------

/// Compares two UTXO tuple-lists `(txid, vout, value, height)`, tolerating
/// exactly ONE shared-node hazard (`PLAN-one-regtest-node.md`): a coin the
/// scenario recorded UNCONFIRMED (`height: None`) may have since been
/// mined by `regtest-automine.service` during a long test run against the
/// Pi's persistent chain — that's fine, `got`'s height for it may be
/// `Some(_)` too. This is a NO-OP against `EsploraFake` (nothing there ever
/// mines anything mid-test, so a recorded `None` always comes back `None`)
/// — the tolerance only ever matters, and only ever loosens the exact
/// case, against a real live backend. Everything else must still match
/// exactly: the coin SET (by txid/vout — sorted on that alone, never on
/// height, so a since-confirmed coin's changed height can't desync the
/// pairing), every value, and any ALREADY-confirmed height (never
/// regresses, never silently changes to a different height — that would be
/// a genuine bug, not a race). `sc_tip` is the scenario's own recorded tip
/// height — a legitimate "since confirmed" height must be at or after it,
/// since mining only ever moves forward.
fn assert_utxos_match_tolerant(
    label: &str,
    mut expected: Vec<(String, u32, u64, Option<u64>)>,
    mut got: Vec<(String, u32, u64, Option<u64>)>,
    sc_tip: u64,
) {
    expected.sort_by(|a, b| (a.0.clone(), a.1).cmp(&(b.0.clone(), b.1)));
    got.sort_by(|a, b| (a.0.clone(), a.1).cmp(&(b.0.clone(), b.1)));
    assert_eq!(
        got.iter().map(|u| (u.0.clone(), u.1)).collect::<Vec<_>>(),
        expected.iter().map(|u| (u.0.clone(), u.1)).collect::<Vec<_>>(),
        "{label}: utxo (txid,vout) set"
    );
    for ((et, ev, eval, eh), (_gt, _gv, gval, gh)) in expected.iter().zip(got.iter()) {
        assert_eq!(gval, eval, "{label}: value for {et}:{ev}");
        match eh {
            Some(_) => assert_eq!(
                gh, eh,
                "{label}: {et}:{ev} was already confirmed at a specific height and must not change"
            ),
            None => assert!(
                gh.is_none() || gh.unwrap() >= sc_tip,
                "{label}: {et}:{ev} recorded unconfirmed — if it has since confirmed (shared node, \
                 PLAN-one-regtest-node.md), the height must be >= the scenario's own tip ({sc_tip}), \
                 got {gh:?}"
            ),
        }
    }
}

/// Backend-agnostic semantics battery: "given this chain state, this method
/// returns this." Contains NO Esplora-specific assertions (no request-path
/// or raw-JSON checks — see `tests/esplora_paths.rs` for those) so it can
/// later be called VERBATIM against `ChainClient<CoreRpcTransport>` pointed
/// at a real `bitcoind` holding the same scenario.
///
/// **Never asserts an exact tip height or an exact confirmed-vs-mempool
/// split** (`PLAN-one-regtest-node.md`: the shared regtest node this may be
/// checked against grows underneath a long test run) — every height/
/// confirmation-state comparison below is a `>=`/tolerant check instead,
/// see [`assert_utxos_match_tolerant`] and the inline comments at each
/// remaining site.
pub fn assert_chain_contract<T: Transport>(client: &ChainClient<T>, sc: &Scenario) {
    let live_tip = client.tip_height().unwrap();
    assert!(
        live_tip >= sc.tip_height,
        "tip_height must be >= what the scenario recorded (a shared node only ever advances): \
         live={live_tip}, scenario={}",
        sc.tip_height
    );

    for address in sc.all_addresses() {
        // utxos: values, confirmed flag (via height), block_height.
        let expected = sc.utxos_for(&address);
        let got: Vec<(String, u32, u64, Option<u64>)> =
            client.utxos(&address).unwrap().into_iter().map(|u| (u.txid, u.vout, u.value, u.height)).collect();
        assert_utxos_match_tolerant(&format!("utxos({address})"), expected, got, sc.tip_height);

        // full_history: complete address history, deduped, regardless of
        // page count.
        let hist = client.full_history(&address).unwrap();
        let mut got_ids: Vec<String> = hist.iter().map(|t| t.txid.clone()).collect();
        let mut dedup_ids = got_ids.clone();
        dedup_ids.sort();
        dedup_ids.dedup();
        assert_eq!(dedup_ids.len(), got_ids.len(), "full_history({address}) must not repeat a txid");
        got_ids.sort();
        let mut exp_ids: Vec<String> = sc.history_desc(&address).iter().map(|t| t.txid.clone()).collect();
        exp_ids.sort();
        assert_eq!(got_ids, exp_ids, "full_history({address}) txid set");

        // address_stats: chain vs mempool funded/spent/tx_count. The
        // CHAIN/MEMPOOL SPLIT is tolerant of the same shared-node hazard as
        // the utxos check above — a scenario-recorded mempool tx may have
        // since been mined, moving its contribution from the mempool
        // bucket to the chain bucket. The TOTALS must still match exactly
        // (nothing may appear/disappear), and the mempool bucket may only
        // ever SHRINK relative to what was recorded (coins graduate
        // mempool -> chain during a long run, never the reverse).
        let (ctc, cf, cs, mtc, mf, ms) = sc.stats_for(&address);
        let stats = client.address_stats(&address).unwrap();
        assert_eq!(
            stats.chain_tx_count + stats.mempool_tx_count,
            ctc + mtc,
            "address_stats({address}) total tx_count"
        );
        assert_eq!(stats.chain_funded + stats.mempool_funded, cf + mf, "address_stats({address}) total funded");
        assert_eq!(stats.chain_spent + stats.mempool_spent, cs + ms, "address_stats({address}) total spent");
        assert!(
            stats.mempool_tx_count <= mtc,
            "address_stats({address}) mempool_tx_count must only shrink (mempool -> chain confirmation), \
             never grow: expected <= {mtc}, got {}",
            stats.mempool_tx_count
        );
        assert!(
            stats.chain_tx_count >= ctc,
            "address_stats({address}) chain_tx_count must never be fewer than what was already recorded \
             confirmed: expected >= {ctc}, got {}",
            stats.chain_tx_count
        );

        // address_used / address_probe.
        assert_eq!(client.address_used(&address).unwrap(), (ctc + mtc) > 0, "address_used({address})");
        let (probe_used, probe_balance) = client.address_probe(&address).unwrap();
        assert_eq!(probe_used, !sc.history_desc(&address).is_empty(), "address_probe({address}).0");
        let expected_balance: u64 = sc.utxos_for(&address).iter().map(|u| u.2).sum();
        assert_eq!(probe_balance, expected_balance, "address_probe({address}).1");
    }

    // An address never mentioned anywhere in the scenario reads as
    // definitively unused (no on-chain history) — never an error/404 (real
    // esplora never 404s an address, only an unknown txid).
    let never_used = "scenario-address-with-no-history";
    if !sc.all_addresses().iter().any(|a| a == never_used) {
        assert_eq!(client.address_used(never_used).unwrap(), false, "an untouched address is never 'used'");
        assert!(client.utxos(never_used).unwrap().is_empty());
    }

    // fetch_tx_hex / fetch_tx_status for every tx in the scenario. A tx
    // recorded CONFIRMED must stay confirmed (exact); one recorded
    // UNCONFIRMED may read back either way (still mempool, or since mined
    // by the shared node's automine — same tolerance as the utxos check
    // above) but must never vanish entirely (`None`).
    for tx in &sc.txs {
        assert_eq!(client.fetch_tx_hex(&tx.txid).unwrap(), tx.hex, "fetch_tx_hex({})", tx.txid);
        let status = client.fetch_tx_status(&tx.txid);
        if tx.confirmed_height.is_some() {
            assert_eq!(status, Some(true), "fetch_tx_status({}) recorded confirmed must stay confirmed", tx.txid);
        } else {
            assert!(
                status.is_some(),
                "fetch_tx_status({}) recorded as mempool must still be known (Some), never disappear \
                 — got None",
                tx.txid
            );
        }
    }

    // tx_lookup_status: Found(true), Found(false)-or-since-confirmed,
    // NotFound.
    if let Some(t) = sc.txs.iter().find(|t| t.confirmed_height.is_some()) {
        assert_eq!(client.tx_lookup_status(&t.txid), TxLookupStatus::Found(true), "tx_lookup_status confirmed");
    }
    if let Some(t) = sc.txs.iter().find(|t| t.confirmed_height.is_none()) {
        let status = client.tx_lookup_status(&t.txid);
        assert!(
            matches!(status, TxLookupStatus::Found(_)),
            "tx_lookup_status({}) recorded as mempool must still be Found — confirmed=true is fine, it \
             may have been mined since the scenario snapshot (shared node) — got {status:?}",
            t.txid
        );
    }
    let unknown_txid = "ff".repeat(32);
    assert_eq!(client.tx_lookup_status(&unknown_txid), TxLookupStatus::NotFound, "tx_lookup_status unknown");

    // outpoint_unspent: a spent AND an unspent outpoint, when the scenario
    // has both.
    let spent_set: HashSet<(String, u32)> = sc.txs.iter().flat_map(|t| t.vin.iter().map(|i| (i.prev_txid.clone(), i.prev_vout))).collect();
    'spent: for t in &sc.txs {
        for (idx, o) in t.vout.iter().enumerate() {
            if let Some(addr) = &o.address {
                if spent_set.contains(&(t.txid.clone(), idx as u32)) {
                    assert_eq!(client.outpoint_unspent(addr, &t.txid, idx as u32), Some(false), "outpoint_unspent: spent");
                    break 'spent;
                }
            }
        }
    }
    'unspent: for t in &sc.txs {
        for (idx, o) in t.vout.iter().enumerate() {
            if let Some(addr) = &o.address {
                if !spent_set.contains(&(t.txid.clone(), idx as u32)) {
                    assert_eq!(client.outpoint_unspent(addr, &t.txid, idx as u32), Some(true), "outpoint_unspent: unspent");
                    break 'unspent;
                }
            }
        }
    }

    // fetch_tx_io: a tx with at least one input — coins + outputs mirror
    // the scenario data exactly.
    if let Some(t) = sc.txs.iter().find(|t| !t.vin.is_empty()) {
        let (coins, outputs, confirmed) = client.fetch_tx_io(&t.txid, |_| None).unwrap();
        assert_eq!(confirmed, t.confirmed_height.is_some(), "fetch_tx_io confirmed flag");
        assert_eq!(coins.len(), t.vin.len(), "fetch_tx_io coin count");
        for (c, i) in coins.iter().zip(t.vin.iter()) {
            assert_eq!(c.txid, i.prev_txid);
            assert_eq!(c.vout, i.prev_vout);
            assert_eq!(c.value, i.prevout_value);
        }
        assert_eq!(outputs.len(), t.vout.len(), "fetch_tx_io output count");
        for (got, o) in outputs.iter().zip(t.vout.iter()) {
            assert_eq!(hex::encode(&got.0), o.script_hex);
            assert_eq!(got.1, o.value);
        }
    }

    // build_bundle: an address with at least one OP_RETURN-carrying tx.
    if let Some(address) = sc.all_addresses().into_iter().find(|a| sc.history_desc(a).iter().any(|t| t.vout.iter().any(|o| o.is_op_return))) {
        let bundle = client.build_bundle(&address, None).unwrap();
        assert!(
            bundle.tip_height >= sc.tip_height,
            "build_bundle tip_height must be >= what the scenario recorded: live={}, scenario={}",
            bundle.tip_height,
            sc.tip_height
        );
        assert!(bundle.full, "build_bundle(since_height=None).full");
        let expected_note_txids: HashSet<String> = sc
            .history_desc(&address)
            .iter()
            .filter(|t| t.vout.iter().any(|o| o.is_op_return))
            .map(|t| t.txid.clone())
            .collect();
        let got_note_txids: HashSet<String> = bundle.notes_onchain.iter().map(|t| t.txid.clone()).collect();
        assert_eq!(got_note_txids, expected_note_txids, "build_bundle notes_onchain for {address}");
        let exp_utxo = sc.utxos_for(&address);
        let got_utxo: Vec<(String, u32, u64, Option<u64>)> =
            bundle.utxos.iter().map(|u| (u.txid.clone(), u.vout, u.value, u.height)).collect();
        assert_utxos_match_tolerant(&format!("build_bundle utxos for {address}"), exp_utxo, got_utxo, sc.tip_height);
    }

    // broadcast: the backend must accept a real tx and echo the txid a
    // genuine decode computes. `EsploraFake` never validates scripts, so an
    // UNSIGNED spend (today's behavior, `build_unsigned_spend_hex`) is fine
    // there; a real backend (`bitcoind`) rejects an unsigned input, so
    // `sc.broadcast_probe` (Trap 1, PLAN-chain-notes-app-core-rpc.md) lets
    // such a caller supply a GENUINELY signed tx instead. Either way the
    // assertion itself — the backend must return the tx's own txid — is
    // identical.
    if let Some((hex_tx, expected_txid)) = &sc.broadcast_probe {
        let got_txid = client.broadcast(hex_tx).unwrap();
        assert_eq!(got_txid, *expected_txid, "broadcast must return the backend's own computed txid");
    } else if let Some(address) = sc.all_addresses().into_iter().find(|a| !sc.utxos_for(a).is_empty()) {
        let (txid, vout, value, _height) = sc.utxos_for(&address)[0].clone();
        let (hex_tx, expected_txid) = build_unsigned_spend_hex(sc.network, &txid, vout, value);
        let got_txid = client.broadcast(&hex_tx).unwrap();
        assert_eq!(got_txid, expected_txid, "broadcast must return the backend's own computed txid");
    }

    // Free scan functions, when the scenario carries wallet context.
    if let Some(w) = &sc.wallet {
        let found = discover_indexes(client, &w.material, sc.network, w.account, &[], w.gap);
        assert_eq!(found, w.used_receive, "discover_indexes (gap-limit walk over the notebook receive chain)");

        let change = scan_change_chain(client, &w.material, sc.network, w.account, w.gap).unwrap();
        let mut change_idx: Vec<u32> = change.iter().map(|c| c.index).collect();
        change_idx.sort();
        change_idx.dedup();
        assert_eq!(change_idx, w.used_change, "scan_change_chain (keyed)");

        let watch_change = scan_change_chain_watch(client, &w.notebook_watch, w.gap).unwrap();
        let mut watch_idx: Vec<u32> = watch_change.iter().map(|c| c.index).collect();
        watch_idx.sort();
        watch_idx.dedup();
        assert_eq!(watch_idx, w.used_change, "scan_change_chain_watch must match the keyed change walk");
        // The watch and keyed walks must agree coin-for-coin, not merely on
        // which indexes are used.
        let mut keyed_coins: Vec<(u32, String, u32, u64)> =
            change.iter().map(|c| (c.index, c.txid.clone(), c.vout, c.value)).collect();
        let mut watch_coins: Vec<(u32, String, u32, u64)> =
            watch_change.iter().map(|c| (c.index, c.txid.clone(), c.vout, c.value)).collect();
        keyed_coins.sort();
        watch_coins.sort();
        assert_eq!(keyed_coins, watch_coins, "keyed vs watch change-chain coins");

        // discover_spending/scan_funding's "next unused index" is a frontier
        // computed the same way for both (first unused index, holes don't
        // count) — already pinned down by chain.rs's own unit tests
        // (`discover_spending_finds_both_chains_past_holes`); this battery's
        // job is the found-address SET, which the two calls must agree on.
        let (spend_used, _next_receive, _next_change) = discover_spending(client, &w.spending, w.gap);
        let mut recv_idx: Vec<u32> = spend_used.iter().filter(|a| a.chain == 0).map(|a| a.index).collect();
        recv_idx.sort();
        assert_eq!(recv_idx, w.used_spending_receive, "discover_spending receive chain");
        let mut chg_idx: Vec<u32> = spend_used.iter().filter(|a| a.chain == 1).map(|a| a.index).collect();
        chg_idx.sort();
        assert_eq!(chg_idx, w.used_spending_change, "discover_spending change chain");

        let scan = client.scan_funding(&w.spending, w.gap).unwrap();
        let mut scan_recv: Vec<u32> = scan.used.iter().filter(|a| a.chain == 0).map(|a| a.index).collect();
        scan_recv.sort();
        assert_eq!(scan_recv, w.used_spending_receive, "scan_funding receive chain matches discover_spending");
        let mut scan_chg: Vec<u32> = scan.used.iter().filter(|a| a.chain == 1).map(|a| a.index).collect();
        scan_chg.sort();
        assert_eq!(scan_chg, w.used_spending_change, "scan_funding change chain matches discover_spending");
    }
}
