//! M6 shell: onboarding (import / create+quiz), home + notes, compose
//! with live cost, contacts picker, settings. Every callback emits a
//! `cb:` log-contract line (grep targets for the M7 UI e2e).
//!
//! Env overrides for tests: APP_DATA_DIR, APP_KEY (bypasses keychain),
//! APP_NETWORK.

mod camera;
mod keychain;
mod platform;
mod qr;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use app_core::bitcoin;
use app_core::chain::{
    default_base, explorer_presets, explorer_tx_url, node_presets, ChainClient, HttpTransport,
};
use app_core::compose::{compose_and_record, ComposeRequest};
use app_core::funding::{FundingSource, FundingUtxo, FundingWallet};
use app_core::identity::{
    generate_mnemonic, generate_mnemonic_with_salt, index_fp8, parse_key_material, realize,
    AppIdentity,
};
use app_core::notebooks::NotebookIndex;
use app_core::psbt_build::{
    build_funded_sweep_psbt, build_funding_psbt, build_watch_bump_psbt, build_watch_note_psbt,
    build_watch_spend_psbt, predict_keyspend_vsize, sign_own_taproot_inputs, BuiltPsbt,
    FundingPlan, NoteParams, WatchCoin,
};
use app_core::psbt_finalize::{
    finalize_extract, parse_psbt, summarize, validate_signed, OutputRole, SummaryContext,
};
use app_core::notes_core::address::{p2tr_script_pubkey, Recipient};
use app_core::notes_core::bundle::{estimate_note_cost, FeeRates};
use app_core::notes_core::Network;
use app_core::store::{NoteStatus, Store, DEFAULT_CHUNK};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use slint::{ComponentHandle, SharedString, VecModel};
use zeroize::Zeroizing;

slint::include_modules!();

const KEYCHAIN_ACCOUNT: &str = "identity-key";
/// Minimum (and default) sats sent to a directed-note recipient.
const DUST_SATS: u64 = app_core::notes_core::DUST_LIMIT;

struct State {
    data_dir: PathBuf,
    network: Network,
    account: u32,
    /// Device-level Settings (config.json, NOT the per-identity store): the
    /// custom Bitcoin-node / block-explorer URLs, keyed by network. Device-
    /// level so switching identity keeps them; per-network because a custom
    /// URL only makes sense on the chain it serves. Absent key = network
    /// default (mempool.space).
    node_urls: HashMap<String, String>,
    explorers: HashMap<String, String>,
    ident: Option<AppIdentity>,
    store: Option<Store>,
    fees: Option<FeeRates>,
    usd: Option<f64>,
    to_address: Option<String>, // None = self-note
    /// Coin control: selected inputs (display-txid, vout) for the compose
    /// in progress; `coins_overridden` = the user has touched the set (so
    /// stop auto-suggesting).
    selected_coins: Vec<(String, u32)>,
    coins_overridden: bool,
    /// Coin-suggestion strategy: false = fewest coins (largest-first),
    /// true = consolidate (smallest-first).
    consolidate_coins: bool,
    material: Option<Zeroizing<String>>, // session cache: avoids re-prompting Touch ID
    /// iCloud Keychain backup opt-in: when true the key is stored as a
    /// synchronizable Keychain item (syncs across the user's Apple devices and
    /// survives reinstall). Reflects the current stored item's sync state.
    icloud_backup: bool,
    pending_import: Option<Zeroizing<String>>, // hierarchical import awaiting account pick
    pending_mnemonic: Option<String>,
    quiz_indices: Vec<usize>,
    /// Edge-tracks whether the current compose draft is over the broadcast
    /// ceiling, so the "too large" dialog pops once on crossing — not on
    /// every keystroke while the draft stays too big.
    compose_oversize: bool,
    /// External-funding session (screens 12–14). The parsed funding source,
    /// its scanned spendable coins + next change index, the built unsigned
    /// PSBT, its animated-UR export frames, and the imported signed PSBT.
    funding: Option<FundingSource>,
    funding_coins: Vec<FundingUtxo>,
    funding_change_index: u32,
    built_psbt: Option<BuiltPsbt>,
    ur_frames: Vec<String>,
    signed_psbt: Option<bitcoin::Psbt>,
    /// Saved watch-only funding wallets (device-level, persisted); and which
    /// one is currently active for the compose in progress.
    funding_wallets: Vec<FundingWallet>,
    active_funding_id: Option<String>,
    /// Watch-only external-sign flow in progress: what the built PSBT on
    /// the sign screen is (sweep/consolidate/bump) and how to record it
    /// after broadcast. None while the sign screen serves external funding.
    watch_spend: Option<WatchSpend>,
    /// Chain data behind an open watch-mode bump dialog (fetched once at
    /// open; confirm rebuilds from it).
    watch_bump: Option<WatchBump>,
    /// Watch-mode compose awaiting external signature (screen 13/14).
    watch_note: Option<WatchNote>,
    /// Notebook index of the active identity (accounts-as-notebooks:
    /// names + archive flags, `notebooks-<net>-<fp8>.json`), plus its
    /// filename key and the derived (account, address, store-fp8) cache
    /// the list and sender labels read — rebuilt on activate, never per
    /// frame.
    notebooks: Option<NotebookIndex>,
    notebooks_fp8: Option<String>,
    nb_addrs: Vec<(u32, String, String)>,
}

/// Watch-mode compose in progress on the sign screen: everything needed
/// to record the (public) note after the externally signed broadcast.
struct WatchNote {
    note_id: [u8; 4],
    text: String,
    recipient: Option<String>,
    gift: u64,
    chunks: usize,
    fee: u64,
    change: u64,
    spent: Vec<app_core::store::OutPointRef>,
}

struct WatchSpend {
    kind: &'static str, // "sweep" | "consolidate" | "bump"
    dest: String,
    dest_spk_hex: String,
    value: u64,
    fee: u64,
    inputs: Vec<app_core::store::TxInput>,
    /// (ref_id, is_note) of the record being replaced when kind == "bump".
    bump_ref: Option<(String, bool)>,
}

struct WatchBump {
    ref_id: String,
    is_note: bool,
    txid: String,
    coins: Vec<WatchCoin>,
    outputs: Vec<(Vec<u8>, u64)>,
    old_fee: u64,
    vsize: u64,
}

impl State {
    /// Per-identity, per-network store file — switching keys or accounts
    /// can never collide notebooks.
    fn store_path(&self) -> Option<PathBuf> {
        let fp = hex::encode(self.ident.as_ref()?.output_x());
        Some(
            self.data_dir
                .join(format!("store-{}-{}.json", self.network.as_str(), &fp[..8])),
        )
    }

    /// The Bitcoin-node base URL: the device-level Settings choice for this
    /// network, else the network default. Configured only through the Settings
    /// screen — no env override, so tests exercise the same path a user does.
    fn base_url(&self) -> Option<String> {
        self.node_urls
            .get(self.network.as_str())
            .cloned()
            .or_else(|| default_base(self.network).map(String::from))
    }

    /// The custom block-explorer base for this network (Settings), or None for
    /// the network default — see [`explorer_tx_url`].
    fn explorer_base(&self) -> Option<String> {
        self.explorers.get(self.network.as_str()).cloned()
    }

    fn save_store(&self) {
        if let (Some(s), Some(p)) = (&self.store, self.store_path()) {
            let _ = s.save(&p);
        }
    }

    fn save_config(&self) {
        let _ = std::fs::write(
            self.data_dir.join("config.json"),
            serde_json::json!({
                "network": self.network.as_str(),
                "account": self.account,
                "nodes": self.node_urls,
                "explorers": self.explorers,
            })
            .to_string(),
        );
    }

    fn save_funding_wallets(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.funding_wallets) {
            let _ = std::fs::write(self.data_dir.join("funding-wallets.json"), json);
        }
    }

    /// The notebook index file of the active identity: keyed by the BIP-32
    /// master fingerprint so every account's notebook shares one index (and
    /// switching identities can never mix indexes).
    fn notebooks_path(&self) -> Option<PathBuf> {
        let fp8 = self.notebooks_fp8.as_ref()?;
        Some(self.data_dir.join(format!("notebooks-{}-{}.json", self.network.as_str(), fp8)))
    }

    fn save_notebooks(&self) {
        if let (Some(ix), Some(p)) = (&self.notebooks, self.notebooks_path()) {
            let _ = ix.save(&p);
        }
    }

    /// A notebook's display name: its local name, else the short form of
    /// its address (never empty — rows and the home title read this).
    fn notebook_display_name(&self, account: u32) -> String {
        let named = self
            .notebooks
            .as_ref()
            .and_then(|ix| ix.get(account))
            .map(|m| m.name.clone())
            .unwrap_or_default();
        if !named.is_empty() {
            return named;
        }
        self.nb_addrs
            .iter()
            .find(|(a, ..)| *a == account)
            .map(|(_, addr, _)| addr_short(addr))
            .unwrap_or_else(|| format!("Notebook {account}"))
    }

    /// The store file of another (not necessarily active) notebook.
    fn store_path_for(&self, address_output_x_fp8: &str) -> PathBuf {
        self.data_dir
            .join(format!("store-{}-{}.json", self.network.as_str(), address_output_x_fp8))
    }
}

/// "tb1p2ylq…q7ax" — the row/label short form of an address.
fn addr_short(a: &str) -> String {
    if a.len() > 14 {
        format!("{}…{}", &a[..9], &a[a.len() - 4..])
    } else {
        a.to_string()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn spendable_inputs(store: &Store) -> Vec<app_core::store::TxInput> {
    store
        .utxos
        .iter()
        .filter(|u| !u.pending_spend)
        .map(|u| app_core::store::TxInput { txid: u.txid.clone(), vout: u.vout, value: u.value })
        .collect()
}

/// "R.R sat/vB · F sats" (or just "F sats" without a known vsize).
fn fee_line_str(fee: Option<u64>, vsize: Option<u64>) -> String {
    match (fee, vsize) {
        (Some(f), Some(v)) if v > 0 => format!("{:.1} sat/vB · {f} sats", f as f64 / v as f64),
        (Some(f), _) => format!("{f} sats"),
        _ => "—".into(),
    }
}

/// "replaced N×" when a tx was RBF-bumped (>1 txids), else empty.
fn replaced_label(txid_count: usize) -> String {
    if txid_count > 1 {
        format!("replaced {}×", txid_count - 1)
    } else {
        String::new()
    }
}

/// "New fee ~N sats (+D)" for a proposed rate over a tx of `vsize`.
fn new_fee_line(rate: f64, vsize: u64, old_fee: u64) -> String {
    let new_fee = (rate * vsize as f64).ceil() as u64;
    let delta = new_fee.saturating_sub(old_fee);
    format!("New fee ~{new_fee} sats  (+{delta} over current)")
}

/// Current rate (sat/vB), fee, vsize for a pending tx referenced by the
/// activity list (note_id if is_note, else txid).
fn tx_rate(store: &Store, ref_id: &str, is_note: bool) -> Option<(f64, u64, u64)> {
    if is_note {
        let n = store.notes.iter().find(|n| n.note_id == ref_id)?;
        let (f, v) = (n.fee?, n.vsize?);
        (v > 0).then(|| (f as f64 / v as f64, f, v))
    } else {
        let t = store.txs.iter().find(|t| t.txids.iter().any(|x| x == ref_id))?;
        (t.vsize > 0).then(|| (t.fee as f64 / t.vsize as f64, t.fee, t.vsize))
    }
}

/// Refresh the consolidate confirm-dialog fee line. Free function (not
/// just the callback) so on_sweep_send can call it WITHOUT re-invoking
/// the slint callback — that re-borrows the State RefCell and panics.
fn refresh_consolidate_preview(w: &AppWindow, s: &mut State) {
    let _ = &s;
    w.set_consolidate_fee_line("".into());
    let rate: f64 = w.get_consolidate_rate().trim().parse().unwrap_or(1.0);
    let net = s.network;
    let Some(ident) = s.ident.as_ref() else { return };
    let Ok(me) = Recipient::parse(net, &ident.address) else { return };
    if ident.is_watch() {
        // Dry-run the same builder the watch consolidate signs externally.
        let Some(src) = ident.watch_source() else { return };
        let Some(store) = s.store.as_ref() else { return };
        let coins: Vec<WatchCoin> = store
            .utxos
            .iter()
            .filter(|u| !u.pending_spend)
            .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value })
            .collect();
        if coins.len() < 2 {
            w.set_consolidate_fee_line("nothing to consolidate — need 2+ spendable coins".into());
            return;
        }
        match build_watch_spend_psbt(src, &coins, me.spk.clone(), rate) {
            Ok(b) => w.set_consolidate_fee_line(
                format!(
                    "fee {} sats · combines {} coins @ {} sat/vB · signs on your external wallet",
                    b.fee,
                    coins.len(),
                    rate
                )
                .into(),
            ),
            Err(e) => w.set_consolidate_fee_line(format!("{e}").into()),
        }
        return;
    }
    let Some(identity) = ident.full().map(|i| i.clone_fields()) else { return };
    let Some(store) = s.store.as_ref() else { return };
    let coins = store.available_utxos();
    if coins.len() < 2 {
        w.set_consolidate_fee_line("nothing to consolidate — need 2+ spendable coins".into());
        return;
    }
    match app_core::notes_core::tx::build_sweep_tx(
        &coins,
        &identity.output_x,
        me.spk,
        rate,
        &identity.tweaked_seckey,
        app_core::notes_core::keys::generate_aux_rand,
    ) {
        Ok(tx) => {
            println!("cb: consolidate-preview coins={} fee={} vsize={}", coins.len(), tx.fee, tx.vsize);
            w.set_consolidate_fee_line(
                format!(
                    "fee {} sats · combines {} coins · {} vB @ {} sat/vB",
                    tx.fee,
                    coins.len(),
                    tx.vsize,
                    rate
                )
                .into(),
            );
        }
        Err(e) => w.set_consolidate_fee_line(format!("estimate failed: {e}").into()),
    }
}

/// Post-broadcast bookkeeping for a watch-mode compose: record the public
/// note as Pending with the same ledger effects as a keyed compose —
/// inputs locked, change (last vout) spendable unconfirmed, raw hex kept
/// for rebroadcast until confirmation.
fn record_watch_note(st: &mut State, wn: &WatchNote, txid: &str, raw: &str, vsize: u64) {
    let Some(store) = st.store.as_mut() else { return };
    let change = (wn.change > 0).then(|| app_core::store::LedgerUtxo {
        txid: txid.to_string(),
        vout: (wn.chunks + usize::from(wn.recipient.is_some())) as u32,
        value: wn.change,
        height: None,
        pending_spend: false,
    });
    store.record_signed(
        app_core::store::NoteRecord {
            note_id: hex::encode(wn.note_id),
            status: NoteStatus::Pending,
            text: Some(wn.text.clone()),
            private: false,
            directed: wn.recipient.is_some(),
            received: false,
            sender: None,
            recipient: wn.recipient.clone(),
            txids: vec![txid.to_string()],
            height: None,
            blocktime: None,
            created_at: Some(now()),
            spent: wn.spent.clone(),
            raw_hex: Some(raw.to_string()),
            fee: Some(wn.fee),
            vsize: Some(vsize),
            change_to: None,
            gift_amount: wn.recipient.is_some().then_some(wn.gift),
        },
        change,
    );
    st.save_store();
}

/// Post-broadcast bookkeeping for a watch-mode external-sign spend: sweep/
/// consolidate become TxRecords (Activity lifecycle + rebroadcast/RBF), a
/// bump rides on the record it replaces; spent coins get pending-locked.
fn record_watch_spend(st: &mut State, ws: &WatchSpend, txid: &str, raw: &str, vsize: u64) {
    let Some(store) = st.store.as_mut() else { return };
    match &ws.bump_ref {
        Some((ref_id, is_note)) => {
            if *is_note {
                if let Some(n) = store.notes.iter_mut().find(|n| n.note_id == *ref_id) {
                    if !n.txids.contains(&txid.to_string()) {
                        n.txids.push(txid.to_string());
                    }
                    n.fee = Some(ws.fee);
                    n.vsize = Some(vsize);
                }
            } else if let Some(t) =
                store.txs.iter_mut().find(|t| t.txids.iter().any(|x| x == ref_id))
            {
                if !t.txids.contains(&txid.to_string()) {
                    t.txids.push(txid.to_string());
                }
                t.fee = ws.fee;
                t.vsize = vsize;
                t.raw_hex = Some(raw.to_string());
            }
        }
        None => {
            store.record_tx(
                ws.kind,
                txid.to_string(),
                ws.value,
                ws.fee,
                vsize,
                raw.to_string(),
                ws.dest.clone(),
                ws.inputs.clone(),
                ws.dest_spk_hex.clone(),
                now(),
            );
            for i in &ws.inputs {
                if let Some(u) =
                    store.utxos.iter_mut().find(|u| u.txid == i.txid && u.vout == i.vout)
                {
                    u.pending_spend = true;
                }
            }
        }
    }
    st.save_store();
}

/// Watch mode: build the external-sign PSBT spending every spendable coin
/// into `dest_spk` and open the sign screen (13). The signed PSBT comes
/// back through the same import paths external funding uses.
fn watch_spend_build(
    w: &AppWindow,
    st: &mut State,
    kind: &'static str,
    dest: String,
    dest_spk: Vec<u8>,
    rate: f64,
) {
    let Some(src) = st.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
    let Some(store) = st.store.as_ref() else { return };
    let coins: Vec<WatchCoin> = store
        .utxos
        .iter()
        .filter(|u| !u.pending_spend)
        .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value })
        .collect();
    if coins.is_empty() || (kind == "consolidate" && coins.len() < 2) {
        w.set_status(
            if kind == "consolidate" { "nothing to consolidate (need 2+ coins)" } else { "nothing to sweep" }.into(),
        );
        return;
    }
    let inputs: Vec<app_core::store::TxInput> = coins
        .iter()
        .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
        .collect();
    match build_watch_spend_psbt(&src, &coins, dest_spk.clone(), rate) {
        Ok(built) => {
            let cost = format!(
                "{kind} · {} sats · fee {} sats · {} input{} · sign with your external wallet",
                built.sent_to_recipient,
                built.fee,
                coins.len(),
                if coins.len() == 1 { "" } else { "s" }
            );
            st.watch_note = None;
            st.watch_spend = Some(WatchSpend {
                kind,
                dest,
                dest_spk_hex: hex::encode(&dest_spk),
                value: built.sent_to_recipient,
                fee: built.fee,
                inputs,
                bump_ref: None,
            });
            println!(
                "cb: watch-spend-build kind={kind} txid={} fee={} inputs={}",
                built.txid,
                built.fee,
                coins.len()
            );
            show_psbt_sign_screen(w, st, built, cost);
        }
        Err(e) => w.set_status(format!("{e}").into()),
    }
}

/// Watch mode bump, step 1: fetch the pending tx from the node (chain-
/// recovered records carry no fee/vsize/raw hex), price it, open the dialog.
fn watch_bump_open(w: &AppWindow, st: &mut State, ref_id: String, is_note: bool) {
    let Some(base) = st.base_url() else {
        w.set_status("no Bitcoin node — set one in Settings".into());
        return;
    };
    let txid = {
        let Some(store) = st.store.as_ref() else { return };
        if is_note {
            store.notes.iter().find(|n| n.note_id == ref_id).and_then(|n| n.txids.last().cloned())
        } else {
            store
                .txs
                .iter()
                .find(|t| t.txids.iter().any(|x| *x == ref_id))
                .and_then(|t| t.txids.last().cloned())
        }
    };
    let Some(txid) = txid else {
        w.set_status("transaction not found".into());
        return;
    };
    let client = ChainClient::new(HttpTransport::new(base), st.network);
    match client.fetch_tx_io(&txid) {
        Ok((coins, outputs, confirmed)) => {
            if confirmed {
                w.set_status("already confirmed — nothing to speed up".into());
                return;
            }
            let in_v: u64 = coins.iter().map(|c| c.value).sum();
            let out_v: u64 = outputs.iter().map(|(_, v)| *v).sum();
            let old_fee = in_v.saturating_sub(out_v);
            let vsize = predict_keyspend_vsize(coins.len(), outputs.iter().map(|(s, _)| s.len()));
            let old_rate = if vsize > 0 { old_fee as f64 / vsize as f64 } else { 0.0 };
            let min_rate = old_rate + 1.0;
            let fast = st.fees.as_ref().map(|f| f.fastest).unwrap_or(min_rate);
            let recommended = fast.max(min_rate);
            println!("cb: bump-open ref={ref_id} old={old_rate:.1} min={min_rate:.1} watch=1");
            w.set_bump_ref(ref_id.clone().into());
            w.set_bump_is_note(is_note);
            w.set_bump_kind(if is_note { "Note transaction" } else { "Sweep / consolidate" }.into());
            w.set_bump_current(format!("Currently {old_rate:.1} sat/vB · {old_fee} sats fee").into());
            w.set_bump_min(format!("Minimum {min_rate:.1} sat/vB — RBF must add ≥1 sat/vB.").into());
            w.set_bump_error("".into());
            w.set_bump_rate(format!("{recommended:.1}").into());
            w.set_bump_new_fee(new_fee_line(recommended, vsize, old_fee).into());
            st.watch_bump = Some(WatchBump { ref_id, is_note, txid, coins, outputs, old_fee, vsize });
            w.set_show_bump_dialog(true);
        }
        Err(e) => w.set_status(format!("can't fetch the pending tx: {e}").into()),
    }
}

/// Watch mode bump, step 2: rebuild the replacement PSBT (same in/outs, fee
/// delta out of our own output) and open the external-sign screen.
fn watch_bump_confirm(w: &AppWindow, st: &mut State, new_rate: f64) {
    let Some(wb) = st.watch_bump.take() else {
        w.set_bump_error("bump context lost — reopen the dialog".into());
        return;
    };
    let min_rate = (wb.old_fee as f64 / wb.vsize.max(1) as f64) + 1.0;
    if new_rate + 1e-9 < min_rate {
        w.set_bump_error(format!("below the {min_rate:.1} sat/vB minimum").into());
        st.watch_bump = Some(wb);
        return;
    }
    let Some(src) = st.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
    let self_spk = p2tr_script_pubkey(&st.ident.as_ref().map(|i| i.output_x()).unwrap_or_default());
    // Take the fee delta from our own output (largest), else the largest
    // non-OP_RETURN output (a sweep pays the fee out of the swept amount).
    let reduce = wb
        .outputs
        .iter()
        .enumerate()
        .filter(|(_, (spk, _))| *spk == self_spk)
        .max_by_key(|(_, (_, v))| *v)
        .map(|(i, _)| i)
        .or_else(|| {
            wb.outputs
                .iter()
                .enumerate()
                .filter(|(_, (spk, _))| spk.first() != Some(&0x6a))
                .max_by_key(|(_, (_, v))| *v)
                .map(|(i, _)| i)
        });
    let Some(reduce) = reduce else {
        w.set_bump_error("no output can absorb the fee bump".into());
        return;
    };
    match build_watch_bump_psbt(&src, &wb.coins, &wb.outputs, reduce, new_rate) {
        Ok(built) => {
            w.set_show_bump_dialog(false);
            let dest = st.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
            let cost = format!(
                "speed-up · replaces {}… · new fee {} sats · sign with your external wallet",
                &wb.txid[..12.min(wb.txid.len())],
                built.fee
            );
            st.watch_note = None;
            st.watch_spend = Some(WatchSpend {
                kind: "bump",
                dest,
                dest_spk_hex: hex::encode(&wb.outputs[reduce].0),
                value: built.sent_to_recipient,
                fee: built.fee,
                inputs: Vec::new(),
                bump_ref: Some((wb.ref_id.clone(), wb.is_note)),
            });
            println!("cb: watch-bump-build ref={} txid={} fee={}", wb.ref_id, built.txid, built.fee);
            show_psbt_sign_screen(w, st, built, cost);
        }
        Err(e) => {
            w.set_bump_error(format!("{e}").into());
            st.watch_bump = Some(wb);
        }
    }
}

/// The sweep screen's fee rate: tier pill (economy/hour/fastest) or the
/// custom sat/vB field — the compose mapping, mirrored.
fn resolve_sweep_rate(w: &AppWindow, st: &State) -> f64 {
    let f = st.fees.clone().unwrap_or_default();
    match w.get_sweep_tier() {
        0 => f.economy.max(1.0),
        2 => f.fastest.max(1.0),
        3 => w.get_sweep_rate_text().trim().parse().unwrap_or(0.0),
        _ => f.hour.max(1.0),
    }
}

/// Refresh the sweep screen (16): read-only inputs list (a sweep spends
/// every spendable coin), inputs title, and the live cost line for the
/// current fee tier / funding mode.
fn update_sweep_screen(w: &AppWindow, st: &mut State) {
    let net = st.network;
    let Some(store) = st.store.as_ref() else { return };
    let exb = st.explorer_base();
    let spendable: Vec<&app_core::store::LedgerUtxo> =
        store.utxos.iter().filter(|u| !u.pending_spend).collect();
    let total: u64 = spendable.iter().map(|u| u.value).sum();
    let n = spendable.len();
    let mut rows: Vec<SpendCoin> = spendable
        .iter()
        .map(|u| SpendCoin {
            outpoint: format!("{}:{}", u.txid, u.vout).into(),
            value: u.value.to_string().into(),
            confirmed: u.height.is_some(),
            selected: true,
            txid_short: u.txid[..8.min(u.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &u.txid).into(),
        })
        .collect();
    rows.sort_by_key(|r| r.value.parse::<u64>().unwrap_or(0));
    w.set_sweep_coins(VecModel::from_slice(&rows));
    let plural = if n == 1 { "" } else { "s" };
    w.set_sweep_inputs_title(format!("Inputs · {n} coin{plural} · {total} sats (all)").into());

    if n == 0 {
        w.set_sweep_cost_line("nothing to sweep — no spendable coins".into());
        return;
    }
    let rate = resolve_sweep_rate(w, st);
    if rate <= 0.0 {
        w.set_sweep_cost_line("enter a fee rate".into());
        return;
    }
    let dest_spk_len = w
        .get_sweep_dest()
        .to_string()
        .parse_dest_len(net)
        .unwrap_or(34);
    if w.get_sweep_fund_external() {
        if st.funding.is_none() || st.funding_coins.is_empty() {
            w.set_sweep_cost_line(format!("sweeps {total} sats in full — pick a funding wallet for the fee").into());
            return;
        }
        // notes inputs (taproot) + funding inputs + dest + funding change.
        use app_core::bitcoin::transaction::{predict_weight, InputWeightPrediction};
        let fund_kind = st.funding.as_ref().map(|f| f.kind);
        let fund_w = match fund_kind {
            Some(app_core::funding::FundingKind::Wpkh) => InputWeightPrediction::P2WPKH_MAX,
            _ => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
        };
        let weights = std::iter::repeat(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH)
            .take(n)
            .chain(std::iter::repeat(fund_w).take(st.funding_coins.len()));
        let vsize = predict_weight(weights, [dest_spk_len, 34usize].into_iter()).to_vbytes_ceil();
        let fee = (vsize as f64 * rate).ceil() as u64;
        let funding_total: u64 = st.funding_coins.iter().map(|c| c.value).sum();
        if funding_total < fee {
            w.set_sweep_cost_line(
                format!("funding wallet holds {funding_total} sats — fee needs ~{fee}").into(),
            );
            return;
        }
        w.set_sweep_cost_line(
            format!(
                "destination receives {total} sats in full · fee ~{fee} sats from the funding wallet ({} sats change back)",
                funding_total.saturating_sub(fee)
            )
            .into(),
        );
    } else {
        let vsize = predict_keyspend_vsize(n, std::iter::once(dest_spk_len));
        let fee = (vsize as f64 * rate).ceil() as u64;
        if total <= fee {
            w.set_sweep_cost_line(format!("balance {total} sats can't cover the ~{fee} sat fee").into());
            return;
        }
        let line = if w.get_sweep_kind().as_str() == "consolidate" {
            format!("combines {n} coins → 1 · fee ~{fee} sats · keeps {}", total - fee)
        } else {
            format!("sweeps {total} sats · fee ~{fee} sats · destination receives {}", total - fee)
        };
        w.set_sweep_cost_line(line.into());
    }
}

trait DestLen {
    fn parse_dest_len(&self, net: Network) -> Option<usize>;
}
impl DestLen for String {
    fn parse_dest_len(&self, net: Network) -> Option<usize> {
        Recipient::parse(net, self).ok().map(|r| r.spk.len())
    }
}

/// chain-notes companion note.html permalink, or empty on regtest.
fn note_web_url(network: Network, address: &str, note_id: &str) -> String {
    match network {
        Network::Regtest => String::new(),
        net => format!(
            "https://objsal.github.io/chain-notes-companion/note.html?address={address}&network={}&note={note_id}",
            net.as_str()
        ),
    }
}

/// Populate the Settings node + explorer dropdown models, selected indices,
/// and custom-URL text from the device-level config (this network's entry).
/// The value is matched against the network's presets; a non-preset value
/// selects the trailing "Custom…" row and prefills its text field. An absent
/// entry (None) matches the first preset (mempool.space, the network default).
fn load_backend_settings(w: &AppWindow, st: &State) {
    fn fill(
        presets: Vec<(&'static str, Option<&'static str>)>,
        cur: Option<&str>,
    ) -> (Vec<SharedString>, i32, SharedString) {
        let mut opts: Vec<SharedString> = presets.iter().map(|(l, _)| (*l).into()).collect();
        opts.push("Custom…".into());
        let idx = presets
            .iter()
            .position(|(_, u)| match (u, cur) {
                (None, None) => true,
                (Some(a), Some(b)) => *a == b,
                _ => false,
            })
            .unwrap_or(presets.len());
        let custom = if idx == presets.len() { cur.unwrap_or("") } else { "" };
        (opts, idx as i32, custom.into())
    }

    let net = st.network;
    let (n_opts, n_idx, n_custom) =
        fill(node_presets(net), st.node_urls.get(net.as_str()).map(String::as_str));
    w.set_node_options(VecModel::from_slice(&n_opts));
    w.set_node_index(n_idx);
    w.set_node_custom_text(n_custom);

    let (e_opts, e_idx, e_custom) =
        fill(explorer_presets(net), st.explorers.get(net.as_str()).map(String::as_str));
    w.set_explorer_options(VecModel::from_slice(&e_opts));
    w.set_explorer_index(e_idx);
    w.set_explorer_custom_text(e_custom);
}

/// Build the unified activity list (note txs + sweep/consolidate),
/// actionable (pending) first, then newest.
fn update_activity(w: &AppWindow, st: &State) {
    let Some(store) = &st.store else { return };
    let net = st.network;
    let exb = st.explorer_base();
    let ex = exb.as_deref();
    let mut items: Vec<(u64, bool, ActivityItem)> = Vec::new(); // (created, confirmed, item)

    for n in &store.notes {
        let Some(txid) = n.txids.last() else { continue };
        let kind = format!(
            "Note · {}{}",
            if n.private { "private" } else { "public" },
            if n.received {
                " · received"
            } else if n.directed {
                " · sent"
            } else {
                ""
            }
        );
        let status = match n.status {
            NoteStatus::Pending => "pending",
            NoteStatus::Confirmed => "confirmed",
            NoteStatus::Orphaned => "orphaned",
        };
        items.push((
            n.created_at.or(n.blocktime).unwrap_or(0),
            n.status == NoteStatus::Confirmed,
            ActivityItem {
                ref_id: n.note_id.clone().into(),
                is_note: true,
                kind: kind.into(),
                title: n.text.clone().unwrap_or_else(|| "(encrypted)".into()).into(),
                txid: txid.clone().into(),
                fee_line: fee_line_str(n.fee, n.vsize).into(),
                status: status.into(),
                explorer: explorer_tx_url(ex, net, txid).into(),
                pending: n.status == NoteStatus::Pending && n.raw_hex.is_some(),
                replaced: replaced_label(n.txids.len()).into(),
            },
        ));
    }

    for t in &store.txs {
        let Some(txid) = t.txids.last() else { continue };
        let status = match t.status {
            NoteStatus::Pending => "pending",
            NoteStatus::Confirmed => "confirmed",
            NoteStatus::Orphaned => "orphaned",
        };
        let title = if t.dest == "self" {
            format!("Consolidate to your address · {} sats", t.value)
        } else {
            format!("To {} · {} sats", t.dest, t.value)
        };
        items.push((
            t.created_at.unwrap_or(0),
            t.status == NoteStatus::Confirmed,
            ActivityItem {
                ref_id: txid.clone().into(),
                is_note: false,
                kind: if t.kind == "consolidate" { "Consolidate" } else { "Sweep" }.into(),
                title: title.into(),
                txid: txid.clone().into(),
                fee_line: fee_line_str(Some(t.fee), Some(t.vsize)).into(),
                status: status.into(),
                explorer: explorer_tx_url(ex, net, txid).into(),
                pending: t.status == NoteStatus::Pending && t.raw_hex.is_some(),
                replaced: replaced_label(t.txids.len()).into(),
            },
        ));
    }

    // Actionable (unconfirmed) first, then newest created.
    items.sort_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)));
    let list: Vec<ActivityItem> = items.into_iter().map(|(_, _, it)| it).collect();
    let pending = list.iter().filter(|i| i.pending).count();
    w.set_activity_summary(
        if list.is_empty() {
            "No transactions yet.".to_string()
        } else {
            format!("{} transaction{} · {pending} pending", list.len(), if list.len() == 1 { "" } else { "s" })
        }
        .into(),
    );
    w.set_activity(VecModel::from_slice(&list));
}

fn normalize_addr(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(rest) = s.strip_prefix("bitcoin:").or_else(|| s.strip_prefix("BITCOIN:")) {
        s = rest.to_string();
    }
    if let Some(q) = s.find('?') {
        s.truncate(q);
    }
    s
}

/// Group digits with thousands separators: 143473 → "143,473".
fn commas(n: u64) -> String {
    let s = n.to_string();
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in b.iter().enumerate() {
        if i > 0 && (b.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c as char);
    }
    out
}

fn activate(st: &mut State, material_str: &str, persist: bool) -> Result<(), String> {
    let material =
        parse_key_material(material_str, st.network).map_err(|e| e.to_string())?;
    let ident = realize(&material, st.network, st.account).map_err(|e| e.to_string())?;
    if persist {
        keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material_str.trim(), st.icloud_backup)?;
    }
    st.material = Some(Zeroizing::new(material_str.trim().to_string()));
    let fp = hex::encode(ident.output_x());
    let path = st
        .data_dir
        .join(format!("store-{}-{}.json", st.network.as_str(), &fp[..8]));
    let mut store = Store::load(&path).unwrap_or_else(|_| Store::new(&ident.output_x(), st.network));
    // Migrate a legacy per-identity node URL (shipped as `esplora`) into the
    // device-level per-network config, then drop it from the store. Only if
    // this network has no node set yet, so a real config choice always wins.
    if let Some(url) = store.node_url.take() {
        st.node_urls.entry(st.network.as_str().to_string()).or_insert(url);
    }
    println!(
        "cb: identity kind={} account={} network={} address={}",
        ident.kind,
        ident.account,
        st.network.as_str(),
        ident.address
    );
    // Notebook index: load (or start) this identity's account→name/archive
    // map, make sure the activated account is in it, and rebuild the
    // (account, address) cache the notebook list + sender labels read.
    let fp8 = index_fp8(&material, st.network).map_err(|e| e.to_string())?;
    let ix_path = st
        .data_dir
        .join(format!("notebooks-{}-{}.json", st.network.as_str(), fp8));
    let mut ix = NotebookIndex::load(&ix_path).unwrap_or_default();
    let added = ix.ensure(ident.account);
    if added {
        let _ = ix.save(&ix_path);
    }
    st.nb_addrs = ix
        .notebooks
        .iter()
        .filter_map(|m| {
            realize(&material, st.network, m.account)
                .ok()
                .map(|i| (m.account, i.address.clone(), hex::encode(&i.output_x()[..4])))
        })
        .collect();
    st.notebooks_fp8 = Some(fp8);
    st.notebooks = Some(ix);
    st.ident = Some(ident);
    st.store = Some(store);
    st.save_store();
    st.save_config();
    Ok(())
}

fn is_hierarchical(material_str: &str, network: Network) -> bool {
    matches!(
        parse_key_material(material_str, network),
        Ok(app_core::identity::KeyMaterial::Mnemonic(_))
    ) || matches!(
        parse_key_material(material_str, network),
        Ok(app_core::identity::KeyMaterial::Xprv(x)) if x.depth == 0
    )
}

/// One picker page: 5 accounts with their derived addresses.
fn account_rows(
    material_str: &str,
    network: Network,
    page: u32,
    active: Option<u32>,
) -> Vec<AccountItem> {
    let Ok(material) = parse_key_material(material_str, network) else { return vec![] };
    (page * 5..page * 5 + 5)
        .filter_map(|i| {
            let ident = realize(&material, network, i).ok()?;
            Some(AccountItem {
                index: i as i32,
                address: ident.address.into(),
                active: active == Some(i),
            })
        })
        .collect()
}

fn show_account_picker(w: &AppWindow, material: &str, network: Network, page: u32, active: Option<u32>) {
    w.set_account_page(page as i32);
    w.set_accounts(VecModel::from_slice(&account_rows(material, network, page, active)));
    w.set_screen(9);
}

/// Push the store's saved recipients into the "Send to" recents list. Kept
/// separate from `update_home` so it can be called the moment a contact is
/// added (pick-contact) — otherwise a freshly-used address only appears after
/// the next full home refresh, not when you press Back from compose.
fn refresh_contacts(w: &AppWindow, st: &State) {
    let Some(store) = &st.store else { return };
    let contacts: Vec<ContactItem> = store
        .contacts
        .iter()
        .map(|c| ContactItem { address: c.address.clone().into(), name: c.name.clone().into() })
        .collect();
    w.set_contacts(VecModel::from_slice(&contacts));
}

/// A (possibly inactive) notebook's store, read from its file on disk;
/// the ACTIVE notebook prefers the live in-memory store.
fn notebook_store(st: &State, account: u32) -> Option<Store> {
    if st.ident.as_ref().map(|i| i.account) == Some(account) {
        if let Some(s) = &st.store {
            return Some(s.clone());
        }
    }
    let (_, _, fp8) = st.nb_addrs.iter().find(|(a, ..)| *a == account)?;
    Store::load(&st.store_path_for(fp8)).ok()
}

/// Sender-filter label rules: "Self · <notebook>" when the sender is one
/// of our own addresses (this notebook's own notes, or directed notes
/// from a sibling notebook), the contact name when known, else the short
/// address form.
fn sender_label(st: &State, store: &Store, key: &str) -> String {
    if let Some((account, ..)) = st.nb_addrs.iter().find(|(_, a, _)| a == key) {
        return format!("Self · {}", st.notebook_display_name(*account));
    }
    if let Some(c) = store.contacts.iter().find(|c| c.address == key && !c.name.is_empty()) {
        return c.name.clone();
    }
    addr_short(key)
}

/// Build the notebook-list rows (screen 17) from the index plus each
/// notebook's store on disk. Snippet and unread respect that notebook's
/// sender filter, so the row preview matches what opening it reveals.
fn update_notebook_list(w: &AppWindow, st: &State) {
    let Some(ix) = &st.notebooks else { return };
    w.set_can_create_notebook(
        st.material
            .as_deref()
            .map(|m| is_hierarchical(m, st.network))
            .unwrap_or(false),
    );
    let mut active_rows: Vec<NotebookItem> = Vec::new();
    let mut archived_rows: Vec<NotebookItem> = Vec::new();
    for meta in &ix.notebooks {
        let Some((_, address, _)) = st.nb_addrs.iter().find(|(a, ..)| *a == meta.account) else {
            continue;
        };
        let store = notebook_store(st, meta.account);
        let (snippet, meta_line, unread) = match &store {
            Some(s) => {
                let visible: Vec<&app_core::store::NoteRecord> = s.visible_notes().collect();
                let snippet = visible
                    .last()
                    .map(|n| {
                        n.text
                            .as_deref()
                            .map(str::trim)
                            .filter(|t| !t.is_empty())
                            .unwrap_or("(encrypted)")
                            .to_string()
                    })
                    .unwrap_or_else(|| "No notes yet".into());
                let meta_line = format!(
                    "{} · {} sats · {} note{}",
                    addr_short(address),
                    commas(s.balance()),
                    visible.len(),
                    if visible.len() == 1 { "" } else { "s" }
                );
                (snippet, meta_line, s.unread_visible_count())
            }
            None => ("No notes yet".into(), format!("{} · not scanned yet", addr_short(address)), 0),
        };
        let row = NotebookItem {
            account: meta.account as i32,
            name: st.notebook_display_name(meta.account).into(),
            snippet: snippet.into(),
            meta: meta_line.into(),
            unread: match unread {
                0 => "".into(),
                1 => "1 new".into(),
                n => format!("{n} new").into(),
            },
            active: st.ident.as_ref().map(|i| i.account) == Some(meta.account),
        };
        if meta.archived {
            archived_rows.push(row);
        } else {
            active_rows.push(row);
        }
    }
    println!("cb: notebooks list n={} archived={}", active_rows.len(), archived_rows.len());
    w.set_notebooks(VecModel::from_slice(&active_rows));
    w.set_archived_notebooks(VecModel::from_slice(&archived_rows));
    w.set_archived_toggle_label(
        if archived_rows.is_empty() {
            String::new()
        } else {
            format!("Archived ({})", archived_rows.len())
        }
        .into(),
    );
}

fn update_home(w: &AppWindow, st: &State) {
    let Some(ident) = &st.ident else { return };
    let Some(store) = &st.store else { return };
    let watch = ident.is_watch();
    w.set_watch_only(watch);
    w.set_notebook_title(st.notebook_display_name(ident.account).into());
    w.set_address(ident.address.as_str().into());
    if let Some(img) = qr::qr_image(&ident.address.to_uppercase()) {
        w.set_address_qr(img);
    }
    w.set_balance_line(
        format!("{} sats · block {}", commas(store.balance()), commas(store.tip_height as u64))
            .into(),
    );
    // Sender filter: the checklist model + the "hidden" pill, then the
    // notes list itself filtered through the persisted exclusion set.
    let senders: Vec<SenderItem> = store
        .senders()
        .into_iter()
        .map(|(key, count)| SenderItem {
            label: sender_label(st, store, &key).into(),
            sub: format!("{count} note{}", if count == 1 { "" } else { "s" }).into(),
            excluded: store.is_excluded(&key),
            key: key.into(),
        })
        .collect();
    let hidden = senders.iter().filter(|s| s.excluded).count();
    w.set_senders(VecModel::from_slice(&senders));
    w.set_hidden_senders_label(
        match hidden {
            0 => String::new(),
            1 => "1 sender hidden".into(),
            n => format!("{n} senders hidden"),
        }
        .into(),
    );
    let address = ident.address.clone();
    let net = st.network;
    let mut items: Vec<NoteItem> = store
        .notes
        .iter()
        .rev()
        .filter(|n| !store.is_excluded(&store.sender_key(n)))
        .map(|n| {
            let badge = match n.status {
                NoteStatus::Pending => "pending",
                NoteStatus::Confirmed => "confirmed",
                NoteStatus::Orphaned => "orphaned",
            };
            let kind = match (n.received, n.directed, n.private) {
                (true, _, true) => "received private",
                (true, _, false) => "received",
                (false, true, true) => "sent private",
                (false, true, false) => "sent",
                (false, false, true) => "private",
                (false, false, false) => "public",
            };
            NoteItem {
                id: n.note_id.clone().into(),
                title: n
                    .text
                    .as_deref()
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .unwrap_or(if watch && n.private {
                        "(private — key not on this device)"
                    } else {
                        "(not decryptable)"
                    })
                    .into(),
                badge: badge.into(),
                meta: format!(
                    "{kind}{}",
                    n.height.map(|h| format!(" · block {h}")).unwrap_or_default()
                )
                .into(),
                web_url: note_web_url(net, &address, &n.note_id).into(),
                private: n.private,
            }
        })
        .collect();
    items.sort_by_key(|i| i.badge == "confirmed");
    w.set_notes(VecModel::from_slice(&items));
    refresh_contacts(w, st);
    w.set_settings_network(st.network.as_str().into());
    w.set_settings_hierarchical(
        st.material
            .as_deref()
            .map(|m| is_hierarchical(m, st.network))
            .unwrap_or(false),
    );
    if let Some(i) = &st.ident {
        w.set_settings_identity(
            format!(
                "{}{}{} · {}",
                i.kind,
                if i.is_watch() { " · watch-only" } else { "" },
                if matches!(i.kind, "mnemonic" | "xprv") {
                    format!(" · account {}", i.account)
                } else {
                    String::new()
                },
                st.network.as_str()
            )
            .into(),
        );
    }
    w.set_chunk_text(store.chunk_size.to_string().into());
    load_backend_settings(w, st);
    // Coins (spendable UTXOs) list + summary.
    let coins: Vec<CoinItem> = store
        .utxos
        .iter()
        .filter(|u| !u.pending_spend)
        .map(|u| CoinItem {
            outpoint: format!("{}:{}", u.txid, u.vout).into(),
            value: u.value.to_string().into(),
            status: if u.height.is_some() { "confirmed" } else { "unconfirmed" }.into(),
        })
        .collect();
    let spendable: u64 = store.utxos.iter().filter(|u| !u.pending_spend).map(|u| u.value).sum();
    let n = coins.len();
    w.set_coins(VecModel::from_slice(&coins));
    w.set_coins_summary(
        if n == 0 {
            "No coins yet — fund your address to add some.".to_string()
        } else {
            format!("{n} coin{} · {spendable} sats total", if n == 1 { "" } else { "s" })
        }
        .into(),
    );
}

fn refresh(w: &AppWindow, st: &mut State) {
    if st.ident.is_none() || st.store.is_none() {
        return;
    }
    let Some(base) = st.base_url() else {
        w.set_status("no Bitcoin node for this network — set one in Settings".into());
        return;
    };
    let client = ChainClient::new(HttpTransport::new(base), st.network);
    let address = st.ident.as_ref().unwrap().address.clone();
    match client.build_bundle(&address, None) {
        Ok(bundle) => {
            st.fees = Some(bundle.fee_rates.clone());
            st.usd = bundle.btc_usd;
            let keyed = st.ident.as_ref().unwrap().full().map(|i| i.clone_fields());
            let output_x = st.ident.as_ref().unwrap().output_x();
            let network = st.network;
            let applied = match &keyed {
                Some(identity) => st.store.as_mut().unwrap().apply_bundle(&bundle, identity, network),
                None => st.store.as_mut().unwrap().apply_bundle_watch(&bundle, &output_x, network),
            };
            match applied {
                Ok(stats) => {
                    // Sweep/consolidate records settle on REAL confirmation
                    // (any of their txids in a block), asked of the node —
                    // mempool acceptance alone keeps them Pending so
                    // Speed-up/Rebroadcast stay available while RBF is.
                    let n = st
                        .store
                        .as_mut()
                        .unwrap()
                        .resolve_spend_statuses(|t| client.fetch_tx_status(t));
                    if n > 0 {
                        println!("cb: spend-confirmed n={n}");
                    }
                    println!(
                        "cb: refresh notes={} new={} orphaned={} balance={} tip={}",
                        stats.notes_seen,
                        stats.notes_new,
                        stats.orphaned,
                        st.store.as_ref().unwrap().balance(),
                        st.store.as_ref().unwrap().tip_height
                    );
                    st.save_store();
                    w.set_status(format!("synced · {} notes", stats.notes_seen).into());
                }
                Err(e) => w.set_status(format!("apply failed: {e}").into()),
            }
        }
        Err(e) => {
            println!("cb: refresh err={e}");
            w.set_status("couldn't reach the network — tap refresh to retry".into());
        }
    }
    update_home(w, st);
}

/// Estimated (chunks, vsize) for a note. `estimate_note_cost` assumes a
/// 34-byte taproot change output; when the change goes to a custom script
/// of `l` bytes, correct the vsize by `l - 34` (outputs aren't
/// witness-discounted, so 1 byte = 1 vB). None → self/taproot change.
/// Bitcoin standardness ceiling on a single transaction: `MAX_STANDARD_TX_WEIGHT`
/// (400_000 WU) / 4 = 100_000 vB. Nodes won't relay a bigger tx, so this — NOT
/// the per-output chunk-size setting — is the hard wall on how much one note can
/// carry. (A note is one tx of ≤255 OP_RETURN chunks.) The chunk setting only
/// decides how the body is sliced across outputs; at a small chunk size the
/// 255-chunk cap binds first, so raising it to Standard can rescue a note.
const MAX_STANDARD_TX_VSIZE: usize = 100_000;

fn note_est(
    store: &Store,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_len: Option<usize>,
    change_spk_len: Option<usize>,
) -> Result<(usize, usize), app_core::notes_core::Error> {
    note_est_at(store.chunk_size, text_len, private, n_inputs, recipient_spk_len, change_spk_len)
}

/// `note_est` at an arbitrary chunk size — used to test whether a note that
/// doesn't fit at the current setting would fit at Standard.
fn note_est_at(
    chunk_size: usize,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_len: Option<usize>,
    change_spk_len: Option<usize>,
) -> Result<(usize, usize), app_core::notes_core::Error> {
    let (chunks, vsize) =
        estimate_note_cost(text_len, private, chunk_size, n_inputs, recipient_spk_len)?;
    let vsize = change_spk_len.map_or(vsize, |l| (vsize as i64 + l as i64 - 34).max(0) as usize);
    Ok((chunks, vsize))
}

/// Whether the composed note can go out as one standard tx, and if not, whether
/// bumping the chunk size to Standard would rescue it.
enum FitCheck {
    /// Broadcastable at the current chunk-size setting.
    Ok,
    /// Over the limit now, but would fit at Standard (the user is on a smaller
    /// setting whose 255-chunk cap binds first) — offer to switch.
    FitsAtStandard,
    /// Over even at Standard: the ~100 kB per-tx network wall. No setting helps.
    HardWall,
}

fn fit_check(
    store: &Store,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_len: Option<usize>,
    change_spk_len: Option<usize>,
) -> FitCheck {
    let fits = |chunk: usize| {
        note_est_at(chunk, text_len, private, n_inputs, recipient_spk_len, change_spk_len)
            .map(|(_, vsize)| vsize <= MAX_STANDARD_TX_VSIZE)
            .unwrap_or(false) // Err = >255 chunks → treat as over-limit
    };
    if fits(store.chunk_size) {
        FitCheck::Ok
    } else if store.chunk_size < DEFAULT_CHUNK && fits(DEFAULT_CHUNK) {
        FitCheck::FitsAtStandard
    } else {
        FitCheck::HardWall
    }
}

/// Suggested coin selection over CONFIRMED coins only (unconfirmed are
/// never auto-selected — the user adds them manually). `consolidate` = pick
/// SMALLEST coins first (sweeps dust up into the change); otherwise LARGEST
/// first (fewest inputs, lowest fee). Stops once the note + fee is covered.
#[allow(clippy::too_many_arguments)]
fn suggested_coins(
    store: &Store,
    text_len: usize,
    private: bool,
    rate: f64,
    spk_len: Option<usize>,
    change_spk_len: Option<usize>,
    sent: u64,
    consolidate: bool,
) -> Vec<(String, u32)> {
    let mut coins: Vec<&app_core::store::LedgerUtxo> = store
        .utxos
        .iter()
        .filter(|u| !u.pending_spend && u.height.is_some())
        .collect();
    if consolidate {
        coins.sort_by(|a, b| a.value.cmp(&b.value)); // smallest first
    } else {
        coins.sort_by(|a, b| b.value.cmp(&a.value)); // largest first
    }
    let mut chosen = Vec::new();
    let mut total = 0u64;
    for u in coins {
        chosen.push((u.txid.clone(), u.vout));
        total += u.value;
        if let Ok((_, vsize)) =
            note_est(store, text_len.max(1), private, chosen.len(), spk_len, change_spk_len)
        {
            let fee = (vsize as f64 * rate).ceil() as u64;
            if total >= fee + sent {
                break;
            }
        }
    }
    chosen
}

/// Recompute the whole compose screen from state: coin list + selection,
/// spend total, live cost, change preview, change-address validation, and
/// the feasibility gate on the Sign button.
fn refresh_compose(w: &AppWindow, st: &mut State) {
    let net = st.network;
    let text = w.get_compose_text().to_string();
    let private = w.get_compose_private();
    let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(1.0);
    // External-funding mode: the coin panel shows the funding wallet's coins,
    // not the self-funded store coins. Handled on its own isolated path.
    if w.get_fund_external() {
        funding_compose_ui(w, st, &text);
        return;
    }
    let spk_len = st
        .to_address
        .as_deref()
        .and_then(|a| Recipient::parse(net, a).ok())
        .map(|r| r.spk.len());
    // Directed notes send a "gift" to the recipient (>= dust); self-notes send 0.
    let gift = w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS);
    let sent = if spk_len.is_some() { gift } else { 0 };

    // Change-address destination label + validation. A valid custom change
    // address also yields its scriptPubKey length so the fee/change preview
    // sizes the real change output (not the assumed taproot one).
    let change_raw = w.get_change_address().to_string();
    let change_trim = change_raw.trim();
    let (change_dest, change_err, change_spk_len) = if change_trim.is_empty() {
        ("your address".to_string(), String::new(), None)
    } else {
        match Recipient::parse(net, change_trim) {
            Ok(r) => (
                format!("{}…", &change_trim[..14.min(change_trim.len())]),
                String::new(),
                Some(r.spk.len()),
            ),
            Err(_) => (
                "⚠ invalid".to_string(),
                format!("Not a valid {} address.", net.as_str()),
                None,
            ),
        }
    };
    w.set_change_error(change_err.clone().into());

    let consolidate = st.consolidate_coins;
    let Some(store) = &st.store else { return };
    // Auto-suggest a selection until the user overrides it.
    if !st.coins_overridden {
        st.selected_coins =
            suggested_coins(store, text.len(), private, rate, spk_len, change_spk_len, sent, consolidate);
    }
    let store = st.store.as_ref().unwrap();
    let exb = st.explorer_base();
    let sel: std::collections::HashSet<(String, u32)> = st.selected_coins.iter().cloned().collect();

    let mut coins: Vec<SpendCoin> = Vec::new();
    let (mut sel_total, mut sel_count) = (0u64, 0usize);
    // Spendable coins, sorted by amount low → high.
    let mut spendable: Vec<&app_core::store::LedgerUtxo> =
        store.utxos.iter().filter(|u| !u.pending_spend).collect();
    spendable.sort_by(|a, b| a.value.cmp(&b.value));
    for u in spendable {
        let selected = sel.contains(&(u.txid.clone(), u.vout));
        if selected {
            sel_total += u.value;
            sel_count += 1;
        }
        coins.push(SpendCoin {
            outpoint: format!("{}:{}", u.txid, u.vout).into(),
            value: u.value.to_string().into(),
            confirmed: u.height.is_some(),
            selected,
            txid_short: u.txid[..8.min(u.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &u.txid).into(),
        });
    }
    w.set_spend_coins(VecModel::from_slice(&coins));
    let plural = if sel_count == 1 { "" } else { "s" };
    w.set_spend_title(format!("Spending {sel_count} coin{plural} · {sel_total} sats").into());

    if text.is_empty() {
        w.set_cost_line("".into());
        w.set_change_amount(format!("Change to {change_dest}").into());
        w.set_spend_enough(true);
        st.compose_oversize = false;
        return;
    }
    let n = sel_count.max(1);
    let est = note_est(store, text.len(), private, n, spk_len, change_spk_len);
    let fit = fit_check(store, text.len(), private, n, spk_len, change_spk_len);
    let over = !matches!(fit, FitCheck::Ok);
    match est {
        Ok((chunks, vsize)) if !over => {
            let fee = (vsize as f64 * rate).ceil() as u64;
            let enough = sel_count > 0 && sel_total >= fee + sent;
            let change = sel_total.saturating_sub(fee + sent);
            let usd = st
                .usd
                .map(|p| format!(" (~${:.2})", fee as f64 * p / 1e8))
                .unwrap_or_default();
            let gift_line = if spk_len.is_some() {
                format!(" + {} sats to recipient", commas(sent))
            } else {
                String::new()
            };
            w.set_cost_line(
                format!("{chunks} chunk(s) · ~{vsize} vB · ~{fee} sats{usd}{gift_line}").into(),
            );
            w.set_change_amount(format!("Change to {change_dest} · ~{change} sats").into());
            w.set_spend_enough(enough);
        }
        // Over the per-tx broadcast ceiling: vsize > 100 kB (Ok arm) or the
        // body needs > 255 chunks (Err arm). Sign is gated off; the dialog
        // below offers the fix.
        Ok((chunks, vsize)) => {
            w.set_cost_line(
                format!("{chunks} chunk(s) · ~{vsize} vB — too large to broadcast").into(),
            );
            w.set_spend_enough(false);
        }
        Err(_) => {
            w.set_cost_line("Too large to broadcast (> 255 chunks)".into());
            w.set_spend_enough(false);
        }
    }

    // Edge-trigger the "too large" dialog: pop once when the draft first
    // crosses the ceiling, not on every keystroke while it stays over.
    if over && !st.compose_oversize {
        match fit {
            FitCheck::FitsAtStandard => {
                w.set_oversize_offer_bump(true);
                w.set_oversize_message(
                    "This note doesn't fit at your current chunk size. \
                     Switch to Standard (a single large chunk) to fit it in one transaction?"
                        .into(),
                );
                w.set_show_oversize_modal(true);
            }
            FitCheck::HardWall => {
                w.set_oversize_offer_bump(false);
                w.set_oversize_message(
                    "This note is too large to broadcast. A single Bitcoin transaction \
                     can't exceed ~100 kB (the network relay limit), whatever the chunk \
                     size. Shorten the note, or split it across several notes. \
                     Multi-transaction notes are planned for a future release."
                        .into(),
                );
                w.set_show_oversize_modal(true);
            }
            FitCheck::Ok => {}
        }
    }
    st.compose_oversize = over;
}

trait CloneFields {
    fn clone_fields(&self) -> app_core::notes_core::bundle::Identity;
}
impl CloneFields for app_core::notes_core::bundle::Identity {
    fn clone_fields(&self) -> app_core::notes_core::bundle::Identity {
        app_core::notes_core::bundle::Identity {
            internal_x: self.internal_x,
            output_x: self.output_x,
            tweaked_seckey: self.tweaked_seckey,
            enc_key: self.enc_key,
        }
    }
}

/// External-funding variant of the compose coin panel: show the funding
/// wallet's scanned coins (all spent) and a source summary, instead of the
/// self-funded store coins. Keeps the intricate self-funded path untouched.
fn funding_compose_ui(w: &AppWindow, st: &State, text: &str) {
    let net = st.network;
    let total: u64 = st.funding_coins.iter().map(|c| c.value).sum();
    let n = st.funding_coins.len();
    let ready = st.funding.is_some() && n > 0;
    w.set_funding_ready(ready);

    // Summary card = which wallet + how much (its first receive address is a
    // recognisable handle for a multi-address wallet).
    match &st.funding {
        Some(src) => {
            let addr0 = src.derive(0, 0).map(|d| d.address).unwrap_or_default();
            w.set_funding_summary(
                format!("{} · {} · {n} coin{} · {total} sats", src.kind.label(), short_addr(&addr0), if n == 1 { "" } else { "s" }).into(),
            );
        }
        None => w.set_funding_summary("Set a funding wallet".into()),
    }

    let exb = st.explorer_base();
    let coins: Vec<SpendCoin> = st
        .funding_coins
        .iter()
        .map(|c| SpendCoin {
            outpoint: format!("{}:{}", c.txid, c.vout).into(),
            value: c.value.to_string().into(),
            confirmed: c.confirmed,
            selected: true,
            txid_short: c.txid[..8.min(c.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &c.txid).into(),
        })
        .collect();
    w.set_spend_coins(VecModel::from_slice(&coins));
    w.set_spend_title(format!("Funding {n} coin{} · {total} sats", if n == 1 { "" } else { "s" }).into());
    w.set_cost_line(if text.is_empty() { String::new() } else { "funded from the external wallet".into() }.into());
    w.set_spend_enough(ready && !text.is_empty());

    // Change: blank = the funding wallet's own change; a valid custom address
    // overrides it. Same validation/label pattern as the self-funded path.
    let change_trim = w.get_change_address().trim().to_string();
    if change_trim.is_empty() {
        w.set_change_amount("Change to funding wallet".into());
        w.set_change_error("".into());
    } else if Recipient::parse(net, &normalize_addr(&change_trim)).is_ok() {
        w.set_change_amount(format!("Change to {}…", &change_trim[..14.min(change_trim.len())]).into());
        w.set_change_error("".into());
    } else {
        w.set_change_amount("Change: ⚠ invalid".into());
        w.set_change_error(format!("Not a valid {} address.", net.as_str()).into());
    }
}

/// A per-frame preview closure for [`camera::capture_frames`] — pushes each
/// downscaled frame to the shared `camera-frame` image so the scan overlay
/// shows a live view (QR detection, not the preview, is what's throttled).
fn scan_preview(weak: slint::Weak<AppWindow>) -> impl FnMut(&[u8], u32, u32) {
    move |rgba: &[u8], pw: u32, ph: u32| {
        let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(pw, ph);
        buf.make_mut_bytes().copy_from_slice(rgba);
        let _ = weak.upgrade_in_event_loop(move |w| w.set_camera_frame(slint::Image::from_rgba8(buf)));
    }
}

/// Show the shared scan overlay and clear the cancel flag (call on the UI thread
/// before spawning the capture thread).
fn begin_scan(weak: &slint::Weak<AppWindow>, cancel: &Arc<AtomicBool>, hint: &str) {
    cancel.store(false, Ordering::Relaxed);
    if let Some(w) = weak.upgrade() {
        w.set_scan_hint(hint.into());
        w.set_scan_progress(0.0);
        w.set_scanning(true);
    }
}

/// Populate the saved-wallet manager list (screen 15).
fn refresh_funding_list(w: &AppWindow, st: &State) {
    let active = st.active_funding_id.clone();
    let rows: Vec<FundingWalletRow> = st
        .funding_wallets
        .iter()
        .map(|fw| {
            let meta = if fw.scanned {
                format!("{} · {} sats · {} coin{}", fw.kind, fw.balance, fw.coins, if fw.coins == 1 { "" } else { "s" })
            } else {
                format!("{} · tap to scan for funds", fw.kind)
            };
            FundingWalletRow {
                id: fw.id.clone().into(),
                label: fw.label.clone().into(),
                meta: meta.into(),
                active: active.as_deref() == Some(fw.id.as_str()),
            }
        })
        .collect();
    w.set_funding_wallets(VecModel::from_slice(&rows));
}

/// Make a saved wallet the active funding source: scan it, cache its balance,
/// and return to compose in external-funding mode.
fn activate_funding_wallet(w: &AppWindow, st: &mut State, id: &str) {
    let net = st.network;
    let Some(idx) = st.funding_wallets.iter().position(|fw| fw.id == id) else { return };
    let descriptor = st.funding_wallets[idx].descriptor.clone();
    let src = match FundingSource::parse(&descriptor, net) {
        Ok(src) => src,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };
    let Some(base) = st.base_url() else {
        w.set_status("no Bitcoin node — set one in Settings".into());
        return;
    };
    w.set_status("scanning funding wallet…".into());
    let client = ChainClient::new(HttpTransport::new(&base), net);
    match client.scan_funding(&src, 20) {
        Ok(scan) => {
            st.funding_wallets[idx].balance = scan.utxos.iter().map(|c| c.value).sum();
            st.funding_wallets[idx].coins = scan.utxos.len();
            st.funding_wallets[idx].scanned = true;
            st.save_funding_wallets();
            let empty = scan.utxos.is_empty();
            st.funding_coins = scan.utxos;
            st.funding_change_index = scan.next_change_index;
            st.funding = Some(src);
            st.active_funding_id = Some(id.to_string());
            w.set_status(if empty { "wallet has no spendable coins yet".to_string() } else { String::new() }.into());
            if w.get_funding_return() == 16 {
                // Came from the sweep screen — return there, funding armed.
                w.set_sweep_fund_external(true);
                w.set_screen(16);
                update_sweep_screen(w, st);
            } else {
                w.set_fund_external(true);
                w.set_spend_expanded(true);
                w.set_screen(6);
                refresh_compose(w, st);
            }
        }
        Err(e) => w.set_status(format!("scan failed: {e}").into()),
    }
}

/// If `text` is a UR account/descriptor export (BCR crypto-account etc.),
/// decode it, save every supported descriptor as a funding wallet, and show the
/// manager list. Returns true if the input was a UR (handled — possibly with an
/// error message); false to fall through to plain descriptor handling.
fn try_import_ur_account(w: &AppWindow, st: &mut State, text: &str) -> bool {
    let t = text.trim();
    if !t.to_lowercase().starts_with("ur:") {
        return false;
    }
    let net = st.network;
    let (ty, bytes) = match app_core::ur::decode_ur_string(t) {
        Ok(x) => x,
        Err(e) => {
            w.set_status(format!("UR: {e}").into());
            return true;
        }
    };
    if ty == "crypto-psbt" {
        w.set_status("that's a transaction QR, not a wallet".into());
        return true;
    }
    match app_core::ur_account::descriptors_from_ur(&ty, &bytes, net) {
        Ok(descs) if !descs.is_empty() => {
            let ds: Vec<String> = descs.iter().map(|d| d.descriptor.clone()).collect();
            let added = save_funding_descriptors(w, st, &ds);
            w.set_status(format!("imported {added} account(s) from {ty}").into());
            true
        }
        Ok(_) => {
            w.set_status("no taproot/segwit accounts in that export".into());
            true
        }
        Err(e) => {
            w.set_status(format!("{e}").into());
            true
        }
    }
}

/// Shorten a bech32 address for display: `bcrt1p2caqg…6hrewe`.
fn short_addr(a: &str) -> String {
    if a.len() > 20 {
        format!("{}…{}", &a[..10], &a[a.len() - 6..])
    } else {
        a.to_string()
    }
}

/// Pull an output descriptor out of pasted text or a wallet-export file:
/// a bare descriptor/xpub passes through; otherwise find an embedded
/// `tr(...)`/`wpkh(...)` token (handles Sparrow-style JSON + text exports).
fn extract_descriptor(text: &str) -> String {
    let t = text.trim();
    for pat in ["tr(", "wpkh("] {
        if let Some(i) = t.find(pat) {
            let rest = &t[i..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '}')
                .unwrap_or(rest.len());
            return rest[..end].to_string();
        }
    }
    t.to_string()
}

/// Pull EVERY `tr()`/`wpkh()` descriptor out of pasted text or a wallet-export
/// file — a single export can list several script types. Falls back to the
/// whole trimmed input as one candidate when no `tr(`/`wpkh(` token is present.
fn extract_all_descriptors(text: &str) -> Vec<String> {
    let t = text.trim();
    let mut found: Vec<String> = Vec::new();
    for pat in ["tr(", "wpkh("] {
        let mut from = 0;
        while let Some(rel) = t[from..].find(pat) {
            let start = from + rel;
            let rest = &t[start..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '}')
                .unwrap_or(rest.len());
            let desc = rest[..end].to_string();
            if !found.contains(&desc) {
                found.push(desc);
            }
            from = start + end.max(1);
        }
    }
    if found.is_empty() {
        vec![t.to_string()]
    } else {
        found
    }
}

/// Create + persist a funding wallet for each descriptor (dedup by id), refresh
/// the manager list, and show it. Returns how many NEW wallets were added.
/// Shared by UR account import and multi-descriptor wallet files — the user
/// then picks which one to use from the list.
fn save_funding_descriptors(w: &AppWindow, st: &mut State, descriptors: &[String]) -> usize {
    let net = st.network;
    let mut added = 0;
    for d in descriptors {
        if let Ok(fw) = FundingWallet::create(d, "", net) {
            if !st.funding_wallets.iter().any(|x| x.id == fw.id) {
                st.funding_wallets.push(fw);
                added += 1;
            }
        }
    }
    if added > 0 {
        st.save_funding_wallets();
    }
    refresh_funding_list(w, st);
    w.set_screen(15);
    added
}

/// Load the device-level saved funding wallets (empty if the file is absent).
fn load_funding_wallets(dir: &std::path::Path) -> Vec<FundingWallet> {
    std::fs::read_to_string(dir.join("funding-wallets.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Import a signed PSBT (from file bytes, a base64/hex string, or a UR string),
/// validate it against the tx we built, render the Sparrow-style confirmation,
/// and advance to the review screen.
fn load_signed_psbt(w: &AppWindow, st: &mut State, data: &[u8]) {
    let psbt: Result<bitcoin::Psbt, String> = if data.starts_with(b"psbt\xff") {
        bitcoin::Psbt::deserialize(data).map_err(|e| e.to_string())
    } else {
        let text = String::from_utf8_lossy(data);
        let t = text.trim();
        if t.to_lowercase().starts_with("ur:") {
            let mut dec = app_core::ur::PsbtUrDecoder::new();
            match dec.receive(t) {
                Ok(true) => dec
                    .psbt_bytes()
                    .map_err(|e| e.to_string())
                    .and_then(|b| bitcoin::Psbt::deserialize(&b).map_err(|e| e.to_string())),
                Ok(false) => Err("multi-frame UR — import the .psbt file instead".into()),
                Err(e) => Err(e.to_string()),
            }
        } else {
            parse_psbt(t).map_err(|e| e.to_string())
        }
    };
    match psbt {
        Ok(p) => set_confirm_from_psbt(w, st, p),
        Err(e) => w.set_status(format!("import: {e}").into()),
    }
}

/// Put a freshly built unsigned PSBT on the sign screen (13): animated-UR
/// QR, cost line, save/copy state. Shared by external funding and the
/// watch-mode spend flows.
fn show_psbt_sign_screen(w: &AppWindow, st: &mut State, built: BuiltPsbt, cost_line: String) {
    let frames = app_core::ur::encode_psbt(&built.to_bytes(), 300);
    w.set_psbt_cost_line(cost_line.into());
    w.set_psbt_qr(qr::qr_image(&frames[0]).unwrap_or_default());
    w.set_psbt_frame_label(
        if frames.len() > 1 { format!("frame 1 / {}", frames.len()).into() } else { "".into() },
    );
    st.ur_frames = frames;
    st.built_psbt = Some(built);
    st.signed_psbt = None;
    w.set_psbt_signed(false);
    w.set_status("".into());
    w.set_screen(13);
}

/// Validate + summarize a signed PSBT into the confirmation screen.
fn set_confirm_from_psbt(w: &AppWindow, st: &mut State, psbt: bitcoin::Psbt) {
    let Some(built) = st.built_psbt.as_ref() else {
        w.set_status("build a transaction first".into());
        return;
    };
    if let Err(e) = validate_signed(&psbt, &built.txid) {
        w.set_status(format!("{e}").into());
        return;
    }
    let Some(output_x) = st.ident.as_ref().map(|i| i.output_x()) else { return };
    // Watch spends label their destination as the recipient; the funding
    // flow labels the compose recipient + the funding wallet's change.
    let recipient_addr = match &st.watch_spend {
        Some(ws) => Some(ws.dest.clone()),
        None => st.to_address.clone(),
    };
    let change_addr = match &st.watch_spend {
        Some(_) => None,
        None => st
            .funding
            .as_ref()
            .and_then(|src| src.derive(1, st.funding_change_index).ok())
            .map(|d| d.address),
    };
    let ctx = SummaryContext {
        identity_output_x: output_x,
        network: st.network,
        recipient_addr: recipient_addr.as_deref(),
        change_addr: change_addr.as_deref(),
    };
    let sum = match summarize(&psbt, &ctx) {
        Ok(s) => s,
        Err(e) => {
            w.set_status(format!("{e}").into());
            return;
        }
    };
    let inputs: Vec<PsbtRow> = sum
        .inputs
        .iter()
        .map(|i| PsbtRow {
            title: i.address.clone().unwrap_or_else(|| "(unknown)".into()).into(),
            subtitle: i.outpoint.clone().into(),
            amount: i.value.to_string().into(),
            kind: "input".into(),
        })
        .collect();
    let mut note_text = String::new();
    let outputs: Vec<PsbtRow> = sum
        .outputs
        .iter()
        .map(|o| {
            let (kind, title, subtitle) = match &o.role {
                OutputRole::Note { text, chunks } => {
                    if let Some(t) = text {
                        note_text = t.clone();
                    }
                    (
                        "note",
                        String::new(),
                        if text.is_some() {
                            "OP_RETURN · PNTE note".to_string()
                        } else {
                            format!("OP_RETURN · encrypted note ({chunks} chunk)")
                        },
                    )
                }
                OutputRole::SelfDust => ("self", o.address.clone().unwrap_or_default(), "your notebook (keeps the note yours)".into()),
                OutputRole::Recipient => ("recipient", o.address.clone().unwrap_or_default(), "directed recipient".into()),
                OutputRole::Change => ("change", o.address.clone().unwrap_or_default(), "change back to the funding wallet".into()),
                OutputRole::Other => ("other", o.address.clone().unwrap_or_default(), String::new()),
            };
            PsbtRow { title: title.into(), subtitle: subtitle.into(), amount: o.value.to_string().into(), kind: kind.into() }
        })
        .collect();
    if note_text.is_empty() {
        note_text = match &st.watch_spend {
            Some(ws) => format!("{} · {} sats → {}", ws.kind, ws.value, ws.dest),
            None => "Encrypted note — readable only by you and the recipient.".into(),
        };
    }
    w.set_confirm_note(note_text.into());
    w.set_confirm_inputs(VecModel::from_slice(&inputs));
    w.set_confirm_outputs(VecModel::from_slice(&outputs));
    w.set_confirm_fee_line(format!("{} sats", sum.fee).into());
    st.signed_psbt = Some(psbt);
    w.set_psbt_signed(true);
    w.set_status("".into());
    w.set_screen(14);
}

/// Read the platform safe-area insets (converting with the window's scale
/// factor) and push them into the UI. Cheap; called on a few startup ticks
/// and a slow rotation poll. No-op on desktop (insets are 0).
fn apply_safe_area(win: &AppWindow) {
    let scale = win.window().scale_factor();
    let (top, bottom) = platform::safe_area_insets(scale);
    if (win.get_safe_top() - top).abs() > 0.5 || (win.get_safe_bottom() - bottom).abs() > 0.5 {
        println!("cb: safe-area top={top:.1} bottom={bottom:.1} scale={scale:.2}");
    }
    win.set_safe_top(top);
    win.set_safe_bottom(bottom);
    // Reveal the UI once the inset is known — immediately on desktop (no
    // insets), or as soon as a mobile window reports a real top inset. Until
    // then a splash cover hides the content so it never visibly slides down
    // from under the status bar on cold start.
    if !platform::has_insets() || top > 0.0 {
        win.set_ready(true);
    }
}

/// Shared entry point. The desktop/iOS bin calls this from `fn main`;
/// the Android cdylib calls it from `android_main` after Slint's
/// android backend is initialized.
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--spike") {
        let result = match args.get(2).map(String::as_str) {
            Some("keychain") => keychain::spike(),
            Some("keychain-auth") => keychain::spike_auth(),
            Some("camera") => {
                camera::spike(args.get(3).and_then(|s| s.parse().ok()).unwrap_or(15))
            }
            other => Err(format!("unknown spike {other:?}")),
        };
        if let Err(e) = result {
            eprintln!("cb: spike err={e}");
            std::process::exit(1);
        }
        return;
    }
    // Headless design preview: `--render <out-dir> <screen>[,<screen>...]`
    // renders each screen to a PNG via the software renderer (no window).
    // macOS-only dev tool (the software renderer isn't in the mobile builds).
    #[cfg(target_os = "macos")]
    {
        if args.get(1).map(String::as_str) == Some("--render") {
            let out_dir = args.get(2).cloned().unwrap_or_else(|| ".".into());
            let screens: Vec<i32> = args
                .get(3)
                .map(|s| s.split(',').filter_map(|n| n.trim().parse().ok()).collect())
                .unwrap_or_else(|| vec![6, 12, 13, 14]);
            render_previews(480, 900, &screens, &out_dir);
            return;
        }
    }

    let data_dir = std::env::var("APP_DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(std::env::var("HOME").expect("HOME"))
            .join("Library/Application Support/ChainNotes")
    });
    let _ = std::fs::create_dir_all(&data_dir);
    let config: serde_json::Value = std::fs::read_to_string(data_dir.join("config.json"))
        .ok()
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or(serde_json::Value::Null);
    let network = std::env::var("APP_NETWORK")
        .ok()
        .or_else(|| config.get("network").and_then(|v| v.as_str()).map(String::from))
        .and_then(|s| Network::from_str_opt(&s))
        .unwrap_or(Network::Testnet4);
    let account: u32 = std::env::var("APP_ACCOUNT")
        .ok()
        .and_then(|a| a.parse().ok())
        .or_else(|| config.get("account").and_then(|v| v.as_u64()).map(|v| v as u32))
        .unwrap_or(0);
    // Device-level per-network Settings (Bitcoin node / block explorer URLs).
    let str_map = |key: &str| -> HashMap<String, String> {
        config
            .get(key)
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    };
    let node_urls = str_map("nodes");
    let explorers = str_map("explorers");
    let funding_wallets = load_funding_wallets(&data_dir);

    let st = Rc::new(RefCell::new(State {
        data_dir,
        network,
        account,
        node_urls,
        explorers,
        ident: None,
        store: None,
        fees: None,
        usd: None,
        to_address: None,
        selected_coins: Vec::new(),
        coins_overridden: false,
        consolidate_coins: false,
        material: None,
        icloud_backup: false,
        pending_import: None,
        pending_mnemonic: None,
        quiz_indices: Vec::new(),
        compose_oversize: false,
        funding: None,
        funding_coins: Vec::new(),
        funding_change_index: 0,
        built_psbt: None,
        ur_frames: Vec::new(),
        signed_psbt: None,
        funding_wallets,
        active_funding_id: None,
        watch_spend: None,
        watch_bump: None,
        watch_note: None,
        notebooks: None,
        notebooks_fp8: None,
        nb_addrs: Vec::new(),
    }));
    let window = AppWindow::new().expect("window");
    // iCloud UI is Apple-only; Android's keystore is device-bound.
    window.set_apple_platform(cfg!(target_vendor = "apple"));
    window.set_desktop_platform(cfg!(target_os = "macos"));
    window.set_biometric_name(
        if cfg!(target_os = "ios") {
            "Face ID"
        } else if cfg!(target_os = "android") {
            "biometrics"
        } else {
            "Touch ID"
        }
        .into(),
    );
    // Back-chevron optical nudge: Roboto's line box differs from the Apple
    // system font's, so Android gets its own calibrated value (see the
    // Metrics global in app.slint; Apple platforms keep the -1.25px default).
    #[cfg(target_os = "android")]
    window.global::<Metrics>().set_back_dy(1.5);

    // EditOps: UTF-8 byte-offset text helpers + platform clipboard for the
    // EditField/EditArea widgets (offsets come from TextInput's cursor API
    // and are always char boundaries; clamp defensively anyway).
    {
        fn clamp_boundary(t: &str, mut i: usize) -> usize {
            i = i.min(t.len());
            while i > 0 && !t.is_char_boundary(i) {
                i -= 1;
            }
            i
        }
        fn range(t: &str, s: i32, e: i32) -> (usize, usize) {
            let s = clamp_boundary(t, s.max(0) as usize);
            let e = clamp_boundary(t, e.max(0) as usize);
            (s.min(e), s.max(e))
        }
        let is_word = |c: char| c.is_alphanumeric() || c == '_';
        let ops = window.global::<EditOps>();
        ops.on_slice(|t, s, e| {
            let (s, e) = range(t.as_str(), s, e);
            t.as_str()[s..e].into()
        });
        ops.on_splice(|t, s, e, ins| {
            let (s, e) = range(t.as_str(), s, e);
            let mut out = String::with_capacity(t.len() + ins.len());
            out.push_str(&t.as_str()[..s]);
            out.push_str(ins.as_str());
            out.push_str(&t.as_str()[e..]);
            out.into()
        });
        ops.on_byte_len(|t| t.len() as i32);
        ops.on_word_start(move |t, off| {
            let t = t.as_str();
            let mut i = clamp_boundary(t, off.max(0) as usize);
            // if the char at the offset isn't a word char, try the one before
            if !t[i..].chars().next().map(is_word).unwrap_or(false)
                && !t[..i].chars().next_back().map(is_word).unwrap_or(false)
            {
                return i as i32;
            }
            while let Some(c) = t[..i].chars().next_back() {
                if is_word(c) {
                    i -= c.len_utf8();
                } else {
                    break;
                }
            }
            i as i32
        });
        ops.on_word_end(move |t, off| {
            let t = t.as_str();
            let mut i = clamp_boundary(t, off.max(0) as usize);
            if !t[i..].chars().next().map(is_word).unwrap_or(false)
                && !t[..i].chars().next_back().map(is_word).unwrap_or(false)
            {
                // not on a word: select the single char under the cursor (if any)
                if let Some(c) = t[i..].chars().next() {
                    return (i + c.len_utf8()) as i32;
                }
                return i as i32;
            }
            while let Some(c) = t[i..].chars().next() {
                if is_word(c) {
                    i += c.len_utf8();
                } else {
                    break;
                }
            }
            i as i32
        });
        ops.on_clip_set(|t| {
            let ok = platform::set_clipboard_text(t.as_str());
            println!("cb: edit-clip-set bytes={} ok={ok}", t.len());
        });
        ops.on_clip_get(|| {
            let t = platform::clipboard_text().unwrap_or_default();
            println!("cb: edit-clip-get bytes={}", t.len());
            t.into()
        });
        #[cfg(any(target_os = "ios", target_os = "android"))]
        ops.set_touch(true);
        #[cfg(target_os = "ios")]
        ops.set_ios(true);
    }

    // Boot identity: APP_KEY env (dev/tests) or the keychain.
    {
        let mut s = st.borrow_mut();
        let material = match std::env::var("APP_KEY") {
            Ok(k) => Some(k),
            Err(_) => match keychain::load_secret_protected(
                KEYCHAIN_ACCOUNT,
                "unlock your Chain Notes identity",
            ) {
                Ok(m) => m,
                Err(e) if e == "cancelled" => {
                    println!("cb: unlock cancelled");
                    window.set_status(
                        "unlock cancelled — restart the app to try again, or import a key".into(),
                    );
                    None
                }
                Err(e) => {
                    window.set_status(format!("keychain: {e}").into());
                    None
                }
            },
        };
        if let Some(m) = material {
            match activate(&mut s, &m, false) {
                Ok(()) => {
                    // The notebook list is the main screen; the active
                    // notebook's home is one tap in.
                    update_home(&window, &s);
                    update_notebook_list(&window, &s);
                    window.set_screen(17);
                    // Initial sync AFTER the first frame. Blocking the launch
                    // path on network I/O gets the app killed by the iOS
                    // launch watchdog (black screen, then 0x8badf00d) when
                    // started from the home screen — devicectl/Xcode launches
                    // relax the watchdog, which masked this. A single-shot
                    // timer lets winit attach the scene and paint first; the
                    // sync itself stays synchronous, same as a manual ↻.
                    let w = window.as_weak();
                    let st_boot = st.clone();
                    slint::Timer::single_shot(std::time::Duration::from_millis(300), move || {
                        if let Some(win) = w.upgrade() {
                            refresh(&win, &mut st_boot.borrow_mut());
                        }
                    });
                }
                Err(e) => window.set_status(format!("stored key failed: {e}").into()),
            }
        }
    }

    // Reflect the stored key's iCloud-sync state, and whether a synced backup
    // exists to offer a restore in onboarding.
    {
        let mut s = st.borrow_mut();
        let synced = keychain::is_synced(KEYCHAIN_ACCOUNT);
        s.icloud_backup = synced;
        window.set_icloud_backup(synced);
        window.set_icloud_available(synced);
    }

    // System back (Android): the ui-side nav-back() already navigated; this
    // just emits the log-contract line (screen = where back landed us). No
    // state borrow — nav-back may have gone through a state-borrowing
    // callback (go-home etc.) synchronously before this fires.
    window.on_back_logged(|handled, screen| {
        println!("cb: sys-back handled={handled} screen={screen}");
    });

    macro_rules! cb {
        ($name:ident, |$w:ident, $s:ident $(, $arg:ident : $ty:ty)*| $body:block) => {{
            let st = st.clone();
            let weak = window.as_weak();
            window.$name(move |$($arg : $ty),*| {
                let $w = weak.unwrap();
                let mut $s = st.borrow_mut();
                $body
            });
        }};
    }

    cb!(on_door_import, |w, s| {
        println!("cb: door=import");
        let _ = &mut s;
        w.set_import_feedback("".into());
        w.set_screen(1);
    });

    cb!(on_door_create, |w, s, words: i32| {
        println!("cb: door=create words={words}");
        match generate_mnemonic(words as usize) {
            Ok(m) => {
                let phrase = m.to_string();
                let grid: String = phrase
                    .split(' ')
                    .enumerate()
                    .map(|(i, wd)| {
                        format!("{:>2}. {:<9}{}", i + 1, wd, if i % 3 == 2 { "\n" } else { " " })
                    })
                    .collect();
                if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
                    // TEST ONLY (env-gated): lets the UI e2e complete the
                    // backup quiz. Never set outside automation.
                    println!("cb-test: words={phrase}");
                }
                w.set_backup_words(grid.into());
                s.pending_mnemonic = Some(phrase);
                w.set_screen(2);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    // "New words" (↻) on the backup screen: reroll a fresh mnemonic of the same
    // length, in case the user didn't like the ones shown.
    cb!(on_regenerate_words, |w, s| {
        let count = s
            .pending_mnemonic
            .as_ref()
            .map(|m| m.split(' ').count())
            .unwrap_or(12);
        let salt = w.get_entropy_salt().to_string();
        match generate_mnemonic_with_salt(count, &salt) {
            Ok(m) => {
                let phrase = m.to_string();
                let grid: String = phrase
                    .split(' ')
                    .enumerate()
                    .map(|(i, wd)| {
                        format!("{:>2}. {:<9}{}", i + 1, wd, if i % 3 == 2 { "\n" } else { " " })
                    })
                    .collect();
                if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
                    println!("cb-test: words={phrase}");
                }
                println!("cb: regenerate-words count={count}");
                w.set_backup_words(grid.into());
                s.pending_mnemonic = Some(phrase);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    // iCloud backup toggle (backup screen + Settings). Sets the sync mode; if a
    // key is already stored this session, re-stores it with the new mode.
    cb!(on_set_icloud_backup, |w, s, enabled: bool| {
        s.icloud_backup = enabled;
        println!("cb: set-icloud-backup {enabled}");
        if let Some(material) = s.material.clone() {
            match keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material.trim(), enabled) {
                Ok(()) => w.set_status(
                    if enabled { "iCloud backup on" } else { "iCloud backup off" }.into(),
                ),
                Err(e) => {
                    w.set_status(format!("iCloud: {e}").into());
                    s.icloud_backup = !enabled;
                    w.set_icloud_backup(!enabled);
                }
            }
        }
    });

    // Restore from an existing iCloud-synced key (onboarding, after reinstall
    // or on a new device).
    cb!(on_restore_icloud, |w, s| {
        match keychain::load_secret_protected(KEYCHAIN_ACCOUNT, "restore your Chain Notes identity") {
            Ok(Some(material)) => {
                s.icloud_backup = true;
                match activate(&mut s, &material, false) {
                    Ok(()) => {
                        println!("cb: restore-icloud ok");
                        w.set_icloud_backup(true);
                        w.set_screen(4);
                        update_home(&w, &s);
                        refresh(&w, &mut s);
                    }
                    Err(e) => w.set_status(format!("restore: {e}").into()),
                }
            }
            Ok(None) => w.set_status("no iCloud backup found".into()),
            Err(e) => w.set_status(format!("restore: {e}").into()),
        }
    });

    cb!(on_backup_continue, |w, s| {
        let Some(phrase) = s.pending_mnemonic.clone() else { return };
        let count = phrase.split(' ').count();
        let mut idx = [0u8; 3];
        let _ = getrandom_fill(&mut idx);
        let mut picks: Vec<usize> = idx.iter().map(|b| (*b as usize) % count).collect();
        picks.sort();
        picks.dedup();
        while picks.len() < 3 {
            picks.push((picks.last().copied().unwrap_or(0) + 3) % count);
            picks.sort();
            picks.dedup();
        }
        if std::env::var("APP_TEST_SHOW_WORDS").is_ok() {
            println!("cb-test: quiz={} {} {}", picks[0] + 1, picks[1] + 1, picks[2] + 1);
        }
        w.set_quiz_prompt(
            format!(
                "Type words #{}, #{} and #{} (space separated):",
                picks[0] + 1,
                picks[1] + 1,
                picks[2] + 1
            )
            .into(),
        );
        s.quiz_indices = picks;
        w.set_quiz_answer("".into());
        w.set_screen(3);
    });

    cb!(on_quiz_submit, |w, s, answer: SharedString| {
        let Some(phrase) = s.pending_mnemonic.clone() else { return };
        let words: Vec<&str> = phrase.split(' ').collect();
        let expect: Vec<&str> = s.quiz_indices.iter().map(|i| words[*i]).collect();
        let got: Vec<String> =
            answer.split_whitespace().map(|x| x.to_lowercase()).collect();
        let ok = got == expect;
        println!("cb: quiz ok={ok}");
        if !ok {
            w.set_status("mismatch — check your written words and try again".into());
            return;
        }
        match activate(&mut s, &phrase, true) {
            Ok(()) => {
                s.pending_mnemonic = None;
                w.set_status("".into());
                w.set_screen(4);
                update_home(&w, &s);
                refresh(&w, &mut s);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_import_changed, |w, s, text: SharedString| {
        let t = text.trim().to_string();
        if t.is_empty() {
            w.set_import_feedback("".into());
            w.set_import_suggestions("".into());
            return;
        }
        // Word autocomplete for the mnemonic path.
        let last = t.split_whitespace().last().unwrap_or("");
        let sugg = if last.len() >= 2 && last.chars().all(|c| c.is_ascii_alphabetic()) {
            let prefix = last.to_lowercase();
            let matches = bip39::Language::English.words_by_prefix(&prefix);
            if matches.len() > 1 || (matches.len() == 1 && matches[0] != last) {
                format!("… {}", matches.iter().take(6).cloned().collect::<Vec<_>>().join(" · "))
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        w.set_import_suggestions(sugg.into());
        let (fb, ok) = match parse_key_material(&t, s.network) {
            Ok(m) if is_hierarchical(&t, s.network) => {
                (format!("{} OK — you'll choose an account next", m.kind()), true)
            }
            Ok(m) => match realize(&m, s.network, 0) {
                Ok(p) => {
                    let a = &p.address;
                    let label = if m.is_watch() {
                        "account xpub OK — watch-only: public notes and balance, no signing"
                    } else {
                        "OK"
                    };
                    let kind_prefix = if m.is_watch() { String::new() } else { format!("{} ", m.kind()) };
                    (format!("{kind_prefix}{label} · {}…{}", &a[..12.min(a.len())], &a[a.len().saturating_sub(6)..]), true)
                }
                Err(e) => (format!("{e}"), false),
            },
            Err(e) => (format!("{e}"), false),
        };
        w.set_import_feedback_ok(ok);
        w.set_import_feedback(fb.into());
    });

    cb!(on_import_confirm, |w, s, text: SharedString| {
        let t = text.trim().to_string();
        if parse_key_material(&t, s.network).is_ok() && is_hierarchical(&t, s.network) {
            println!("cb: import hierarchical → account picker");
            s.pending_import = Some(Zeroizing::new(t.clone()));
            show_account_picker(&w, &t, s.network, 0, None);
            return;
        }
        s.account = 0;
        match activate(&mut s, text.trim(), true) {
            Ok(()) => {
                println!("cb: import ok");
                w.set_import_text("".into());
                w.set_screen(4);
                update_home(&w, &s);
                refresh(&w, &mut s);
            }
            Err(e) => {
                println!("cb: import err={e}");
                w.set_import_feedback_ok(false);
                w.set_import_feedback(format!("{e}").into());
            }
        }
    });

    // Shared cancel flag for every "Scan QR" path (set by the overlay's Cancel).
    let scan_cancel = Arc::new(AtomicBool::new(false));
    {
        let sc = scan_cancel.clone();
        let weak = window.as_weak();
        window.on_cancel_scan(move || {
            sc.store(true, Ordering::Relaxed);
            if let Some(w) = weak.upgrade() {
                w.set_scanning(false);
            }
        });
    }
    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.on_import_scan(move || {
            println!("cb: import-scan start");
            let weak = weak.clone();
            let cancel = scan_cancel.clone();
            begin_scan(&weak, &cancel, "Point your key or SeedQR at the camera");
            std::thread::spawn(move || {
                let preview = scan_preview(weak.clone());
                let text = match camera::capture_and_decode(30, &cancel, preview) {
                    Ok(Some(payload)) => match app_core::seedqr::decode(&payload) {
                        Ok(m) => m.to_string(),
                        Err(_) => String::from_utf8_lossy(&payload).to_string(),
                    },
                    Ok(None) => String::new(),
                    Err(e) => {
                        println!("cb: import-scan err={e}");
                        String::new()
                    }
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_scanning(false);
                    if !text.is_empty() {
                        println!("cb: import-scan ok len={}", text.len());
                        w.set_import_text(text.clone().into());
                        w.invoke_import_changed(text.into());
                    } else {
                        w.set_import_feedback_ok(false);
                        w.set_import_feedback("scan: no QR seen".into());
                    }
                });
            });
        });
    }

    // Paste from the system clipboard — Slint's iOS text fields don't surface
    // the native paste menu, so this reads UIPasteboard directly. Deferred to
    // the event loop so import-changed re-runs without a State double-borrow.
    cb!(on_paste_import, |w, s| {
        let _ = &mut s;
        match platform::clipboard_text() {
            Some(text) => {
                let _ = w.as_weak().upgrade_in_event_loop(move |w| {
                    w.set_import_text(text.clone().into());
                    w.invoke_import_changed(text.into());
                });
            }
            None => {
                w.set_import_feedback_ok(false);
                w.set_import_feedback("clipboard empty".into());
            }
        }
    });

    // Paste into the compose note (appends clipboard to the current text).
    cb!(on_paste_compose, |w, s| {
        let _ = &mut s;
        if let Some(text) = platform::clipboard_text() {
            let combined = format!("{}{}", w.get_compose_text(), text);
            let _ = w.as_weak().upgrade_in_event_loop(move |w| {
                w.set_compose_text(combined.clone().into());
                w.invoke_compose_changed();
            });
        }
    });

    cb!(on_import_file, |w, s| {
        let _ = &mut s;
        if let Some(path) = platform::pick_file(&[]) {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    println!("cb: import-file len={}", text.trim().len());
                    w.set_import_text(text.trim().into());
                    w.invoke_import_changed(text.trim().into());
                }
                Err(e) => {
                    w.set_import_feedback_ok(false);
                    w.set_import_feedback(format!("file: {e}").into());
                }
            }
        }
    });

    cb!(on_refresh, |w, s| {
        refresh(&w, &mut s);
    });

    cb!(on_open_note, |w, s, id: SharedString| {
        let Some(store) = &s.store else { return };
        if let Some(n) = store.notes.iter().find(|n| n.note_id.as_str() == id.as_str()) {
            println!("cb: open-note id={} status={:?}", n.note_id, n.status);
            let watch = s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
            let detail = format!(
                "{}\n\nid: {}\nkind: {}{}{}\ntxids: {}\nheight: {}\n{}{}",
                n.text.as_deref().unwrap_or(if watch && n.private {
                    "(private — the key that reads this note isn't on this device)"
                } else {
                    "(not decryptable)"
                }),
                n.note_id,
                if n.received { "received" } else { "own" },
                if n.directed { " · directed" } else { "" },
                if n.private { " · private" } else { " · public" },
                n.txids.join(", "),
                n.height.map(|h| h.to_string()).unwrap_or_else(|| "unconfirmed".into()),
                n.sender.as_deref().map(|a| format!("from: {a}\n")).unwrap_or_default(),
                n.recipient.as_deref().map(|a| format!("to: {a}\n")).unwrap_or_default(),
            );
            w.set_note_detail(detail.into());
            w.set_note_view_id(n.note_id.clone().into());
            w.set_note_pending(n.status == NoteStatus::Pending && n.raw_hex.is_some());
            w.set_note_txid(n.txids.last().cloned().unwrap_or_default().into());
            let web = match s.network {
                Network::Regtest => String::new(),
                net => {
                    let addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
                    format!(
                        "https://objsal.github.io/chain-notes-companion/note.html?address={addr}&network={}&note={}",
                        net.as_str(),
                        n.note_id
                    )
                }
            };
            w.set_note_web_url(web.into());
            w.set_screen(5);
        }
    });

    cb!(on_open_note_web, |w, s| {
        let _ = &mut s;
        let url = w.get_note_web_url().to_string();
        if url.is_empty() {
            return;
        }
        println!("cb: open-note-web url={url}");
        let _ = platform::open_url(&url);
    });

    cb!(on_copy_text, |w, s, kind: SharedString, text: SharedString| {
        let _ = &mut s;
        let _ = &w;
        let ok = platform::set_clipboard_text(text.as_str());
        println!("cb: copy kind={kind} len={} ok={ok}", text.len());
    });

    cb!(on_set_fee_tier, |w, s, tier: i32| {
        let f = s.fees.clone().unwrap_or_default();
        let rate = match tier {
            0 => f.economy,
            2 => f.fastest,
            _ => f.hour,
        }
        .max(1.0);
        w.set_fee_tier(tier);
        w.set_rate_text(format!("{rate}").into());
        println!("cb: fee-tier {tier} rate={rate}");
        refresh_compose(&w, &mut s);
    });

    cb!(on_open_coins, |w, s| {
        println!("cb: open-coins");
        update_home(&w, &s);
        w.set_status("".into());
        w.set_screen(10);
    });

    cb!(on_open_activity, |w, s| {
        println!("cb: open-activity");
        update_activity(&w, &s);
        w.set_status("".into());
        w.set_screen(11);
    });

    cb!(on_act_retry, |w, s, ref_id: SharedString, is_note: bool| {
        let Some(base) = s.base_url() else { return };
        let client = ChainClient::new(HttpTransport::new(base), s.network);
        let (raw, last_txid) = if is_note {
            let n = s
                .store
                .as_ref()
                .and_then(|st| st.notes.iter().find(|n| n.note_id.as_str() == ref_id.as_str()));
            (n.and_then(|n| n.raw_hex.clone()), n.and_then(|n| n.txids.last().cloned()))
        } else {
            let t = s
                .store
                .as_ref()
                .and_then(|st| st.txs.iter().find(|t| t.txids.iter().any(|x| x == ref_id.as_str())));
            (t.and_then(|t| t.raw_hex.clone()), t.and_then(|t| t.txids.last().cloned()))
        };
        // Chain-recovered records (watch mode) carry no raw hex — the node
        // that already knows the tx is the keyless rebroadcast source.
        let raw = match raw.or_else(|| last_txid.and_then(|t| client.fetch_tx_hex(&t).ok())) {
            Some(r) if !r.is_empty() => r,
            _ => {
                w.set_status("nothing to rebroadcast".into());
                return;
            }
        };
        match client.broadcast(&raw) {
            Ok(txid) => {
                println!("cb: act-retry ref={ref_id} txid={txid} ok");
                w.set_status(format!("rebroadcast {}…", &txid[..12.min(txid.len())]).into());
            }
            Err(e) => {
                println!("cb: act-retry ref={ref_id} err={e}");
                w.set_status(format!("rebroadcast failed: {e}").into());
            }
        }
    });

    cb!(on_act_bump_open, |w, s, ref_id: SharedString, is_note: bool| {
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            watch_bump_open(&w, &mut s, ref_id.to_string(), is_note);
            return;
        }
        let Some(store) = &s.store else { return };
        let Some((old_rate, fee, vsize)) = tx_rate(store, ref_id.as_str(), is_note) else {
            w.set_status("can't determine current fee rate".into());
            return;
        };
        // BIP-125: the replacement must add at least 1 sat/vB (incremental
        // relay) over the original, and pay a strictly higher total fee.
        let min_rate = old_rate + 1.0;
        let fast = s.fees.as_ref().map(|f| f.fastest).unwrap_or(min_rate);
        let recommended = fast.max(min_rate);
        println!("cb: bump-open ref={ref_id} old={old_rate:.1} min={min_rate:.1}");
        w.set_bump_ref(ref_id.clone());
        w.set_bump_is_note(is_note);
        w.set_bump_kind(if is_note { "Note transaction" } else { "Sweep / consolidate" }.into());
        w.set_bump_current(format!("Currently {old_rate:.1} sat/vB · {fee} sats fee").into());
        w.set_bump_min(format!("Minimum {min_rate:.1} sat/vB — RBF must add ≥1 sat/vB.").into());
        w.set_bump_error("".into());
        w.set_bump_rate(format!("{recommended:.1}").into());
        w.set_bump_new_fee(new_fee_line(recommended, vsize, fee).into());
        w.set_show_bump_dialog(true);
    });

    cb!(on_act_bump_rate_changed, |w, s, rate_s: SharedString| {
        let ref_id = w.get_bump_ref().to_string();
        let is_note = w.get_bump_is_note();
        if let Some(wb) =
            s.watch_bump.as_ref().filter(|wb| wb.ref_id == ref_id && wb.is_note == is_note)
        {
            match rate_s.trim().parse::<f64>() {
                Ok(r) if r > 0.0 => w.set_bump_new_fee(new_fee_line(r, wb.vsize, wb.old_fee).into()),
                _ => w.set_bump_new_fee("".into()),
            }
            return;
        }
        let Some((_, old_fee, vsize)) = s.store.as_ref().and_then(|st| tx_rate(st, &ref_id, is_note))
        else {
            return;
        };
        match rate_s.trim().parse::<f64>() {
            Ok(r) if r > 0.0 => w.set_bump_new_fee(new_fee_line(r, vsize, old_fee).into()),
            _ => w.set_bump_new_fee("".into()),
        }
    });

    cb!(on_act_bump_confirm, |w, s| {
        let ref_id = w.get_bump_ref().to_string();
        let is_note = w.get_bump_is_note();
        let Ok(new_rate) = w.get_bump_rate().trim().parse::<f64>() else {
            w.set_bump_error("enter a number".into());
            return;
        };
        let net = s.network;
        let Some(base) = s.base_url() else { return };
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            watch_bump_confirm(&w, &mut s, new_rate);
            return;
        }
        let min_rate = match s.store.as_ref().and_then(|st| tx_rate(st, &ref_id, is_note)) {
            Some((old_rate, _, _)) => old_rate + 1.0,
            None => {
                w.set_bump_error("transaction no longer pending".into());
                return;
            }
        };
        if new_rate + 1e-9 < min_rate {
            w.set_bump_error(format!("below the {min_rate:.1} sat/vB minimum").into());
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.set_bump_error("no identity".into());
            return;
        };
        let result: Result<(String, String, u64), app_core::Error> = if is_note {
            app_core::compose::bump_fee(s.store.as_mut().unwrap(), &identity, net, &ref_id, new_rate)
                .map(|c| (c.tx.raw_hex.clone(), c.tx.txid_hex.clone(), c.tx.fee))
        } else {
            app_core::compose::bump_raw_tx(s.store.as_mut().unwrap(), &identity, &ref_id, new_rate)
                .map(|tx| (tx.raw_hex.clone(), tx.txid_hex.clone(), tx.fee))
        };
        match result {
            Ok((raw, txid, fee)) => {
                s.save_store();
                w.set_show_bump_dialog(false);
                let client = ChainClient::new(HttpTransport::new(base), net);
                match client.broadcast(&raw) {
                    Ok(bt) => {
                        println!("cb: act-bump ref={ref_id} txid={txid} fee={fee} rate={new_rate:.1} ok");
                        w.set_status(format!("sped up: {}…", &bt[..12.min(bt.len())]).into());
                    }
                    Err(e) => {
                        println!("cb: act-bump ref={ref_id} broadcast err={e}");
                        w.set_status(format!("signed but broadcast failed: {e}").into());
                    }
                }
                update_activity(&w, &s);
                update_home(&w, &s);
            }
            Err(e) => {
                println!("cb: act-bump ref={ref_id} err={e}");
                w.set_bump_error(format!("{e}").into());
            }
        }
    });

    cb!(on_act_explorer, |w, s, url: SharedString| {
        let _ = &mut s;
        if url.is_empty() {
            return;
        }
        println!("cb: act-explorer");
        let _ = platform::open_url(url.as_str());
    });

    // Fee preview for the consolidate dialog: dry-run the SAME builder the
    // Consolidate button broadcasts. Key-spend signatures are constant-size,
    // so the previewed fee/vsize match the broadcast tx exactly.
    cb!(on_consolidate_preview, |w, s| {
        refresh_consolidate_preview(&w, &mut s);
    });

    cb!(on_consolidate, |w, s| {
        w.set_show_consolidate_confirm(false);
        let rate: f64 = w.get_consolidate_rate().trim().parse().unwrap_or(1.0);
        let net = s.network;
        let Some(base) = s.base_url() else { return };
        // Self-send: consolidate all spendable coins into one output at
        // our own address.
        let Some(self_addr) = s.ident.as_ref().map(|i| i.address.clone()) else { return };
        let Ok(me) = Recipient::parse(net, &self_addr) else { return };
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            let spk = me.spk.clone();
            watch_spend_build(&w, &mut s, "consolidate", self_addr, spk, rate);
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields())
        else {
            w.set_status("no identity".into());
            return;
        };
        let store = s.store.as_mut().unwrap();
        if store.available_utxos().len() < 2 {
            w.set_status("nothing to consolidate (need 2+ coins)".into());
            return;
        }
        let inputs = spendable_inputs(store);
        let dest_spk_hex = hex::encode(&me.spk);
        let tx = app_core::notes_core::tx::build_sweep_tx(
            &store.available_utxos(),
            &identity.output_x,
            me.spk,
            rate,
            &identity.tweaked_seckey,
            app_core::notes_core::keys::generate_aux_rand,
        );
        match tx {
            Ok(tx) => {
                let client = ChainClient::new(HttpTransport::new(base), net);
                match client.broadcast(&tx.raw_hex) {
                    Ok(txid) => {
                        for u in &mut store.utxos {
                            u.pending_spend = true;
                        }
                        store.record_tx("consolidate", txid.clone(), tx.tx.outputs[0].value, tx.fee, tx.vsize as u64, tx.raw_hex.clone(), "self".into(), inputs, dest_spk_hex, now());
                        s.save_store();
                        println!("cb: consolidate txid={txid} value={} fee={}", tx.tx.outputs[0].value, tx.fee);
                        w.set_status(format!("consolidating: {}…", &txid[..12.min(txid.len())]).into());
                        w.set_screen(4); // done — home, like the PSBT flow
                        update_home(&w, &s);
                    }
                    Err(e) => w.set_status(format!("consolidate broadcast failed: {e}").into()),
                }
            }
            Err(e) => w.set_status(format!("consolidate: {e}").into()),
        }
    });

    cb!(on_sweep, |w, s| {
        w.set_show_sweep_confirm(false);
        let dest = w.get_sweep_dest().to_string();
        let rate: f64 = w.get_sweep_rate().trim().parse().unwrap_or(1.0);
        let net = s.network;
        let Some(base) = s.base_url() else { return };
        let Ok(recipient) = Recipient::parse(net, &dest) else {
            w.set_status(format!("not a valid {} address", net.as_str()).into());
            return;
        };
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            watch_spend_build(&w, &mut s, "sweep", dest.clone(), recipient.spk.clone(), rate);
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.set_status("no identity".into());
            return;
        };
        let store = s.store.as_mut().unwrap();
        let inputs = spendable_inputs(store);
        let dest_spk_hex = hex::encode(&recipient.spk);
        let sweep = app_core::notes_core::tx::build_sweep_tx(
            &store.available_utxos(),
            &identity.output_x,
            recipient.spk,
            rate,
            &identity.tweaked_seckey,
            app_core::notes_core::keys::generate_aux_rand,
        );
        match sweep {
            Ok(tx) => {
                let client = ChainClient::new(HttpTransport::new(base), net);
                match client.broadcast(&tx.raw_hex) {
                    Ok(txid) => {
                        for u in &mut store.utxos {
                            u.pending_spend = true;
                        }
                        store.record_tx("sweep", txid.clone(), tx.tx.outputs[0].value, tx.fee, tx.vsize as u64, tx.raw_hex.clone(), dest.clone(), inputs, dest_spk_hex, now());
                        s.save_store();
                        println!(
                            "cb: sweep txid={txid} value={} fee={}",
                            tx.tx.outputs[0].value, tx.fee
                        );
                        w.set_status(format!("swept {} sats to {}…", tx.tx.outputs[0].value, &dest[..14.min(dest.len())]).into());
                        w.set_screen(4); // done — home, like the PSBT flow
                        update_home(&w, &s);
                    }
                    Err(e) => w.set_status(format!("sweep broadcast failed: {e}").into()),
                }
            }
            Err(e) => w.set_status(format!("sweep: {e}").into()),
        }
    });

    cb!(on_open_note_web_url, |w, s, url: SharedString| {
        let _ = &mut s;
        if url.is_empty() {
            return;
        }
        println!("cb: open-note-web-url");
        let _ = platform::open_url(url.as_str());
    });

    cb!(on_compose_open, |w, s| {
        println!("cb: compose-open");
        w.set_pick_mode("compose".into());
        refresh_contacts(&w, &s);
        w.set_contact_input("".into());
        w.set_status("".into());
        w.set_screen(7);
    });

    cb!(on_sweep_open, |w, s| {
        println!("cb: sweep-open");
        w.set_sweep_kind("sweep".into());
        w.set_pick_mode("sweep".into());
        refresh_contacts(&w, &s);
        w.set_contact_input("".into());
        w.set_status("".into());
        w.set_screen(7);
    });

    cb!(on_consolidate_open, |w, s| {
        let spendable = s
            .store
            .as_ref()
            .map(|st| st.utxos.iter().filter(|u| !u.pending_spend).count())
            .unwrap_or(0);
        if spendable < 2 {
            w.set_status("nothing to consolidate (need 2+ coins)".into());
            return;
        }
        let Some(addr) = s.ident.as_ref().map(|i| i.address.clone()) else { return };
        println!("cb: consolidate-open coins={spendable}");
        w.set_sweep_kind("consolidate".into());
        w.set_sweep_dest(addr.clone().into());
        w.set_sweep_to_label(format!("Consolidate to your address · {addr}").into());
        w.set_sweep_tier(1);
        let rate = s.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
        w.set_sweep_rate_text(format!("{rate}").into());
        w.set_sweep_fund_external(false);
        w.set_sweep_inputs_expanded(false);
        w.set_status("".into());
        update_sweep_screen(&w, &mut s);
        w.set_screen(16);
    });

    cb!(on_set_sweep_tier, |w, s, tier: i32| {
        w.set_sweep_tier(tier);
        let f = s.fees.clone().unwrap_or_default();
        let rate = match tier {
            0 => f.economy,
            2 => f.fastest,
            _ => f.hour,
        }
        .max(1.0);
        if tier != 3 {
            w.set_sweep_rate_text(format!("{rate}").into());
        }
        println!("cb: sweep-tier {tier} rate={rate}");
        update_sweep_screen(&w, &mut s);
    });

    cb!(on_sweep_rate_changed, |w, s| {
        update_sweep_screen(&w, &mut s);
    });

    cb!(on_toggle_sweep_fund_external, |w, s, on: bool| {
        println!("cb: sweep-fund-external {on}");
        w.set_status("".into());
        if on && s.funding.is_none() {
            // No funding wallet active yet — pick one; Back returns here.
            w.set_funding_return(16);
            refresh_funding_list(&w, &s);
            w.set_screen(15);
            return;
        }
        update_sweep_screen(&w, &mut s);
    });

    cb!(on_sweep_send, |w, s| {
        let dest = w.get_sweep_dest().to_string();
        let net = s.network;
        let Ok(recipient) = Recipient::parse(net, &dest) else {
            w.set_status(format!("not a valid {} address", net.as_str()).into());
            return;
        };
        let rate = resolve_sweep_rate(&w, &s);
        if rate <= 0.0 {
            w.set_status("enter a fee rate".into());
            return;
        }
        if w.get_sweep_fund_external() {
            // Fee from the funding wallet: the FULL balance rides to the
            // destination, funding change returns to the funding wallet.
            let Some(fund_src) = s.funding.clone() else {
                w.set_status("set a funding wallet first".into());
                return;
            };
            if s.funding_coins.is_empty() {
                w.set_status("funding wallet has no spendable coins".into());
                return;
            }
            let notes_coins: Vec<WatchCoin> = s
                .store
                .as_ref()
                .map(|store| {
                    store
                        .utxos
                        .iter()
                        .filter(|u| !u.pending_spend)
                        .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value })
                        .collect()
                })
                .unwrap_or_default();
            if notes_coins.is_empty() {
                w.set_status("nothing to sweep".into());
                return;
            }
            let inputs: Vec<app_core::store::TxInput> = notes_coins
                .iter()
                .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
                .collect();
            let Some(ident) = s.ident.as_ref() else { return };
            let identity_spk = p2tr_script_pubkey(&ident.output_x());
            let identity_source = ident.watch_source().cloned();
            let fund_coins = s.funding_coins.clone();
            let plan = FundingPlan {
                source: &fund_src,
                coins: &fund_coins,
                change_index: s.funding_change_index,
                fee_rate: rate,
                change_override: None,
            };
            match build_funded_sweep_psbt(
                identity_spk,
                identity_source.as_ref(),
                &notes_coins,
                &plan,
                recipient.spk.clone(),
            ) {
                Ok(mut built) => {
                    // Keyed identity: the app signs its own inputs here and
                    // now — only the funding wallet still needs to sign.
                    if let Some(id) = s.ident.as_ref().and_then(|i| i.full()) {
                        match sign_own_taproot_inputs(&mut built.psbt, &id.output_x, &id.tweaked_seckey) {
                            Ok(k) => println!("cb: sweep-own-signed inputs={k}"),
                            Err(e) => {
                                w.set_status(format!("{e}").into());
                                return;
                            }
                        }
                    }
                    let cost = format!(
                        "sweep · {} sats arrive in full · fee {} sats from the funding wallet",
                        built.sent_to_recipient, built.fee
                    );
                    s.watch_note = None;
                    s.watch_spend = Some(WatchSpend {
                        kind: if w.get_sweep_kind().as_str() == "consolidate" { "consolidate" } else { "sweep" },
                        dest: dest.clone(),
                        dest_spk_hex: hex::encode(&recipient.spk),
                        value: built.sent_to_recipient,
                        fee: built.fee,
                        inputs,
                        bump_ref: None,
                    });
                    println!(
                        "cb: sweep-build funded=1 txid={} fee={} notes_in={} fund_in={}",
                        built.txid,
                        built.fee,
                        notes_coins.len(),
                        fund_coins.len()
                    );
                    show_psbt_sign_screen(&w, &mut s, built, cost);
                }
                Err(e) => w.set_status(format!("{e}").into()),
            }
            return;
        }
        let consolidate = w.get_sweep_kind().as_str() == "consolidate";
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            let kind = if consolidate { "consolidate" } else { "sweep" };
            watch_spend_build(&w, &mut s, kind, dest, recipient.spk.clone(), rate);
            return;
        }
        // Keyed, self-paid: resolved rate feeds the classic confirm modal —
        // on_sweep / on_consolidate sign + broadcast in-app.
        if consolidate {
            w.set_consolidate_rate(format!("{rate}").into());
            refresh_consolidate_preview(&w, &mut s);
            w.set_show_consolidate_confirm(true);
        } else {
            w.set_sweep_rate(format!("{rate}").into());
            w.set_show_sweep_confirm(true);
        }
    });

    cb!(on_pick_contact, |w, s, addr: SharedString| {
        // Sweep mode: the picker chooses the sweep DESTINATION, then opens
        // the compose-like sweep screen (16) instead of compose.
        if w.get_pick_mode().as_str() == "sweep" {
            let mut a = normalize_addr(addr.as_str());
            if a == "self" || a.is_empty() {
                w.set_status("pick a destination address".into());
                return;
            }
            if Recipient::parse(s.network, &a).is_err() {
                let lower = a.to_lowercase();
                if Recipient::parse(s.network, &lower).is_ok() {
                    a = lower;
                } else {
                    println!("cb: sweep-pick err=bad-address");
                    w.set_status(format!("not a valid {} address", s.network.as_str()).into());
                    return;
                }
            }
            println!("cb: sweep-pick to={a}");
            if let Some(store) = &mut s.store {
                store.touch_contact(&a);
            }
            s.save_store();
            refresh_contacts(&w, &s);
            let name = s
                .store
                .as_ref()
                .and_then(|st| st.contacts.iter().find(|c| c.address == a))
                .map(|c| c.name.clone())
                .filter(|n| !n.is_empty());
            w.set_sweep_to_label(
                match &name {
                    Some(n) => format!("Everything to: {n} · {a}"),
                    None => format!("Everything to: {a}"),
                }
                .into(),
            );
            w.set_sweep_dest(a.into());
            w.set_sweep_tier(1);
            let rate = s.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
            w.set_sweep_rate_text(format!("{rate}").into());
            w.set_sweep_fund_external(false);
            w.set_sweep_inputs_expanded(false);
            w.set_status("".into());
            update_sweep_screen(&w, &mut s);
            w.set_screen(16);
            return;
        }
        if addr.as_str() == "self" {
            s.to_address = None;
            w.set_to_label("To: Self (my notebook)".into());
            w.set_directed(false);
            println!("cb: pick-contact to=self");
        } else {
            let mut a = normalize_addr(addr.as_str());
            if Recipient::parse(s.network, &a).is_err() {
                let lower = a.to_lowercase();
                if Recipient::parse(s.network, &lower).is_ok() {
                    a = lower;
                } else {
                    println!("cb: pick-contact err=bad-address");
                    w.set_status(format!("not a valid {} address", s.network.as_str()).into());
                    return;
                }
            }
            println!("cb: pick-contact to={a}");
            if let Some(store) = &mut s.store {
                store.touch_contact(&a);
            }
            s.save_store();
            // Rebuild the recents now so the address is in the list when the
            // user presses Back from compose.
            refresh_contacts(&w, &s);
            w.set_to_label(format!("To: {a}").into());
            s.to_address = Some(a);
            w.set_directed(true);
        }
        let rate = s.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            w.set_compose_private(false); // no sealing key on this device
        }
        w.set_fee_tier(1);
        w.set_rate_text(format!("{rate}").into());
        w.set_change_address("".into());
        w.set_change_expanded(false);
        w.set_spend_expanded(false);
        s.coins_overridden = false;
        s.consolidate_coins = false;
        w.set_coin_strategy(0);
        w.set_gift_sats(format!("{DUST_SATS}").into());
        w.set_gift_expanded(false);
        s.selected_coins.clear();
        w.set_status("".into());
        w.set_screen(6);
        refresh_compose(&w, &mut s);
    });

    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.on_contact_scan(move || {
            println!("cb: contact-scan start");
            let weak = weak.clone();
            let cancel = scan_cancel.clone();
            begin_scan(&weak, &cancel, "Point the recipient's address QR at the camera");
            std::thread::spawn(move || {
                let preview = scan_preview(weak.clone());
                let text = match camera::capture_and_decode(30, &cancel, preview) {
                    Ok(Some(p)) => String::from_utf8_lossy(&p).to_string(),
                    _ => String::new(),
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_scanning(false);
                    if text.is_empty() {
                        w.set_status("scan: no QR seen".into());
                    } else {
                        println!("cb: contact-scan ok");
                        let a = normalize_addr(&text);
                        // Prefill so a failed validation leaves it editable,
                        // then pick directly — a valid scan goes straight
                        // to Compose (the Prime picker behavior).
                        w.set_contact_input(a.clone().into());
                        w.invoke_pick_contact(a.into());
                    }
                });
            });
        });
    }

    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.on_change_scan(move || {
            println!("cb: change-scan start");
            let weak = weak.clone();
            let cancel = scan_cancel.clone();
            begin_scan(&weak, &cancel, "Point the change-address QR at the camera");
            std::thread::spawn(move || {
                let preview = scan_preview(weak.clone());
                let text = match camera::capture_and_decode(30, &cancel, preview) {
                    Ok(Some(p)) => String::from_utf8_lossy(&p).to_string(),
                    _ => String::new(),
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_scanning(false);
                    if text.is_empty() {
                        w.set_status("scan: no QR seen".into());
                    } else {
                        println!("cb: change-scan ok");
                        w.set_change_address(normalize_addr(&text).into());
                        w.set_change_expanded(true);
                        w.invoke_compose_changed();
                    }
                });
            });
        });
    }

    // Scan a funding descriptor / xpub / account-UR QR → prefill + validate.
    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.on_funding_scan(move || {
            println!("cb: funding-scan start");
            let weak = weak.clone();
            let cancel = scan_cancel.clone();
            begin_scan(&weak, &cancel, "Point the funding-wallet QR at the camera");
            std::thread::spawn(move || {
                let preview = scan_preview(weak.clone());
                let pweak = weak.clone();
                // Reassemble an animated account UR across frames (a hardware
                // wallet's crypto-account export can span several QR frames); a
                // single non-UR descriptor/xpub QR completes on the first frame.
                let mut dec = app_core::ur::UrDecoder::new();
                let mut parts: Vec<String> = Vec::new();
                let mut single: Option<String> = None;
                let done = camera::capture_frames(45, &cancel, preview, |payload| {
                    let s = String::from_utf8_lossy(payload);
                    let t = s.trim();
                    if t.to_lowercase().starts_with("ur:") {
                        let complete = dec.receive(t).unwrap_or(false);
                        parts.push(t.to_string());
                        let p = dec.progress();
                        let _ = pweak.upgrade_in_event_loop(move |w| w.set_scan_progress(p));
                        complete
                    } else {
                        single = Some(t.to_string());
                        true
                    }
                });
                let result: Option<Result<String, String>> = match done {
                    Ok(true) => match single {
                        Some(d) => Some(Ok(d)),           // non-UR descriptor
                        None if !parts.is_empty() => Some(Err(parts.join(" "))), // UR frames
                        None => None,
                    },
                    _ => None,
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_scanning(false);
                    match result {
                        Some(Err(ur)) => {
                            println!("cb: funding-scan ur (multi-frame)");
                            w.invoke_funding_import_ur(ur.into());
                        }
                        Some(Ok(desc)) => {
                            println!("cb: funding-scan ok");
                            let t: SharedString = extract_descriptor(&desc).into();
                            w.set_funding_descriptor(t.clone());
                            w.invoke_funding_changed(t);
                        }
                        None => w.set_status("scan: no complete QR seen".into()),
                    }
                });
            });
        });
    }

    // Scan a signed PSBT QR (single-frame crypto-psbt) → validate + confirm.
    // The decode/validate runs back on the UI thread via the psbt-loaded
    // callback (which has state access), so no Rc crosses the thread boundary.
    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.on_psbt_import_scan(move || {
            println!("cb: psbt-scan start");
            let weak = weak.clone();
            let cancel = scan_cancel.clone();
            begin_scan(&weak, &cancel, "Point the signed-transaction QR at the camera");
            std::thread::spawn(move || {
                let preview = scan_preview(weak.clone());
                let pweak = weak.clone();
                // Reassemble an animated crypto-psbt UR across frames (a hardware
                // wallet hands the signed PSBT back as a multi-part QR); a single
                // non-UR QR (hex/base64) completes on the first frame.
                let mut dec = app_core::ur::PsbtUrDecoder::new();
                let mut single: Option<String> = None;
                let done = camera::capture_frames(45, &cancel, preview, |payload| {
                    let s = String::from_utf8_lossy(payload);
                    let t = s.trim();
                    if t.to_lowercase().starts_with("ur:") {
                        let _ = dec.receive(t);
                        let p = dec.progress();
                        let _ = pweak.upgrade_in_event_loop(move |w| w.set_scan_progress(p));
                        dec.is_complete()
                    } else {
                        single = Some(t.to_string());
                        true
                    }
                });
                let result: Option<String> = match done {
                    Ok(true) => single.or_else(|| dec.psbt_bytes().ok().map(hex::encode)),
                    _ => None,
                };
                let _ = weak.upgrade_in_event_loop(move |w| {
                    w.set_scanning(false);
                    match result {
                        Some(text) => {
                            println!("cb: psbt-scan ok");
                            w.invoke_psbt_loaded(text.into());
                        }
                        None => w.set_status("scan: no complete PSBT seen".into()),
                    }
                });
            });
        });
    }

    cb!(on_start_rename, |w, s, addr: SharedString, name: SharedString| {
        let _ = &mut s;
        println!("cb: rename-start addr={addr}");
        w.set_status("".into());
        w.set_rename_address(addr);
        w.set_rename_input(name);
    });

    cb!(on_save_rename, |w, s, name: SharedString| {
        let addr = w.get_rename_address().to_string();
        if let Some(store) = &mut s.store {
            store.name_contact(&addr, name.trim());
        }
        s.save_store();
        println!("cb: save-contact addr={addr} name-len={}", name.trim().len());
        w.set_status("".into());
        w.set_rename_address("".into());
        w.set_rename_input("".into());
        update_home(&w, &s);
    });

    cb!(on_cancel_rename, |w, s| {
        let _ = &mut s;
        w.set_rename_address("".into());
        w.set_rename_input("".into());
    });

    cb!(on_confirm_remove, |w, s, addr: SharedString, name: SharedString| {
        let _ = &mut s;
        println!("cb: confirm-remove addr={addr}");
        w.set_confirm_remove_name(name);
        w.set_confirm_remove_address(addr);
    });

    cb!(on_cancel_remove, |w, s| {
        let _ = &mut s;
        w.set_confirm_remove_address("".into());
    });

    cb!(on_remove_contact, |w, s, addr: SharedString| {
        if let Some(store) = &mut s.store {
            store.remove_contact(addr.as_str());
        }
        s.save_store();
        println!("cb: remove-contact addr={addr}");
        w.set_status("".into());
        w.set_confirm_remove_address("".into());
        if w.get_rename_address() == addr {
            w.set_rename_address("".into());
        }
        update_home(&w, &s);
    });

    cb!(on_compose_changed, |w, s| {
        refresh_compose(&w, &mut s);
    });

    cb!(on_toggle_coin, |w, s, outpoint: SharedString| {
        // "txid:vout" → (txid, vout)
        let op = outpoint.as_str();
        if let Some((txid, vout)) = op.rsplit_once(':') {
            if let Ok(vout) = vout.parse::<u32>() {
                let key = (txid.to_string(), vout);
                if let Some(i) = s.selected_coins.iter().position(|c| c == &key) {
                    s.selected_coins.remove(i);
                } else {
                    s.selected_coins.push(key);
                }
                s.coins_overridden = true;
                println!("cb: toggle-coin selected={}", s.selected_coins.len());
                refresh_compose(&w, &mut s);
            }
        }
    });

    cb!(on_set_coin_strategy, |w, s, strategy: i32| {
        // 0 = fewest coins (largest-first), 1 = consolidate (smallest-first).
        // Re-applies the suggestion (clears any manual override).
        s.consolidate_coins = strategy == 1;
        s.coins_overridden = false;
        w.set_coin_strategy(strategy);
        println!("cb: coin-strategy {}", if strategy == 1 { "consolidate" } else { "fewest" });
        refresh_compose(&w, &mut s);
    });

    cb!(on_refresh_coins, |w, s| {
        println!("cb: refresh-coins");
        refresh(&w, &mut s);
        w.set_status("".into());
        refresh_compose(&w, &mut s);
    });

    // ---------- external funding (PSBT) ----------
    cb!(on_toggle_fund_external, |w, s, on: bool| {
        println!("cb: fund-external {on}");
        if !on {
            s.funding_coins.clear();
        }
        w.set_status("".into());
        refresh_compose(&w, &mut s);
        // Turning it on with no wallet active → go to the saved-wallets list.
        if on && s.funding.is_none() {
            w.set_funding_return(6);
            refresh_funding_list(&w, &s);
            w.set_screen(15);
        }
    });

    cb!(on_open_funding, |w, s| {
        println!("cb: open-funding");
        w.set_status("".into());
        refresh_funding_list(&w, &s);
        w.set_screen(15);
    });

    cb!(on_add_funding_wallet, |w, s| {
        let _ = &mut s;
        w.set_status("".into());
        w.set_funding_descriptor("".into());
        w.set_funding_feedback("".into());
        w.set_funding_valid(false);
        w.set_screen(12);
    });

    cb!(on_use_funding_wallet, |w, s, id: SharedString| {
        activate_funding_wallet(&w, &mut s, id.as_str());
    });

    cb!(on_remove_funding_wallet, |w, s, id: SharedString| {
        println!("cb: remove-funding-wallet");
        s.funding_wallets.retain(|fw| fw.id != id.as_str());
        if s.active_funding_id.as_deref() == Some(id.as_str()) {
            s.active_funding_id = None;
            s.funding = None;
            s.funding_coins.clear();
        }
        s.save_funding_wallets();
        refresh_funding_list(&w, &s);
    });

    cb!(on_refresh_funding_wallet, |w, s, id: SharedString| {
        let net = s.network;
        let Some(idx) = s.funding_wallets.iter().position(|fw| fw.id == id.as_str()) else { return };
        let descriptor = s.funding_wallets[idx].descriptor.clone();
        let Some(base) = s.base_url() else {
            w.set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let Ok(src) = FundingSource::parse(&descriptor, net) else { return };
        w.set_status("scanning…".into());
        let client = ChainClient::new(HttpTransport::new(&base), net);
        if let Ok(scan) = client.scan_funding(&src, 20) {
            s.funding_wallets[idx].balance = scan.utxos.iter().map(|c| c.value).sum();
            s.funding_wallets[idx].coins = scan.utxos.len();
            s.funding_wallets[idx].scanned = true;
            s.save_funding_wallets();
        }
        w.set_status("".into());
        refresh_funding_list(&w, &s);
    });

    cb!(on_fund_rename_start, |w, s, id: SharedString, label: SharedString| {
        let _ = &mut s;
        w.set_fund_rename_input(label);
        w.set_fund_rename_id(id);
    });

    cb!(on_fund_rename_save, |w, s, text: SharedString| {
        let id = w.get_fund_rename_id().to_string();
        let name = text.trim();
        if !name.is_empty() {
            if let Some(fw) = s.funding_wallets.iter_mut().find(|fw| fw.id == id) {
                fw.label = name.to_string();
            }
            s.save_funding_wallets();
        }
        w.set_fund_rename_id("".into());
        refresh_funding_list(&w, &s);
    });

    cb!(on_fund_rename_cancel, |w, s| {
        let _ = &mut s;
        w.set_fund_rename_id("".into());
    });

    cb!(on_funding_changed, |w, s, text: SharedString| {
        let net = s.network;
        let _ = &mut s;
        let t = text.trim();
        if t.is_empty() {
            w.set_funding_feedback("".into());
            w.set_funding_valid(false);
            return;
        }
        if t.to_lowercase().starts_with("ur:") {
            w.set_funding_feedback("Hardware-wallet export (UR) — press Save & use to import.".into());
            w.set_funding_valid(true);
            return;
        }
        match FundingSource::parse(&extract_descriptor(t), net) {
            Ok(src) => {
                let a0 = src.derive(0, 0).map(|d| d.address).unwrap_or_default();
                w.set_funding_feedback(format!("{} wallet · first address\n{a0}", src.kind.label()).into());
                w.set_funding_valid(true);
            }
            Err(e) => {
                w.set_funding_feedback(format!("{e}").into());
                w.set_funding_valid(false);
            }
        }
    });

    cb!(on_funding_use, |w, s| {
        // A UR hardware-wallet export imports its account(s) into the list.
        if try_import_ur_account(&w, &mut s, &w.get_funding_descriptor()) {
            return;
        }
        // Otherwise: validate the descriptor, save to the list if new, activate.
        let input = extract_descriptor(&w.get_funding_descriptor());
        let net = s.network;
        let wallet = match FundingWallet::create(&input, "", net) {
            Ok(fw) => fw,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        if !s.funding_wallets.iter().any(|x| x.id == wallet.id) {
            s.funding_wallets.push(wallet.clone());
            s.save_funding_wallets();
        }
        activate_funding_wallet(&w, &mut s, &wallet.id);
    });

    cb!(on_funding_file, |w, s| {
        if let Some(path) =
            platform::pick_file(&[("Descriptor / wallet export", &["txt", "json", "desc", "ur"])])
        {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    if try_import_ur_account(&w, &mut s, &content) {
                        return;
                    }
                    // A wallet-export file can list several script-type descriptors.
                    let descs = extract_all_descriptors(&content);
                    if descs.len() > 1 {
                        let added = save_funding_descriptors(&w, &mut s, &descs);
                        w.set_status(format!("imported {added} wallet(s) from file — pick one").into());
                    } else {
                        let d = descs.into_iter().next().unwrap_or_default();
                        w.set_funding_descriptor(d.clone().into());
                        w.invoke_funding_changed(d.into());
                    }
                }
                Err(e) => w.set_status(format!("read failed: {e}").into()),
            }
        }
    });

    cb!(on_funding_import_ur, |w, s, text: SharedString| {
        try_import_ur_account(&w, &mut s, text.as_str());
    });

    cb!(on_funding_clear, |w, s| {
        s.funding = None;
        s.funding_coins.clear();
        s.built_psbt = None;
        s.signed_psbt = None;
        w.set_funding_descriptor("".into());
        w.set_funding_feedback("".into());
        w.set_funding_valid(false);
        refresh_compose(&w, &mut s);
    });

    cb!(on_fund_build, |w, s| {
        let text = w.get_compose_text().to_string();
        let private = w.get_compose_private();
        let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.set_status("empty note or bad fee rate".into());
            return;
        }
        if s.funding.is_none() || s.funding_coins.is_empty() {
            w.set_status("set a funding wallet first".into());
            return;
        }
        let net = s.network;
        let to = s.to_address.clone();
        let recipient = match to.as_deref() {
            Some(a) => match Recipient::parse(net, a) {
                Ok(r) => Some(r),
                Err(e) => {
                    w.set_status(format!("{e}").into());
                    return;
                }
            },
            None => None,
        };
        // Change destination: blank field = the funding wallet's own change
        // address; a valid custom address overrides it.
        let change_raw = normalize_addr(w.get_change_address().as_str());
        let change_override = if change_raw.is_empty() {
            None
        } else {
            match Recipient::parse(net, &change_raw) {
                Ok(r) => Some(r.spk),
                Err(_) => {
                    w.set_status(format!("change address isn't a valid {} address", net.as_str()).into());
                    return;
                }
            }
        };
        let src = s.funding.clone().unwrap();
        let coins = s.funding_coins.clone();
        let change_index = s.funding_change_index;
        let r = app_core::notes_core::keys::generate_aux_rand()
            .map(|x| [x[0], x[1], x[2], x[3]])
            .unwrap_or([1, 2, 3, 4]);
        let plan =
            FundingPlan { source: &src, coins: &coins, change_index, fee_rate: rate, change_override };
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            // Watch identity + funding wallet: PUBLIC note paid entirely by
            // the funding coins; both signatures happen externally. Frozen-
            // scan caveat: a rescan attributes an externally funded PUBLIC
            // note as received-from-funder — the local record keeps it own.
            if private {
                w.set_status("watch-only identities can only compose public notes".into());
                return;
            }
            let output_x = s.ident.as_ref().map(|i| i.output_x()).unwrap_or_default();
            let gift = if recipient.is_some() {
                w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
            } else {
                0
            };
            let chunk = s.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);
            match app_core::psbt_build::build_watch_funded_note_psbt(
                &output_x,
                &plan,
                &text,
                recipient.as_ref().map(|rc| rc.spk.clone()),
                gift,
                r,
                chunk,
            ) {
                Ok(built) => {
                    let payload_outputs = built
                        .psbt
                        .unsigned_tx
                        .output
                        .iter()
                        .filter(|o| o.script_pubkey.is_op_return())
                        .count();
                    s.watch_spend = None;
                    s.watch_note = Some(WatchNote {
                        note_id: r,
                        text: text.clone(),
                        recipient: to.clone(),
                        gift,
                        chunks: payload_outputs,
                        fee: built.fee,
                        change: 0, // funding change isn't an own coin
                        spent: Vec::new(),
                    });
                    let n = coins.len();
                    let cost = format!(
                        "public note · fee {} sats · {n} funding input{} · sign with your external wallet{}",
                        built.fee,
                        if n == 1 { "" } else { "s" },
                        if gift > 0 { format!(" · {gift} sats to recipient") } else { String::new() }
                    );
                    println!(
                        "cb: watch-note-build id={} txid={} fee={} chunks={payload_outputs} funded=1",
                        hex::encode(r),
                        built.txid,
                        built.fee
                    );
                    show_psbt_sign_screen(&w, &mut s, built, cost);
                }
                Err(e) => w.set_status(format!("{e}").into()),
            }
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.set_status("no identity".into());
            return;
        };
        let np = NoteParams {
            identity: &identity,
            text: &text,
            private,
            recipient: recipient.as_ref(),
            note_id: r,
            max_op_return_bytes: DEFAULT_CHUNK,
            network: net,
        };
        match build_funding_psbt(&plan, &np) {
            Ok(built) => {
                let n = coins.len();
                let cost =
                    format!("fee {} sats · {n} input{}", built.fee, if n == 1 { "" } else { "s" });
                s.watch_spend = None; // this sign screen serves external funding
                s.watch_note = None;
                show_psbt_sign_screen(&w, &mut s, built, cost);
                println!("cb: fund-build ok");
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_psbt_save, |w, s| {
        let Some(built) = s.built_psbt.as_ref() else { return };
        let bytes = built.to_bytes();
        if let Some(path) = platform::save_file("note.psbt") {
            match std::fs::write(&path, &bytes) {
                Ok(()) => w.set_status("saved .psbt".into()),
                Err(e) => w.set_status(format!("save failed: {e}").into()),
            }
        }
    });

    cb!(on_psbt_copy, |w, s| {
        let b64 = s.built_psbt.as_ref().map(|b| b.to_base64()).unwrap_or_default();
        if b64.is_empty() {
            return;
        }
        let ok = platform::set_clipboard_text(&b64);
        w.set_status(if ok { "copied PSBT (base64)" } else { "copy failed" }.into());
    });

    cb!(on_psbt_goto_import, |w, s| {
        let _ = &mut s;
        w.set_status("".into());
        w.set_screen(14);
    });

    cb!(on_psbt_loaded, |w, s, text: SharedString| {
        load_signed_psbt(&w, &mut s, text.as_bytes());
    });

    cb!(on_psbt_import_file, |w, s| {
        if let Some(path) = platform::pick_file(&[("PSBT", &["psbt", "txt"])]) {
            match std::fs::read(&path) {
                Ok(bytes) => load_signed_psbt(&w, &mut s, &bytes),
                Err(e) => w.set_status(format!("read failed: {e}").into()),
            }
        }
    });

    cb!(on_psbt_broadcast, |w, s| {
        let Some(psbt) = s.signed_psbt.clone() else {
            w.set_status("no signed PSBT".into());
            return;
        };
        let Some(base) = s.base_url() else {
            w.set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let client = ChainClient::new(HttpTransport::new(&base), s.network);
        match client.broadcast(&raw) {
            Ok(_got) => {
                if let Some(wn) = s.watch_note.take() {
                    // Watch-mode compose: the note enters the store as
                    // Pending exactly like a keyed compose (inputs locked,
                    // change spendable, raw hex kept for rebroadcast).
                    record_watch_note(&mut s, &wn, &txid, &raw, vsize as u64);
                    println!(
                        "cb: compose id={} txid={txid} fee={} vsize={vsize} to={} private=false gift={} watch=1 broadcast=ok",
                        hex::encode(wn.note_id),
                        wn.fee,
                        wn.recipient.as_deref().unwrap_or("self"),
                        wn.gift
                    );
                } else if let Some(ws) = s.watch_spend.take() {
                    // Watch-mode spend: record it so Activity gets the
                    // pending→confirmed lifecycle, and lock the coins.
                    record_watch_spend(&mut s, &ws, &txid, &raw, vsize as u64);
                    println!("cb: watch-{} txid={txid} fee={} ok", ws.kind, ws.fee);
                } else {
                    println!("cb: fund-broadcast txid={txid} ok");
                }
                w.set_status(format!("broadcast {}…", &txid[..12.min(txid.len())]).into());
                s.funding_coins.clear();
                s.built_psbt = None;
                s.signed_psbt = None;
                s.ur_frames.clear();
                w.set_compose_text("".into());
                w.set_fund_external(false);
                w.set_psbt_signed(false);
                w.set_screen(4);
                refresh(&w, &mut s);
            }
            Err(e) => w.set_status(format!("broadcast failed: {e}").into()),
        }
    });

    cb!(on_compose_send, |w, s| {
        let text = w.get_compose_text().to_string();
        let private = w.get_compose_private();
        let rate: f64 = w.get_rate_text().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.set_status("empty note or bad fee rate".into());
            return;
        }
        // Optional custom change address (empty = back to self).
        let change_addr = normalize_addr(w.get_change_address().as_str());
        if !change_addr.is_empty() && Recipient::parse(s.network, &change_addr).is_err() {
            w.set_status(format!("change address isn't a valid {} address", s.network.as_str()).into());
            return;
        }
        let net = s.network;
        let to = s.to_address.clone();
        let Some(base) = s.base_url() else {
            w.set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        if !w.get_spend_enough() {
            w.set_status("selected coins don't cover the note + fee".into());
            return;
        }
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            // Watch compose: PUBLIC note as an external-sign PSBT over the
            // selected coins; recorded on broadcast like a keyed compose.
            if private {
                w.set_status("watch-only identities can only compose public notes".into());
                return;
            }
            let Some(src) = s.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
            let recipient = match to.as_deref() {
                Some(a) => match Recipient::parse(net, a) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        w.set_status(format!("{e}").into());
                        return;
                    }
                },
                None => None,
            };
            let gift = if recipient.is_some() {
                w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
            } else {
                0
            };
            let Some(store) = s.store.as_ref() else { return };
            let sel: std::collections::HashSet<(String, u32)> =
                s.selected_coins.iter().cloned().collect();
            let coins: Vec<WatchCoin> = store
                .utxos
                .iter()
                .filter(|u| !u.pending_spend && sel.contains(&(u.txid.clone(), u.vout)))
                .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value })
                .collect();
            if coins.is_empty() {
                w.set_status("no coins selected".into());
                return;
            }
            let mut note_id = [0u8; 4];
            loop {
                let r = app_core::notes_core::keys::generate_aux_rand()
                    .map(|x| [x[0], x[1], x[2], x[3]])
                    .unwrap_or([1, 2, 3, 4]);
                note_id = r;
                if !store.note_id_taken(&note_id) {
                    break;
                }
            }
            let chunk = store.chunk_size;
            match build_watch_note_psbt(
                &src,
                &coins,
                &text,
                recipient.as_ref().map(|r| r.spk.clone()),
                gift,
                note_id,
                chunk,
                rate,
            ) {
                Ok(built) => {
                    let payload_outputs = built
                        .psbt
                        .unsigned_tx
                        .output
                        .iter()
                        .filter(|o| o.script_pubkey.is_op_return())
                        .count();
                    s.watch_spend = None;
                    s.watch_note = Some(WatchNote {
                        note_id,
                        text: text.clone(),
                        recipient: to.clone(),
                        gift,
                        chunks: payload_outputs,
                        fee: built.fee,
                        change: built.change,
                        spent: coins
                            .iter()
                            .map(|c| app_core::store::OutPointRef { txid: c.txid.clone(), vout: c.vout })
                            .collect(),
                    });
                    let cost = format!(
                        "public note · fee {} sats{} · sign with your external wallet",
                        built.fee,
                        if gift > 0 { format!(" · {gift} sats to recipient") } else { String::new() }
                    );
                    println!(
                        "cb: watch-note-build id={} txid={} fee={} chunks={payload_outputs}",
                        hex::encode(note_id),
                        built.txid,
                        built.fee
                    );
                    show_psbt_sign_screen(&w, &mut s, built, cost);
                }
                Err(e) => w.set_status(format!("{e}").into()),
            }
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.set_status("no identity".into());
            return;
        };
        let coins_vec = s.selected_coins.clone();
        let result = compose_and_record(
            s.store.as_mut().unwrap(),
            &identity,
            net,
            &ComposeRequest {
                text: &text,
                private,
                recipient: to.as_deref(),
                change_to: (!change_addr.is_empty()).then_some(change_addr.as_str()),
                coins: (!coins_vec.is_empty()).then_some(coins_vec.as_slice()),
                fee_rate: rate,
                gift_amount: to.as_ref().map(|_| {
                    w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
                }),
                now: now(),
            },
        );
        match result {
            Ok(c) => {
                s.save_store();
                let client = ChainClient::new(HttpTransport::new(base), net);
                match client.broadcast(&c.tx.raw_hex) {
                    Ok(txid) => {
                        println!(
                            "cb: compose id={} txid={txid} fee={} vsize={} to={} private={} broadcast=ok",
                            c.note_id, c.tx.fee, c.tx.vsize,
                            to.as_deref().unwrap_or("self"), private
                        );
                        w.set_status(format!("broadcast {}…", &txid[..12]).into());
                        w.set_compose_text("".into());
                        w.set_change_address("".into());
                        w.set_change_expanded(false);
                        w.set_spend_expanded(false);
                        s.coins_overridden = false;
                        s.selected_coins.clear();
                        w.set_screen(4);
                        refresh(&w, &mut s);
                    }
                    Err(e) => {
                        println!("cb: compose broadcast err={e}");
                        w.set_status(format!("signed but broadcast failed ({e}) — note is pending, Refresh to retry visibility. If relay-policy, lower chunk bytes in Settings and recompose.").into());
                        update_home(&w, &s);
                        w.set_screen(4);
                    }
                }
            }
            Err(e) => {
                println!("cb: compose err={e}");
                w.set_status(format!("{e}").into());
            }
        }
    });

    cb!(on_settings_open, |w, s| {
        println!("cb: settings-open");
        w.set_reveal_text("".into());
        w.set_status("".into());
        w.set_chunk_custom(false);
        load_backend_settings(&w, &s);
        w.set_screen(8);
    });

    cb!(on_open_account_picker, |w, s| {
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else { return };
        println!("cb: account-picker open");
        let page = s.account / 5;
        show_account_picker(&w, &material, s.network, page, Some(s.account));
    });

    cb!(on_accounts_page, |w, s, delta: i32| {
        let page = (w.get_account_page() + delta).max(0) as u32;
        let material = s
            .pending_import
            .as_ref()
            .or(s.material.as_ref())
            .map(|z| String::from(z.as_str()));
        let Some(material) = material else { return };
        let active = if s.pending_import.is_some() { None } else { Some(s.account) };
        show_account_picker(&w, &material, s.network, page, active);
    });

    cb!(on_pick_account, |w, s, idx: i32| {
        let first_import = s.pending_import.is_some();
        let Some(material) = s
            .pending_import
            .take()
            .map(|z| String::from(z.as_str()))
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())))
        else {
            return;
        };
        s.account = idx.max(0) as u32;
        println!("cb: pick-account {}", s.account);
        match activate(&mut s, &material, first_import) {
            Ok(()) => {
                w.set_import_text("".into());
                w.set_status("".into());
                w.set_screen(4);
                update_home(&w, &s);
                refresh(&w, &mut s);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_account_cancel, |w, s| {
        if s.pending_import.take().is_some() {
            w.set_screen(1); // abandon import → back to the import form
        } else {
            update_home(&w, &s);
            w.set_screen(8); // came from settings
        }
    });

    cb!(on_reset_identity, |w, s| {
        println!("cb: reset-identity");
        let _ = keychain::delete_secret(KEYCHAIN_ACCOUNT);
        // Privacy: local stores cache decrypted note text — delete them.
        if let Ok(entries) = std::fs::read_dir(&s.data_dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if (name.starts_with("store-") || name.starts_with("notebooks-"))
                    && name.ends_with(".json")
                {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        s.ident = None;
        s.store = None;
        s.material = None;
        s.account = 0;
        s.notebooks = None;
        s.notebooks_fp8 = None;
        s.nb_addrs.clear();
        s.to_address = None;
        s.icloud_backup = false;
        w.set_icloud_backup(false);
        w.set_icloud_available(false);
        w.set_show_reset_confirm(false);
        w.set_reveal_text("".into());
        w.set_status("".into());
        w.set_import_text("".into());
        w.set_screen(0);
    });

    cb!(on_hide_backup, |w, s| {
        let _ = &mut s;
        w.set_reveal_text("".into());
    });

    cb!(on_set_network, |w, s, net: SharedString| {
        let Some(n) = Network::from_str_opt(net.as_str()) else { return };
        if n == s.network {
            return;
        }
        s.network = n;
        println!("cb: set-network {}", s.network.as_str());
        s.save_config();
        // Same key material, new network: re-derive + reload store.
        let material = std::env::var("APP_KEY")
            .ok()
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())));
        if let Some(m) = material {
            match activate(&mut s, &m, false) {
                Ok(()) => {
                    update_home(&w, &s);
                    refresh(&w, &mut s);
                }
                Err(e) => w.set_status(format!("network switch: {e}").into()),
            }
        }
        w.set_settings_network(s.network.as_str().into());
    });

    cb!(on_set_chunk, |w, s, t: SharedString| {
        match t.trim().parse::<usize>() {
            Ok(n) if (20..=100_000).contains(&n) => {
                if let Some(store) = &mut s.store {
                    store.chunk_size = n;
                }
                s.save_store();
                println!("cb: set-chunk-size {n} ok");
                w.set_chunk_text(n.to_string().into());
                if n == 100_000 || n == 80 {
                    w.set_chunk_custom(false);
                }
                w.set_status("".into());
            }
            _ => {
                println!("cb: set-chunk-size err=range");
                w.set_status("chunk bytes must be 20..=100000".into());
            }
        }
    });

    // Compose "too large" dialog: raise the chunk size to Standard and reprice
    // the draft in place. Only offered when the note actually fits at Standard.
    cb!(on_oversize_bump, |w, s| {
        if let Some(store) = &mut s.store {
            store.chunk_size = DEFAULT_CHUNK;
        }
        s.save_store();
        println!("cb: set-chunk-size {DEFAULT_CHUNK} ok (oversize-bump)");
        w.set_chunk_text(DEFAULT_CHUNK.to_string().into());
        w.set_chunk_custom(false);
        w.set_show_oversize_modal(false);
        refresh_compose(&w, &mut s);
    });

    // Bitcoin node dropdown: a preset row writes its base (None = network
    // default) to the device config for this network; the trailing "Custom…"
    // row just reveals the text field (the Slint side already moved node-index)
    // — the value follows when the user submits it via set-node-custom.
    cb!(on_set_node_preset, |w, s, i: i32| {
        let net = s.network.as_str().to_string();
        let presets = node_presets(s.network);
        let i = i as usize;
        if i < presets.len() {
            match presets[i].1 {
                Some(url) => { s.node_urls.insert(net, url.to_string()); }
                None => { s.node_urls.remove(&net); }
            }
            s.save_config();
            println!("cb: set-node-preset {}", presets[i].0);
        } else {
            println!("cb: set-node-preset custom");
        }
        w.set_status("".into());
    });

    cb!(on_set_node_custom, |w, s, t: SharedString| {
        let net = s.network.as_str().to_string();
        let v = t.trim().to_string();
        if v.is_empty() {
            s.node_urls.remove(&net);
        } else {
            s.node_urls.insert(net, v.clone());
        }
        s.save_config();
        println!("cb: set-node-custom {}", if v.is_empty() { "default" } else { &v });
        w.set_status("".into());
    });

    cb!(on_set_explorer_preset, |w, s, i: i32| {
        let net = s.network.as_str().to_string();
        let presets = explorer_presets(s.network);
        let i = i as usize;
        if i < presets.len() {
            match presets[i].1 {
                Some(url) => { s.explorers.insert(net, url.to_string()); }
                None => { s.explorers.remove(&net); }
            }
            s.save_config();
            update_activity(&w, &s); // refresh live Explorer links
            println!("cb: set-explorer-preset {}", presets[i].0);
        } else {
            println!("cb: set-explorer-preset custom");
        }
        w.set_status("".into());
    });

    cb!(on_set_explorer_custom, |w, s, t: SharedString| {
        let net = s.network.as_str().to_string();
        let v = t.trim().to_string();
        if v.is_empty() {
            s.explorers.remove(&net);
        } else {
            s.explorers.insert(net, v.clone());
        }
        s.save_config();
        update_activity(&w, &s); // refresh live Explorer links
        println!("cb: set-explorer-custom {}", if v.is_empty() { "default" } else { &v });
        w.set_status("".into());
    });

    cb!(on_reveal_backup, |w, s| {
        let _ = &mut s;
        match keychain::reveal_secret(KEYCHAIN_ACCOUNT, "reveal your backup words") {
            Ok(Some(secret)) => {
                println!("cb: reveal-backup ok len={}", secret.len());
                w.set_reveal_text(secret.into());
            }
            Ok(None) => w.set_reveal_text("(no key in keychain — APP_KEY env session?)".into()),
            Err(e) if e == "cancelled" => {
                println!("cb: reveal-backup cancelled");
                w.set_reveal_text("authentication cancelled".into());
            }
            Err(e) => w.set_reveal_text(format!("keychain: {e}").into()),
        }
    });

    cb!(on_go_home, |w, s| {
        w.set_reveal_text("".into());
        update_home(&w, &s);
        w.set_screen(4);
    });

    cb!(on_open_notebooks, |w, s| {
        // Leaving the open notebook: everything that was on screen counts
        // as read, so the list badge only flags what arrived since.
        if let Some(store) = s.store.as_mut() {
            if store.mark_seen() > 0 {
                s.save_store();
            }
        }
        w.set_status("".into());
        update_notebook_list(&w, &s);
        w.set_screen(17);
    });

    cb!(on_open_notebook, |w, s, account: i32| {
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        s.account = account.max(0) as u32;
        println!("cb: open-notebook account={}", s.account);
        match activate(&mut s, &material, false) {
            Ok(()) => {
                w.set_status("".into());
                update_home(&w, &s);
                w.set_screen(4);
                refresh(&w, &mut s);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_create_notebook, |w, s| {
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        if !is_hierarchical(&material, s.network) {
            return; // button is hidden; a stray call must not add phantom rows
        }
        let Some(account) = s.notebooks.as_ref().map(|ix| ix.next_account()) else { return };
        println!("cb: create-notebook account={account}");
        s.account = account;
        // activate() adds the account to the index, persists it, and
        // rebuilds the address cache — the new row appears behind the
        // naming dialog.
        match activate(&mut s, &material, false) {
            Ok(()) => {
                update_notebook_list(&w, &s);
                w.set_nb_rename_input("".into());
                w.set_nb_rename_account(account as i32);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_nb_rename_start, |w, s, account: i32, _display: SharedString| {
        let _ = &mut s;
        // Prefill the RAW local name (the display name may be the address
        // short form, which must not become a name by accident).
        let raw = s
            .notebooks
            .as_ref()
            .and_then(|ix| ix.get(account.max(0) as u32))
            .map(|m| m.name.clone())
            .unwrap_or_default();
        w.set_nb_rename_input(raw.into());
        w.set_nb_rename_account(account);
    });

    cb!(on_nb_rename_save, |w, s, name: SharedString| {
        let account = w.get_nb_rename_account();
        if account < 0 {
            return;
        }
        let account = account as u32;
        if let Some(ix) = s.notebooks.as_mut() {
            ix.rename(account, name.as_str());
            s.save_notebooks();
            println!("cb: rename-notebook account={account}");
        }
        w.set_nb_rename_account(-1);
        w.set_nb_rename_input("".into());
        update_notebook_list(&w, &s);
        if s.ident.as_ref().map(|i| i.account) == Some(account) {
            w.set_notebook_title(s.notebook_display_name(account).into());
        }
    });

    cb!(on_nb_rename_cancel, |w, s| {
        let _ = &mut s;
        w.set_nb_rename_account(-1);
        w.set_nb_rename_input("".into());
    });

    cb!(on_nb_archive, |w, s, account: i32, archived: bool| {
        let account = account.max(0) as u32;
        let Some(ix) = s.notebooks.as_ref() else { return };
        if archived {
            // Guards: the list must keep at least one active notebook, and
            // funds never disappear from view silently — sweep first.
            if ix.active().count() <= 1 {
                w.set_status("can't archive the last notebook".into());
                return;
            }
            let balance = notebook_store(&s, account).map(|st2| st2.balance()).unwrap_or(0);
            if balance > 0 {
                w.set_status(
                    format!(
                        "this notebook holds {} sats — sweep it first (Settings → Funds)",
                        commas(balance)
                    )
                    .into(),
                );
                return;
            }
        }
        if let Some(ix) = s.notebooks.as_mut() {
            ix.set_archived(account, archived);
            s.save_notebooks();
            println!("cb: archive-notebook account={account} archived={archived}");
        }
        w.set_status("".into());
        update_notebook_list(&w, &s);
    });

    cb!(on_toggle_sender, |w, s, key: SharedString, excluded: bool| {
        let Some(store) = s.store.as_mut() else { return };
        store.set_excluded(key.as_str(), excluded);
        let hidden = store.excluded_senders.len();
        println!("cb: toggle-sender excluded={excluded} hidden={hidden}");
        s.save_store();
        update_home(&w, &s);
    });

    let auto_refresh = slint::Timer::default();
    {
        let st = st.clone();
        let weak = window.as_weak();
        auto_refresh.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(60),
            move || {
                if let Some(w) = weak.upgrade() {
                    if w.get_screen() == 4 {
                        let mut s = st.borrow_mut();
                        if s.ident.is_some() {
                            refresh(&w, &mut s);
                        }
                    }
                }
            },
        );
    }

    // Design-preview harness: `CN_PREVIEW=<screen>` boots straight into a
    // funding screen with mock data so the UI can be screenshotted and
    // iterated without wiring or clicking through onboarding. Dev-only.
    if let Ok(scr) = std::env::var("CN_PREVIEW") {
        if let Ok(n) = scr.parse::<i32>() {
            preview_mock(&window);
            window.set_screen(n);
        }
    }

    // Apply safe-area insets (iOS status bar / Dynamic Island / home
    // indicator; Android status/nav bars). Applied on the very first
    // event-loop ticks (0/100/250 ms) so the layout is positioned correctly
    // from the first painted frame — no visible "slide down" on cold start —
    // with a couple of quick retries covering the window/insets not being
    // ready at tick 0. Then polled at a slow cadence for rotation. No-op on
    // desktop (returns 0,0). The timer is kept alive for the run's lifetime.
    for delay_ms in [0_u64, 16, 50, 100, 250] {
        let w = window.as_weak();
        slint::Timer::single_shot(std::time::Duration::from_millis(delay_ms), move || {
            if let Some(win) = w.upgrade() {
                apply_safe_area(&win);
            }
        });
    }
    // Fallback: reveal the UI after a short delay no matter what, so the splash
    // cover can never stick if the inset never reports a value.
    {
        let w = window.as_weak();
        slint::Timer::single_shot(std::time::Duration::from_millis(700), move || {
            if let Some(win) = w.upgrade() {
                win.set_ready(true);
            }
        });
    }
    let safe_area_timer = slint::Timer::default();
    {
        let w = window.as_weak();
        safe_area_timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(500),
            move || {
                if let Some(win) = w.upgrade() {
                    apply_safe_area(&win);
                }
            },
        );
    }

    window.run().expect("event loop");
    let _ = safe_area_timer;
}

/// Populate every external-funding screen with representative mock data for
/// the `CN_PREVIEW` design harness.
fn preview_mock(w: &AppWindow) {
    w.set_directed(true);
    w.set_gift_sats("330".into());
    w.set_backup_words(
        " 1. legal      2. winner    3. thank\n 4. year       5. wave      6. sausage\n 7. worth      8. useful    9. dawn\n10. absorb    11. pledge   12. yellow\n"
            .into(),
    );
    w.set_fund_external(true);
    w.set_funding_ready(true);
    w.set_funding_summary("taproot · bcrt1p2caq…6hrewe · 2 coins · 220,000 sats".into());
    w.set_change_amount("Change to funding wallet".into());
    w.set_funding_descriptor("tr([a1b2c3d4/86h/1h/0h]tpub…/<0;1>/*)".into());
    w.set_funding_feedback(
        "Taproot wallet · fingerprint a1b2c3d4 · first address\nbcrt1p2caqg0ht8m7dykfrx2lnrcc85kxs09m3vgur9fl6emljxktnu7es6hrewe"
            .into(),
    );
    w.set_funding_valid(true);
    w.set_to_label("To  bcrt1pxs94vakt8gnq…rqmeyu58".into());
    w.set_compose_text("Happy birthday! Paid from cold storage.".into());
    w.set_rate_text("2".into());
    w.set_cost_line("1 chunk · ~180 vB · ~360 sats".into());

    let coins = [
        SpendCoin { outpoint: "aa:0".into(), value: "200,000".into(), confirmed: true, selected: true, txid_short: "aaaa…aaaa".into(), explorer: "".into() },
        SpendCoin { outpoint: "bb:1".into(), value: "20,000".into(), confirmed: false, selected: false, txid_short: "bbbb…bbbb".into(), explorer: "".into() },
    ];
    w.set_spend_coins(VecModel::from_slice(&coins));
    w.set_spend_title("Spending 1 coin · 200,000 sats".into());
    w.set_spend_expanded(true);

    w.set_psbt_qr(qr::qr_image("UR:CRYPTO-PSBT/1-1/HKADCSJNCPFGAXHDMOCKPREVIEWFRAME").unwrap_or_default());
    w.set_psbt_cost_line("fee 360 sats · 1 input · 180 vB".into());
    w.set_psbt_frame_label("frame 1 / 1".into());

    w.set_psbt_signed(true);
    w.set_confirm_note("Happy birthday! Paid from cold storage.".into());
    w.set_confirm_fee_line("360 sats · 2.0 sat/vB".into());
    let ins = [PsbtRow {
        title: "bcrt1p2caqg0ht8m7dykfrx2lnrcc85kx…".into(),
        subtitle: "aaaaaaaa…aaaaaaaa : 0".into(),
        amount: "200,000".into(),
        kind: "input".into(),
    }];
    w.set_confirm_inputs(VecModel::from_slice(&ins));
    let outs = [
        PsbtRow { title: "".into(), subtitle: "OP_RETURN · PNTE note".into(), amount: "0".into(), kind: "note".into() },
        PsbtRow { title: "bcrt1pxs94vakt8gnqrwhuxdscwkx5e…".into(), subtitle: "directed recipient".into(), amount: "330".into(), kind: "recipient".into() },
        PsbtRow { title: "bcrt1p8wpt9v4frpf3tkn0srd97pks…".into(), subtitle: "your notebook (keeps the note yours)".into(), amount: "330".into(), kind: "self".into() },
        PsbtRow { title: "bcrt1p2caqg0ht8m7dykfrx2lnrcc…".into(), subtitle: "change back to the funding wallet".into(), amount: "198,980".into(), kind: "change".into() },
    ];
    w.set_confirm_outputs(VecModel::from_slice(&outs));

    let wallets = [
        FundingWalletRow { id: "aa".into(), label: "Signer · bc1p5cyxnux…".into(), meta: "taproot · 220,000 sats · 2 coins".into(), active: true },
        FundingWalletRow { id: "bb".into(), label: "Sparrow hot wallet".into(), meta: "segwit · 45,000 sats · 1 coin".into(), active: false },
        FundingWalletRow { id: "cc".into(), label: "segwit · tb1qr8k2p9…".into(), meta: "segwit · tap to scan for funds".into(), active: false },
    ];
    w.set_funding_wallets(VecModel::from_slice(&wallets));
}

/// Render each screen to `<out_dir>/screen-<n>.png` via the software renderer,
/// with no on-screen window — for headless design iteration. macOS-only.
#[cfg(target_os = "macos")]
fn render_previews(w: u32, h: u32, screens: &[i32], out_dir: &str) {
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
    use std::rc::Rc;

    struct HeadlessPlatform {
        win: Rc<MinimalSoftwareWindow>,
    }
    impl slint::platform::Platform for HeadlessPlatform {
        fn create_window_adapter(
            &self,
        ) -> Result<Rc<dyn slint::platform::WindowAdapter>, slint::PlatformError> {
            Ok(self.win.clone())
        }
    }

    let win = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(HeadlessPlatform { win: win.clone() }))
        .expect("set_platform");
    let app = AppWindow::new().expect("window");
    win.set_size(slint::PhysicalSize::new(w, h));

    for &n in screens {
        preview_mock(&app);
        app.set_screen(n);
        slint::platform::update_timers_and_animations();
        win.request_redraw();
        let mut buf = vec![Rgb565Pixel(0); (w * h) as usize];
        win.draw_if_needed(|renderer| {
            renderer.render(&mut buf, w as usize);
        });
        // Rgb565 → RGB8.
        let mut rgb = Vec::with_capacity((w * h * 3) as usize);
        for px in &buf {
            let v = px.0;
            let r = ((v >> 11) & 0x1f) as u8;
            let g = ((v >> 5) & 0x3f) as u8;
            let b = (v & 0x1f) as u8;
            rgb.push((r << 3) | (r >> 2));
            rgb.push((g << 2) | (g >> 4));
            rgb.push((b << 3) | (b >> 2));
        }
        let path = format!("{out_dir}/screen-{n}.png");
        let file = std::fs::File::create(&path).expect("create png");
        let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w, h);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        enc.write_header().unwrap().write_image_data(&rgb).unwrap();
        eprintln!("rendered screen {n} -> {path}");
    }
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), ()> {
    getrandom::getrandom(buf).map_err(|_| ())
}

/// Android entry point. NativeActivity (via android-activity, which
/// Slint's backend wraps) calls this instead of `fn main`. There is no
/// `HOME` and no CLI args on Android, so we point the store at the app's
/// private internal storage before handing off to the shared `run()`.
#[cfg(target_os = "android")]
static ANDROID_APP: std::sync::OnceLock<slint::android::AndroidApp> = std::sync::OnceLock::new();

/// The `AndroidApp` handle, stashed in `android_main`, so `platform::
/// safe_area_insets` can read the content rect (status-bar / nav-bar insets).
#[cfg(target_os = "android")]
pub(crate) fn android_app() -> Option<&'static slint::android::AndroidApp> {
    ANDROID_APP.get()
}

#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: slint::android::AndroidApp) {
    if let Some(path) = app.internal_data_path() {
        std::env::set_var("APP_DATA_DIR", path);
    }
    // Keep a handle for safe-area insets (content_rect); AndroidApp is a
    // cheap clonable handle.
    let _ = ANDROID_APP.set(app.clone());
    // Stash the JavaVM + Activity so the keystore/camera JNI backends can
    // reach them (ndk-context is populated by android-activity at startup;
    // this is a belt-and-suspenders no-op if already set).
    slint::android::init(app).expect("slint android init");
    run();
}
