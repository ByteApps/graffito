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

use slint::{ComponentHandle, Model, SharedString, VecModel};
use zeroize::Zeroizing;

slint::include_modules!();

const KEYCHAIN_ACCOUNT: &str = "identity-key";

/// Opened by Settings → About & help → "Source code".
const SOURCE_URL: &str = "https://github.com/ObjSal/chain-notes-app";
/// Minimum (and default) sats sent to a directed-note recipient.
const DUST_SATS: u64 = app_core::notes_core::DUST_LIMIT;

// ---- About / Help / Privacy / Q&A / disclaimer copy (info screens 24/25) ----

const DISCLAIMER: &str = "Chain Notes is free software provided \"as is\", without warranty of any kind. You alone control your keys and funds. The authors accept no liability for any loss of funds or data — from lost or leaked keys, fees, failed or malformed transactions, or bugs. Bitcoin transactions are irreversible and on-chain data is public and permanent. This is a hot wallet: keep only small, note-fee amounts here and use it at your own risk.";

const ABOUT: &str = concat!(
    "Chain Notes writes short personal notes onto the Bitcoin blockchain, signed by keys that never leave your device. Notes can be public, or private — encrypted so only you (or a chosen recipient) can read them. Read them back on any device from your key alone.\n\n",
    "Version ", env!("CARGO_PKG_VERSION"), "\n\n",
    "Companion & viewer:\nobjsal.github.io/chain-notes-companion"
);

const PRIVACY: &str = "Chain Notes collects no personal data, has no accounts, and runs no servers of its own.\n\nYour keys stay in your device's secure keychain — and in iCloud Keychain only if you turn on iCloud backup.\n\nTo read the chain and broadcast, the app talks to the Bitcoin node / block explorer you choose in Settings. That server sees the addresses you look up and your IP address.\n\nNotes you publish are stored on the public Bitcoin blockchain. Private-note contents are encrypted so only you (or a note's intended recipient) can read them, but the fact that a transaction exists, its timing, and its amounts are public and permanent.";

const HELP: &str = "Getting started\n\n1. Create a new key (12/18/24 words) or import one — a BIP-39 phrase, xprv, WIF, or hex — by typing it, scanning a QR, or loading a file. You can also import an account xpub as a watch-only notebook.\n\n2. Fund your notebook's address with a small amount for fees. This is a hot wallet — keep only note-fee amounts here.\n\n3. Write a note, pick a fee, and broadcast. Notes can be public, private to you, or directed to another address.\n\n4. Read your notes back any time — they live on-chain. Recover everything on a new device from your recovery phrase or iCloud backup.\n\nTip: for real savings, keep your bitcoin on a hardware wallet and import it here as watch-only.";

const FAQ: &str = "Q.  What is Chain Notes?\nA.  A way to write short personal notes onto the Bitcoin blockchain, signed by keys that stay on your device. A note can be public (anyone can read it) or private (encrypted for you or a chosen recipient).\n\nQ.  Is my money safe here?\nA.  This is a hot wallet — its keys live on an online device. Keep only small, note-fee amounts here; hold savings on a hardware wallet and import it as watch-only.\n\nQ.  Can I recover my notes and funds?\nA.  Yes. Your recovery phrase is a standard BIP-39 seed — re-import it (or restore from iCloud backup) in Chain Notes to bring back your notes and funds. Your funds sit at taproot addresses, so any taproot-capable wallet can recover the funds too; but only Chain Notes (or a compatible app) can decrypt and read your private notes.\n\nQ.  Are my private notes really private?\nA.  Yes — a private note's contents are encrypted so only you or the intended recipient can read them (public notes are readable by anyone). Either way, the transaction itself — that it happened, when, and for how much — is public and permanent.\n\nQ.  Who can see my activity?\nA.  Anyone who has your address or public keys can see this notebook's balance and full transaction history. The block explorer you pick also sees your IP. Share your public keys only with people you trust.";

struct State {
    data_dir: PathBuf,
    network: Network,
    /// The BIP-86 wallet account (Settings-level context; rev 3). Its
    /// notebooks are receive-chain address indexes — see `nb_index`.
    account: u32,
    /// Active notebook: the receive-chain address index within `account`.
    nb_index: u32,
    /// Device-level Settings (config.json, NOT the per-identity store): the
    /// custom Bitcoin-node / block-explorer URLs, keyed by network. Device-
    /// level so switching identity keeps them; per-network because a custom
    /// URL only makes sense on the chain it serves. Absent key = network
    /// default (mempool.space).
    node_urls: HashMap<String, String>,
    explorers: HashMap<String, String>,
    /// Device-level note-size limit (config.json). Some = the user chose
    /// one in Settings; applied to every notebook's store on activate, so
    /// the wallet-level Settings pill really is wallet-wide. None = each
    /// store keeps its own (legacy per-store value or the default).
    chunk: Option<usize>,
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
    /// First-run disclaimer accepted (config.json "terms_accepted"). When false
    /// the app opens on the accept gate (screen 24) before anything else.
    terms_accepted: bool,
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
    /// Notebook index of the active identity (address-indexes-as-
    /// notebooks, per account: names + archive flags,
    /// `notebooks-<net>-<fp8>.json`), plus its filename key and the
    /// derived (index, address, store-fp8) cache — for the ACTIVE
    /// account — the list and sender labels read; rebuilt on activate,
    /// never per frame.
    notebooks: Option<NotebookIndex>,
    notebooks_fp8: Option<String>,
    nb_addrs: Vec<(u32, String, String)>,
    /// Cross-account self addresses: (account, address) for every OTHER
    /// account's listed notebooks (rev-3 follow-up 3, Sal 2026-07-12) —
    /// `sender_label` reads it so a directed note from a sibling account
    /// labels "Self · account N" instead of a bare address. Rebuilt on
    /// activate from the index file (cheap — it lists them all).
    xacct_addrs: Vec<(u32, String)>,
    /// Receive-chain gap discovery is due: activate() found a FRESH index
    /// file for multi-notebook material (a seed re-import). Consumed by
    /// `maybe_start_discovery` — the probe itself runs on a worker thread,
    /// never inline on the (iOS-watchdogged) launch path.
    discovery_pending: bool,
    /// Wallet-level consolidate in progress: sources snapshotted at open,
    /// destination + fee filled in by the picker, consumed by confirm.
    wconsol: Option<WConsol>,
    /// Private-keys reveal session (screen 19): populated by a FRESH
    /// `keychain::reveal_secret` at the Settings entry point (never from
    /// the cached `material`), so every distinct format the picker can
    /// switch to is already derived — `private-select` just reads a
    /// field, no re-derivation/re-auth. Dropped (zeroized) on hide/back/
    /// reset. Public keys never touch this — they derive from `material`.
    reveal_formats: Option<app_core::keyexport::ExportFormats>,
    /// Funding-unification M3: whether the active identity's key material
    /// can derive a BIP-84 spending wallet (mnemonic / master xprv) —
    /// computed once per `activate()`, gates the Settings toggle and the
    /// compose "Pay from · Spending wallet" option. Watch/WIF/hex/
    /// account-xprv identities are never capable.
    spending_capable: bool,
    /// The identity's spending wallet, once derived + scanned this
    /// session: the descriptor-backed source (scanning + funded-note
    /// assembly reuse the exact same `FundingSource` machinery external
    /// funding wallets use — see app-core `spending.rs`), its spendable
    /// coins, and whether a scan has completed at least once (gates the
    /// UI from showing a stale "0 sats" before the first scan finishes).
    spending_source: Option<FundingSource>,
    spending_coins: Vec<FundingUtxo>,
    spending_scanned: bool,
    /// Settings → "Sweep notebook funds here": the spending-wallet receive
    /// index the sweep destination was set to, so the broadcast handler
    /// can mark it used on success (fresh-address discipline). None for
    /// every other sweep destination.
    pending_spending_sweep_index: Option<u32>,
}

/// One wallet-consolidate session (Coins → "Consolidate into one coin…").
struct WConsol {
    /// (notebook index, spendable coins, their value) per source
    /// notebook — all within the ACTIVE account.
    sources: Vec<(u32, Vec<app_core::notes_core::tx::Utxo>, u64)>,
    dest_index: u32,
    dest_addr: String,
    rate: f64,
    fee: u64,
    vsize: u64,
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
    /// Funding-unification M3: `Some("wallet:<label>")` when an external
    /// funding wallet paid (Activity's source pill); `None` for a watch
    /// identity's own-coin self-funded compose.
    funded: Option<String>,
}

struct WatchSpend {
    kind: &'static str, // "sweep" | "consolidate" | "bump"
    dest: String,
    dest_spk_hex: String,
    value: u64,
    fee: u64,
    inputs: Vec<app_core::store::TxInput>,
    /// Owning notebook index per input (parallel to `inputs`) — watch
    /// wallet-level spends span several notebooks (rev-3 follow-up 1):
    /// bookkeeping locks each input in ITS store and the TxRecord carries
    /// `input_indexes` so a later bump re-derives every leaf.
    input_indexes: Vec<u32>,
    /// Consolidate-to-notebook: the destination's receive index — the
    /// TxRecord (+ the new unconfirmed coin) lands in THAT store,
    /// mirroring the keyed wallet-consolidate bookkeeping. None = the
    /// record stays in the active store (sweeps leave the wallet; bumps
    /// ride their original record).
    dest_index: Option<u32>,
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
                "index": self.nb_index,
                "nodes": self.node_urls,
                "explorers": self.explorers,
                "chunk": self.chunk,
                "terms_accepted": self.terms_accepted,
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
    fn notebook_display_name(&self, index: u32) -> String {
        let named = self
            .notebooks
            .as_ref()
            .and_then(|ix| ix.get(self.account, index))
            .map(|m| m.name.clone())
            .unwrap_or_default();
        if !named.is_empty() {
            return named;
        }
        self.nb_addrs
            .iter()
            .find(|(a, ..)| *a == index)
            .map(|(_, addr, _)| addr_short(addr))
            .unwrap_or_else(|| format!("Notebook {index}"))
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

/// Show the transient "Copied" toast. Bumps toast-nonce so a repeat copy
/// while a toast is still on screen extends the ~1.5s auto-dismiss window
/// (the countdown reset lives in app.slint's `changed toast-nonce` handler).
fn show_toast(w: &AppWindow, text: &str) {
    w.set_toast_text(text.into());
    w.set_toast_nonce(w.get_toast_nonce() + 1);
    w.set_toast_open(true);
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

/// The active external funding wallet's Activity pill value
/// (`"wallet:<label>"`), or `None` if no funding wallet is active — used
/// when recording a note an external wallet paid for.
fn active_funding_pill(st: &State) -> Option<String> {
    let id = st.active_funding_id.as_ref()?;
    let fw = st.funding_wallets.iter().find(|f| &f.id == id)?;
    Some(format!("wallet:{}", fw.label))
}

/// Activity's funding-source pill (funding-unification M3): `NoteRecord.
/// funded_by` is `Some("spending")` for the internal BIP-84 spending
/// wallet or `Some("wallet:<label>")` for an external funding wallet;
/// `None` (every pre-M3 record, and every notebook-funded note) shows no
/// pill at all — byte-identical to today's Activity row.
fn funded_pill(funded_by: Option<&str>) -> String {
    match funded_by {
        Some("spending") => "spending wallet".to_string(),
        Some(s) => s.strip_prefix("wallet:").map(str::to_string).unwrap_or_default(),
        None => String::new(),
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
        let nb = ident.index;
        let coins: Vec<WatchCoin> = store
            .utxos
            .iter()
            .filter(|u| !u.pending_spend)
            .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, index: nb })
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
            funded_by: wn.funded.clone(),
        },
        change,
    );
    st.save_store();
}

/// Post-broadcast bookkeeping for a watch-mode external-sign spend: sweep/
/// consolidate become TxRecords (Activity lifecycle + rebroadcast/RBF), a
/// bump rides on the record it replaces; spent coins get pending-locked.
fn record_watch_spend(st: &mut State, ws: &WatchSpend, txid: &str, raw: &str, vsize: u64) {
    if st.store.is_none() {
        return;
    }
    match &ws.bump_ref {
        Some((ref_id, is_note)) => {
            let store = st.store.as_mut().expect("checked above");
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
            // Wallet-level (rev 3): inputs may span notebooks — lock each
            // one in ITS OWN store (the active store in memory, siblings on
            // disk), mirroring the keyed sweep's bookkeeping.
            let active_index = st.ident.as_ref().map(|i| i.index);
            let mut owners: Vec<u32> = ws.input_indexes.clone();
            owners.sort_unstable();
            owners.dedup();
            if owners.is_empty() {
                owners.push(active_index.unwrap_or(0)); // legacy single-notebook shape
            }
            let lock = |store: &mut Store, index: u32| {
                for (i, input) in ws.inputs.iter().enumerate() {
                    let owner = ws.input_indexes.get(i).copied().unwrap_or(index);
                    if owner != index {
                        continue;
                    }
                    if let Some(u) =
                        store.utxos.iter_mut().find(|u| u.txid == input.txid && u.vout == input.vout)
                    {
                        u.pending_spend = true;
                    }
                }
            };
            for index in &owners {
                if active_index == Some(*index) {
                    if let Some(store) = st.store.as_mut() {
                        lock(store, *index);
                    }
                } else if let Some(mut store) = notebook_store(st, *index) {
                    lock(&mut store, *index);
                    if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == *index) {
                        let _ = store.save(&st.store_path_for(fp8));
                    }
                }
            }
            // The TxRecord lands in the destination store for a consolidate-
            // to-notebook (plus its unconfirmed coin, so the balance shows
            // before the next scan); sweeps/legacy keep it in the ACTIVE
            // store — Activity is wallet-wide either way.
            let record = |store: &mut Store| {
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
                if let Some(rec) = store.txs.last_mut() {
                    rec.input_indexes = ws.input_indexes.clone();
                }
            };
            match ws.dest_index {
                Some(dest) if active_index != Some(dest) => {
                    if let Some(mut dstore) = notebook_store(st, dest) {
                        record(&mut dstore);
                        dstore.utxos.push(app_core::store::LedgerUtxo {
                            txid: txid.to_string(),
                            vout: 0,
                            value: ws.value,
                            height: None,
                            pending_spend: false,
                        });
                        if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == dest) {
                            let _ = dstore.save(&st.store_path_for(fp8));
                        }
                    }
                }
                Some(_) => {
                    // Destination IS the active notebook.
                    if let Some(store) = st.store.as_mut() {
                        record(store);
                        store.utxos.push(app_core::store::LedgerUtxo {
                            txid: txid.to_string(),
                            vout: 0,
                            value: ws.value,
                            height: None,
                            pending_spend: false,
                        });
                    }
                }
                None => {
                    if let Some(store) = st.store.as_mut() {
                        record(store);
                    }
                }
            }
        }
    }
    st.save_store();
}

/// Every ACTIVE notebook's spendable coins as WatchCoins stamped with
/// their owning receive index — the gather behind the watch wallet-level
/// flows (rev-3 follow-up 1: sweep/consolidate span notebooks in ONE
/// externally-signed PSBT). Falls back to the active store alone when no
/// index is loaded.
fn watch_wallet_coins(st: &State) -> Vec<WatchCoin> {
    let mut coins = Vec::new();
    if let Some(ix) = &st.notebooks {
        for m in ix.active(st.account) {
            let Some(store) = notebook_store(st, m.index) else { continue };
            coins.extend(store.utxos.iter().filter(|u| !u.pending_spend).map(|u| WatchCoin {
                txid: u.txid.clone(),
                vout: u.vout,
                value: u.value,
                index: m.index,
            }));
        }
    } else if let Some(store) = &st.store {
        let nb = st.ident.as_ref().map(|i| i.index).unwrap_or(0);
        coins.extend(store.utxos.iter().filter(|u| !u.pending_spend).map(|u| WatchCoin {
            txid: u.txid.clone(),
            vout: u.vout,
            value: u.value,
            index: nb,
        }));
    }
    coins
}

/// Watch mode: build the external-sign PSBT spending every ACTIVE
/// notebook's spendable coins into `dest_spk` and open the sign screen
/// (13) — wallet-level, like the keyed sweep (rev-3 follow-up 1). The
/// signed PSBT comes back through the same import paths external funding
/// uses.
fn watch_spend_build(
    w: &AppWindow,
    st: &mut State,
    kind: &'static str,
    dest: String,
    dest_spk: Vec<u8>,
    rate: f64,
) {
    let Some(src) = st.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
    let coins = watch_wallet_coins(st);
    if coins.is_empty() || (kind == "consolidate" && coins.len() < 2) {
        w.set_status(
            if kind == "consolidate" { "nothing to consolidate (need 2+ coins)" } else { "nothing to sweep" }.into(),
        );
        return;
    }
    let notebooks = {
        let mut ids: Vec<u32> = coins.iter().map(|c| c.index).collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len()
    };
    let inputs: Vec<app_core::store::TxInput> = coins
        .iter()
        .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
        .collect();
    let input_indexes: Vec<u32> = coins.iter().map(|c| c.index).collect();
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
                input_indexes,
                dest_index: None,
                bump_ref: None,
            });
            println!(
                "cb: watch-spend-build kind={kind} txid={} fee={} inputs={} notebooks={notebooks}",
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
    // Multi-notebook records: stamp each input's owning receive index by
    // its prevout address (fetch_tx_io alone can't know our leaves) — the
    // rebuild derives every input's spk/key-origin from that index.
    let index_by_addr: HashMap<String, u32> =
        st.nb_addrs.iter().map(|(i, a, _)| (a.clone(), *i)).collect();
    let client = ChainClient::new(HttpTransport::new(base), st.network);
    match client.fetch_tx_io(&txid, |a| index_by_addr.get(a).copied()) {
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
                input_indexes: Vec::new(),
                dest_index: None,
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
    // A SWEEP is wallet-level (leaving the wallet): every active
    // notebook's coins ride — scoped to the ACTIVE account, keyed AND
    // watch alike (rev-3 follow-up 1). Consolidate (kind) stays on the
    // active store (the legacy screen-16 flow).
    let wallet_mode = w.get_sweep_kind().as_str() == "sweep";
    let spendable: Vec<app_core::store::LedgerUtxo> = if wallet_mode {
        let mut v = Vec::new();
        if let Some(ix) = &st.notebooks {
            for m in ix.active(st.account) {
                if let Some(s2) = notebook_store(st, m.index) {
                    v.extend(s2.utxos.iter().filter(|u| !u.pending_spend).cloned());
                }
            }
        }
        v
    } else {
        store.utxos.iter().filter(|u| !u.pending_spend).cloned().collect()
    };
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
    let net = st.network;
    let exb = st.explorer_base();
    let ex = exb.as_deref();
    let mut items: Vec<(u64, bool, ActivityItem)> = Vec::new(); // (created, confirmed, item)

    // Wallet-wide: every ACTIVE notebook's notes + txs, tagged. Only the
    // active notebook's rows are actionable (bump/rebroadcast sign with
    // the live store + key); the rest keep the Explorer link.
    let current = st.ident.as_ref().map(|i| i.index);
    let mut sources: Vec<(String, bool, Store)> = Vec::new(); // (tag, actionable, store)
    if let Some(ix) = &st.notebooks {
        for m in ix.active(st.account) {
            let Some(store) = notebook_store(st, m.index) else { continue };
            sources.push((
                st.notebook_display_name(m.index),
                current == Some(m.index),
                store,
            ));
        }
    } else if let Some(store) = &st.store {
        sources.push((String::new(), true, store.clone()));
    }

    for (tag, actionable, store) in &sources {
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
                pending: *actionable && n.status == NoteStatus::Pending && n.raw_hex.is_some(),
                replaced: replaced_label(n.txids.len()).into(),
                notebook: tag.clone().into(),
                funded: funded_pill(n.funded_by.as_deref()).into(),
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
            format!("Consolidate · {} sats arrived here", t.value)
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
                pending: *actionable && t.status == NoteStatus::Pending && t.raw_hex.is_some(),
                replaced: replaced_label(t.txids.len()).into(),
                notebook: tag.clone().into(),
                funded: "".into(), // sweeps/consolidates aren't funded-note records
            },
        ));
    }
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
    let ident =
        realize(&material, st.network, st.account, st.nb_index).map_err(|e| e.to_string())?;
    if persist {
        keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material_str.trim(), st.icloud_backup)?;
    }
    st.material = Some(Zeroizing::new(material_str.trim().to_string()));
    // Funding-unification M3: the spending wallet is per (identity,
    // account) — reset session state on every activate() (boot, network/
    // account switch, identity reset→reimport) and recompute capability
    // from the fresh material. Cheap: no chain call, just a key-type check.
    st.spending_capable = app_core::spending::can_derive_spending(&material);
    st.spending_source = None;
    st.spending_coins.clear();
    st.spending_scanned = false;
    let fp = hex::encode(ident.output_x());
    let path = st
        .data_dir
        .join(format!("store-{}-{}.json", st.network.as_str(), &fp[..8]));
    let store_existed = path.exists();
    let mut store = Store::load(&path).unwrap_or_else(|_| Store::new(&ident.output_x(), st.network));
    // Migrate a legacy per-identity node URL (shipped as `esplora`) into the
    // device-level per-network config, then drop it from the store. Only if
    // this network has no node set yet, so a real config choice always wins.
    if let Some(url) = store.node_url.take() {
        st.node_urls.entry(st.network.as_str().to_string()).or_insert(url);
    }
    // The note-size limit is a device-level Settings choice: apply it to
    // whichever notebook is being activated (stores of users who never
    // touched the pill keep their own value).
    if let Some(c) = st.chunk {
        store.chunk_size = c;
    }
    println!(
        "cb: identity kind={} account={} index={} network={} address={}",
        ident.kind,
        ident.account,
        ident.index,
        st.network.as_str(),
        ident.address
    );
    // Notebook index: load (or start) this identity's per-account
    // index→name/archive map (v1 accounts-as-notebooks files migrate on
    // load) and rebuild the (index, address) cache — for the ACTIVE
    // account — the notebook list + sender labels read. Notebooks are
    // created DELIBERATELY (the name-first dialog, an import's account
    // pick — via ensure_notebook); activate() itself adds one only for:
    //   * migration: a pre-notebooks install (no index file yet, but this
    //     leaf already has a store on disk) becomes notebook "Main";
    //   * non-multi-notebook identities (WIF/hex): exactly one intrinsic
    //     notebook — nothing to choose, nothing to create.
    // Saving the (possibly empty) index on first touch marks the identity
    // as initialized, so later boots respect an emptied list.
    let fp8 = index_fp8(&material, st.network).map_err(|e| e.to_string())?;
    let ix_path = st
        .data_dir
        .join(format!("notebooks-{}-{}.json", st.network.as_str(), fp8));
    let index_existed = ix_path.exists();
    let mut ix = NotebookIndex::load(&ix_path).unwrap_or_default();
    let migrate = !index_existed && store_existed;
    let mut dirty = !index_existed;
    if (migrate || !material.is_multi_notebook()) && ix.ensure(ident.account, ident.index) {
        if migrate {
            ix.rename(ident.account, ident.index, app_core::notebooks::FIRST_NOTEBOOK_NAME);
        }
        dirty = true;
    }
    if dirty {
        let _ = ix.save(&ix_path);
    }
    st.nb_addrs = ix
        .books(st.account)
        .iter()
        .filter_map(|m| {
            realize(&material, st.network, st.account, m.index)
                .ok()
                .map(|i| (m.index, i.address.clone(), hex::encode(&i.output_x()[..4])))
        })
        .collect();
    // Cross-account self labels (rev-3 follow-up 3, Sal 2026-07-12):
    // realize every OTHER account's listed notebooks into an
    // address → account map, so sender_label can say "Self · account N"
    // for directed notes between our own accounts. Cheap — the index file
    // lists exactly what to derive.
    st.xacct_addrs = ix
        .accounts
        .iter()
        .filter(|a| a.account != st.account)
        .flat_map(|a| a.notebooks.iter().map(move |m| (a.account, m.index)))
        .filter_map(|(acct, idx)| {
            realize(&material, st.network, acct, idx).ok().map(|i| (acct, i.address.clone()))
        })
        .collect();
    // Gap discovery is due when this identity's index file is FRESH for
    // multi-notebook material (a seed re-import; rev-3 follow-up 2). The
    // probe itself runs later on a worker thread (maybe_start_discovery)
    // — NEVER here: activate() sits on the iOS-watchdogged launch path.
    if !index_existed && material.is_multi_notebook() {
        st.discovery_pending = true;
    }
    st.notebooks_fp8 = Some(fp8);
    st.notebooks = Some(ix);
    st.ident = Some(ident);
    st.store = Some(store);
    st.save_store();
    st.save_config();
    Ok(())
}

fn is_hierarchical(material_str: &str, network: Network) -> bool {
    parse_key_material(material_str, network).map(|m| m.is_hierarchical()).unwrap_or(false)
}

/// Whether the material can hold more than one notebook (receive indexes
/// of one account) — everything but raw WIF/hex keys, including ranged
/// watch-only descriptors.
fn is_multi_notebook(material_str: &str, network: Network) -> bool {
    parse_key_material(material_str, network).map(|m| m.is_multi_notebook()).unwrap_or(false)
}

/// One picker page: 5 ACCOUNTS, each shown by its notebook-0 address.
fn account_rows(
    material_str: &str,
    network: Network,
    page: u32,
    active: Option<u32>,
) -> Vec<AccountItem> {
    let Ok(material) = parse_key_material(material_str, network) else { return vec![] };
    (page * 5..page * 5 + 5)
        .filter_map(|i| {
            let ident = realize(&material, network, i, 0).ok()?;
            Some(AccountItem {
                index: i as i32,
                address: ident.address.into(),
                active: active == Some(i),
                pill: "".into(),
                balance: "".into(),
            })
        })
        .collect()
}

/// One picker page: 5 NOTEBOOK ADDRESSES — receive-chain indexes `0/i`
/// of the ACTIVE account (create-notebook / consolidate-destination
/// rows).
fn index_rows(st: &State, page: u32) -> Vec<AccountItem> {
    let Some(material_str) = st.material.as_deref() else { return vec![] };
    let Ok(material) = parse_key_material(material_str, st.network) else { return vec![] };
    let active = st.ident.as_ref().map(|i| i.index);
    (page * 5..page * 5 + 5)
        .filter_map(|i| {
            let ident = realize(&material, st.network, st.account, i).ok()?;
            Some(AccountItem {
                index: i as i32,
                address: ident.address.into(),
                active: active == Some(i),
                pill: "".into(),
                balance: "".into(),
            })
        })
        .collect()
}

/// The create-notebook flavor of the picker: 5-per-page NOTEBOOK ADDRESS
/// rows (receive indexes of the active account), plus a "notebook" pill
/// for indexes already in the index file and — when a node is configured —
/// a used/new pill with the address's current balance, so recovering an
/// already-used address is a visible, deliberate choice.
fn show_notebook_picker(w: &AppWindow, st: &State, page: u32, mode: &str) {
    if st.material.is_none() {
        return;
    }
    // Paint immediately with local data — the "notebook" pill for indexes
    // already in the index file, plain rows otherwise. The used/new probe
    // is network, so it runs OFF the main thread below; before this, tapping
    // "+ New notebook" hung the UI on up to 5 blocking HTTP calls
    // (Sal 2026-07-13).
    let mut rows = index_rows(st, page);
    let mut to_probe: Vec<(u32, String)> = Vec::new(); // (receive index, address)
    for row in &mut rows {
        let index = row.index as u32;
        if st.notebooks.as_ref().and_then(|ix| ix.get(st.account, index)).is_some() {
            row.pill = "notebook".into();
        } else {
            to_probe.push((index, row.address.to_string()));
        }
    }
    w.set_account_page(page as i32);
    w.set_accounts(VecModel::from_slice(&rows));
    w.set_account_pick_mode(mode.into());
    w.set_screen(9);

    // Probe used/new on a worker thread; results fill the pills in via the
    // apply-pending-picker-probe trampoline (offline / no rows → plain rows).
    let Some(base) = st.base_url() else { return };
    if to_probe.is_empty() {
        return;
    }
    let network = st.network;
    let account = st.account;
    let weak = w.as_weak();
    std::thread::spawn(move || {
        let client = ChainClient::new(HttpTransport::new(base), network);
        let mut results: Vec<(u32, &'static str, String)> = Vec::new();
        for (index, addr) in &to_probe {
            if let Ok((used, balance)) = client.address_probe(addr) {
                let pill = if used { "used" } else { "new" };
                let bal = if used { format!("{} sats", commas(balance)) } else { String::new() };
                results.push((*index, pill, bal));
            }
        }
        PICKER_PROBE_RESULTS
            .lock()
            .expect("picker probe mutex")
            .push(PickerProbeResult { account, page, rows: results });
        let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_picker_probe());
    });
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

/// Deliberate notebook creation for receive `index` of the ACTIVE
/// account: add it to the index file (if missing), persist, and extend
/// the address cache. The ONLY entry points are user intent — the create
/// dialog, an import's account pick (notebook 0), and APP_KEY automation
/// boots (their index choice is explicit config).
fn ensure_notebook(st: &mut State, index: u32) {
    let account = st.account;
    let Some(ix) = st.notebooks.as_mut() else { return };
    if !ix.ensure(account, index) {
        return;
    }
    st.save_notebooks();
    if !st.nb_addrs.iter().any(|(a, ..)| *a == index) {
        if let Some(material_str) = st.material.as_deref() {
            if let Ok(material) = parse_key_material(material_str, st.network) {
                if let Ok(i) = realize(&material, st.network, account, index) {
                    st.nb_addrs.push((
                        index,
                        i.address.clone(),
                        hex::encode(&i.output_x()[..4]),
                    ));
                }
            }
        }
    }
}

/// "Home" for flows that end at the active notebook — unless the active
/// account has no notebook entry (create-seed just finished, an iCloud
/// restore onto a fresh install), in which case home would be a trap only
/// reachable by accident: land on the notebook list instead.
/// Wipe any revealed key-export material from the UI (nav away / reset /
/// hide) AND drop the cached private-reveal formats (`State.reveal_formats`
/// — the only place a freshly-authenticated secret is held; dropping it
/// zeroizes via `Zeroizing`). Values otherwise live only in these props, so
/// clearing them is the wipe.
fn clear_reveal(w: &AppWindow, s: &mut State) {
    let empty: Vec<RevealRow> = Vec::new();
    w.set_reveal_public_rows(VecModel::from_slice(&empty));
    w.set_reveal_public_hint("".into());
    w.set_reveal_fingerprint("".into());
    w.set_reveal_has_recovery(false);
    w.set_reveal_has_xprv(false);
    w.set_reveal_has_hex(false);
    w.set_reveal_has_wif(false);
    w.set_reveal_private_format("".into());
    w.set_reveal_private_value("".into());
    w.set_reveal_private_qr(slint::Image::default());
    w.set_reveal_words_col1("".into());
    w.set_reveal_words_col2("".into());
    w.set_reveal_show_seedqr(false);
    w.set_reveal_seedqr_image(slint::Image::default());
    w.set_reveal_nb_rows(VecModel::from_slice(&Vec::<NbPickRow>::new()));
    w.set_reveal_nb_index(0);
    s.reveal_formats = None;
}

/// The active account's notebook picker rows for the Private-keys hex/WIF
/// views (archived notebooks excluded — matches the notebook list). `name`
/// falls back to the short address when unnamed (`notebook_display_name`),
/// `addr` is always the short address so an unnamed row isn't just a
/// duplicate string.
fn private_nb_rows(st: &State) -> Vec<NbPickRow> {
    let Some(ix) = &st.notebooks else { return Vec::new() };
    ix.books(st.account)
        .iter()
        .filter(|m| !m.archived)
        .map(|m| {
            let addr = st
                .nb_addrs
                .iter()
                .find(|(a, ..)| *a == m.index)
                .map(|(_, a, _)| addr_short(a))
                .unwrap_or_default();
            // Named notebooks show their name; unnamed ones read "Notebook N"
            // (not the address again — the addr already sits in its own column).
            let name = if m.name.trim().is_empty() {
                format!("Notebook {}", m.index)
            } else {
                m.name.clone()
            };
            NbPickRow {
                index: m.index as i32,
                name: name.into(),
                addr: addr.into(),
            }
        })
        .collect()
}

/// Derive the CURRENTLY-selected picker notebook's hex/WIF leaf key from
/// the session-cached material (no re-auth) — shared by `private-select`
/// (switching format pills) and `private-pick-notebook` (switching
/// notebooks), so whichever changes last always shows the right value.
fn derive_leaf_value(s: &State, w: &AppWindow, which: &str) -> Option<String> {
    let material = s.material.as_ref().map(|z| String::from(z.as_str()))?;
    let index = w.get_reveal_nb_index() as u32;
    let f = app_core::keyexport::export_formats(&material, s.network, s.account, index).ok()?;
    match which {
        "hex" => f.leaf_hex.as_ref().map(|z| z.as_str().to_string()),
        "wif" => f.leaf_wif.as_ref().map(|z| z.as_str().to_string()),
        _ => None,
    }
}

fn go_home_or_list(w: &AppWindow, st: &State) {
    let listed = st
        .ident
        .as_ref()
        .and_then(|i| st.notebooks.as_ref().map(|ix| ix.get(i.account, i.index).is_some()))
        .unwrap_or(false);
    if listed {
        update_home(w, st);
        w.set_screen(4);
    } else {
        update_notebook_list(w, st);
        w.set_screen(17);
    }
}

/// Route a validated sweep destination to the compose-like sweep screen:
/// label (notebook name → contact name → bare address), the on-chain
/// linkage caveat when the destination is one of OUR notebooks (and no
/// contacts pollution for those), fee tier defaults, screen 16.
fn set_sweep_dest(w: &AppWindow, st: &mut State, a: String) {
    let own_index = st.nb_addrs.iter().find(|(_, ad, _)| *ad == a).map(|(idx, ..)| *idx);
    match own_index {
        Some(acct) => {
            println!("cb: sweep-pick to={a} (notebook {acct})");
            w.set_sweep_to_label(
                format!(
                    "Everything to: {} · {}",
                    st.notebook_display_name(acct),
                    addr_short(&a)
                )
                .into(),
            );
            w.set_sweep_dest_note(
                "Heads up: sweeping between your own notebooks publicly links their addresses on-chain.".into(),
            );
        }
        None => {
            println!("cb: sweep-pick to={a}");
            if let Some(store) = &mut st.store {
                store.touch_contact(&a);
            }
            st.save_store();
            refresh_contacts(w, st);
            let name = st
                .store
                .as_ref()
                .and_then(|s| s.contacts.iter().find(|c| c.address == a))
                .map(|c| c.name.clone())
                .filter(|n| !n.is_empty());
            w.set_sweep_to_label(
                match &name {
                    Some(n) => format!("Everything to: {n} · {a}"),
                    None => format!("Everything to: {a}"),
                }
                .into(),
            );
            w.set_sweep_dest_note("".into());
        }
    }
    w.set_sweep_dest(a.into());
    w.set_sweep_tier(1);
    let rate = st.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
    w.set_sweep_rate_text(format!("{rate}").into());
    w.set_sweep_fund_external(false);
    w.set_sweep_inputs_expanded(false);
    w.set_status("".into());
    update_sweep_screen(w, st);
    w.set_screen(16);
}

/// The per-notebook self-consolidate flow (screen 16, kind
/// "consolidate") — still the watch-only path, where signing happens on
/// an external wallet and one notebook is all there is.
fn open_notebook_consolidate(w: &AppWindow, st: &mut State) {
    let spendable = st
        .store
        .as_ref()
        .map(|s| s.utxos.iter().filter(|u| !u.pending_spend).count())
        .unwrap_or(0);
    if spendable < 2 {
        w.set_status("nothing to consolidate (need 2+ coins)".into());
        return;
    }
    let Some(addr) = st.ident.as_ref().map(|i| i.address.clone()) else { return };
    println!("cb: consolidate-open coins={spendable}");
    w.set_sweep_kind("consolidate".into());
    w.set_sweep_dest(addr.clone().into());
    w.set_sweep_dest_note("".into());
    let nb_name = st
        .ident
        .as_ref()
        .map(|i| st.notebook_display_name(i.index))
        .unwrap_or_else(|| "this notebook".into());
    w.set_sweep_to_label(format!("Consolidate within {nb_name} · {}", addr_short(&addr)).into());
    w.set_sweep_tier(1);
    let rate = st.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
    w.set_sweep_rate_text(format!("{rate}").into());
    w.set_sweep_fund_external(false);
    w.set_sweep_inputs_expanded(false);
    w.set_status("".into());
    update_sweep_screen(w, st);
    w.set_screen(16);
}

/// A (possibly inactive) notebook's store (by receive index within the
/// active account), read from its file on disk; the ACTIVE notebook
/// prefers the live in-memory store.
fn notebook_store(st: &State, index: u32) -> Option<Store> {
    if st.ident.as_ref().map(|i| i.index) == Some(index) {
        if let Some(s) = &st.store {
            return Some(s.clone());
        }
    }
    let (_, _, fp8) = st.nb_addrs.iter().find(|(a, ..)| *a == index)?;
    Store::load(&st.store_path_for(fp8)).ok()
}

/// Sender-filter label rules, in priority order: "Self · <notebook>" when
/// the sender is one of the ACTIVE account's addresses (this notebook's
/// own notes, or directed notes from a sibling notebook),
/// "Self · account N" when it belongs to another of our accounts (rev-3
/// follow-up 3 — accounts are separate wallets, but the sender is still
/// us), the contact name when known, else the short address form.
fn sender_label(st: &State, store: &Store, key: &str) -> String {
    if let Some((index, ..)) = st.nb_addrs.iter().find(|(_, a, _)| a == key) {
        return format!("Self · {}", st.notebook_display_name(*index));
    }
    if let Some((acct, _)) = st.xacct_addrs.iter().find(|(_, a)| a == key) {
        return format!("Self · account {acct}");
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
            .map(|m| is_multi_notebook(m, st.network))
            .unwrap_or(false),
    );
    let mut active_rows: Vec<NotebookItem> = Vec::new();
    let mut archived_rows: Vec<NotebookItem> = Vec::new();
    for meta in ix.books(st.account) {
        let Some((_, address, _)) = st.nb_addrs.iter().find(|(a, ..)| *a == meta.index) else {
            continue;
        };
        let store = notebook_store(st, meta.index);
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
            index: meta.index as i32,
            name: st.notebook_display_name(meta.index).into(),
            snippet: snippet.into(),
            meta: meta_line.into(),
            unread: match unread {
                0 => "".into(),
                1 => "1 new".into(),
                n => format!("{n} new").into(),
            },
            active: st.ident.as_ref().map(|i| i.index) == Some(meta.index),
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
    // Single-key imports (wif/hex) have no account-level public material —
    // no xpub/descriptor to export — so hide the "Public keys" entry rather
    // than route to a dead-end hint (mirrors hiding Private for watch-only).
    w.set_reveal_can_public(!matches!(ident.kind, "wif" | "hex"));
    w.set_notebook_title(st.notebook_display_name(ident.index).into());
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
        let (active_n, archived_n) = st
            .notebooks
            .as_ref()
            .map(|ix| (ix.active(st.account).count(), ix.archived_count(st.account)))
            .unwrap_or((0, 0));
        let acct_part = if st
            .material
            .as_deref()
            .map(|m| is_hierarchical(m, st.network))
            .unwrap_or(false)
        {
            format!(" · account {}", st.account)
        } else {
            String::new()
        };
        w.set_settings_identity(
            format!(
                "{}{} · {}{acct_part} · {} notebook{}{}",
                i.kind,
                if i.is_watch() { " · watch-only" } else { "" },
                st.network.as_str(),
                active_n,
                if active_n == 1 { "" } else { "s" },
                if archived_n > 0 { format!(" ({archived_n} archived)") } else { String::new() }
            )
            .into(),
        );
    }
    w.set_chunk_text(store.chunk_size.to_string().into());
    load_backend_settings(w, st);
    update_wallet_coins(w, st);
    update_spending_ui(w, st);
}

/// The wallet-wide coins viewer (screen 10 + the Settings Coins card):
/// every ACTIVE notebook's spendable UTXOs, each tagged with its
/// notebook, plus the cross-wallet summary — data as of each notebook's
/// last scan (the ↻ on the coins screen rescans them all).
fn update_wallet_coins(w: &AppWindow, st: &State) {
    let mut coins: Vec<CoinItem> = Vec::new();
    let mut spendable: u64 = 0;
    let mut notebooks = 0usize;
    if let Some(ix) = &st.notebooks {
        for m in ix.active(st.account) {
            let Some(store) = notebook_store(st, m.index) else { continue };
            let name = st.notebook_display_name(m.index);
            let mut any = false;
            for u in store.utxos.iter().filter(|u| !u.pending_spend) {
                coins.push(CoinItem {
                    outpoint: format!("{}:{}", u.txid, u.vout).into(),
                    value: u.value.to_string().into(),
                    status: if u.height.is_some() { "confirmed" } else { "unconfirmed" }.into(),
                    notebook: name.clone().into(),
                });
                spendable += u.value;
                any = true;
            }
            if any {
                notebooks += 1;
            }
        }
    }
    let n = coins.len();
    w.set_coins(VecModel::from_slice(&coins));
    w.set_coins_summary(
        if n == 0 {
            "No coins anywhere yet — fund a notebook's address to add some.".to_string()
        } else {
            format!(
                "{n} coin{} · {} sats across {notebooks} notebook{}",
                if n == 1 { "" } else { "s" },
                commas(spendable),
                if notebooks == 1 { "" } else { "s" }
            )
        }
        .into(),
    );
}

/// Rescan every ACTIVE notebook except the current one (the caller runs
/// the full refresh() for that): bundle per address, apply, save. Used by
/// the coins screen's ↻ so the wallet-wide view is live, not last-scan.
fn refresh_wallet_stores(st: &State) -> usize {
    let Some(base) = st.base_url() else { return 0 };
    let Some(material_str) = st.material.as_deref() else { return 0 };
    let Ok(material) = parse_key_material(material_str, st.network) else { return 0 };
    let Some(ix) = &st.notebooks else { return 0 };
    let client = ChainClient::new(HttpTransport::new(base), st.network);
    let current = st.ident.as_ref().map(|i| i.index);
    let mut scanned = 0;
    for m in ix.active(st.account) {
        if current == Some(m.index) {
            continue;
        }
        let Ok(ident) = realize(&material, st.network, st.account, m.index) else { continue };
        let mut store = notebook_store(st, m.index)
            .unwrap_or_else(|| Store::new(&ident.output_x(), st.network));
        let Ok(bundle) = client.build_bundle(&ident.address, None) else { continue };
        let applied = match ident.full() {
            Some(id) => store.apply_bundle(&bundle, id, st.network),
            None => store.apply_bundle_watch(&bundle, &ident.output_x(), st.network),
        };
        if applied.is_ok() {
            if let Some((_, _, fp8)) = st.nb_addrs.iter().find(|(a, ..)| *a == m.index) {
                let _ = store.save(&st.store_path_for(fp8));
            }
            scanned += 1;
        }
    }
    scanned
}

/// One finished background scan, waiting to be applied on the UI thread.
/// `address` guards staleness: if the user switched notebooks while the
/// worker ran, the result is dropped (apply_bundle would refuse anyway —
/// this just keeps the failure silent and correct).
struct RefreshResult {
    address: String,
    bundle: Result<app_core::notes_core::bundle::SyncBundle, String>,
    /// (txid, confirmed?) for the pending sweep/consolidate records that
    /// existed at snapshot time — fetched on the worker so
    /// resolve_spend_statuses never blocks the UI thread.
    statuses: Vec<(String, Option<bool>)>,
}

static REFRESH_RESULTS: std::sync::Mutex<Vec<RefreshResult>> = std::sync::Mutex::new(Vec::new());

/// One finished notebook gap-discovery walk (worker thread), waiting to be
/// applied on the UI thread. The identity/network/account snapshot guards
/// staleness — switching identities mid-probe drops the result.
struct DiscoveryResult {
    fp8: String,
    network: Network,
    account: u32,
    found: Vec<u32>,
}

static DISCOVERY_RESULTS: std::sync::Mutex<Vec<DiscoveryResult>> = std::sync::Mutex::new(Vec::new());

/// Finished used/new address probes for the create-notebook picker (worker
/// thread). Applied to the picker rows on the UI thread; the (account, page)
/// snapshot guards staleness — paging or switching account/screen drops it.
struct PickerProbeResult {
    account: u32,
    page: u32,
    /// (receive index, pill "used"|"new", balance string) per probed row.
    rows: Vec<(u32, &'static str, String)>,
}

static PICKER_PROBE_RESULTS: std::sync::Mutex<Vec<PickerProbeResult>> =
    std::sync::Mutex::new(Vec::new());

/// Kick off receive-chain notebook gap discovery on a worker thread when
/// activate() flagged a fresh index file (seed re-import; rev-3
/// follow-up 2). Needs a configured node — with none the flag stays
/// pending, so setting a node later (any refresh) retries. Results land
/// through [`DISCOVERY_RESULTS`] + the `apply-pending-discovery`
/// trampoline; callers are all post-first-frame (iOS launch rule).
fn maybe_start_discovery(w: &AppWindow, st: &mut State) {
    if !st.discovery_pending {
        return;
    }
    let Some(base) = st.base_url() else { return };
    let Some(material_str) = st.material.clone() else { return };
    let Some(fp8) = st.notebooks_fp8.clone() else { return };
    st.discovery_pending = false;
    let network = st.network;
    let account = st.account;
    let weak = w.as_weak();
    std::thread::spawn(move || {
        let found = parse_key_material(&material_str, network)
            .map(|material| {
                let client = ChainClient::new(HttpTransport::new(base), network);
                app_core::chain::discover_indexes(&client, &material, network, account, 5)
            })
            .unwrap_or_default();
        drop(material_str); // Zeroizing — wiped as soon as the walk is done
        DISCOVERY_RESULTS
            .lock()
            .expect("discovery results mutex")
            .push(DiscoveryResult { fp8, network, account, found });
        let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_discovery());
    });
}

/// [`refresh`] with the network half on a worker thread (Sal 2026-07-11:
/// opening a notebook took 3-4 s on the phone because the tap handler
/// scanned synchronously — the screen never painted until it finished).
/// The screen paints immediately with "syncing…", the worker fetches the
/// bundle + pending-tx statuses, and the result comes back through
/// [`REFRESH_RESULTS`] + the `apply-pending-refresh` trampoline callback
/// (the UI thread applies it with full State access, exactly like the
/// synchronous refresh did).
fn refresh_async(w: &AppWindow, st: &mut State) {
    if st.ident.is_none() || st.store.is_none() {
        return;
    }
    maybe_start_discovery(w, st);
    let Some(base) = st.base_url() else {
        w.set_status("no Bitcoin node for this network — set one in Settings".into());
        return;
    };
    let address = st.ident.as_ref().unwrap().address.clone();
    let network = st.network;
    let pending_txids: Vec<String> = st
        .store
        .as_ref()
        .unwrap()
        .txs
        .iter()
        .filter(|t| t.status == NoteStatus::Pending)
        .flat_map(|t| t.txids.iter().cloned())
        .collect();
    w.set_status("syncing…".into());
    let weak = w.as_weak();
    std::thread::spawn(move || {
        let client = ChainClient::new(HttpTransport::new(base), network);
        let bundle = client.build_bundle(&address, None).map_err(|e| format!("{e}"));
        let statuses = pending_txids
            .iter()
            .map(|t| (t.clone(), client.fetch_tx_status(t)))
            .collect();
        REFRESH_RESULTS
            .lock()
            .expect("refresh results mutex")
            .push(RefreshResult { address, bundle, statuses });
        let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_refresh());
    });
}

/// The UI-thread half of [`refresh_async`]: identical bookkeeping to the
/// synchronous [`refresh`], fed from the worker's results.
fn apply_refresh_results(w: &AppWindow, st: &mut State) {
    let results: Vec<RefreshResult> =
        REFRESH_RESULTS.lock().expect("refresh results mutex").drain(..).collect();
    for r in results {
        if st.ident.as_ref().map(|i| i.address.as_str()) != Some(r.address.as_str()) {
            println!("cb: refresh stale-drop address={}", &r.address[..12.min(r.address.len())]);
            continue;
        }
        match r.bundle {
            Ok(bundle) => {
                st.fees = Some(bundle.fee_rates.clone());
                st.usd = bundle.btc_usd;
                let keyed = st.ident.as_ref().unwrap().full().map(|i| i.clone_fields());
                let output_x = st.ident.as_ref().unwrap().output_x();
                let network = st.network;
                let applied = match &keyed {
                    Some(identity) => {
                        st.store.as_mut().unwrap().apply_bundle(&bundle, identity, network)
                    }
                    None => st.store.as_mut().unwrap().apply_bundle_watch(&bundle, &output_x, network),
                };
                match applied {
                    Ok(stats) => {
                        let n = st
                            .store
                            .as_mut()
                            .unwrap()
                            .resolve_spend_statuses(|t| {
                                r.statuses.iter().find(|(x, _)| x == t).and_then(|(_, s)| *s)
                            });
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
}

fn refresh(w: &AppWindow, st: &mut State) {
    if st.ident.is_none() || st.store.is_none() {
        return;
    }
    maybe_start_discovery(w, st);
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

/// One finished spending-wallet scan (worker thread), waiting to be applied
/// on the UI thread. (fp8, network, account) guards staleness — switching
/// identity/network/account mid-scan drops the result, same pattern as
/// [`RefreshResult`]/[`DiscoveryResult`]. Carries BOTH a `discover_spending`
/// gap-walk (which addresses have history — merged into `store.spending.
/// used` so the self-spk SET recognizes a spending-wallet-funded note as
/// OWN on the next rescan; a plain `scan_funding` alone finds spendable
/// coins but never marks their addresses "used") and a `scan_funding` call
/// (the coins themselves, with values — what the funded-note builder needs).
struct SpendingRefreshResult {
    fp8: String,
    network: Network,
    account: u32,
    discovery: Option<(Vec<app_core::store::SpendingAddr>, u32, u32)>,
    scan: Result<app_core::funding::FundingScan, String>,
}

static SPENDING_REFRESH_RESULTS: std::sync::Mutex<Vec<SpendingRefreshResult>> =
    std::sync::Mutex::new(Vec::new());

/// Kick off a spending-wallet coin scan on a worker thread (funding-
/// unification M3) — never block the UI thread with the chain call. A
/// no-op when the identity can't derive a spending wallet, or none is
/// configured (no node). Results land through [`SPENDING_REFRESH_RESULTS`]
/// + the `apply-pending-spending-refresh` trampoline, exactly like
/// [`refresh_async`].
fn spending_refresh_async(w: &AppWindow, st: &mut State) {
    if !st.spending_capable {
        return;
    }
    let Some(material) = st.material.clone() else { return };
    let Some(base) = st.base_url() else { return };
    let network = st.network;
    let account = st.account;
    let Some(fp8) = st.notebooks_fp8.clone() else { return };
    w.set_status("scanning spending wallet…".into());
    let weak = w.as_weak();
    std::thread::spawn(move || {
        let material_parsed = parse_key_material(&material, network);
        let source = material_parsed
            .as_ref()
            .map_err(|e| e.to_string())
            .and_then(|m| app_core::spending::funding_source(m, network, account).map_err(|e| e.to_string()));
        let client = ChainClient::new(HttpTransport::new(base), network);
        // Gap-walk first (marks every used address, receive AND change, so
        // OWN-detection on rescan covers coins this app never explicitly
        // "handed out" — e.g. an address funded before the app ever showed
        // it), then the plain coin scan for spendable values.
        let discovery =
            source.as_ref().ok().map(|src| app_core::chain::discover_spending(&client, src, 20));
        let scan = source.and_then(|src| client.scan_funding(&src, 20).map_err(|e| e.to_string()));
        drop(material); // Zeroizing — wiped as soon as the scan is done
        SPENDING_REFRESH_RESULTS
            .lock()
            .expect("spending refresh mutex")
            .push(SpendingRefreshResult { fp8, network, account, discovery, scan });
        let _ = weak.upgrade_in_event_loop(|w| w.invoke_apply_pending_spending_refresh());
    });
}

/// The UI-thread half of [`spending_refresh_async`]: cache the coins +
/// source, log the result, and repaint every screen that shows the
/// spending wallet (Settings card, compose picker, Coins segment).
fn apply_spending_refresh_results(w: &AppWindow, st: &mut State) {
    let results: Vec<SpendingRefreshResult> =
        SPENDING_REFRESH_RESULTS.lock().expect("spending refresh mutex").drain(..).collect();
    for r in results {
        if st.notebooks_fp8.as_deref() != Some(r.fp8.as_str())
            || st.network != r.network
            || st.account != r.account
        {
            println!("cb: spending-refresh stale-drop");
            continue;
        }
        if let (Some((used, next_receive, next_change)), Some(store)) =
            (r.discovery, st.store.as_mut())
        {
            store.spending_apply_discovery(used, next_receive, next_change);
        }
        match r.scan {
            Ok(scan) => {
                st.spending_coins = scan.utxos;
                if let Some(material) = st.material.as_ref() {
                    if let Ok(m) = parse_key_material(material.as_str(), st.network) {
                        st.spending_source = app_core::spending::funding_source(&m, st.network, st.account).ok();
                    }
                }
                st.save_store();
                st.spending_scanned = true;
                let balance: u64 = st.spending_coins.iter().map(|c| c.value).sum();
                println!("cb: spending-refresh utxos={} balance={balance}", st.spending_coins.len());
                w.set_status("".into());
            }
            Err(e) => {
                println!("cb: spending-refresh err={e}");
                w.set_status(format!("spending wallet scan failed: {e}").into());
            }
        }
        update_spending_ui(w, st);
        if w.get_screen() == 6 && w.get_pay_from() == "spending" {
            refresh_compose(w, st);
        }
    }
}

/// Populate every spending-wallet-facing property: the Settings card
/// (capability/enabled/balance/next-receive QR), the compose picker's
/// subtitle, and the Coins screen's "spending" segment rows. Cheap local
/// derivation only — no chain call (callers that need fresh data call
/// [`spending_refresh_async`] first).
fn update_spending_ui(w: &AppWindow, st: &State) {
    w.set_spending_capable(st.spending_capable);
    let enabled = st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false);
    w.set_spending_enabled(enabled);
    if !st.spending_capable {
        w.set_spending_summary("".into());
        w.set_spending_balance_line("".into());
        w.set_spending_address("".into());
        w.set_spending_qr(slint::Image::default());
        let empty: Vec<SpendingCoinItem> = Vec::new();
        w.set_spending_coins_list(VecModel::from_slice(&empty));
        return;
    }
    let n = st.spending_coins.len();
    let total: u64 = st.spending_coins.iter().map(|c| c.value).sum();
    if !st.spending_scanned {
        w.set_spending_summary(if enabled { "tap to scan…".to_string() } else { String::new() }.into());
        w.set_spending_balance_line("not scanned yet — tap refresh".into());
    } else {
        let line = format!("{} sats · {n} coin{}", commas(total), if n == 1 { "" } else { "s" });
        w.set_spending_summary(line.clone().into());
        w.set_spending_balance_line(line.into());
    }
    if let (Some(src), Some(store)) = (st.spending_source.as_ref(), st.store.as_ref()) {
        if let Ok(d) = src.derive(0, store.spending.next_receive) {
            w.set_spending_address(d.address.clone().into());
            w.set_spending_qr(qr::qr_image(&d.address.to_uppercase()).unwrap_or_default());
        }
    }
    let exb = st.explorer_base();
    let _ = exb; // per-coin explorer link not shown here — status is enough
    let rows: Vec<SpendingCoinItem> = st
        .spending_coins
        .iter()
        .map(|c| SpendingCoinItem {
            address: short_addr(&c.address).into(),
            value: c.value.to_string().into(),
            status: if c.confirmed { "confirmed" } else { "unconfirmed" }.into(),
        })
        .collect();
    w.set_spending_coins_list(VecModel::from_slice(&rows));
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
/// Apply a "Pay from" picker selection on compose (funding-unification
/// M3): "notebook" (today's path, default) or "spending" (the identity's
/// own BIP-84 wallet). External wallets go through [`activate_funding_wallet`]
/// instead (it sets `pay-from` to `"wallet:<id>"` itself, since picking one
/// also has to scan it). Kicks a background scan the first time "spending"
/// is chosen this session.
fn apply_pay_from(w: &AppWindow, st: &mut State, kind: &str) {
    match kind {
        "spending" => {
            w.set_pay_from("spending".into());
            w.set_pay_from_label("Spending wallet".into());
            w.set_fund_external(false);
            w.set_spend_from_wallet(true);
            if !st.spending_scanned {
                spending_refresh_async(w, st);
            }
        }
        _ => {
            w.set_pay_from("notebook".into());
            w.set_pay_from_label("Notebook".into());
            w.set_fund_external(false);
            w.set_spend_from_wallet(false);
        }
    }
}

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
    // Internal spending-wallet mode (funding-unification M3): same idea,
    // but the source is the identity's OWN BIP-84 wallet, signed in-app.
    if w.get_spend_from_wallet() {
        spending_compose_ui(w, st, &text);
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

/// Internal-spending-wallet variant of the compose coin panel (funding-
/// unification M3): shows the identity's OWN BIP-84 spending-wallet coins
/// (all of them — no coin control, matching the external funded path
/// above) and a LIVE cost/change preview from a dry-run of the exact same
/// funded-note assembly the broadcast path uses
/// (`psbt_build::build_funding_psbt_amount`), so the preview and the real
/// build can never disagree.
fn spending_compose_ui(w: &AppWindow, st: &State, text: &str) {
    let net = st.network;
    let n = st.spending_coins.len();
    let total: u64 = st.spending_coins.iter().map(|c| c.value).sum();
    let exb = st.explorer_base();
    let coins: Vec<SpendCoin> = st
        .spending_coins
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
    w.set_spend_title(
        format!("Spending wallet · {n} coin{} · {} sats", if n == 1 { "" } else { "s" }, commas(total)).into(),
    );

    // Change destination: blank = a fresh spending-wallet address; a valid
    // custom address overrides it — same pattern as the other two panels.
    let change_trim = w.get_change_address().trim().to_string();
    let change_override_spk = if change_trim.is_empty() {
        w.set_change_error("".into());
        None
    } else {
        match Recipient::parse(net, &normalize_addr(&change_trim)) {
            Ok(r) => {
                w.set_change_error("".into());
                Some(r.spk)
            }
            Err(_) => {
                w.set_change_amount("Change: ⚠ invalid".into());
                w.set_change_error(format!("Not a valid {} address.", net.as_str()).into());
                w.set_spend_enough(false);
                return;
            }
        }
    };

    if n == 0 {
        w.set_cost_line("".into());
        w.set_change_amount("Spending wallet has no coins yet — fund its receive address in Settings.".into());
        w.set_spend_enough(false);
        return;
    }
    if text.is_empty() {
        w.set_cost_line("".into());
        w.set_change_amount(
            if change_override_spk.is_some() {
                format!("Change to {}…", &change_trim[..14.min(change_trim.len())])
            } else {
                "Change to a fresh spending-wallet address".to_string()
            }
            .into(),
        );
        w.set_spend_enough(true);
        return;
    }
    let (Some(source), Some(store), Some(identity)) = (
        st.spending_source.as_ref(),
        st.store.as_ref(),
        st.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()),
    ) else {
        w.set_cost_line("".into());
        w.set_spend_enough(false);
        return;
    };
    let recipient = st.to_address.as_deref().and_then(|a| Recipient::parse(net, a).ok());
    let gift = if recipient.is_some() {
        w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
    } else {
        0
    };
    let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(1.0);
    let change_index = store.spending.next_change;
    let has_custom_change = change_override_spk.is_some();
    let plan = FundingPlan {
        source,
        coins: &st.spending_coins,
        change_index,
        fee_rate: rate,
        change_override: change_override_spk,
    };
    let np = NoteParams {
        identity: &identity,
        text,
        private: w.get_compose_private(),
        recipient: recipient.as_ref(),
        note_id: [0, 0, 0, 0], // preview only — the real send draws a fresh id
        max_op_return_bytes: store.chunk_size,
        network: net,
    };
    match app_core::psbt_build::build_funding_psbt_amount(&plan, &np, gift) {
        Ok(built) => {
            let usd = st.usd.map(|p| format!(" (~${:.2})", built.fee as f64 * p / 1e8)).unwrap_or_default();
            let gift_line = if recipient.is_some() {
                format!(" + {} sats to recipient", commas(built.sent_to_recipient))
            } else {
                String::new()
            };
            w.set_cost_line(
                format!("~{} sats fee{usd}{gift_line} · +330 sats dust-to-self", built.fee).into(),
            );
            w.set_change_amount(
                if has_custom_change {
                    format!("Change to {}… · ~{} sats", &change_trim[..14.min(change_trim.len())], built.change)
                } else {
                    format!("Change to a fresh spending-wallet address · ~{} sats", built.change)
                }
                .into(),
            );
            w.set_spend_enough(true);
        }
        Err(e) => {
            w.set_cost_line("".into());
            w.set_change_amount(format!("{e}").into());
            w.set_spend_enough(false);
        }
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
                w.set_spend_from_wallet(false);
                let label = st.funding_wallets[idx].label.clone();
                w.set_pay_from(format!("wallet:{id}").into());
                w.set_pay_from_label(label.clone().into());
                println!("cb: pay-from wallet:{label}");
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
        // First-run default only (APP_NETWORK env + a saved config.json network
        // both win above): release builds — the ones shipped to iOS / Mac /
        // Android — start a fresh install on MAINNET; dev/debug builds start on
        // testnet4 for safe testing.
        .unwrap_or(if cfg!(debug_assertions) {
            Network::Testnet4
        } else {
            Network::Mainnet
        });
    let account: u32 = std::env::var("APP_ACCOUNT")
        .ok()
        .and_then(|a| a.parse().ok())
        .or_else(|| config.get("account").and_then(|v| v.as_u64()).map(|v| v as u32))
        .unwrap_or(0);
    let nb_index: u32 = std::env::var("APP_INDEX")
        .ok()
        .and_then(|a| a.parse().ok())
        .or_else(|| config.get("index").and_then(|v| v.as_u64()).map(|v| v as u32))
        .unwrap_or(0);
    let chunk: Option<usize> =
        config.get("chunk").and_then(|v| v.as_u64()).map(|v| v as usize);
    let terms_accepted = config
        .get("terms_accepted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
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
        nb_index,
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
        terms_accepted,
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
        chunk,
        notebooks: None,
        notebooks_fp8: None,
        nb_addrs: Vec::new(),
        xacct_addrs: Vec::new(),
        discovery_pending: false,
        wconsol: None,
        reveal_formats: None,
        spending_capable: false,
        spending_source: None,
        spending_coins: Vec::new(),
        spending_scanned: false,
        pending_spending_sweep_index: None,
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
                    // APP_KEY boots (automation, dev) name their notebook via
                    // APP_ACCOUNT/APP_INDEX/config — that's an explicit
                    // choice, so it counts as deliberate notebook creation.
                    // Keychain boots never auto-create: the index is whatever
                    // onboarding and the user left behind.
                    if std::env::var("APP_KEY").is_ok() {
                        let index = s.nb_index;
                        ensure_notebook(&mut s, index);
                    }
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
                            refresh_async(&win, &mut st_boot.borrow_mut());
                        }
                    });
                }
                Err(e) => window.set_status(format!("stored key failed: {e}").into()),
            }
        }
    }

    // iCloud state: (a) whether iCloud is available at all (gates the "Back up
    // to iCloud" affordance + its default-on), (b) whether a synced backup
    // already exists (offers a restore door in onboarding). For an EXISTING
    // stored key the toggle reflects that key's real sync state; for a fresh
    // install it defaults ON when iCloud is available.
    {
        let mut s = st.borrow_mut();
        let synced = keychain::is_synced(KEYCHAIN_ACCOUNT);
        let icloud_avail = keychain::icloud_available();
        let has_key = s.material.is_some();
        s.icloud_backup = if has_key { synced } else { icloud_avail };
        window.set_icloud_backup(s.icloud_backup);
        window.set_icloud_available(synced); // restore door: a synced backup exists
        window.set_icloud_enabled(icloud_avail); // iCloud usable for new backups
    }

    // First-run disclaimer gate: before anything else, a fresh install (or an
    // upgrade that predates the gate) must accept the terms. The key/notebook
    // state was already loaded above, so accepting just reveals the screen the
    // boot would otherwise have shown (list if a key exists, else onboarding).
    window.set_disclaimer_body(DISCLAIMER.into());
    if !st.borrow().terms_accepted {
        window.set_terms_accept_mode(true);
        window.set_screen(24);
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
        w.set_import_feedback("".into());
        // Default the iCloud backup ON for the imported key when iCloud is
        // available (parity with create; the toggle stays user-overridable).
        let avail = keychain::icloud_available();
        s.icloud_backup = avail;
        w.set_icloud_backup(avail);
        w.set_icloud_enabled(avail);
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
                // New key on an online device → default the iCloud backup ON
                // when iCloud is available (the user can still turn it off).
                let avail = keychain::icloud_available();
                s.icloud_backup = avail;
                w.set_icloud_backup(avail);
                w.set_icloud_enabled(avail);
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

    // Funding-unification M3: "Separate spending wallet" toggle. Persisted
    // per-identity (store.spending.enabled) like any other store setting —
    // survives restarts, resets to off on a fresh identity.
    cb!(on_set_spending_enabled, |w, s, on: bool| {
        println!("cb: set-spending enabled={on}");
        if let Some(store) = s.store.as_mut() {
            store.spending_set_enabled(on);
        }
        s.save_store();
        update_spending_ui(&w, &s);
        if on && !s.spending_scanned {
            spending_refresh_async(&w, &mut s);
        }
    });

    cb!(on_spending_refresh, |w, s| {
        spending_refresh_async(&w, &mut s);
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
                        // A fresh install restoring a hierarchical key has no
                        // notebook index yet — land on the (empty) list, not
                        // an unlisted account's home.
                        go_home_or_list(&w, &s);
                        refresh_async(&w, &mut s);
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
                // A brand-new seed has NO notebooks (Sal 2026-07-11:
                // onboarding must not auto-create one) — land on the empty
                // list; the first notebook is created deliberately there.
                go_home_or_list(&w, &s);
                refresh_async(&w, &mut s);
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
            Ok(m) => match realize(&m, s.network, 0, 0) {
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
            w.set_account_pick_mode("switch".into());
            show_account_picker(&w, &t, s.network, 0, None);
            return;
        }
        s.account = 0;
        s.nb_index = 0;
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
        refresh_async(&w, &mut s);
    });

    // Trampoline: a finished background scan invokes this from the event
    // loop; the UI thread applies it with full State access.
    cb!(on_apply_pending_refresh, |w, s| {
        apply_refresh_results(&w, &mut s);
    });

    // Trampoline: a finished spending-wallet scan (funding-unification M3)
    // landed — same pattern as apply-pending-refresh.
    cb!(on_apply_pending_spending_refresh, |w, s| {
        apply_spending_refresh_results(&w, &mut s);
    });

    // Trampoline: worker-thread used/new probes for the create-notebook
    // picker landed — fill in the pills/balances without having blocked the
    // tap. Guarded by account/page/screen so a stale probe (user paged or
    // left) is dropped.
    cb!(on_apply_pending_picker_probe, |w, s| {
        let results: Vec<PickerProbeResult> =
            PICKER_PROBE_RESULTS.lock().expect("picker probe mutex").drain(..).collect();
        for r in results {
            if s.account != r.account
                || w.get_account_page() != r.page as i32
                || w.get_screen() != 9
            {
                println!("cb: picker-probe stale-drop");
                continue;
            }
            let model = w.get_accounts();
            for i in 0..model.row_count() {
                if let Some(mut row) = model.row_data(i) {
                    if let Some((_, pill, bal)) =
                        r.rows.iter().find(|(idx, ..)| *idx == row.index as u32)
                    {
                        row.pill = (*pill).into();
                        row.balance = bal.clone().into();
                        model.set_row_data(i, row);
                    }
                }
            }
        }
    });

    // Trampoline: a finished notebook gap-discovery walk (seed re-import).
    // Discovery is the sanctioned exception to deliberate notebook
    // creation — every found index has on-chain history, so recovering it
    // is what the user meant by importing the seed.
    cb!(on_apply_pending_discovery, |w, s| {
        let results: Vec<DiscoveryResult> =
            DISCOVERY_RESULTS.lock().expect("discovery results mutex").drain(..).collect();
        for r in results {
            if s.notebooks_fp8.as_deref() != Some(r.fp8.as_str())
                || s.network != r.network
                || s.account != r.account
            {
                println!("cb: notebook-discovery stale-drop");
                continue;
            }
            let mut added = 0;
            for index in &r.found {
                if s.notebooks.as_ref().and_then(|ix| ix.get(r.account, *index)).is_none() {
                    ensure_notebook(&mut s, *index);
                    added += 1;
                }
            }
            println!("cb: notebook-discovery found={} added={added}", r.found.len());
            if added > 0 {
                update_notebook_list(&w, &s);
            }
        }
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
        let ok = platform::set_clipboard_text(text.as_str());
        println!("cb: copy kind={kind} len={} ok={ok}", text.len());
        let msg = if ok {
            match kind.as_str() {
                "address" => "Address copied",
                "backup-words" => "Recovery phrase copied",
                "note-text" => "Note copied",
                "txid" => "Txid copied",
                _ => "Copied",
            }
        } else {
            "Copy failed"
        };
        show_toast(&w, msg);
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
        update_spending_ui(&w, &s);
        if w.get_coins_segment() == "spending" && s.spending_capable && !s.spending_scanned {
            spending_refresh_async(&w, &mut s);
        }
        w.set_status("".into());
        w.set_screen(10);
    });

    // Coins screen "spending" segment: scan on first view (data otherwise
    // stays "as of the last scan", matching the notebook segment's rule).
    cb!(on_set_coins_segment, |w, s, seg: SharedString| {
        w.set_coins_segment(seg.clone());
        if seg.as_str() == "spending" && s.spending_capable && !s.spending_scanned {
            spending_refresh_async(&w, &mut s);
        }
    });

    cb!(on_open_activity, |w, s| {
        println!("cb: open-activity");
        w.set_return_screen(if w.get_screen() == 17 { 17 } else { 4 });
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
        // Multi-key records (wallet sweep/consolidate) carry per-input
        // owners — rev-3 records list notebook INDEXES within the active
        // account (`input_indexes`); legacy records list ACCOUNTS
        // (`input_accounts`, notebook 0 implied). Re-sign each input with
        // its owner's key.
        let (owner_ids, owners_are_indexes): (Vec<u32>, bool) = s
            .store
            .as_ref()
            .and_then(|st| st.txs.iter().find(|t| t.txids.iter().any(|x| x == &ref_id)))
            .map(|t| {
                if !t.input_indexes.is_empty() {
                    (t.input_indexes.clone(), true)
                } else {
                    (t.input_accounts.clone(), false)
                }
            })
            .unwrap_or_default();
        let active_account = s.account;
        let result: Result<(String, String, u64), app_core::Error> = if is_note {
            app_core::compose::bump_fee(s.store.as_mut().unwrap(), &identity, net, &ref_id, new_rate)
                .map(|c| (c.tx.raw_hex.clone(), c.tx.txid_hex.clone(), c.tx.fee))
        } else if !owner_ids.is_empty() {
            let mut distinct = owner_ids.clone();
            distinct.sort_unstable();
            distinct.dedup();
            let idents: Result<Vec<(u32, app_core::notes_core::bundle::Identity)>, app_core::Error> =
                s.material
                    .as_deref()
                    .ok_or_else(|| app_core::Error::Store("no key material".into()))
                    .and_then(|m| {
                        parse_key_material(m, net)
                            .map_err(|e| app_core::Error::Store(format!("{e}")))
                    })
                    .and_then(|material| {
                        distinct
                            .iter()
                            .map(|a| {
                                let (acct, idx) = if owners_are_indexes {
                                    (active_account, *a)
                                } else {
                                    (*a, 0)
                                };
                                realize(&material, net, acct, idx)
                                    .map_err(|e| app_core::Error::Store(format!("{e}")))
                                    .and_then(|i| {
                                        i.full().map(|f| (*a, f.clone_fields())).ok_or_else(|| {
                                            app_core::Error::Store("watch key can't bump".into())
                                        })
                                    })
                            })
                            .collect()
                    });
            idents.and_then(|idents| {
                app_core::compose::bump_raw_tx_multi(
                    s.store.as_mut().unwrap(),
                    &idents,
                    &ref_id,
                    new_rate,
                )
                .map(|tx| (tx.raw_hex.clone(), tx.txid_hex.clone(), tx.fee))
            })
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

    cb!(on_open_source, |w, s| {
        let _ = (&w, &mut s);
        println!("cb: open-source");
        let _ = platform::open_url(SOURCE_URL);
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
        // Wallet-level sweep: gather every active notebook's coins + keys
        // (sweep = leaving the wallet — one multi-key tx, like consolidate
        // but with an external destination).
        let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        let Ok(material) = parse_key_material(&material_str, net) else { return };
        let mut idents: Vec<(u32, app_core::notes_core::bundle::Identity, Vec<app_core::notes_core::tx::Utxo>)> =
            Vec::new();
        if let Some(ix) = &s.notebooks {
            for m in ix.active(s.account) {
                let Some(store) = notebook_store(&s, m.index) else { continue };
                let coins = store.available_utxos();
                if coins.is_empty() {
                    continue;
                }
                let Ok(ident) = realize(&material, net, s.account, m.index) else { continue };
                let Some(full) = ident.full().map(|i| i.clone_fields()) else { continue };
                idents.push((m.index, full, coins));
            }
        }
        if idents.is_empty() {
            w.set_status("nothing to sweep".into());
            return;
        }
        let all_inputs: Vec<app_core::store::TxInput> = idents
            .iter()
            .flat_map(|(_, _, coins)| coins.iter())
            .map(|u| {
                let mut t = u.txid;
                t.reverse();
                app_core::store::TxInput { txid: hex::encode(t), vout: u.vout, value: u.value }
            })
            .collect();
        let dest_spk_hex = hex::encode(&recipient.spk);
        let sources: Vec<app_core::notes_core::tx::SweepSource> = idents
            .iter()
            .map(|(_, id, coins)| app_core::notes_core::tx::SweepSource {
                utxos: coins,
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
            })
            .collect();
        let sweep = app_core::notes_core::tx::build_sweep_tx_multi(
            &sources,
            recipient.spk,
            rate,
            app_core::notes_core::keys::generate_aux_rand,
        );
        match sweep {
            Ok(tx) => {
                let client = ChainClient::new(HttpTransport::new(base), net);
                match client.broadcast(&tx.raw_hex) {
                    Ok(txid) => {
                        // Lock every source's inputs; the record lives in the
                        // ACTIVE notebook's store (Activity is wallet-wide).
                        for (index, _, coins) in &idents {
                            let active = s.ident.as_ref().map(|i| i.index) == Some(*index);
                            let mark = |store: &mut Store| {
                                for u in coins {
                                    let mut t = u.txid;
                                    t.reverse();
                                    let txid_hex = hex::encode(t);
                                    if let Some(l) = store
                                        .utxos
                                        .iter_mut()
                                        .find(|l| l.txid == txid_hex && l.vout == u.vout)
                                    {
                                        l.pending_spend = true;
                                    }
                                }
                            };
                            if active {
                                if let Some(store) = s.store.as_mut() {
                                    mark(store);
                                }
                            } else if let Some(mut store) = notebook_store(&s, *index) {
                                mark(&mut store);
                                if let Some((_, _, fp8)) =
                                    s.nb_addrs.iter().find(|(a, ..)| *a == *index)
                                {
                                    let _ = store.save(&s.store_path_for(fp8));
                                }
                            }
                        }
                        let input_indexes: Vec<u32> = idents
                            .iter()
                            .flat_map(|(a, _, coins)| std::iter::repeat(*a).take(coins.len()))
                            .collect();
                        if let Some(store) = s.store.as_mut() {
                            store.record_tx(
                                "sweep",
                                txid.clone(),
                                tx.tx.outputs[0].value,
                                tx.fee,
                                tx.vsize as u64,
                                tx.raw_hex.clone(),
                                dest.clone(),
                                all_inputs,
                                dest_spk_hex,
                                now(),
                            );
                            if let Some(rec) = store.txs.last_mut() {
                                rec.input_indexes = input_indexes;
                            }
                        }
                        // Funding-unification M3: this sweep's destination was
                        // the spending wallet's next receive address — mark it
                        // used so the NEXT sweep/compose hands out a fresh one.
                        if let Some(idx) = s.pending_spending_sweep_index.take() {
                            if let (Some(src), Some(store)) =
                                (s.spending_source.clone(), s.store.as_mut())
                            {
                                if let Ok(addr) = src.derive(0, idx) {
                                    store.spending_mark_used(app_core::store::SpendingAddr {
                                        chain: 0,
                                        index: idx,
                                        address: addr.address,
                                        script_pubkey_hex: hex::encode(&addr.spk),
                                    });
                                }
                            }
                        }
                        s.save_store();
                        println!(
                            "cb: sweep txid={txid} value={} fee={} notebooks={}",
                            tx.tx.outputs[0].value,
                            tx.fee,
                            idents.len()
                        );
                        w.set_status(
                            format!(
                                "swept the wallet — {} sats to {}…",
                                commas(tx.tx.outputs[0].value),
                                &dest[..14.min(dest.len())]
                            )
                            .into(),
                        );
                        update_notebook_list(&w, &s);
                        w.set_screen(17); // wallet-level flow → the list
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
        s.pending_spending_sweep_index = None; // a fresh manual pick, not the spending-wallet shortcut
        w.set_sweep_kind("sweep".into());
        w.set_pick_mode("sweep".into());
        refresh_contacts(&w, &s);
        w.set_contact_input("".into());
        w.set_status("".into());
        w.set_screen(7);
    });

    // Funding-unification M3: Settings spending-wallet card "Sweep notebook
    // funds here…" — routes through the EXISTING sweep flow (screen 7 →
    // 16), just pre-picking the destination = the spending wallet's next
    // receive address. `pending_spending_sweep_index` tells on_sweep's
    // success handler to mark that address used (fresh-address discipline).
    cb!(on_spending_sweep_here, |w, s| {
        let Some(src) = s.spending_source.clone() else {
            w.set_status("spending wallet not scanned yet".into());
            return;
        };
        let Some(idx) = s.store.as_ref().map(|st| st.spending.next_receive) else { return };
        let Ok(d) = src.derive(0, idx) else { return };
        s.pending_spending_sweep_index = Some(idx);
        w.set_sweep_kind("sweep".into());
        w.set_pick_mode("sweep".into());
        set_sweep_dest(&w, &mut s, d.address);
    });

    cb!(on_consolidate_open, |w, s| {
        open_notebook_consolidate(&w, &mut s);
    });

    cb!(on_consolidate_wallet_open, |w, s| {
        // Keyed AND watch identities take the same wallet-level flow
        // (rev-3 follow-up 1): snapshot every active notebook's coins,
        // pick the destination notebook, confirm. Watch identities sign
        // the one resulting PSBT externally (screens 13/14).
        let Some(ix) = &s.notebooks else { return };
        let mut sources: Vec<(u32, Vec<app_core::notes_core::tx::Utxo>, u64)> = Vec::new();
        let mut coins_total = 0usize;
        for m in ix.active(s.account) {
            let Some(store) = notebook_store(&s, m.index) else { continue };
            let coins = store.available_utxos();
            if coins.is_empty() {
                continue;
            }
            coins_total += coins.len();
            let value: u64 = coins.iter().map(|u| u.value).sum();
            sources.push((m.index, coins, value));
        }
        if coins_total < 2 {
            w.set_status("nothing to consolidate (need 2+ coins across the wallet)".into());
            return;
        }
        println!(
            "cb: wallet-consolidate open coins={coins_total} notebooks={}",
            sources.len()
        );
        s.wconsol = Some(WConsol {
            sources,
            dest_index: 0,
            dest_addr: String::new(),
            rate: 0.0,
            fee: 0,
            vsize: 0,
        });
        w.set_nb_create_name("".into());
        show_notebook_picker(&w, &s, 0, "wconsol");
    });

    cb!(on_wallet_consolidate, |w, s| {
        w.set_show_wconsol_confirm(false);
        w.set_account_pick_mode("switch".into());
        let Some(wc) = s.wconsol.take() else { return };
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            // Watch: ONE external-sign PSBT over every source notebook's
            // coins — each input's key origin carries its own receive
            // index, so the signer recognizes them all in one pass. The
            // cross-store bookkeeping runs post-broadcast
            // (record_watch_spend, dest_index = the picked notebook).
            let Some(src) = s.ident.as_ref().and_then(|i| i.watch_source()).cloned() else {
                return;
            };
            let dest_spk = match Recipient::parse(s.network, &wc.dest_addr) {
                Ok(r) => r.spk,
                Err(e) => {
                    w.set_status(format!("{e}").into());
                    return;
                }
            };
            let coins: Vec<WatchCoin> = wc
                .sources
                .iter()
                .flat_map(|(index, coins, _)| {
                    coins.iter().map(move |u| {
                        let mut t = u.txid;
                        t.reverse();
                        WatchCoin {
                            txid: hex::encode(t),
                            vout: u.vout,
                            value: u.value,
                            index: *index,
                        }
                    })
                })
                .collect();
            let inputs: Vec<app_core::store::TxInput> = coins
                .iter()
                .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
                .collect();
            let input_indexes: Vec<u32> = coins.iter().map(|c| c.index).collect();
            match build_watch_spend_psbt(&src, &coins, dest_spk.clone(), wc.rate) {
                Ok(built) => {
                    let cost = format!(
                        "consolidate · {} sats · fee {} sats · {} input{} from {} notebook{} · sign with your external wallet",
                        built.sent_to_recipient,
                        built.fee,
                        coins.len(),
                        if coins.len() == 1 { "" } else { "s" },
                        wc.sources.len(),
                        if wc.sources.len() == 1 { "" } else { "s" }
                    );
                    s.watch_note = None;
                    s.watch_spend = Some(WatchSpend {
                        kind: "consolidate",
                        dest: wc.dest_addr.clone(),
                        dest_spk_hex: hex::encode(&dest_spk),
                        value: built.sent_to_recipient,
                        fee: built.fee,
                        inputs,
                        input_indexes,
                        dest_index: Some(wc.dest_index),
                        bump_ref: None,
                    });
                    println!(
                        "cb: wallet-consolidate build txid={} coins={} notebooks={} fee={}",
                        built.txid,
                        coins.len(),
                        wc.sources.len(),
                        built.fee
                    );
                    show_psbt_sign_screen(&w, &mut s, built, cost);
                }
                Err(e) => w.set_status(format!("{e}").into()),
            }
            return;
        }
        let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        let Ok(material) = parse_key_material(&material_str, s.network) else { return };
        let Some(base) = s.base_url() else {
            w.set_status("no Bitcoin node for this network — set one in Settings".into());
            return;
        };
        // Realize every source's full identity; a failure aborts cleanly.
        let mut idents = Vec::new();
        for (index, coins, _) in &wc.sources {
            let ident = match realize(&material, s.network, s.account, *index) {
                Ok(i) => i,
                Err(e) => {
                    w.set_status(format!("{e}").into());
                    return;
                }
            };
            let Some(full) = ident.full().map(|i| i.clone_fields()) else {
                w.set_status("wallet consolidate needs the full key".into());
                return;
            };
            idents.push((*index, full, coins.clone()));
        }
        let dest_spk = match Recipient::parse(s.network, &wc.dest_addr) {
            Ok(r) => r.spk,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let sources: Vec<app_core::notes_core::tx::SweepSource> = idents
            .iter()
            .map(|(_, id, coins)| app_core::notes_core::tx::SweepSource {
                utxos: coins,
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
            })
            .collect();
        let built = match app_core::notes_core::tx::build_sweep_tx_multi(
            &sources,
            dest_spk.clone(),
            wc.rate,
            app_core::notes_core::keys::generate_aux_rand,
        ) {
            Ok(t) => t,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let client = ChainClient::new(HttpTransport::new(base), s.network);
        let txid = match client.broadcast(&built.raw_hex) {
            Ok(t) => t,
            Err(e) => {
                w.set_status(format!("broadcast failed: {e}").into());
                return;
            }
        };
        let value = built.tx.outputs[0].value;
        println!(
            "cb: wallet-consolidate txid={txid} coins={} notebooks={} value={value} fee={}",
            built.tx.inputs.len(),
            wc.sources.len(),
            built.fee
        );
        // Bookkeeping across stores: the destination gets the TxRecord and
        // the unconfirmed coin; every source's spent inputs lock. The next
        // scans reconcile everything authoritatively.
        let all_inputs: Vec<app_core::store::TxInput> = wc
            .sources
            .iter()
            .flat_map(|(_, coins, _)| coins.iter())
            .map(|u| {
                let mut t = u.txid;
                t.reverse();
                app_core::store::TxInput { txid: hex::encode(t), vout: u.vout, value: u.value }
            })
            .collect();
        let dest_ident_ok = realize(&material, s.network, s.account, wc.dest_index).ok();
        if let Some(dest_ident) = dest_ident_ok {
            let mut dstore = notebook_store(&s, wc.dest_index)
                .unwrap_or_else(|| Store::new(&dest_ident.output_x(), s.network));
            dstore.record_tx(
                "consolidate",
                txid.clone(),
                value,
                built.fee,
                built.vsize as u64,
                built.raw_hex.clone(),
                "self".into(),
                all_inputs,
                hex::encode(&dest_spk),
                now(),
            );
            if let Some(rec) = dstore.txs.last_mut() {
                rec.input_indexes = wc
                    .sources
                    .iter()
                    .flat_map(|(a, coins, _)| std::iter::repeat(*a).take(coins.len()))
                    .collect();
            }
            // Sources' inputs lock (the dest store handles its own below).
            for (index, coins, _) in &wc.sources {
                if *index == wc.dest_index {
                    for u in coins {
                        let mut t = u.txid;
                        t.reverse();
                        let txid_hex = hex::encode(t);
                        if let Some(l) = dstore
                            .utxos
                            .iter_mut()
                            .find(|l| l.txid == txid_hex && l.vout == u.vout)
                        {
                            l.pending_spend = true;
                        }
                    }
                }
            }
            dstore.utxos.push(app_core::store::LedgerUtxo {
                txid: txid.clone(),
                vout: 0,
                value,
                height: None,
                pending_spend: false,
            });
            if let Some((_, _, fp8)) =
                s.nb_addrs.iter().find(|(a, ..)| *a == wc.dest_index)
            {
                let _ = dstore.save(&s.store_path_for(fp8));
            }
        }
        for (index, coins, _) in &wc.sources {
            if *index == wc.dest_index {
                continue; // handled with the destination store above
            }
            let Some(mut store) = notebook_store(&s, *index) else { continue };
            for u in coins {
                let mut t = u.txid;
                t.reverse();
                let txid_hex = hex::encode(t);
                if let Some(l) =
                    store.utxos.iter_mut().find(|l| l.txid == txid_hex && l.vout == u.vout)
                {
                    l.pending_spend = true;
                }
            }
            if let Some((_, _, fp8)) = s.nb_addrs.iter().find(|(a, ..)| *a == *index) {
                let _ = store.save(&s.store_path_for(fp8));
            }
        }
        // Reload the active store from disk (it may be source and/or dest),
        // then land on the list — the wallet-level money flow's home.
        let _ = activate(&mut s, &material_str, false);
        update_notebook_list(&w, &s);
        w.set_status(
            format!("consolidated — {} sats now at {}", commas(value), s.notebook_display_name(wc.dest_index)).into(),
        );
        w.set_screen(17);
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
            // Watch identities sweep the whole WALLET (every active
            // notebook's coins, per-index key origins); a keyed identity
            // signs its own inputs with the one active key, so it stays on
            // the active store.
            let watch = s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
            let notes_coins: Vec<WatchCoin> = if watch {
                watch_wallet_coins(&s)
            } else {
                let nb = s.ident.as_ref().map(|i| i.index).unwrap_or(0);
                s.store
                    .as_ref()
                    .map(|store| {
                        store
                            .utxos
                            .iter()
                            .filter(|u| !u.pending_spend)
                            .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, index: nb })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            if notes_coins.is_empty() {
                w.set_status("nothing to sweep".into());
                return;
            }
            let inputs: Vec<app_core::store::TxInput> = notes_coins
                .iter()
                .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
                .collect();
            let input_indexes: Vec<u32> = notes_coins.iter().map(|c| c.index).collect();
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
                        input_indexes,
                        dest_index: None,
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
            // A manual pick here always replaces whatever destination was
            // set before (including the spending-wallet shortcut) — don't
            // mark a stale index used for an address the user didn't pick.
            s.pending_spending_sweep_index = None;
            set_sweep_dest(&w, &mut s, a);
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
        w.set_payfrom_expanded(false);
        // Funding-unification M3: default to the spending wallet when the
        // setting is on (PLAN "UI" section); a watch identity has none.
        let spending_default = s.spending_capable
            && !s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false)
            && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false);
        apply_pay_from(&w, &mut s, if spending_default { "spending" } else { "notebook" });
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
        let scanned = refresh_wallet_stores(&s);
        println!("cb: refresh-coins notebooks={}", scanned + 1);
        refresh(&w, &mut s); // the active notebook + fees; rebuilds the view
        w.set_status("".into());
        if s.spending_capable
            && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false)
        {
            spending_refresh_async(&w, &mut s);
        }
        refresh_compose(&w, &mut s);
    });

    // Notebook-list (main screen) header ↻: rescan every active notebook and
    // rebuild the list so balances / note counts / unread badges are current.
    cb!(on_refresh_notebooks, |w, s| {
        let scanned = refresh_wallet_stores(&s);
        refresh(&w, &mut s); // active notebook's live store (+ fees/view)
        update_notebook_list(&w, &s);
        println!("cb: refresh-notebooks notebooks={}", scanned + 1);
        w.set_status("".into());
    });

    // First-run disclaimer accepted → persist + reveal the real first screen.
    cb!(on_accept_terms, |w, s| {
        s.terms_accepted = true;
        s.save_config();
        let target = if s.material.is_some() { 17 } else { 0 };
        w.set_terms_accept_mode(false);
        w.set_screen(target);
        println!("cb: accept-terms target={target}");
    });

    // About / Privacy / Help / Q&A — one info screen, content set per button.
    cb!(on_open_info, |w, s, kind: slint::SharedString| {
        let _ = &mut s;
        let (title, body) = match kind.as_str() {
            "about" => ("About", ABOUT),
            "privacy" => ("Privacy", PRIVACY),
            "help" => ("Help", HELP),
            "faq" => ("Q & A", FAQ),
            // Terms & disclaimer re-views through the SAME info screen (25) as
            // the others, so Settings sub-screens share one scroll-top UX. The
            // centered screen 24 is now purely the first-run accept gate.
            "terms" => ("Terms & disclaimer", DISCLAIMER),
            _ => return,
        };
        w.set_info_title(title.into());
        w.set_info_body(body.into());
        w.set_screen(25);
        println!("cb: open-info {kind}");
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

    // Funding-unification M3: compose "Pay from" picker — "notebook" or
    // "spending". External wallets are picked via use-funding-wallet
    // directly (they need a scan first, same as before this milestone).
    cb!(on_set_pay_from, |w, s, kind: SharedString| {
        println!("cb: pay-from {kind}");
        apply_pay_from(&w, &mut s, kind.as_str());
        refresh_compose(&w, &mut s);
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
                        funded: active_funding_pill(&s),
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
        if !ok {
            w.set_status("copy failed".into());
        }
        show_toast(&w, if ok { "PSBT copied" } else { "Copy failed" });
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
                // Wallet-level money flows (watch sweep/consolidate) land on
                // the notebook LIST — the wallet's home — like their keyed
                // twins; notes and bumps keep landing on the active notebook.
                let mut wallet_flow = false;
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
                    wallet_flow = ws.bump_ref.is_none()
                        && (ws.kind == "sweep" || ws.kind == "consolidate");
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
                if wallet_flow {
                    refresh(&w, &mut s); // active store first — the list rows read disk + memory
                    update_notebook_list(&w, &s);
                    w.set_screen(17);
                } else {
                    w.set_screen(4);
                    refresh(&w, &mut s);
                }
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
            let nb = s.ident.as_ref().map(|i| i.index).unwrap_or(0);
            let coins: Vec<WatchCoin> = store
                .utxos
                .iter()
                .filter(|u| !u.pending_spend && sel.contains(&(u.txid.clone(), u.vout)))
                .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, index: nb })
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
                        funded: None, // spends the notebook's own coins
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

    // Funding-unification M3: the internal spending-wallet compose path —
    // build the SAME funded-note shape the external path uses
    // (`build_funding_psbt_amount`), sign every P2WPKH input in-process
    // (`sign_own_wpkh_inputs` — no PSBT export/import round trip), and
    // broadcast in one tap. Mirrors `examples/cli.rs`'s `note-spend-funded`
    // recipe exactly.
    cb!(on_spending_compose_send, |w, s| {
        let text = w.get_compose_text().to_string();
        let private = w.get_compose_private();
        let rate: f64 = w.get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.set_status("empty note or bad fee rate".into());
            return;
        }
        let net = s.network;
        let Some(base) = s.base_url() else {
            w.set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
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
        let Some(source) = s.spending_source.clone() else {
            w.set_status("spending wallet not scanned yet".into());
            return;
        };
        if s.spending_coins.is_empty() {
            w.set_status("spending wallet has no coins — fund it from Settings".into());
            return;
        }
        let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            w.set_status("no identity".into());
            return;
        };
        let Ok(key_material) = parse_key_material(&material_str, net) else {
            w.set_status("identity parse failed".into());
            return;
        };
        let account = s.account;
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.set_status("no identity".into());
            return;
        };
        let Some(change_index) = s.store.as_ref().map(|st| st.spending.next_change) else { return };
        let chunk = s.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);
        let gift = if recipient.is_some() {
            w.get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
        } else {
            0
        };
        let mut note_id = [1u8, 2, 3, 4];
        for _ in 0..8 {
            let r = app_core::notes_core::keys::generate_aux_rand()
                .map(|x| [x[0], x[1], x[2], x[3]])
                .unwrap_or(note_id);
            note_id = r;
            if !s.store.as_ref().map(|st| st.note_id_taken(&note_id)).unwrap_or(false) {
                break;
            }
        }
        let plan = FundingPlan {
            source: &source,
            coins: &s.spending_coins,
            change_index,
            fee_rate: rate,
            change_override,
        };
        let np = NoteParams {
            identity: &identity,
            text: &text,
            private,
            recipient: recipient.as_ref(),
            note_id,
            max_op_return_bytes: chunk,
            network: net,
        };
        let built = match app_core::psbt_build::build_funding_psbt_amount(&plan, &np, gift) {
            Ok(b) => b,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let mut psbt = built.psbt.clone();
        let signed = match app_core::psbt_build::sign_own_wpkh_inputs(
            &mut psbt,
            &key_material,
            net,
            account,
            &s.spending_coins,
        ) {
            Ok(n) if n > 0 => n,
            Ok(_) => {
                w.set_status("no spending-wallet inputs signed".into());
                return;
            }
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.set_status(format!("{e}").into());
                return;
            }
        };
        let client = ChainClient::new(HttpTransport::new(&base), net);
        match client.broadcast(&raw) {
            Ok(got_txid) => {
                if built.change > 0 {
                    if let Ok(change_addr) = source.derive(1, change_index) {
                        if let Some(store) = s.store.as_mut() {
                            store.spending_mark_used(app_core::store::SpendingAddr {
                                chain: 1,
                                index: change_index,
                                address: change_addr.address,
                                script_pubkey_hex: hex::encode(&change_addr.spk),
                            });
                        }
                    }
                }
                if let Some(store) = s.store.as_mut() {
                    store.record_signed(
                        app_core::store::NoteRecord {
                            note_id: hex::encode(note_id),
                            status: NoteStatus::Pending,
                            text: Some(text.clone()),
                            private,
                            directed: recipient.is_some(),
                            received: false,
                            sender: None,
                            recipient: to.clone(),
                            txids: vec![got_txid.clone()],
                            height: None,
                            blocktime: None,
                            created_at: Some(now()),
                            spent: Vec::new(), // spending-wallet inputs only — no notebook coin locked
                            raw_hex: Some(raw.clone()),
                            fee: Some(built.fee),
                            vsize: Some(vsize as u64),
                            change_to: (!change_raw.is_empty()).then(|| change_raw.clone()),
                            gift_amount: recipient.as_ref().map(|_| gift),
                            funded_by: Some("spending".into()),
                        },
                        None,
                    );
                }
                s.save_store();
                println!(
                    "cb: compose id={} txid={got_txid} fee={} vsize={vsize} to={} private={private} funded=spending broadcast=ok",
                    hex::encode(note_id),
                    built.fee,
                    to.as_deref().unwrap_or("self"),
                );
                w.set_status(format!("broadcast {}…", &got_txid[..12.min(got_txid.len())]).into());
                w.set_compose_text("".into());
                w.set_change_address("".into());
                w.set_change_expanded(false);
                w.set_spend_expanded(false);
                w.set_payfrom_expanded(false);
                w.set_screen(4);
                refresh(&w, &mut s);
            }
            Err(e) => w.set_status(format!("broadcast failed: {e}").into()),
        }
    });

    cb!(on_settings_open, |w, s| {
        w.set_return_screen(if w.get_screen() == 17 { 17 } else { 4 });
        println!("cb: settings-open");
        clear_reveal(&w, &mut s);
        w.set_status("".into());
        w.set_chunk_custom(false);
        load_backend_settings(&w, &s);
        update_spending_ui(&w, &s);
        if s.spending_capable
            && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false)
            && !s.spending_scanned
        {
            spending_refresh_async(&w, &mut s);
        }
        // Fresh entry from the list starts at the top; returning from a Settings
        // sub-screen (via nav-back, which doesn't call this) keeps its position.
        w.set_settings_scroll_y(0.0);
        w.set_screen(8);
    });

    cb!(on_open_account_picker, |w, s| {
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else { return };
        println!("cb: account-picker open");
        let page = s.account / 5;
        w.set_account_pick_mode("switch".into());
        show_account_picker(&w, &material, s.network, page, Some(s.account));
    });

    cb!(on_accounts_page, |w, s, delta: i32| {
        let page = (w.get_account_page() + delta).max(0) as u32;
        let mode = w.get_account_pick_mode();
        if mode == "notebook" || mode == "wconsol" {
            show_notebook_picker(&w, &s, page, mode.as_str());
            return;
        }
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
        if w.get_account_pick_mode() == "wconsol" {
            // Wallet consolidate: the pick is the DESTINATION — a notebook
            // address (receive index) of the active account. A non-
            // notebook address becomes a notebook (named inline) so the
            // gathered coin can never land somewhere invisible.
            let index = idx.max(0) as u32;
            let Some(mut wc) = s.wconsol.take() else { return };
            // An archived destination un-archives: the wallet's coin must
            // never land in a hidden notebook.
            if s.notebooks.as_ref().and_then(|ix| ix.get(s.account, index)).map(|m| m.archived)
                == Some(true)
            {
                let account = s.account;
                if let Some(ix) = s.notebooks.as_mut() {
                    ix.set_archived(account, index, false);
                    s.save_notebooks();
                    println!("cb: archive-notebook index={index} archived=false");
                }
            }
            if s.notebooks.as_ref().and_then(|ix| ix.get(s.account, index)).is_none() {
                // Unnamed on purpose — the picker has no name field in this
                // mode; the row shows the address short form until renamed.
                ensure_notebook(&mut s, index);
            }
            let Some(addr) =
                s.nb_addrs.iter().find(|(a, ..)| *a == index).map(|(_, ad, _)| ad.clone())
            else {
                return;
            };
            let n: usize = wc.sources.iter().map(|(_, c, _)| c.len()).sum();
            let total: u64 = wc.sources.iter().map(|(_, _, v)| *v).sum();
            let vsize = app_core::notes_core::tx::estimate_sweep_vsize(n, 34);
            let rate = s.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
            let fee = (vsize as f64 * rate).ceil() as u64;
            if total <= fee || total - fee < DUST_SATS {
                w.set_status("not enough across the wallet to cover the fee".into());
                s.wconsol = None;
                return;
            }
            let watch_note = if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
                "\nSigns on your external wallet."
            } else {
                ""
            };
            w.set_wconsol_summary(
                format!(
                    "{n} coin{} from {} notebook{} become one coin at {} · {}.\n{} sats arrive after a ~{} sats fee ({rate:.1} sat/vB).{watch_note}",
                    if n == 1 { "" } else { "s" },
                    wc.sources.len(),
                    if wc.sources.len() == 1 { "" } else { "s" },
                    s.notebook_display_name(index),
                    addr_short(&addr),
                    commas(total - fee),
                    commas(fee)
                )
                .into(),
            );
            wc.dest_index = index;
            wc.dest_addr = addr;
            wc.rate = rate;
            wc.fee = fee;
            wc.vsize = vsize as u64;
            s.wconsol = Some(wc);
            w.set_show_wconsol_confirm(true);
            return;
        }
        if w.get_account_pick_mode() == "notebook" {
            // Create flow: the inline name field is already filled (or
            // deliberately empty) — tapping an address creates right away.
            let index = idx.max(0) as u32;
            if s.notebooks.as_ref().and_then(|ix| ix.get(s.account, index)).is_some() {
                return; // row is disabled in the UI; never re-add
            }
            let name = w.get_nb_create_name().trim().to_string();
            println!("cb: create-notebook index={index}");
            let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
                return;
            };
            s.nb_index = index;
            match activate(&mut s, &material, false) {
                Ok(()) => {
                    ensure_notebook(&mut s, index);
                    if !name.is_empty() {
                        let account = s.account;
                        if let Some(ix) = s.notebooks.as_mut() {
                            ix.rename(account, index, &name);
                            s.save_notebooks();
                            println!("cb: rename-notebook index={index}");
                        }
                    }
                    w.set_account_pick_mode("switch".into());
                    w.set_nb_create_name("".into());
                    w.set_status("".into());
                    update_notebook_list(&w, &s);
                    w.set_screen(17);
                }
                Err(e) => w.set_status(format!("{e}").into()),
            }
            return;
        }
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
        s.nb_index = 0;
        println!("cb: pick-account {}", s.account);
        match activate(&mut s, &material, first_import) {
            Ok(()) => {
                if first_import {
                    // An import's account pick IS deliberate — the account's
                    // notebook 0 is created (unnamed; renameable from the
                    // list) and its home opens.
                    ensure_notebook(&mut s, 0);
                    w.set_import_text("".into());
                    w.set_status("".into());
                    w.set_screen(4);
                    update_home(&w, &s);
                    refresh_async(&w, &mut s);
                } else {
                    // Settings account switch: the account is a wallet —
                    // land on ITS notebook list (possibly empty; creation
                    // stays deliberate).
                    w.set_status("".into());
                    update_notebook_list(&w, &s);
                    w.set_screen(17);
                }
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_account_cancel, |w, s| {
        if w.get_account_pick_mode() == "wconsol" {
            // Abandon wallet consolidate: back to settings, untouched.
            w.set_account_pick_mode("switch".into());
            w.set_nb_create_name("".into());
            s.wconsol = None;
            w.set_status("".into());
            w.set_screen(8);
            return;
        }
        if w.get_account_pick_mode() == "notebook" {
            // Abandon create → back to the notebook list, untouched.
            w.set_account_pick_mode("switch".into());
            w.set_nb_create_name("".into());
            w.set_status("".into());
            update_notebook_list(&w, &s);
            w.set_screen(17);
            return;
        }
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
        s.nb_index = 0;
        s.notebooks = None;
        s.notebooks_fp8 = None;
        s.nb_addrs.clear();
        s.xacct_addrs.clear();
        s.discovery_pending = false;
        s.to_address = None;
        s.icloud_backup = false;
        w.set_icloud_backup(false);
        w.set_icloud_available(false);
        w.set_show_reset_confirm(false);
        clear_reveal(&w, &mut s);
        w.set_status("".into());
        w.set_import_text("".into());
        w.set_screen(0);
    });

    cb!(on_reveal_hide, |w, s| {
        clear_reveal(&w, &mut s);
        println!("cb: hide-reveal");
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
                    refresh_async(&w, &mut s);
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
                s.chunk = Some(n); // device-level: every notebook, on activate
                s.save_config();
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

    // ---- Public keys (screen 18): derived from the SESSION-CACHED
    // material only — never a fresh biometric. Watch-only identities show
    // whatever public material `export_formats` yields (their `material`
    // IS the xpub/descriptor string itself, so this works unchanged).
    cb!(on_reveal_public, |w, s| {
        let material = std::env::var("APP_KEY")
            .ok()
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())));
        let Some(material) = material else {
            w.set_reveal_public_rows(VecModel::from_slice(&Vec::<RevealRow>::new()));
            w.set_reveal_fingerprint("".into());
            w.set_reveal_public_hint(
                "No key material cached this session — open Private keys once (it re-authenticates), or restart the app."
                    .into(),
            );
            w.set_screen(18);
            println!("cb: reveal-public no-material");
            return;
        };
        match app_core::keyexport::export_formats(&material, s.network, s.account, s.nb_index) {
            Ok(f) => {
                let mut rows: Vec<RevealRow> = Vec::new();
                if let Some(v) = f.account_xpub.as_deref() {
                    rows.push(RevealRow {
                        label: "Account xpub".into(),
                        value: v.into(),
                        qr: qr::qr_image(v).unwrap_or_default(),
                        expanded: false,
                    });
                }
                if let Some(v) = f.descriptor.as_deref() {
                    rows.push(RevealRow {
                        label: "Descriptor (tr)".into(),
                        value: v.into(),
                        qr: qr::qr_image(v).unwrap_or_default(),
                        expanded: false,
                    });
                }
                let fp_line = match f.fingerprint.as_deref() {
                    Some(fp) => format!("{fp} · account {}", s.account),
                    None => format!("account {}", s.account),
                };
                println!("cb: reveal-public ok rows={}", rows.len());
                w.set_reveal_fingerprint(fp_line.into());
                w.set_reveal_public_rows(VecModel::from_slice(&rows));
                // A single hex/WIF key import has a leaf key but no account
                // node — legitimately nothing public to export. Explain the
                // empty screen instead of leaving it blank.
                w.set_reveal_public_hint(if rows.is_empty() {
                    "This key has no account-level public material — a single hex/WIF import can't yield a watch-only xpub or descriptor.".into()
                } else {
                    "".into()
                });
            }
            Err(e) => {
                w.set_reveal_public_rows(VecModel::from_slice(&Vec::<RevealRow>::new()));
                w.set_reveal_public_hint(format!("Couldn't derive public keys: {e}").into());
                println!("cb: reveal-public err");
            }
        }
        w.set_screen(18);
    });

    // ---- Private keys (screen 19): ALWAYS a fresh biometric — never the
    // session cache. Only on success do we derive + navigate; failures
    // surface as a status message on Settings (screen stays 8). Every
    // format this identity supports is derived up front and cached in
    // `s.reveal_formats` so the picker (`private-select`) never re-prompts
    // — but nothing is shown until the user taps a pill (progressive
    // disclosure).
    cb!(on_reveal_private, |w, s| {
        match keychain::reveal_secret(KEYCHAIN_ACCOUNT, "reveal your keys") {
            Ok(Some(secret)) => {
                match app_core::keyexport::export_formats(&secret, s.network, s.account, s.nb_index)
                {
                    Ok(f) => {
                        let fp_line = match f.fingerprint.as_deref() {
                            Some(fp) => format!("{fp} · account {}", s.account),
                            None => format!("account {}", s.account),
                        };
                        w.set_reveal_fingerprint(fp_line.into());
                        w.set_reveal_has_recovery(f.mnemonic.is_some());
                        w.set_reveal_has_xprv(f.account_xprv.is_some());
                        w.set_reveal_has_hex(f.leaf_hex.is_some());
                        w.set_reveal_has_wif(f.leaf_wif.is_some());
                        // Nothing selected yet — the screen shows only the
                        // pills until one is tapped.
                        w.set_reveal_private_format("".into());
                        w.set_reveal_private_value("".into());
                        w.set_reveal_private_qr(slint::Image::default());
                        w.set_reveal_words_col1("".into());
                        w.set_reveal_words_col2("".into());
                        w.set_reveal_show_seedqr(false);
                        w.set_reveal_seedqr_image(slint::Image::default());
                        // Hex/WIF picker: the active account's notebooks,
                        // defaulting to the active notebook. Hidden in the UI
                        // for recovery/xprv, but harmless to populate always.
                        w.set_reveal_nb_rows(VecModel::from_slice(&private_nb_rows(&s)));
                        w.set_reveal_nb_index(s.nb_index as i32);
                        println!("cb: reveal-private ok");
                        s.reveal_formats = Some(f);
                        w.set_status("".into());
                        w.set_screen(19);
                    }
                    Err(e) => {
                        println!("cb: reveal-private err");
                        w.set_status(format!("export: {e}").into());
                    }
                }
            }
            Ok(None) => {
                println!("cb: reveal-private no-key");
                w.set_status("(no key in keychain — APP_KEY env session?)".into());
            }
            Err(e) if e == "cancelled" => {
                println!("cb: reveal-private cancelled");
                w.set_status("authentication cancelled".into());
            }
            Err(e) => {
                println!("cb: reveal-private err");
                w.set_status(format!("keychain: {e}").into());
            }
        }
    });

    // Switch which single format is on screen (progressive disclosure —
    // only one value visible at a time). Reads the formats derived at
    // reveal-private time; never re-authenticates. Hex/WIF derive from
    // whichever notebook the picker currently has selected (not always
    // the active notebook) so switching back to a pill after picking a
    // different notebook shows the right value.
    cb!(on_private_select, |w, s, fmt: SharedString| {
        let fmt = fmt.as_str();
        if fmt == "hex" || fmt == "wif" {
            let Some(v) = derive_leaf_value(&s, &w, fmt) else { return };
            w.set_reveal_show_seedqr(false);
            w.set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
            w.set_reveal_private_value(v.into());
            w.set_reveal_private_format(fmt.into());
            println!("cb: private-select fmt={fmt}");
            return;
        }
        let Some(f) = s.reveal_formats.as_ref() else { return };
        w.set_reveal_show_seedqr(false);
        match fmt {
            "recovery" => {
                let Some(words) = f.mnemonic.as_ref().map(|z| z.as_str().to_string()) else {
                    return;
                };
                let list: Vec<&str> = words.split_whitespace().collect();
                let half = list.len() / 2;
                let col = |range: std::ops::Range<usize>| -> String {
                    range
                        .map(|i| format!("{:2}. {}", i + 1, list[i]))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                w.set_reveal_words_col1(col(0..half).into());
                w.set_reveal_words_col2(col(half..list.len()).into());
                if let Ok(m) = bip39::Mnemonic::parse(&words) {
                    let digits = app_core::seedqr::encode_standard(&m);
                    w.set_reveal_seedqr_image(qr::qr_image(&digits).unwrap_or_default());
                }
                w.set_reveal_private_value(words.into());
                w.set_reveal_private_qr(slint::Image::default());
            }
            "xprv" => {
                let Some(v) = f.account_xprv.as_ref().map(|z| z.as_str().to_string()) else {
                    return;
                };
                w.set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
                w.set_reveal_private_value(v.into());
            }
            // hex/wif are handled above (picker-aware, returns early).
            _ => return,
        }
        w.set_reveal_private_format(fmt.into());
        println!("cb: private-select fmt={fmt}");
    });

    // Hex/WIF only: switch the picker's selected notebook and re-derive
    // its leaf key from the session-cached material — NO re-auth. A no-op
    // for recovery/xprv (the picker is hidden for those, and the shown
    // format is index-independent anyway).
    cb!(on_private_pick_notebook, |w, s, index: i32| {
        w.set_reveal_nb_index(index);
        println!("cb: private-pick-notebook index={index}");
        let fmt = w.get_reveal_private_format().to_string();
        if fmt != "hex" && fmt != "wif" {
            return;
        }
        let Some(v) = derive_leaf_value(&s, &w, &fmt) else { return };
        w.set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
        w.set_reveal_private_value(v.into());
    });

    cb!(on_copy_value, |w, s, value: SharedString| {
        let _ = &mut s;
        let ok = platform::set_clipboard_text(value.as_str());
        println!("cb: copy-value len={}", value.len());
        show_toast(&w, if ok { "Copied" } else { "Copy failed" });
    });

    cb!(on_go_home, |w, s| {
        clear_reveal(&w, &mut s);
        go_home_or_list(&w, &s);
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

    cb!(on_open_notebook, |w, s, index: i32| {
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        s.nb_index = index.max(0) as u32;
        println!("cb: open-notebook index={}", s.nb_index);
        match activate(&mut s, &material, false) {
            Ok(()) => {
                update_home(&w, &s);
                w.set_screen(4); // paint first — the scan runs in the background
                refresh_async(&w, &mut s);
            }
            Err(e) => w.set_status(format!("{e}").into()),
        }
    });

    cb!(on_create_notebook, |w, s| {
        // Address-first, then name-first: "+ New notebook" opens the
        // account picker (used/new pills + balances) so recovering a used
        // address is a visible choice; the naming dialog follows the pick.
        // Nothing is derived or persisted until the dialog's Create.
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        if !is_multi_notebook(&material, s.network) {
            return; // button is hidden; a stray call must not add phantom rows
        }
        println!("cb: create-notebook picker open");
        w.set_nb_create_name("".into());
        show_notebook_picker(&w, &s, 0, "notebook");
    });

    cb!(on_nb_rename_start, |w, s, index: i32, _display: SharedString| {
        let _ = &mut s;
        // Prefill the RAW local name (the display name may be the address
        // short form, which must not become a name by accident).
        let raw = s
            .notebooks
            .as_ref()
            .and_then(|ix| ix.get(s.account, index.max(0) as u32))
            .map(|m| m.name.clone())
            .unwrap_or_default();
        w.set_nb_rename_input(raw.into());
        w.set_nb_rename_index(index);
    });

    cb!(on_nb_rename_save, |w, s, name: SharedString| {
        let sel = w.get_nb_rename_index();
        if sel < 0 {
            return;
        }
        w.set_nb_rename_index(-1);
        w.set_nb_rename_input("".into());
        let index = sel as u32;
        let account = s.account;
        if let Some(ix) = s.notebooks.as_mut() {
            ix.rename(account, index, name.as_str());
            s.save_notebooks();
            println!("cb: rename-notebook index={index}");
        }
        update_notebook_list(&w, &s);
        if s.ident.as_ref().map(|i| i.index) == Some(index) {
            w.set_notebook_title(s.notebook_display_name(index).into());
        }
    });

    cb!(on_nb_rename_cancel, |w, s| {
        let _ = &mut s;
        w.set_nb_rename_index(-1);
        w.set_nb_rename_input("".into());
    });

    cb!(on_nb_archive, |w, s, index: i32, archived: bool| {
        let index = index.max(0) as u32;
        if s.notebooks.is_none() {
            return;
        }
        if archived {
            // One guard only: funds never disappear from view silently —
            // sweep first. Archiving EVERY notebook is allowed (the list
            // shows its empty state); Restore brings any of them back.
            let balance = notebook_store(&s, index).map(|st2| st2.balance()).unwrap_or(0);
            if balance > 0 {
                w.set_status(
                    format!(
                        "this notebook holds {} sats — consolidate the wallet first (Coins)",
                        commas(balance)
                    )
                    .into(),
                );
                return;
            }
        }
        let account = s.account;
        if let Some(ix) = s.notebooks.as_mut() {
            ix.set_archived(account, index, archived);
            s.save_notebooks();
            println!("cb: archive-notebook index={index} archived={archived}");
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
