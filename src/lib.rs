//! M6 shell: onboarding (import / create+quiz), home + notes, compose
//! with live cost, contacts picker, settings. Every callback emits a
//! `cb:` log-contract line (grep targets for the M7 UI e2e).
//!
//! Env overrides for tests: APP_DATA_DIR, APP_KEY (bypasses keychain),
//! APP_NETWORK.

mod boot;
mod camera;
mod editops;
mod icloud;
mod keychain;
mod pending;
mod platform;
mod qr;
mod screens;
mod util;

pub(crate) use pending::*;
pub(crate) use screens::*;
pub(crate) use util::*;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use app_core::bitcoin;
use app_core::chain::{
    default_base, explorer_presets, explorer_tx_url, node_backend_label, node_presets,
    scan_change_chain, scan_change_chain_watch, AddrStats, AnyTransport, ChainClient, ChangeCoin,
    NodeStatus, TxLookupStatus,
};
use app_core::compose::ComposeRequest;
use app_core::funding::{FundingSource, FundingUtxo, FundingWallet};
use app_core::identity::{
    active_notebook_spks, generate_mnemonic, generate_mnemonic_with_salt, index_fp8,
    parse_key_material, realize, realize_change, AppIdentity,
};
use app_core::notebooks::{NotebookIndex, SpendingAddr};
use app_core::psbt_build::{
    build_funded_sweep_psbt, build_funding_psbt, build_watch_bump_psbt, build_watch_note_psbt_multi,
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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use slint::{ComponentHandle, Model, SharedString, VecModel};
use zeroize::{Zeroize, Zeroizing};

slint::include_modules!();

/// The `Screen` enum's kebab-case names — the ONE table (U2,
/// PLAN-graffito-app-arch.md) driving `--render`'s CLI parser, its PNG
/// file names, and the `cb: sys-back` log line. Order matches the enum's
/// declaration (types.slint), which is the app's historical screen-number
/// order.
const SCREENS: &[(Screen, &str)] = &[
    (Screen::Onboarding, "onboarding"),
    (Screen::ImportKey, "import-key"),
    (Screen::BackupWords, "backup-words"),
    (Screen::Quiz, "quiz"),
    (Screen::Home, "home"),
    (Screen::Note, "note"),
    (Screen::Compose, "compose"),
    (Screen::Contacts, "contacts"),
    (Screen::Settings, "settings"),
    (Screen::AccountPicker, "account-picker"),
    (Screen::Coins, "coins"),
    (Screen::Activity, "activity"),
    (Screen::FundingWallet, "funding-wallet"),
    (Screen::ExportPsbt, "export-psbt"),
    (Screen::ImportSignedPsbt, "import-signed-psbt"),
    (Screen::FundingWallets, "funding-wallets"),
    (Screen::Sweep, "sweep"),
    (Screen::Notebooks, "notebooks"),
    (Screen::PublicKeys, "public-keys"),
    (Screen::PrivateKeys, "private-keys"),
    (Screen::PayFrom, "pay-from"),
    (Screen::Change, "change"),
    (Screen::Terms, "terms"),
    (Screen::Info, "info"),
    (Screen::Confirm, "confirm"),
    (Screen::EntropySource, "entropy-source"),
    (Screen::Dice, "dice"),
    (Screen::QuantumKeys, "quantum-keys"),
];

fn screen_name(screen: Screen) -> &'static str {
    SCREENS.iter().find(|(s, _)| *s == screen).map(|(_, n)| *n).unwrap_or("?")
}

fn screen_by_name(name: &str) -> Option<Screen> {
    SCREENS.iter().find(|(_, n)| *n == name).map(|(s, _)| *s)
}

const KEYCHAIN_ACCOUNT: &str = "identity-key";
/// An externally imported ML-KEM secret key (Settings → Quantum keys →
/// "Import a key"), Keychain-stored exactly like `KEYCHAIN_ACCOUNT` (crash-
/// safe two-phase write, local-only — never synced) but under its own
/// account: one slot, overwriting replaces whatever was there.
const PQ_IMPORTED_ACCOUNT: &str = "pq-imported";

/// Opened by Settings → About & help → "Source code".
const SOURCE_URL: &str = "https://github.com/ByteApps/graffito";
/// Minimum (and default) sats sent to a directed-note recipient.
const DUST_SATS: u64 = app_core::notes_core::DUST_LIMIT;

// ---- About / Help / Privacy / Q&A / disclaimer copy (info screens 24/25) ----

const DISCLAIMER: &str = "Graffito is free software provided \"as is\", without warranty of any kind. You alone control your keys and funds. The authors accept no liability for any loss of funds or data — from lost or leaked keys, fees, failed or malformed transactions, or bugs. Bitcoin transactions are irreversible and on-chain data is public and permanent. This is a hot wallet: keep only small, note-fee amounts here and use it at your own risk.";

const ABOUT_INTRO: &str = "Graffito writes short personal notes onto the Bitcoin blockchain, signed by keys that never leave your device. Notes can be public, or private — encrypted so only you (or a chosen recipient) can read them. Read them back on any device from your key alone.";
const ABOUT_FOOTER: &str = "Companion & viewer:\nbyteapps.com/graffito/companion";



const PRIVACY: &str = "Graffito collects no personal data, has no accounts, and runs no servers of its own.\n\nYour keys stay in your device's secure keychain — and in iCloud Keychain only if you turn on iCloud backup.\n\nTo read the chain and broadcast, the app talks to the Bitcoin node / block explorer you choose in Settings. That server sees the addresses you look up and your IP address.\n\nNotes you publish are stored on the public Bitcoin blockchain. Private-note contents are encrypted so only you (or a note's intended recipient) can read them, but the fact that a transaction exists, its timing, and its amounts are public and permanent.";

const HELP: &str = "Getting started\n\n1. Create a new key (12/18/24 words) or import one — a BIP-39 phrase, xprv, WIF, or hex — by typing it, scanning a QR, or loading a file. You can also import an account xpub as a watch-only notebook.\n\n2. Fund your notebook's address with a small amount for fees. This is a hot wallet — keep only note-fee amounts here.\n\n3. Write a note, pick a fee, and broadcast. Notes can be public, private to you, or directed to another address.\n\n4. Read your notes back any time — they live on-chain. Recover everything on a new device from your recovery phrase or iCloud backup.\n\nTip: for real savings, keep your bitcoin on a hardware wallet and import it here as watch-only.";

const FAQ: &str = "Q.  What is Graffito?\nA.  A way to write short personal notes onto the Bitcoin blockchain, signed by keys that stay on your device. A note can be public (anyone can read it) or private (encrypted for you or a chosen recipient).\n\nQ.  Is my money safe here?\nA.  This is a hot wallet — its keys live on an online device. Keep only small, note-fee amounts here; hold savings on a hardware wallet and import it as watch-only.\n\nQ.  Can I recover my notes and funds?\nA.  Yes. Your recovery phrase is a standard BIP-39 seed — re-import it (or restore from iCloud backup) in Graffito to bring back your notes and funds. Your funds sit at taproot addresses, so any taproot-capable wallet can recover the funds too; but only Graffito (or a compatible app) can decrypt and read your private notes.\n\nQ.  Are my private notes really private?\nA.  Yes — a private note's contents are encrypted so only you or the intended recipient can read them (public notes are readable by anyone). Either way, the transaction itself — that it happened, when, and for how much — is public and permanent.\n\nQ.  Who can see my activity?\nA.  Anyone who has your address or public keys can see this notebook's balance and full transaction history. The block explorer you pick also sees your IP. Share your public keys only with people you trust.";



















/// The last OBSERVED outcome of pushing `State.contacts` to iCloud's KV
/// store (contacts sync-status UI, 2026-07-20). Global, not per-contact —
/// `NSUbiquitousKeyValueStore.synchronize()` covers the whole blob in one
/// call, so every synced contact necessarily shares one status; the
/// picker just maps it onto each `synced` row (`refresh_contacts`).
/// `Unknown` only appears before the first `save_contacts`/boot-init call
/// ever runs — in practice `run()` stamps a real value before the window
/// is even shown, so the UI should never actually render it, but it's the
/// harmless neutral default for `Cell::new`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SyncStatus {
    Unknown,
    Ok,
    Failed,
}

/// [`State::pq_recipient_cache`]'s value: whether the cached contact has a
/// key on file at all (outer `Option`), and if so, whether the stored
/// armor parsed (inner `Result`).
type PqRecipientCacheEntry = (String, Option<Result<(app_core::passphrase::MlKemLevel, String), String>>);

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
    /// Bitcoin Core RPC "Save credentials" switch (config.json, per network
    /// — same device-level convention as `node_urls`/`explorers`): true
    /// persists to the Keychain (today's unconditional default behavior);
    /// false keeps credentials in `core_rpc_session_creds` only. An absent
    /// key (every pre-U10 config, and every network never touched) means
    /// true, so nobody who already saved credentials sees a change (plan
    /// §2.4 / U10, `core_rpc_should_persist`).
    core_rpc_save_creds: HashMap<String, bool>,
    /// Session-only Bitcoin Core RPC credentials — populated ONLY while
    /// `core_rpc_save_creds` is false for that network. Never serialized to
    /// config.json and never read by the launch path; gone on relaunch.
    /// `Zeroizing` wipes the password on drop (switch flipped back to
    /// persist-on, replaced with new text, or process exit).
    core_rpc_session_creds: HashMap<String, (String, Zeroizing<String>)>,
    /// U11 defense-in-depth: networks whose config.json node URL carried
    /// inline `user:pass@` userinfo when it was LOADED (a hand-edited,
    /// migrated, or pre-`on_set_node_custom`-stripping config) —
    /// `migrate_inline_node_creds` stashes the creds into
    /// `core_rpc_session_creds` at load time (safe: in-memory only) and
    /// records the network here; `flush_core_rpc_migration` (called from
    /// `refresh_node_health`, a Settings-only lazy point, NEVER the launch
    /// path) routes them to the Keychain if this network's "Save
    /// credentials" switch is on, exactly like a freshly typed credential.
    core_rpc_migrate_pending: std::collections::HashSet<String>,
    /// Device-level note-size limit (config.json). Some = the user chose
    /// one in Settings; applied to every notebook's store on activate, so
    /// the wallet-level Settings pill really is wallet-wide. None = each
    /// store keeps its own (legacy per-store value or the default).
    chunk: Option<usize>,
    /// nLockTime policy (anti-fee-sniping), device-level exactly like
    /// `chunk`: owned here + config.json, mirrored onto every store on
    /// activate so the Settings control is genuinely wallet-wide.
    lock_time_policy: app_core::notes_core::tx::LockTimePolicy,
    /// Per-tx locktime OVERRIDE set on the compose (screen 6) or sweep/
    /// consolidate (screen 16) collapsible panel — an override of
    /// `lock_time_policy` for THIS transaction only, never a replacement
    /// for it. `None` = use the device default; `Some(policy)` = the panel
    /// picked one. Reset to `None` every time either flow is (re)opened
    /// (`reset_tx_lock_time_override`), and NEVER written to config.json or
    /// any store — `State` itself isn't serialized, so this can't survive
    /// past the screen it was set on by construction, not by discipline.
    tx_lock_time_override: Option<app_core::notes_core::tx::LockTimePolicy>,
    ident: Option<AppIdentity>,
    store: Option<Store>,
    fees: Option<FeeRates>,
    usd: Option<f64>,
    /// Session cache stamp for [`refresh_fees_price`] (network-efficiency,
    /// 2026-07-23): `fees`/`usd` are only read by the fee-showing screens
    /// (compose/sweep/consolidate/pay-from/bump), not the scan path, so
    /// they're fetched lazily on those screens' open — this stamps WHEN,
    /// so a repeat open within ~60s is a free cache hit instead of another
    /// pair of requests. `None` = never fetched this session.
    fees_fetched_at: Option<std::time::Instant>,
    to_address: Option<String>, // None = self-note
    /// Multi-recipient directed notes: EXTRA recipient addresses beyond
    /// `to_address` (the compose screen's removable To-chips). Empty =
    /// today's ordinary single-recipient flow. Notebook-funded compose
    /// only (`pay_from == "notebook"`) — hidden/disabled for watch-only
    /// and for the spending/mixed/external funding paths (a later unit;
    /// see the PR description). Reset by `pick_contact_core` (a fresh
    /// primary pick starts a fresh recipient list) and on any compose-
    /// session reset.
    to_addresses_extra: Vec<String>,
    /// True while the send-to picker (screen 7) was opened via "+ Add
    /// recipient" on compose — `on_pick_contact` appends to
    /// `to_addresses_extra` instead of replacing the primary recipient,
    /// and Back returns to compose (screen 6) instead of home.
    picking_extra: bool,
    /// Post-quantum compose layers (screen 6 "Security" collapsible) —
    /// per-compose-session state, reset by `pick_contact_core` exactly
    /// like every other field on this list. `true` ONLY while the current
    /// `pq-passphrase-text` window text is exactly what
    /// `passphrase::generate` last produced for THIS session, unedited
    /// since (`on_pq_passphrase_changed` flips it false on any edit that
    /// doesn't match) — see `passphrase::SecurityChoice::passphrase_verified`'s
    /// doc for why an unverified estimate must never count.
    pq_passphrase_verified: bool,
    /// The last text `passphrase::generate()` produced this session, so
    /// `on_pq_passphrase_changed` can tell "still exactly the generated
    /// phrase" (stays verified) from "the user touched it" (reverts to
    /// unverified) without re-running generate or trusting the toggle
    /// alone. `None` before the first Generate tap this session.
    pq_passphrase_generated: Option<String>,
    /// Resolved recipient's ML-KEM display, cached by address so it's only
    /// reparsed when the recipient actually changes (parsing armor on
    /// every repaint would be wasted work — `pqkeys::contact_pq_display`'s
    /// own doc comment asks for this). Outer `Option` on the value =
    /// whether that contact has a key on file at all; inner `Result` =
    /// whether the stored armor parsed.
    pq_recipient_cache: Option<PqRecipientCacheEntry>,
    /// Settings → "Quantum keys" (screen 29): device-level default ML-KEM
    /// parameter level for THIS notebook's derived receive key
    /// (config.json "pq_level"). Absent config key (every pre-C2 config)
    /// => `MlKemLevel::DEFAULT` (768) — matches the compose Security
    /// section's own picker default. Distinct from the compose screen's
    /// per-note `pq-mlkem-enabled` toggle: this only picks WHICH level the
    /// Quantum keys screen shows/exports; compose always seals to whatever
    /// level the RECIPIENT's stored contact key declares.
    pq_level: app_core::passphrase::MlKemLevel,
    /// An externally IMPORTED ML-KEM secret key, cached in-session only —
    /// loaded from the `pq-imported` Keychain account ONLY when the user
    /// opens the Quantum keys screen or taps Unlock on a locked note
    /// (`ensure_pq_imported_loaded`; LAUNCH-PATH rule — never at boot or
    /// from a scan). `mlkem_secrets_for` appends its decapsulation secret
    /// to a notebook's own derived candidates so a scan/unlock can also
    /// open notes sealed to this imported key. Zeroized on drop
    /// (`MlKemKeypair`'s own `Drop`); `None` before the first load/import
    /// this session, or after "Remove imported key".
    pq_imported: Option<app_core::notes_core::pq::MlKemKeypair>,
    /// "My quantum key" replace guard (PLAN-graffito-quantum-key.md):
    /// Generate/Import over an EXISTING `pq_imported` key routes through a
    /// confirm modal instead of acting immediately — this remembers WHICH
    /// action to actually run once the user confirms
    /// (`on_pq_replace_confirm`), and is cleared on confirm or cancel. The
    /// pending action's own input (the generate level/extra fields, or the
    /// import text) stays live in the Slint UI properties across the round
    /// trip — nothing sensitive is stashed here.
    pq_pending_replace: Option<PqReplaceKind>,
    /// Coin control: selected inputs (display-txid, vout) for the compose
    /// in progress; `coins_overridden` = the user has touched the set (so
    /// stop auto-suggesting).
    selected_coins: Vec<(String, u32)>,
    coins_overridden: bool,
    /// Coin-suggestion strategy: false = fewest coins (largest-first),
    /// true = consolidate (smallest-first).
    consolidate_coins: bool,
    material: Option<Zeroizing<String>>, // session cache: avoids re-prompting Touch ID
    /// Bitcoin Core RPC ranged-watch descriptors (U7,
    /// `../PLAN-chain-notes-app-core-rpc.md` §2.2's "ranged descriptor
    /// import" finally gets a caller) for the ACTIVE (identity, account,
    /// network) — computed ONCE by `activate()` from `material` via
    /// `app_core::chain::identity_watch_descriptors` and cloned into every
    /// `open_client_watched` call from here, rather than re-derived (a
    /// handful of secp256k1 scalar multiplications each) on every one of
    /// `open_client`'s ~24 call sites. Empty for single-key (WIF/hex)
    /// material or when nothing is active — those addresses/identities are
    /// unaffected: `open_client_watched` degrades to the plain per-address
    /// `addr()` fallback exactly like `open_client` always has. Irrelevant
    /// (never read) for an Esplora backend.
    core_rpc_watch: Vec<app_core::chain::WatchDescriptor>,
    /// iCloud Keychain backup opt-in: when true the key is stored as a
    /// synchronizable Keychain item (syncs across the user's Apple devices and
    /// survives reinstall). Reflects the current stored item's sync state.
    icloud_backup: bool,
    /// First-run disclaimer accepted (config.json "terms_accepted"). When false
    /// the app opens on the accept gate (screen 24) before anything else.
    terms_accepted: bool,
    /// The user has opted into unlocking the saved key automatically
    /// (config.json "auto_unlock"). Set once they restore a saved key or save
    /// a new one; cleared by reset-identity. Even when true the unlock runs
    /// AFTER the first frame — never on the launch path, or the Face ID
    /// prompt blocks launch and the watchdog kills the app.
    auto_unlock: bool,
    /// A saved identity exists in the keychain (probed WITHOUT unlocking it).
    /// Drives onboarding's "Restore saved key" door.
    saved_key_present: bool,
    pending_import: Option<Zeroizing<String>>, // hierarchical import awaiting account pick
    pending_mnemonic: Option<String>,
    /// Dice rolls typed on screen 28. These ARE the seed for a dice
    /// identity, so they are held Zeroizing and never logged — only the
    /// count and the (public, on-screen) hash ever reach a log line.
    dice_rolls: Zeroizing<String>,
    /// Word count picked on the onboarding door, carried through screen 27.
    new_word_count: usize,
    quiz_indices: Vec<usize>,
    /// Edge-tracks whether the current compose draft is over the broadcast
    /// ceiling, so the "too large" dialog pops once on crossing — not on
    /// every keystroke while the draft stays too big.
    compose_oversize: bool,
    /// Last-logged sub-dust fold amount (0 sats) for the compose cost-line
    /// prediction — a last-value guard so `cb: compose-est fold=<S>` prints
    /// once per distinct value instead of on every keystroke while a fold
    /// keeps holding at the same figure (honest-fee-label feature,
    /// 2026-07-18).
    compose_fold_shown: u64,
    /// Last-logged (dust_to_self, fee) pair from the MIXED compose preview
    /// (`mixed_compose_ui`) — same last-value guard style as
    /// `compose_fold_shown`, so `cb: compose-est shape=mixed dust=<n>
    /// fee=<n>` prints once per distinct value instead of every keystroke.
    /// The e2e asserts this line's fee equals the confirm screen's
    /// byte-truth fee for the same compose (TestFlight build-20 fix,
    /// 2026-07-18).
    mixed_est_shown: Option<(u64, u64)>,
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
    /// Taproot CHANGE-chain coins (`m/86'/{coin}'/{account}'/1/{index}`,
    /// [`app_core::identity::realize_change`]) for the ACTIVE account —
    /// account-level (one change chain per account), not per-notebook.
    /// Gap-walked alongside every wallet-stores rescan
    /// ([`scan_change_chain`], gap 1 — external taproot wallets allocate
    /// change sequentially, so the app's own usage never leaves a gap) and
    /// folded into the Coins screen's unified coin list, each row tagged
    /// "change" (Sal's decision: ONE balance, not a separate segment —
    /// see `update_wallet_coins`). Empty for watch/WIF/hex identities
    /// (`scan_change_chain` is a no-op for non-hierarchical material).
    /// The wallet Sweep consumes these too (unit 4, see
    /// `../PLAN-chain-notes-app-taproot-change.md`): `build_sweep_confirm`
    /// derives each unique chain-1 index's owner via `realize_change` and
    /// folds its coins into the swept inputs, signed by that owner's own
    /// tweaked key — same own-coin discipline as notebook coins. Compose /
    /// pay-from ALSO consumes them now (unit 5): change coins fold into the
    /// Pay-from "Notebook" panel (tagged, `payfrom_panel_coins`), tracked
    /// under a DISTINCT `"change"` key in `mixed_selected` (their signing
    /// owner is per-index, unlike the notebook's one fixed leaf), and any
    /// selection containing one forces the mixed compose path
    /// (`payfrom_state`'s `PayfromShape::Mixed`) — see
    /// `mixed_compose_args`/`on_compose_send_mixed`. Watch-only still
    /// doesn't consume them (a later unit; `change_coins` is empty for
    /// watch material anyway, `realize_change` errors on it).
    change_coins: Vec<ChangeCoin>,
    /// The `(fp8, network, account)` context `change_coins` was last scanned
    /// under (taproot-change unit 7 fix). Change coins are ACCOUNT-level —
    /// shared by every notebook of the account — so `activate()` must NOT
    /// wipe them on a mere notebook switch within the SAME context (no
    /// wallet-stores rescan follows a plain notebook open, so a wipe left the
    /// compose Pay-from panel unable to offer change coins; the regtest e2e
    /// caught it). `activate()` clears `change_coins` only when this context
    /// changes; the wallet-stores apply stamps it whenever it repopulates.
    change_coins_ctx: Option<(String, Network, u32)>,
    /// Settings → "Sweep notebook funds here": the spending-wallet receive
    /// index the sweep destination was set to, so the broadcast handler
    /// can mark it used on success (fresh-address discipline). None for
    /// every other sweep destination.
    pending_spending_sweep_index: Option<u32>,
    /// Cross-wallet coin selection for the Pay-from screen (funding-
    /// unification UI rework, 2026-07-16): (source key, txid, vout). Source
    /// key uses the convention `pay_from`/`use-funding-wallet` already use:
    /// "notebook" | "spending" | "wallet:<id>" | "change" (taproot-change
    /// unit 5 — a chain-1 coin's owner is per-INDEX, unlike the notebook's
    /// one fixed leaf, so it gets its own key even though its rows render
    /// inside the SAME "Notebook" panel — see `payfrom_panel_coins`). A
    /// note may spend coins tagged with different source keys in ONE tx.
    /// This is a per-source MEMORY the existing single-source scratch state
    /// (`selected_coins`/`coins_overridden`) mirrors into/out of whenever
    /// the active source (`payfrom_active_source`) changes — so every
    /// existing single-source compute/send path keeps working on
    /// `selected_coins` unmodified, and re-expanding a previously-touched
    /// wallet row restores exactly what was selected there. "change" is
    /// NEVER mirrored into `selected_coins` (mirrors "wallet:<id>"'s
    /// treatment — see `on_toggle_coin`/`sync_and_finalize_payfrom`).
    mixed_selected: Vec<(String, String, u32)>,
    /// Which EXTERNAL WALLET row is expanded on the Pay-from screen — ""
    /// = none. Independent-expand rework (2026-07-18, Sal's iPhone
    /// feedback): Notebook/Spending got their own booleans below
    /// (`nb_expanded`/`sp_expanded`) that toggle without touching this or
    /// each other; external wallets stay an accordion AMONG THEMSELVES
    /// only (a pre-existing scope boundary — this app only ever keeps ONE
    /// external wallet's coins scanned/cached at a time, see
    /// `payfrom_wallet_coins`). A header tap here ONLY flips this string —
    /// it never selects/deselects coins or changes which source is the
    /// compose engine's active pay-from (`payfrom_active_source` below);
    /// that's `on_toggle_coin`'s job now, triggered by an actual coin tap.
    payfrom_expanded_source: String,
    /// Pay-from screen: is the Notebook section visually expanded?
    /// Independent of `sp_expanded`/`payfrom_expanded_source` — see the
    /// doc comment above. Re-derived (never persisted) every time the
    /// screen opens: every source holding a selected coin starts expanded.
    nb_expanded: bool,
    /// Pay-from screen: is the Spending-wallet section visually expanded?
    /// See `nb_expanded`.
    sp_expanded: bool,
    /// The compose engine's ACTIVE pay-from source — drives `pay_from`/
    /// `fund_external`/`spend_from_wallet` and which of `refresh_compose`'s
    /// three branches computes the live fee/change preview
    /// (`spend_coins`/`spend_title`/`spend_enough`/`cost_line`) that feeds
    /// the compose screen's compact row and the Pay-from screen's summary
    /// card. Renamed off `payfrom_expanded_source` in the independent-
    /// expand rework (2026-07-18): visibility and "active" are now two
    /// separate concerns — this only ever changes via `resolve_payfrom_default`
    /// (fresh compose session) or an explicit coin tap (`on_toggle_coin`),
    /// NEVER a mere header tap that only shows/hides a section.
    payfrom_active_source: String,
    /// Per-wallet coin cache for the Pay-from screen's independently-
    /// expandable external-wallet rows (2026-07-18 rework) — separate from
    /// `funding_coins`/`active_funding_id` (the SINGLE "real" active
    /// external source the compose/broadcast plumbing reads) so merely
    /// expanding a row to LOOK at a wallet can never clobber a DIFFERENT
    /// wallet's live selection. Populated by `payfrom_scan_wallet_for_display`
    /// on first expand; cleared at the start of every fresh compose session.
    payfrom_wallet_coins: std::collections::HashMap<String, Vec<FundingUtxo>>,
    /// Re-entrancy guard for `sync_and_finalize_payfrom`'s dispatch
    /// alignment (it re-runs `refresh_compose` once after switching the
    /// active source to match the verdict's shape — TestFlight-13 fix,
    /// 2026-07-18).
    payfrom_aligning: bool,
    /// Explicit change destination pick made this compose session (screen
    /// 21) — "" = unset, `app_core::mixed::resolve_change_default` applies.
    /// Never overridden by a refresh once chosen; cleared with the rest of
    /// the compose draft on open/broadcast.
    change_choice: String,
    /// Async sign+broadcast (2026-07-16): true while any of the three
    /// compose send paths (notebook/spending/mixed) has a build+broadcast
    /// in flight on a worker thread — re-entrancy guard so a double-tap on
    /// Sign can't double-broadcast, and drives the button's disabled
    /// "Signing…"/"Broadcasting…" state.
    compose_busy: bool,
    /// Activity screen (2026-07-16): the ref_id of a Rebroadcast/Speed-up
    /// currently in flight on a worker thread, if any — only that row's
    /// button shows the busy state and is disabled; other rows stay
    /// tappable. None when nothing is in flight.
    act_pending_ref: Option<String>,
    /// CHANGE 5 (activate()-spending-cache fix, 2026-07-17): true once the
    /// user has EXPLICITLY picked a "Pay from" source this compose session
    /// (the compact picker or the Pay-from screen's row tap) — guards a
    /// landed `spending_refresh_async` scan from yanking the default back
    /// to "spending" out from under a deliberate "notebook" pick. Reset to
    /// false at the start of every fresh compose session (`pick_contact_core`).
    payfrom_manual: bool,
    /// CHANGE 4 (async wallet-tx broadcast, 2026-07-17): true while a
    /// consolidate / sweep / wallet-consolidate / psbt-broadcast has a
    /// `client.broadcast()` in flight on a worker thread — re-entrancy
    /// guard so a double-tap can't double-broadcast (mirrors
    /// `compose_busy`, kept separate since the two never overlap but
    /// represent different flows).
    wallet_tx_busy: bool,
    /// Re-entrancy guard for `wallet_stores_refresh_async` — the Coins
    /// screen's and notebook-list's ↻ (TODO(watchdog) fix, 2026-07-20: both
    /// used to rescan every active notebook synchronously on the UI thread,
    /// same freeze class the auto-refresh timer had before it moved to
    /// `refresh_async`). True while a wallet-wide rescan is in flight on a
    /// worker thread; a second tap is ignored rather than queued (simpler
    /// than overlapping store-file writes) — see
    /// `apply_wallet_stores_refresh_results`'s own (fp8, network, account)
    /// staleness guard for the identity-switch-mid-scan case.
    /// Scan-freshness gate (2026-07-21, the stale-sign-window follow-up to
    /// the 429-politeness work): tracks in-flight notebook refreshes
    /// (`refresh_async`), spending-wallet scans (`spending_refresh_async`),
    /// and a wallet-wide stores refresh (`wallet_stores_refresh_async`) —
    /// the pure counter/flag bookkeeping lives in
    /// `app_core::scan_gate::ScanGate` (host-tested there), this field is
    /// just where `State` holds one. Incremented/set on the UI thread right
    /// before each worker spawn; decremented/cleared once per drained
    /// result in the apply half (BEFORE its staleness guard, so a
    /// stale-dropped result still releases its slot). Money-flow Sign
    /// buttons (compose + sweep/consolidate, screen 16) disable while
    /// `wallet-scan-busy` — signing against a mid-scan coin cache builds a
    /// tx that broadcasts into missing-inputs (loud + fund-safe, but
    /// user-hostile; the window grows as public-host pacing slows scans).
    /// Full serialization is the deferred network-operation-queue item in
    /// PLAN-chain-notes-app.md.
    scan_gate: app_core::scan_gate::ScanGate,
    /// The universal confirm screen (26) session in progress, if any — see
    /// [`PendingBroadcast`]. `show_confirm` sets it, `on_confirm_broadcast`
    /// consumes it, `on_confirm_cancel` drops it (leaving zero trace: stage
    /// A never mutates the store, so cancel is just a navigation).
    pending_broadcast: Option<PendingBroadcast>,
    /// DEVICE-LEVEL contacts (iCloud-contacts feature, 2026-07-20): ONE
    /// address book shared across every notebook/identity/network on this
    /// device — superseding the old per-notebook `Store.contacts` as the
    /// source of truth (that field stays on `Store` only for serde back-
    /// compat with existing store files; nothing reads it anymore).
    /// Persisted to `data_dir/contacts.json` (`save_contacts`) and mirrored
    /// to iCloud's `NSUbiquitousKeyValueStore` (`icloud.rs`) so it survives
    /// uninstall/reinstall and stays live across the user's iOS + Mac. Same
    /// recents rule as the old per-notebook list (front = latest use,
    /// dedupe by address) but a bigger cap (100) since this is now one
    /// list for the whole device. See `State::touch_contact`/
    /// `name_contact`/`remove_contact`/`save_contacts` and
    /// `load_or_migrate_contacts` (the one-time union-from-every-store
    /// migration for existing installs).
    contacts: Vec<app_core::store::Contact>,
    /// Tombstones for `(address, network)` contacts DELETED on this or
    /// another device (contacts-tombstones feature, 2026-07-20) — the
    /// synced record of "this was removed", so a device that still has an
    /// older copy of a deleted contact drops it on the next merge instead
    /// of resurrecting it. Together with `contacts` this is exactly the
    /// `app_core::contacts::ContactState` this device tracks; same
    /// persistence (`contacts.json`) and iCloud KV sync path as
    /// `contacts` — see that module's doc for the full merge design
    /// (wall-clock assumption, 90-day GC).
    tombstones: Vec<app_core::contacts::Tombstone>,
    /// Last-observed outcome of an iCloud contacts push (sync-status UI,
    /// 2026-07-20) — see `SyncStatus`. Interior mutability because
    /// `save_contacts` is `&self` (called from dozens of sites that only
    /// hold a shared borrow) but still needs to record the write's
    /// outcome; `Cell` is enough since `SyncStatus` is a plain `Copy` enum,
    /// no need for `RefCell`'s borrow machinery. Runtime-only: NOT
    /// serialized to `contacts.json` (a fresh boot always re-derives it —
    /// see `run()`'s init and `icloud::available()`).
    last_sync: std::cell::Cell<SyncStatus>,
}

/// Cap for the device-level contacts list — mirrors
/// `app_core::contacts::MERGE_CAP` (the iCloud merge cap); kept as its own
/// constant here since local mutations (touch/name) don't go through the
/// merge function.
const CONTACTS_CAP: usize = 100;

/// A build+sign result awaiting the user's explicit "Broadcast" tap on the
/// universal confirm screen (26). `raw_hex`/`txid` are the byte-truth of
/// the signed tx (already decoded once by `show_confirm`'s
/// `summarize_signed_tx` call — stage B doesn't re-derive them, just POSTs
/// `raw_hex`). `payload` carries exactly what each `kind` needs to finish:
/// record-then-broadcast for the notebook path, or (for every other path)
/// the same fields its pre-existing async broadcast thread already closed
/// over, now deferred from "right after Sign" to "right after Broadcast".
///
/// Cloned (not taken) out of `State` at the Broadcast tap — `on_psbt_broadcast`
/// (the "psbt" kind's stage B) reads `State.signed_psbt` directly and
/// manages its own retry, so leaving this in place lets a failed PSBT POST
/// be retried by tapping Broadcast again. Every other kind drops it
/// (`on_confirm_broadcast` sets `pending_broadcast = None` once stage B
/// fires): the notebook kind's record is one-shot (its existing failure
/// path redirects to Activity/Rebroadcast instead), and the spending/mixed
/// kinds' failure path returns to compose (screen 6, draft intact) to
/// rebuild rather than re-POST possibly-stale signed bytes.
#[derive(Clone)]
struct PendingBroadcast {
    kind: &'static str, // "compose" | "compose-spending" | "compose-mixed" | "psbt" |
    // "sweep" | "consolidate" | "wconsol" | "spending-consolidate" | "bump" | "rebroadcast"
    raw_hex: String,
    txid: String,
    vsize: usize,
    /// The confirm screen's one-liner caption (`confirm-context`), e.g.
    /// "Public note · testnet4" / "Sweep to bc1q…" — computed by the
    /// caller (it knows things `summarize_signed_tx`'s byte-truth view
    /// deliberately doesn't, like the human note-kind label) and just
    /// carried through by `show_confirm`.
    context: String,
    return_screen: Screen,
    payload: PendingPayload,
}

#[derive(Clone)]
enum PendingPayload {
    /// Notebook compose (`on_compose_send`'s keyed non-watch path): stage A
    /// built + signed via `compose::compose_note` (no store mutation).
    /// Stage B calls `compose::record_composed_note` + `save_store()` —
    /// exactly what `compose_and_record` used to do before its POST — then
    /// spawns the SAME broadcast worker pushing `NotebookComposeResult`.
    Compose {
        composed: app_core::compose::ComposedNote,
        text: String,
        private: bool,
        change_to: Option<String>,
        created_at: u64,
        to: Option<String>,
    },
    /// Spending-wallet-funded compose (`on_spending_compose_send`): already
    /// recorded nothing until broadcast success today, so stage B is just
    /// the pre-existing thread-spawn verbatim — this carries exactly the
    /// fields `SpendingComposeResult` needs minus `result`/`raw`/`txid`/
    /// `vsize` (those live on `PendingBroadcast` itself).
    ComposeSpending {
        text: String,
        private: bool,
        to: Option<String>,
        /// Multi-recipient (2+ only, empty for a self-note or an ordinary
        /// single-recipient directed note — same "empty means single"
        /// convention as `ComposedNote.recipients`/`NoteRecord.recipients`).
        recipients: Vec<String>,
        gift: u64,
        built_fee: u64,
        built_change: u64,
        spent_outpoints: Vec<(String, u32)>,
        change_index: u32,
        change_raw: String,
        source: FundingSource,
    },
    /// Mixed-source direct-broadcast compose (`on_compose_send_mixed`'s
    /// no-external-coin tail): same "nothing recorded until broadcast"
    /// shape as spending — stage B is the pre-existing thread-spawn
    /// verbatim.
    ComposeMixed {
        text: String,
        private: bool,
        to: Option<String>,
        /// Multi-recipient (2+ only) — see `ComposeSpending.recipients`.
        recipients: Vec<String>,
        gift: u64,
        built_fee: u64,
        built_change: u64,
        change_default: app_core::mixed::ChangeDefault,
        notebook_spent: Vec<app_core::store::OutPointRef>,
        spent_spending: Vec<(String, u32)>,
        /// Taproot CHANGE-chain coins ridden as inputs (unit 5, see
        /// `../PLAN-chain-notes-app-taproot-change.md`) — same shape+timing
        /// as `SweepSnapshot.change_spent`: pruned from `State.change_coins`
        /// on broadcast success only (`apply_mixed_compose_result`).
        change_spent: Vec<(String, u32)>,
        payloads_len: usize,
        /// Recipient OUTPUT count (0 = self-note, 1 = ordinary directed
        /// note, 2+ = multi) — drives the change-vout arithmetic in
        /// `apply_mixed_compose_result`; was a `bool` before multi-
        /// recipient support, renamed since "present" no longer captures
        /// how many slots the recipient outputs occupy.
        recipient_count: usize,
        change_index: u32,
        spending_source: Option<FundingSource>,
    },
    /// External-wallet-funded / watch-only signed-PSBT path
    /// (`set_confirm_from_psbt` + `on_psbt_broadcast`): every bookkeeping
    /// field this needs (`State.signed_psbt`/`built_psbt`/`watch_note`/
    /// `watch_spend`) already lives in `State` untouched by the confirm
    /// screen's navigation, so stage B is the pre-existing
    /// `on_psbt_broadcast` body verbatim — this variant carries nothing.
    Psbt,
    /// Wallet-level sweep (`on_sweep_send`'s keyed self-paid tail → the
    /// (removed) sweep-confirm modal used to trigger `on_sweep`, kind
    /// "sweep"): build+sign already ran in stage A; stage B is the
    /// pre-existing `SWEEP_BROADCAST_RESULTS` thread-spawn, moved
    /// verbatim.
    Sweep { snap: SweepSnapshot },
    /// Single-notebook consolidate (`on_sweep_send`'s keyed self-paid
    /// tail, kind "consolidate") — same shape as `Sweep`.
    Consolidate { snap: ConsolidateSnapshot },
    /// Wallet-level consolidate (account picker "wconsol" mode — picking
    /// the destination row IS the trigger now, kind "wconsol").
    WConsol { snap: WConsolSnapshot },
    /// Spending-wallet consolidate ("Consolidate spending coins…", kind
    /// "spending-consolidate").
    SpendingConsolidate { snap: SpendingConsolidateSnapshot },
    /// Activity Speed-up (`on_act_bump_confirm`, kind "bump") — stage A
    /// runs the PURE `bump_*_build` halves only (zero-trace cancel: the
    /// store still points at the ORIGINAL pending tx until Broadcast);
    /// stage B applies the matching `record_bumped_*` mutation +
    /// `save_store()` FIRST (record-before-POST, exactly like the
    /// notebook-compose arm), re-arms `act_pending_ref`, and spawns the
    /// SAME broadcast worker pushing `ActBumpResult`.
    Bump { ref_id: String, fee: u64, new_rate: f64, bumped: BumpedBuild },
    /// Activity Rebroadcast (`on_act_retry`, kind "rebroadcast") — stage A
    /// already resolved the raw hex (locally cached, or via a worker
    /// fetch for chain-recovered/watch records with none cached); stage B
    /// is the pre-existing broadcast thread-spawn pushing `ActRetryResult`.
    Rebroadcast { ref_id: String },
}

/// A Speed-up's signed-but-not-yet-recorded replacement, built by the pure
/// `app_core::compose::bump_*_build` halves at stage A and applied by the
/// matching `record_bumped_*` at stage B's Broadcast tap. A note bump
/// carries the full [`app_core::compose::ComposedNote`] (its record step
/// also swaps the ledger change UTXO); a sweep/consolidate bump needs only
/// the bare signed tx.
#[derive(Clone)]
enum BumpedBuild {
    Note(app_core::compose::ComposedNote),
    Tx(app_core::notes_core::tx::NoteTx),
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
    text: String,
    recipient: Option<String>,
    /// Multi-recipient (2+ only) — see `PendingPayload::ComposeSpending.
    /// recipients`. Covers every path that ends up on the shared PSBT sign
    /// screen with a note payload: `on_compose_send`'s watch branch
    /// (self-funded), `on_fund_build`'s watch branch (externally funded),
    /// and `on_compose_send_mixed`'s external-wallet branch (a keyed mixed
    /// compose that routes through this same screen).
    recipients: Vec<String>,
    gift: u64,
    chunks: usize,
    fee: u64,
    change: u64,
    spent: Vec<app_core::store::OutPointRef>,
    /// Funding-unification M3: `Some("wallet:<label>")` when an external
    /// funding wallet paid (Activity's source pill); `None` for a watch
    /// identity's own-coin self-funded compose. Funding-unification UI
    /// rework: `Some("mixed")` for a keyed mixed-source compose whose
    /// selection included an external wallet.
    funded: Option<String>,
    /// True for a genuine watch identity's compose (drives the broadcast
    /// log's `private=false`/`watch=1`, both hardcoded before this field
    /// existed). False for a keyed mixed-source compose routed through the
    /// same sign screen — those keep their real `private` flag.
    is_watch: bool,
    /// The real private/public flag — only meaningful when `is_watch` is
    /// false (a genuine watch compose is always public, unconditionally).
    private: bool,
    /// Whether the built tx carries a separate dust-to-self output BEFORE
    /// change (funding-unification UI rework's mixed builder always adds
    /// one; a watch identity's self-funded compose never does — it already
    /// spends from self) — shifts the change output's vout by one.
    dust_to_self: bool,
    /// Taproot CHANGE-chain coins (chain 1) ridden as inputs by a keyed
    /// mixed compose that ALSO pulled an external funding wallet (unit-5
    /// follow-up): the change inputs are signed in-app before this note is
    /// handed to the external signer, but — like `WatchSpend.change_spent`
    /// (unit 6) — they must be pruned from `State.change_coins` on broadcast
    /// success (`record_watch_note`), or the next compose would re-offer an
    /// already-spent coin until the next chain-1 rescan. Empty for a genuine
    /// watch identity's public-note compose (its coin control never offers
    /// change coins) and for any selection without a change coin.
    change_spent: Vec<(String, u32)>,
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
    /// (txid, vout) of any taproot CHANGE-chain (chain 1) coins riding as
    /// inputs (unit 6, see `../PLAN-chain-notes-app-taproot-change.md`) —
    /// pruned from `State.change_coins` on broadcast success, same
    /// treatment `SweepSnapshot.change_spent` gives the keyed sweep.
    /// Non-empty makes the record non-bumpable (mirrors keyed CHANGE 2's
    /// `mixed_inputs`): the bump reconstruction (`fetch_tx_io`'s
    /// address→index resolver) only knows NOTEBOOK addresses, so it can't
    /// safely re-derive a chain-1 leaf — see `watch_bump_open`.
    change_spent: Vec<(String, u32)>,
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

    /// Whether the "Save credentials" switch is ON for `network` — default
    /// true (an absent config key preserves today's unconditional-Keychain
    /// behavior; only an explicit `false` opts a network out). Plan §2.4 /
    /// U10. Delegates to the free function so the default-true rule is
    /// testable without constructing a `State`.
    fn core_rpc_should_persist(&self, network: Network) -> bool {
        core_rpc_persist_default_true(&self.core_rpc_save_creds, network.as_str())
    }

    fn save_store(&self) {
        if let (Some(s), Some(p)) = (&self.store, self.store_path()) {
            save_store_file(s, &p);
        }
    }

    /// Device-level contacts file (NOT per-identity — see `State.contacts`).
    fn contacts_path(&self) -> PathBuf {
        self.data_dir.join("contacts.json")
    }

    /// This device's full synced state (contacts + tombstones) — the
    /// `app_core::contacts::ContactState` `save_contacts`/the merge paths
    /// operate on.
    fn contact_state(&self) -> app_core::contacts::ContactState {
        app_core::contacts::ContactState {
            contacts: self.contacts.clone(),
            tombstones: self.tombstones.clone(),
        }
    }

    /// Persist `contacts.json` (contacts + tombstones) and mirror it into
    /// iCloud's KV store (a no-op off Apple platforms, or when the OS
    /// entitlement/iCloud account isn't available — see
    /// `icloud::save_blob`). Only WRITES the KV blob when this device's
    /// serialized state actually differs from what's already there, to
    /// avoid needless sync churn between two devices that just merged the
    /// same result.
    ///
    /// Sync-status UI (2026-07-20): every call stamps `self.last_sync` with
    /// what actually happened, since `synchronize()`'s `BOOL` is the only
    /// ground truth the OS gives us that a push reached iCloud (see
    /// `icloud::save_blob`'s doc). Three cases: (1) the blob changed and
    /// `save_blob` ran — its return value IS the verdict; (2) the blob
    /// changed but iCloud is simply unavailable (never reaches `save_blob`
    /// at all, same verdict either way); (3) the blob was UNCHANGED, so no
    /// write happens here at all — that's still a legitimate "in sync"
    /// state as long as iCloud is available, not an error, so it maps to
    /// `Ok`/`Failed` purely off `icloud::available()`.
    fn save_contacts(&self) {
        let state = self.contact_state();
        // LOCAL file keeps the FULL state (unchanged) — every contact, synced flag included.
        if let Ok(json) = serde_json::to_string_pretty(&state) {
            let _ = std::fs::write(self.contacts_path(), json);
        }
        // iCloud gets ONLY the opt-in subset (synced==true contacts + all tombstones).
        let synced = state.synced_only();
        let blob = app_core::contacts::serialize_contacts_blob(&synced);
        let status = if icloud::load_blob().as_deref() != Some(blob.as_str()) {
            let accepted = icloud::save_blob(&blob);
            println!("cb: icloud-contacts synced n={}", synced.contacts.len());
            accepted || icloud::available()
        } else {
            icloud::available()
        };
        self.last_sync.set(if status { SyncStatus::Ok } else { SyncStatus::Failed });
    }

    /// Device-level contacts, Prime rules: front = latest use, dedupe by
    /// (address, network), cap [`CONTACTS_CAP`]; naming does not bump
    /// recency. Same shape as the old per-notebook `Store::touch_contact`,
    /// just scoped to the whole device (and every network on it) now.
    ///
    /// Identity is (address, network), NOT address alone — testnet4 and
    /// signet share the `tb1…` HRP, so the same address string can be two
    /// genuinely different contacts. This always stamps the address with
    /// the ACTIVE network (`self.network`) at touch time. The existing-
    /// entry match is a bit looser than a strict tuple match, though: it
    /// also matches a LEGACY untagged entry (`network == ""`, from before
    /// this field shipped) for the same address, so touching an old
    /// contact again upgrades it in place (tags it, keeps its name) rather
    /// than leaving a stale blank-tagged duplicate beside a new one.
    ///
    /// Contacts-tombstones (2026-07-20): stamps `updated_at = now_ms()`
    /// and drops any tombstone for this `(address, network)` — re-adding/
    /// touching a contact is an intentional resurrection, and its fresh
    /// `updated_at` is by construction newer than any prior deletion, so
    /// the stale tombstone must not survive to fight the next merge.
    fn touch_contact(&mut self, address: &str) {
        let net = self.network.as_str().to_string();
        let existing = self
            .contacts
            .iter()
            .position(|c| c.address == address && (c.network == net || c.network.is_empty()))
            .map(|i| self.contacts.remove(i));
        let name = existing.as_ref().map(|c| c.name.clone()).unwrap_or_default();
        // Preserve the opt-in sync flag across a re-touch — recency bumps
        // must never silently flip a contact's iCloud-sync opt-in either
        // way. A brand-new contact defaults unsynced (serde-default).
        let synced = existing.as_ref().map(|c| c.synced).unwrap_or(false);
        // Preserve a contact's shared PQ key across a re-touch too — a
        // recency bump (e.g. picking them again in compose) must not lose
        // an ML-KEM key set via Contacts, exactly like `synced` above.
        let mlkem_ek = existing.as_ref().and_then(|c| c.mlkem_ek.clone());
        self.contacts.insert(
            0,
            app_core::store::Contact {
                address: address.to_string(),
                name,
                network: net.clone(),
                updated_at: now_ms(),
                synced,
                mlkem_ek,
            },
        );
        self.contacts.truncate(CONTACTS_CAP);
        self.tombstones
            .retain(|t| !(t.address == address && (t.network == net || t.network.is_empty())));
    }

    /// Same (address, network-or-legacy-blank) match as `touch_contact` —
    /// the rename dialog always opens from a network-filtered picker row,
    /// so "the entry this address means on the active network" is
    /// unambiguous even if the same address string also exists as a
    /// distinct contact on another network. Stamps `updated_at` and clears
    /// any tombstone, same reasoning as `touch_contact`.
    fn name_contact(&mut self, address: &str, name: &str, synced: bool) {
        let net = self.network.as_str().to_string();
        if let Some(c) = self
            .contacts
            .iter_mut()
            .find(|c| c.address == address && (c.network == net || c.network.is_empty()))
        {
            c.name = name.to_string();
            c.updated_at = now_ms();
            c.synced = synced;
        }
        self.tombstones
            .retain(|t| !(t.address == address && (t.network == net || t.network.is_empty())));
    }

    /// Same (address, network-or-legacy-blank) match as `touch_contact` —
    /// removes only the ACTIVE network's entry for this address, never a
    /// same-string contact that belongs to a different network.
    ///
    /// Contacts-tombstones (2026-07-20): deletion is now a first-class
    /// synced event, not just an absence — records/refreshes a
    /// `Tombstone { address, network: <active>, deleted_at: now_ms() }`
    /// so the other device drops its own (older) copy of this contact on
    /// the next merge instead of resurrecting it here. Re-deleting an
    /// already-tombstoned contact just bumps the timestamp (harmless,
    /// idempotent).
    fn remove_contact(&mut self, address: &str) {
        let net = self.network.as_str().to_string();
        self.contacts
            .retain(|c| !(c.address == address && (c.network == net || c.network.is_empty())));
        let now = now_ms();
        match self.tombstones.iter_mut().find(|t| t.address == address && t.network == net) {
            Some(t) => t.deleted_at = now,
            None => self.tombstones.push(app_core::contacts::Tombstone {
                address: address.to_string(),
                network: net,
                deleted_at: now,
            }),
        }
    }

    /// The `nLockTime` to build the next transaction with (anti-fee-sniping):
    /// the active store's policy resolved against the height it last scanned
    /// to. No store loaded (watch/PSBT flows before activate) falls back to 0,
    /// the same "we don't know a height" answer `LockTimePolicy::Tip` gives —
    /// never a guess, since a locktime in the FUTURE makes the transaction
    /// non-final and gets it rejected from the mempool.
    fn lock_time(&self) -> u32 {
        self.store.as_ref().map(|st| st.lock_time()).unwrap_or(0)
    }

    /// The resolved `nLockTime` override, if the compose/sweep panel set
    /// one THIS session — `None` when no override is active, meaning the
    /// caller should fall back to `lock_time()`. Resolved against the same
    /// tip `lock_time()` itself uses, so an override of `LockTimePolicy::Tip`
    /// (picking "Chain height" explicitly) behaves identically to leaving
    /// the device default alone.
    fn lock_time_override_value(&self) -> Option<u32> {
        self.tx_lock_time_override.map(|policy| {
            let tip = self.store.as_ref().and_then(|s| u32::try_from(s.tip_height).ok());
            policy.resolve(tip)
        })
    }

    /// The `nLockTime` THIS build should actually use: the per-tx override
    /// if the compose/sweep panel set one, else the device default
    /// (`lock_time()`) — every non-`ComposeRequest` builder call site
    /// (spending-wallet/mixed/watch compose, keyed + watch sweep/
    /// consolidate, watch bump) reads this instead of calling `lock_time()`
    /// directly, so the override reaches every path the panel is shown on.
    fn effective_lock_time(&self) -> u32 {
        self.lock_time_override_value().unwrap_or_else(|| self.lock_time())
    }

    /// Drop any per-tx locktime override — called every time a compose or
    /// sweep/consolidate flow is (re)opened, so the panel always starts
    /// from the device default and an override can never survive past the
    /// screen it was set on.
    fn reset_tx_lock_time_override(&mut self) {
        self.tx_lock_time_override = None;
    }

    /// The tip height to hand `ConfirmCtx.tip_height` — `None` when there's
    /// no store loaded OR it has never scanned (`tip_height == 0`, the
    /// fresh-`Store::new` default), same "never guess" filter
    /// `locktime_caption` already applies to its own caption. A confirm
    /// screen reached with a genuine tip of 0 is not realistically
    /// reachable (building a tx needs a scanned UTXO set first), so this
    /// only ever suppresses the warning on an honestly-unknown tip, never
    /// a real one.
    fn confirm_tip_height(&self) -> Option<u32> {
        self.store.as_ref().and_then(|s| u32::try_from(s.tip_height).ok()).filter(|h| *h > 0)
    }

    /// The exact `serde_json::Value` `save_config` writes to `config.json`
    /// — extracted to its own method (rather than inlined in `save_config`)
    /// so a test can assert on the REAL production payload instead of a
    /// hand-built mirror that can silently drift from it (U10 review fix:
    /// a mirror-based test kept passing after `save_config` was edited, in
    /// a review experiment, to leak `core_rpc_session_creds` in plaintext
    /// under a new key — see `core_rpc_settings_tests::
    /// config_payload_never_carries_session_credentials`). Deliberately
    /// does NOT take `core_rpc_session_creds` as a parameter anywhere in
    /// this list — the absence is what keeps it out.
    fn config_payload(&self) -> serde_json::Value {
        serde_json::json!({
            "network": self.network.as_str(),
            "account": self.account,
            "index": self.nb_index,
            "nodes": self.node_urls,
            "explorers": self.explorers,
            "core_rpc_save_creds": self.core_rpc_save_creds,
            "chunk": self.chunk,
            "terms_accepted": self.terms_accepted,
            "auto_unlock": self.auto_unlock,
            "locktime": self.lock_time_policy,
            "pq_level": self.pq_level,
        })
    }

    fn save_config(&self) {
        let _ = std::fs::write(self.data_dir.join("config.json"), self.config_payload().to_string());
    }

    /// Test-only full `State` builder — every field the config-payload
    /// tests don't care about gets the same inert default `run()`'s own
    /// boot literal uses (`None`/empty/`false`), so a fresh test `State`
    /// behaves like a just-booted app with no identity loaded. Only the
    /// fields `config_payload` (or a test wanting to poke at them) reads
    /// are parameters. Kept out of production builds entirely.
    #[cfg(test)]
    fn test_stub(
        network: Network,
        node_urls: HashMap<String, String>,
        explorers: HashMap<String, String>,
        core_rpc_save_creds: HashMap<String, bool>,
        core_rpc_session_creds: HashMap<String, (String, Zeroizing<String>)>,
    ) -> State {
        State {
            data_dir: PathBuf::new(),
            network,
            account: 0,
            nb_index: 0,
            node_urls,
            explorers,
            core_rpc_save_creds,
            core_rpc_session_creds,
            core_rpc_migrate_pending: std::collections::HashSet::new(),
            chunk: None,
            lock_time_policy: Default::default(),
            // Per-tx locktime override: always None in a stub. This builder
            // enumerates every `State` field on purpose, so a new field is a
            // COMPILE error here rather than a silently-defaulted one — which
            // is how this merge (per-tx locktime × the core-rpc config_payload
            // tests) surfaced at all.
            tx_lock_time_override: None,
            ident: None,
            store: None,
            fees: None,
            usd: None,
            fees_fetched_at: None,
            to_address: None,
            to_addresses_extra: Vec::new(),
            picking_extra: false,
            pq_passphrase_verified: false,
            pq_passphrase_generated: None,
            pq_recipient_cache: None,
            pq_level: app_core::passphrase::MlKemLevel::DEFAULT,
            pq_imported: None,
            pq_pending_replace: None,
            selected_coins: Vec::new(),
            coins_overridden: false,
            consolidate_coins: false,
            material: None,
            core_rpc_watch: Vec::new(),
            icloud_backup: false,
            terms_accepted: false,
            auto_unlock: false,
            saved_key_present: false,
            pending_import: None,
            pending_mnemonic: None,
            dice_rolls: Zeroizing::new(String::new()),
            new_word_count: 12,
            quiz_indices: Vec::new(),
            compose_oversize: false,
            compose_fold_shown: 0,
            mixed_est_shown: None,
            funding: None,
            funding_coins: Vec::new(),
            funding_change_index: 0,
            built_psbt: None,
            ur_frames: Vec::new(),
            signed_psbt: None,
            funding_wallets: Vec::new(),
            active_funding_id: None,
            watch_spend: None,
            watch_bump: None,
            watch_note: None,
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
            change_coins: Vec::new(),
            change_coins_ctx: None,
            pending_spending_sweep_index: None,
            mixed_selected: Vec::new(),
            payfrom_expanded_source: String::new(),
            nb_expanded: false,
            sp_expanded: false,
            payfrom_active_source: String::new(),
            payfrom_wallet_coins: std::collections::HashMap::new(),
            payfrom_aligning: false,
            change_choice: String::new(),
            compose_busy: false,
            act_pending_ref: None,
            payfrom_manual: false,
            wallet_tx_busy: false,
            scan_gate: app_core::scan_gate::ScanGate::new(),
            pending_broadcast: None,
            contacts: Vec::new(),
            tombstones: Vec::new(),
            last_sync: std::cell::Cell::new(SyncStatus::Unknown),
        }
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

    /// Persist a spending-wallet mutation to its ACCOUNT-level home
    /// (funding-unification M3.1): copy the active store's runtime
    /// `spending` cache into the notebooks index entry for the active
    /// account, then save it — so every OTHER notebook of the account
    /// picks up the change the next time it activates (they share ONE
    /// section; see `app_core::notebooks::SpendingSection`). Callers
    /// mutate `store.spending` via the usual `Store::spending_*` methods
    /// FIRST, then call this instead of (or beside) `save_store()`.
    fn save_spending(&mut self) {
        let Some(section) = self.store.as_ref().map(|s| s.spending.clone()) else { return };
        let account = self.account;
        if let Some(ix) = self.notebooks.as_mut() {
            ix.set_spending(account, section);
        }
        self.save_notebooks();
    }

    /// A notebook's display name: its local name, else the 1-based default
    /// "Notebook <index+1>" (never empty — rows and the home title read
    /// this). Every notebook is created named, so the fallback only covers
    /// entries written before that rule.
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
        app_core::notebooks::default_name(index)
    }

    /// The store file of another (not necessarily active) notebook.
    fn store_path_for(&self, address_output_x_fp8: &str) -> PathBuf {
        self.data_dir
            .join(format!("store-{}-{}.json", self.network.as_str(), address_output_x_fp8))
    }

pub(crate) fn activate(&mut self, material_str: &str, persist: bool) -> Result<(), String> {
    let st = self;
    let material =
        parse_key_material(material_str, st.network).map_err(|e| e.to_string())?;
    let ident =
        realize(&material, st.network, st.account, st.nb_index).map_err(|e| e.to_string())?;
    if persist {
        // Overwrites any existing entry — including one the user just chose to
        // ignore at the "Restore saved key" door. Safe by construction: the
        // two-phase write never leaves the device without a copy (audit H1).
        keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material_str.trim(), st.icloud_backup)?;
        // Saving a key IS the opt-in for automatic unlock, same as restoring
        // one — from here launches unlock on their own (after the first frame).
        st.saved_key_present = true;
        if !st.auto_unlock {
            st.auto_unlock = true;
            st.save_config(); // or the opt-in dies with the process
        }
    }
    st.material = Some(Zeroizing::new(material_str.trim().to_string()));
    // U7 (Bitcoin Core RPC ranged-watch wiring): (re)computed HERE, the
    // established choke point for every (identity, account, network)
    // change (boot, import, restore, network switch, account switch —
    // `activate()` is the sole place all of those funnel through), so the
    // account-level EC derivation this does runs once per such change
    // rather than on every one of `open_client_watched`'s call sites.
    // Cheap to always compute regardless of the active backend — it's only
    // READ when `open_client_watched` finds a Core transport underneath.
    st.core_rpc_watch =
        app_core::chain::identity_watch_descriptors(material_str.trim(), st.network, st.account);
    // Funding-unification M3: the spending wallet is per (identity,
    // account) — reset session state on every activate() (boot, network/
    // account switch, identity reset→reimport) and recompute capability
    // from the fresh material. Cheap: no chain call, just a key-type check.
    st.spending_capable = app_core::spending::can_derive_spending(&material);
    st.spending_source = None;
    st.spending_coins.clear();
    st.spending_scanned = false;
    // Taproot change-chain coins are per (identity, account, network) — but
    // UNLIKE the spending wallet above, they must survive a mere notebook
    // switch WITHIN the same context: they're account-level (shared by every
    // notebook of the account) and no wallet-stores rescan follows a plain
    // notebook open, so wiping them here left the compose Pay-from panel
    // unable to offer change coins (unit 7 regtest e2e caught this). Clear
    // ONLY when the (fp8, network, account) context actually changes — a
    // genuine identity/account/network switch; a same-context re-activation
    // keeps the last scan's coins until the next wallet-stores refresh
    // replaces them (its `(fp8,network,account)` staleness guard still drops
    // any result from the wrong context).
    let change_ctx = index_fp8(&material, st.network)
        .ok()
        .map(|fp8| (fp8, st.network, st.account));
    if st.change_coins_ctx != change_ctx {
        st.change_coins.clear();
        st.change_coins_ctx = None;
    }
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
    store.lock_time = st.lock_time_policy;
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
    //     leaf already has a store on disk) becomes notebook "Main"
    //     (the one notebook that does not take the default name);
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
    // Funding-unification M3.1: stamp the RUNTIME spending cache from the
    // ACCOUNT-level section in the notebooks index — every notebook of
    // this account (this one included) shares it, so re-activating any of
    // them always reads the same enabled flag / indexes / used list.
    store.spending = ix.spending_for(st.account);
    st.notebooks_fp8 = Some(fp8);
    st.notebooks = Some(ix);
    st.ident = Some(ident);
    st.store = Some(store);
    st.save_store();
    st.save_config();
    Ok(())
}

/// A (possibly inactive) notebook's store (by receive index within the
/// active account), read from its file on disk; the ACTIVE notebook
/// prefers the live in-memory store.
pub(crate) fn notebook_store(&self, index: u32) -> Option<Store> {
    let st = self;
    if st.ident.as_ref().map(|i| i.index) == Some(index) {
        if let Some(s) = &st.store {
            return Some(s.clone());
        }
    }
    let (_, _, fp8) = st.nb_addrs.iter().find(|(a, ..)| *a == index)?;
    Store::load(&st.store_path_for(fp8)).ok()
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























































































/// Which action is behind the "My quantum key" replace-guard confirm
/// (`State.pq_pending_replace`) — see that field's doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PqReplaceKind {
    Generate,
    Import,
}

























































































impl WalletStoresPurpose {
    fn label(self) -> &'static str {
        match self {
            WalletStoresPurpose::Coins => "refresh-coins",
            WalletStoresPurpose::Notebooks => "refresh-notebooks",
        }
    }
}













/// Result of the deferred auto-unlock, handed from its worker thread to the
/// UI thread via the `apply-pending-unlock` trampoline (same shape as
/// REFRESH_RESULTS / DISCOVERY_RESULTS).
static UNLOCK_RESULT: std::sync::Mutex<Option<Result<Option<String>, String>>> =
    std::sync::Mutex::new(None);
















// ---- CHANGE 4: async wallet-tx broadcast (2026-07-17) ----
//
// consolidate / sweep / wallet-consolidate / psbt-broadcast all build+sign
// synchronously (fast, no network) exactly as before; only the
// `client.broadcast()` POST moves to a worker thread — the part that used
// to visibly freeze the confirm button on a slow connection. Each flow's
// `apply_*_result` replays its EXACT pre-existing Ok/Err bookkeeping, once,
// from the worker's result, via the shared `apply-pending-wallet-tx`
// trampoline (`apply_pending_wallet_tx_results` drains every queue) — same
// shape as `apply_compose_results`. `State.wallet_tx_busy` is the shared
// re-entrancy guard; every entry point returns early when it's set.


































// ---- Async compose send (2026-07-16) ----
//
// Each of the three compose send paths (notebook / spending / mixed) builds
// + signs synchronously (fast, no network) exactly as before, then hands
// ONLY the `client.broadcast()` POST to a worker thread — the part that
// used to visibly freeze the Sign button on a slow connection. The UI-
// thread `apply_*_compose_result` functions replay each path's EXACT
// pre-existing Ok/Err bookkeeping, now run once from the worker's result via
// the shared `apply-pending-compose` trampoline (`apply_compose_results`
// drains all three). The external/watch/fund-external route is untouched —
// it already hands off to the sign screen instead of broadcasting itself.








































/// Automatic (non-deep) spending-wallet scan gap: the app hands out
/// spending addresses itself, sequentially, so its own usage has no gaps —
/// a small look-ahead past the last handed-out index is enough. See
/// [`SPENDING_GAP_DEEP`] for the manual fallback covering a seed that was
/// heavily used in ANOTHER BIP-84 wallet (gappy external usage a shallow
/// walk can't see).
const SPENDING_GAP_SHALLOW: u32 = 3;

/// Manual "Scan for existing funds…" deep scan gap — the same gap
/// `discover_indexes`/full notebook discovery use elsewhere in this file.
const SPENDING_GAP_DEEP: u32 = 20;

















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































// ---- Universal confirm screen (26) — infrastructure shared by every
// broadcast path (funding-unification follow-up, 2026-07-17). See
// `app_core::confirm` for the byte-truth summarizer this all feeds; the
// philosophy is the same here: every fact on screen 26 is decoded from the
// SIGNED raw tx about to hit the wire, never from the app's own intent.





/// Spending-self-notes fix window sizing (PLAN-chain-notes-app-spending-
/// self-notes.md, Unit A / RC1 — LOCKED decision 4): self-extending, no
/// magic cap. `WINDOW_MIN` is the floor for a fresh/lightly-used spending
/// wallet; `WINDOW_BUFFER` covers addresses handed out but not yet recorded
/// as `used` by THIS device (a scan that hasn't landed, or a disk-loaded
/// non-active store). Derivation is pure secp math (no network) — "generous"
/// is nearly free, computed ONCE per scan/apply pass (see call sites) and
/// reused across every notebook, never re-derived per notebook.
const SPENDING_WINDOW_MIN: u32 = 100;
const SPENDING_WINDOW_BUFFER: u32 = 50;





































/// Shared entry point. The desktop/iOS bin calls this from `fn main`;
/// the Android cdylib calls it from `android_main` after Slint's
/// android backend is initialized.
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--spike") {
        let result = match args.get(2).map(String::as_str) {
            Some("keychain") => keychain::spike(),
            Some("keychain-auth") => keychain::spike_auth(),
            // Crash-safe two-phase write (H1). The plain one is
            // automation-safe; `-auth` prompts and is human-run.
            #[cfg(target_vendor = "apple")]
            Some("keychain-atomic") => keychain::spike_atomic(),
            #[cfg(target_vendor = "apple")]
            Some("keychain-atomic-auth") => keychain::spike_atomic_auth(),
            #[cfg(target_vendor = "apple")]
            Some("file-protection") => platform::spike_file_protection(),
            #[cfg(target_os = "macos")]
            Some("clipboard") => platform::spike_clipboard(),
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
    // Screen names are the kebab-case `SCREENS` table entries.
    #[cfg(target_os = "macos")]
    {
        if args.get(1).map(String::as_str) == Some("--render") {
            let out_dir = args.get(2).cloned().unwrap_or_else(|| ".".into());
            let screens: Vec<Screen> = args
                .get(3)
                .map(|s| s.split(',').filter_map(|n| screen_by_name(n.trim())).collect())
                .unwrap_or_else(|| {
                    vec![Screen::Compose, Screen::FundingWallet, Screen::ExportPsbt, Screen::Confirm]
                });
            render_previews(480, 900, &screens, &out_dir);
            return;
        }
    }

    let st = boot::boot();
    let window = AppWindow::new().expect("window");
    // iCloud UI is Apple-only; Android's keystore is device-bound.
    window.global::<Ui>().set_apple_platform(cfg!(target_vendor = "apple"));
    window.global::<Ui>().set_desktop_platform(cfg!(target_os = "macos"));
    window.global::<Ui>().set_biometric_name(
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

    // Quantum keys (screen 29) level-picker captions — pinned copy from
    // `passphrase::MlKemLevel::describe()`, set once (never changes at
    // runtime, so no need to re-derive it on every screen open).
    window.global::<QuantumKeys>().set_pq_desc_512(app_core::passphrase::MlKemLevel::MlKem512.describe().into());
    window.global::<QuantumKeys>().set_pq_desc_768(app_core::passphrase::MlKemLevel::MlKem768.describe().into());
    window.global::<QuantumKeys>().set_pq_desc_1024(app_core::passphrase::MlKemLevel::MlKem1024.describe().into());

    // EditOps global wiring — src/editops.rs (U4, PLAN-graffito-app-arch.md).
    editops::wire(&window);

    // Boot identity: APP_KEY env (dev/tests) or the keychain.
    //
    // **THE LAUNCH PATH NEVER UNLOCKS THE KEYCHAIN.** `load_secret_protected`
    // on a UserPresence item makes the OS put up Face ID and BLOCKS this
    // thread until the user answers — on the launch path that is a hung
    // launch, and iOS kills the app (black screen → `0x8badf00d`). It is the
    // same rule the post-first-frame network sync below already follows, and
    // it is invisible under Xcode/devicectl because those relax the watchdog:
    // only a home-screen tap shows it. Reported from TestFlight on build 42
    // ("something is blocking a smooth launch, then it asked for Face ID"),
    // though the call has been on this path since 2026-07-09 — it stayed
    // hidden while iCloud backup was on, since a synced item carries no ACL
    // and so never prompts.
    //
    // So boot only PROBES (attributes only, no prompt). What happens next:
    //   - no saved key            → onboarding, exactly as before
    //   - saved key, auto_unlock  → unlock AFTER the first frame (deferred)
    //   - saved key, not opted in → onboarding shows the "Restore saved key"
    //                               door; Face ID fires on that TAP, which is
    //                               user-initiated and can't trip a watchdog
    {
        let mut s = st.borrow_mut();
        let material = match std::env::var("APP_KEY") {
            Ok(k) => Some(k),
            Err(_) => {
                // NOT EVEN A PROBE ON THIS THREAD. `identity_exists` looked
                // safe — attributes only, never kSecReturnData — and was not:
                // SecItemCopyMatching evaluates an item's access control to
                // decide whether it MATCHES, so a UserPresence item drags in
                // LAContext and blocks on XPC. That killed build 44 at launch,
                // in the very code added to stop build 42 doing the same
                // thing. `item_exists` now forbids the auth UI so it answers
                // immediately, but the probe ALSO moved off this thread:
                // after being wrong twice about what blocks, the launch path
                // gets to make no keychain calls at all.
                println!("cb: boot auto-unlock={}", u8::from(s.auto_unlock));
                None
            }
        };
        if let Some(m) = material {
            match s.activate(&m, false) {
                Ok(()) => {
                    // APP_KEY boots (automation, dev) name their notebook via
                    // APP_ACCOUNT/APP_INDEX/config — that's an explicit
                    // choice, so it counts as deliberate notebook creation.
                    // Keychain boots never auto-create: the index is whatever
                    // onboarding and the user left behind.
                    if std::env::var("APP_KEY").is_ok() {
                        let index = s.nb_index;
                        s.ensure_notebook(index);
                    }
                    // The notebook list is the main screen; the active
                    // notebook's home is one tap in.
                    s.update_home(&window);
                    s.update_notebook_list(&window);
                    window.global::<Ui>().set_screen(Screen::Notebooks);
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
                            let mut s = st_boot.borrow_mut();
                            s.refresh_async(&win);
                            // CHANGE 5: boot is an activate()-then-refresh
                            // site too — without this, the spending cache
                            // stays empty until something else triggers a
                            // scan (Settings, or opening compose).
                            s.spending_refresh_async(&win);
                        }
                    });
                }
                Err(e) => window.global::<Ui>().set_status(format!("stored key failed: {e}").into()),
            }
        } else if s.auto_unlock {
            // Opted in already, so don't ask again — but still AFTER the first
            // frame. "Automatic" must never mean "during launch": the Face ID
            // prompt blocks, and a user who looks away long enough would be
            // right back at the watchdog kill this whole change exists to fix.
            // OFF the main thread, and only after the first frame. Deferring
            // alone is NOT enough: the crash log for build 42 shows the
            // watchdog budget that ran out is `process-launch`, 20 s of WALL
            // CLOCK — so a main-thread Face ID prompt that the user is slow to
            // answer can still exhaust it even once the UI is up. On a worker
            // thread nothing the user does can block the main thread, so the
            // watchdog cannot fire no matter how long they take. (The system
            // presents the prompt itself; it needs nothing from us.) The
            // result comes back through UNLOCK_RESULT + `apply-pending-unlock`,
            // the same trampoline shape the async scans use.
            let w = window.as_weak();
            slint::Timer::single_shot(std::time::Duration::from_millis(700), move || {
                let weak = w.clone();
                std::thread::spawn(move || {
                    let r = keychain::load_secret_protected(
                        KEYCHAIN_ACCOUNT,
                        "unlock your Graffito identity",
                    );
                    *UNLOCK_RESULT.lock().expect("unlock result mutex") = Some(r);
                    let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_unlock());
                });
            });
        } else {
            // Not opted in: we still need to know whether to offer the
            // "Restore saved key" door — but off the main thread and after the
            // first frame, same reasoning. The door just appears a moment
            // after onboarding paints.
            let w = window.as_weak();
            slint::Timer::single_shot(std::time::Duration::from_millis(700), move || {
                let weak = w.clone();
                std::thread::spawn(move || {
                    let found = keychain::identity_exists(KEYCHAIN_ACCOUNT);
                    println!("cb: probe saved-key={}", u8::from(found));
                    // Window-only: no State borrow crosses the thread.
                    let _ = weak.upgrade_in_event_loop(move |w| w.global::<Onboarding>().set_saved_key_present(found));
                });
            });
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
        window.global::<Ui>().set_icloud_backup(s.icloud_backup);
        window.global::<Ui>().set_icloud_enabled(icloud_avail); // iCloud usable for new backups
    }

    // First-run disclaimer gate: before anything else, a fresh install (or an
    // upgrade that predates the gate) must accept the terms. The key/notebook
    // state was already loaded above, so accepting just reveals the screen the
    // boot would otherwise have shown (list if a key exists, else onboarding).
    window.global::<Terms>().set_disclaimer_body(DISCLAIMER.into());
    if !st.borrow().terms_accepted {
        window.global::<Ui>().set_terms_accept_mode(true);
        window.global::<Ui>().set_screen(Screen::Terms);
    }

    // System back (Android): the ui-side nav-back() already navigated; this
    // just emits the log-contract line (screen = where back landed us). No
    // state borrow — nav-back may have gone through a state-borrowing
    // callback (go-home etc.) synchronously before this fires.
    window.global::<Ui>().on_back_logged(|handled, screen| {
        println!("cb: sys-back handled={handled} screen={}", screen_name(screen));
    });

    macro_rules! cb {
        ($global:ident, $name:ident, |$w:ident, $s:ident $(, $arg:ident : $ty:ty)*| $body:block) => {{
            let st = st.clone();
            let weak = window.as_weak();
            window.global::<$global>().$name(move |$($arg : $ty),*| {
                // Not every callback body uses both the window handle and a
                // mutable state borrow — `#[allow]` here (once, at the
                // macro definition) rather than at each of the ~170 call
                // sites, which don't control whether their body needs `mut`.
                #[allow(unused_variables, unused_mut)]
                let $w = weak.unwrap();
                #[allow(unused_variables, unused_mut)]
                let mut $s = st.borrow_mut();
                $body
            });
        }};
    }

    // Onboarding's "Restore saved key" door. This is the ONLY place a user
    // meets the Face ID prompt for the stored key on a cold start, and it is
    // reached by a tap — so it can block for as long as it likes.
    // Written out rather than via cb!: that macro takes a State borrow for the
    // whole body, and this body sits on a Face ID prompt that can last as long
    // as the user does. Borrow only AFTER the prompt returns.
    {
        let st_restore = st.clone();
        let weak = window.as_weak();
        window.global::<Onboarding>().on_restore_saved_key(move || {
            let w = weak.unwrap();
            println!("cb: restore-saved-key");
            if let Some(m) = read_saved_material(&w) {
                let mut s = st_restore.borrow_mut();
                s.activate_restored(&w, m, true); // onboarding exit
            }
        });
    }

    cb!(Onboarding, on_door_import, |w, s| {
        println!("cb: door=import");
        w.global::<ImportKey>().set_import_feedback("".into());
        // Default the iCloud backup ON for the imported key when iCloud is
        // available (parity with create; the toggle stays user-overridable).
        let avail = keychain::icloud_available();
        s.icloud_backup = avail;
        w.global::<Ui>().set_icloud_backup(avail);
        w.global::<Ui>().set_icloud_enabled(avail);
        w.global::<Ui>().set_screen(Screen::ImportKey);
    });

    // Creating a seed is now TWO steps: this door only records the length and
    // opens the entropy-source screen (27). Generating immediately would deny
    // the user the one choice they may actually care about — where the
    // randomness came from.
    cb!(Onboarding, on_door_create, |w, s, words: i32| {
        println!("cb: door=create words={words}");
        s.new_word_count = words as usize;
        s.dice_rolls = Zeroizing::new(String::new());
        w.global::<Ui>().set_new_word_count(words);
        w.global::<BackupWords>().set_seed_from_dice(false);
        w.global::<Ui>().set_screen(Screen::EntropySource);
    });

    cb!(EntropySource, on_pick_entropy_source, |w, s, kind: SharedString| {
        let words = s.new_word_count;
        println!("cb: entropy-source {kind} words={words}");
        match kind.as_str() {
            "dice" => {
                // Deliberately does NOT reset the rolls: the back chevron on
                // the dice screen lands here, so wiping on entry meant a
                // mis-tap silently destroyed several minutes of rolling with
                // no warning and no undo. A fresh sequence starts at
                // `door_create` (a genuinely new seed) or via "Start over",
                // which now confirms.
                w.global::<BackupWords>().set_seed_from_dice(true);
                s.update_dice_ui(&w);
                w.global::<Ui>().set_screen(Screen::Dice);
            }
            _ => match generate_mnemonic(words) {
                Ok(m) => {
                    w.global::<BackupWords>().set_seed_from_dice(false);
                    s.stage_new_mnemonic(&w, m.to_string());
                }
                Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
            },
        }
    });

    cb!(Ui, on_dice_roll, |w, s, face: i32| {
        if (1..=6).contains(&face) {
            s.dice_rolls.push(char::from_digit(face as u32, 10).expect("1..=6 is a digit"));
            s.update_dice_ui(&w);
        }
    });

    cb!(Dice, on_dice_undo, |w, s| {
        s.dice_rolls.pop();
        s.update_dice_ui(&w);
    });

    cb!(Ui, on_dice_clear, |w, s| {
        s.dice_rolls = Zeroizing::new(String::new());
        println!("cb: dice-clear");
        s.update_dice_ui(&w);
    });

    cb!(Dice, on_dice_continue, |w, s| {
        let words = s.new_word_count;
        let rolls = s.dice_rolls.clone();
        match app_core::identity::mnemonic_from_dice(&rolls, words) {
            Ok(m) => {
                // Count + the (already on-screen, therefore non-secret) hash
                // only — never the rolls, which are the seed itself.
                println!(
                    "cb: dice-continue rolls={} words={words} entropy={}",
                    rolls.len(),
                    hex::encode(
                        &app_core::identity::dice_entropy(&rolls).unwrap_or([0u8; 32])[..4]
                    )
                );
                s.stage_new_mnemonic(&w, m.to_string());
                // The rolls ARE the seed, so drop them the moment the mnemonic
                // exists — holding them for the rest of the session would keep
                // a second copy of the secret in memory for no reason. Nothing
                // can navigate back to the dice screen from here (back on the
                // words screen goes to onboarding), so there is nothing to
                // preserve them for.
                s.dice_rolls = Zeroizing::new(String::new());
            }
            Err(e) => {
                println!("cb: dice-continue err");
                w.global::<Ui>().set_status(format!("{e}").into());
            }
        }
    });

    // "New words" (↻) on the backup screen: reroll a fresh mnemonic of the same
    // length, in case the user didn't like the ones shown.
    cb!(BackupWords, on_regenerate_words, |w, s| {
        let count = s
            .pending_mnemonic
            .as_ref()
            .map(|m| m.split(' ').count())
            .unwrap_or(12);
        let salt = w.global::<BackupWords>().get_entropy_salt().to_string();
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
                w.global::<Ui>().set_backup_words(grid.into());
                s.pending_mnemonic = Some(phrase);
            }
            Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
        }
    });

    // iCloud backup toggle (backup screen + Settings). Sets the sync mode; if a
    // key is already stored this session, re-stores it with the new mode.
    cb!(Ui, on_set_icloud_backup, |w, s, enabled: bool| {
        s.icloud_backup = enabled;
        println!("cb: set-icloud-backup {enabled}");
        if let Some(material) = s.material.clone() {
            match keychain::store_secret_protected(KEYCHAIN_ACCOUNT, material.trim(), enabled) {
                Ok(()) => {
                    // Re-stored under a new sync mode — still a saved key.
                    s.saved_key_present = true;
                    w.global::<Onboarding>().set_saved_key_present(true);
                    w.global::<Ui>().set_status(
                        if enabled { "iCloud backup on" } else { "iCloud backup off" }.into(),
                    );
                }
                Err(e) => {
                    w.global::<Ui>().set_status(format!("iCloud: {e}").into());
                    s.icloud_backup = !enabled;
                    w.global::<Ui>().set_icloud_backup(!enabled);
                }
            }
        }
    });

    // Funding-unification M3: "Separate spending wallet" toggle. Persisted
    // per (identity, account) — M3.1: in the notebooks index, shared by
    // every notebook of the account — survives restarts, resets to off on
    // a fresh identity.
    cb!(Settings, on_set_spending_enabled, |w, s, on: bool| {
        println!("cb: set-spending enabled={on}");
        if let Some(store) = s.store.as_mut() {
            store.spending_set_enabled(on);
        }
        s.save_spending();
        s.update_spending_ui(&w);
        if on && !s.spending_scanned {
            s.spending_refresh_async(&w);
        }
    });

    cb!(Settings, on_spending_refresh, |w, s| {
        s.spending_refresh_async(&w);
    });

    // "Scan for existing funds…" manual deep scan (network-efficiency
    // follow-up): gap-20 full discovery for a seed used elsewhere with gaps
    // the shallow automatic scan wouldn't reach.
    cb!(Coins, on_spending_scan_deep, |w, s| {
        s.spending_scan_deep_async(&w);
    });

    // (`on_restore_icloud` lived here until 2026-07-26. A synced key is a
    // saved key — the same `load_secret_protected` call behind the same
    // onboarding door — so the separate handler only duplicated the door and
    // left different state behind. See `activate_restored`.)

    cb!(BackupWords, on_backup_continue, |w, s| {
        let Some(phrase) = s.pending_mnemonic.clone() else { return };
        let count = phrase.split(' ').count();
        let mut idx = [0u8; 3];
        // `idx` is NOT key material — it only selects which 3 of the
        // already-generated words the backup quiz asks the user to
        // retype. A failure here still leaves a valid (if predictable,
        // zeroed) selection, so we log and carry on rather than fail the
        // backup flow or reach for a fallback RNG.
        if getrandom_fill(&mut idx).is_err() {
            println!("cb: backup-quiz entropy err");
        }
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
        w.global::<Quiz>().set_quiz_prompt(
            format!(
                "Type words #{}, #{} and #{} (space separated):",
                picks[0] + 1,
                picks[1] + 1,
                picks[2] + 1
            )
            .into(),
        );
        s.quiz_indices = picks;
        w.global::<Quiz>().set_quiz_answer("".into());
        w.global::<Ui>().set_screen(Screen::Quiz);
    });

    cb!(Quiz, on_quiz_submit, |w, s, answer: SharedString| {
        let Some(phrase) = s.pending_mnemonic.clone() else { return };
        let words: Vec<&str> = phrase.split(' ').collect();
        let expect: Vec<&str> = s.quiz_indices.iter().map(|i| words[*i]).collect();
        let got: Vec<String> =
            answer.split_whitespace().map(|x| x.to_lowercase()).collect();
        let ok = got == expect;
        println!("cb: quiz ok={ok}");
        if !ok {
            w.global::<Ui>().set_status("mismatch — check your written words and try again".into());
            return;
        }
        // A freshly created seed is a NEW identity — start at account 0, never
        // inheriting a persisted account from a previous identity (Sal
        // 2026-07-22; config.account survives an identity reset).
        s.account = 0;
        s.nb_index = 0;
        match s.activate(&phrase, true) {
            Ok(()) => {
                s.pending_mnemonic = None;
                w.global::<Ui>().set_status("".into());
                // Onboarding unification (Sal 2026-07-21, superseding the
                // 2026-07-11 empty-list rule): creating a seed behaves
                // exactly like importing one — the account's notebook 0
                // (the FIRST receive address) is created, auto-named
                // "Notebook 1", and the notebook LIST opens. More
                // notebooks are added from the list later; unwanted ones
                // archive.
                s.ensure_first_onboarded_notebook();
                s.update_notebook_list(&w);
                w.global::<Ui>().set_screen(Screen::Notebooks);
                s.refresh_async(&w);
                s.spending_refresh_async(&w); // CHANGE 5
            }
            Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
        }
    });

    cb!(ImportKey, on_import_changed, |w, s, text: SharedString| {
        let t = text.trim().to_string();
        if t.is_empty() {
            w.global::<ImportKey>().set_import_feedback("".into());
            w.global::<ImportKey>().set_import_suggestions("".into());
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
        w.global::<ImportKey>().set_import_suggestions(sugg.into());
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
        w.global::<ImportKey>().set_import_feedback_ok(ok);
        w.global::<ImportKey>().set_import_feedback(fb.into());
    });

    cb!(ImportKey, on_import_confirm, |w, s, text: SharedString| {
        // Sal 2026-07-22: a SEED (hierarchical: mnemonic/xprv) no longer
        // branches into the account picker — it activates account 0 directly,
        // auto-creates its first notebook, and lands on the notebook LIST.
        // Single-key imports (WIF/hex) are unchanged: activate() adds their one
        // intrinsic notebook and they land on its home.
        let hierarchical = parse_key_material(text.trim(), s.network).is_ok()
            && is_hierarchical(text.trim(), s.network);
        s.account = 0;
        s.nb_index = 0;
        match s.activate(text.trim(), true) {
            Ok(()) => {
                println!("cb: import ok");
                w.global::<ImportKey>().set_import_text("".into());
                if hierarchical {
                    s.ensure_first_onboarded_notebook();
                    s.update_notebook_list(&w);
                    w.global::<Ui>().set_screen(Screen::Notebooks);
                    s.refresh_async(&w);
                    s.spending_refresh_async(&w);
                } else {
                    w.global::<Ui>().set_screen(Screen::Home);
                    s.update_home(&w);
                    s.refresh_async(&w);
                }
            }
            Err(e) => {
                println!("cb: import err={e}");
                w.global::<ImportKey>().set_import_feedback_ok(false);
                w.global::<ImportKey>().set_import_feedback(e.to_string().into());
            }
        }
    });

    // Shared cancel flag for every "Scan QR" path (set by the overlay's Cancel).
    let scan_cancel = Arc::new(AtomicBool::new(false));
    {
        let sc = scan_cancel.clone();
        let weak = window.as_weak();
        window.global::<Ui>().on_cancel_scan(move || {
            sc.store(true, Ordering::Relaxed);
            if let Some(w) = weak.upgrade() {
                w.global::<Ui>().set_scanning(false);
            }
        });
    }
    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.global::<ImportKey>().on_import_scan(move || {
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
                    w.global::<Ui>().set_scanning(false);
                    if !text.is_empty() {
                        println!("cb: import-scan ok len={}", text.len());
                        w.global::<ImportKey>().set_import_text(text.clone().into());
                        w.global::<ImportKey>().invoke_import_changed(text.into());
                    } else {
                        w.global::<ImportKey>().set_import_feedback_ok(false);
                        w.global::<ImportKey>().set_import_feedback("scan: no QR seen".into());
                    }
                });
            });
        });
    }

    // Paste from the system clipboard — Slint's iOS text fields don't surface
    // the native paste menu, so this reads UIPasteboard directly. Deferred to
    // the event loop so import-changed re-runs without a State double-borrow.
    cb!(ImportKey, on_paste_import, |w, s| {
        let _ = &mut s;
        match platform::clipboard_text() {
            Some(text) => {
                let _ = w.as_weak().upgrade_in_event_loop(move |w| {
                    w.global::<ImportKey>().set_import_text(text.clone().into());
                    w.global::<ImportKey>().invoke_import_changed(text.into());
                });
            }
            None => {
                w.global::<ImportKey>().set_import_feedback_ok(false);
                w.global::<ImportKey>().set_import_feedback("clipboard empty".into());
            }
        }
    });

    // Paste into the compose note (appends clipboard to the current text).
    cb!(Ui, on_paste_compose, |w, s| {
        let _ = &mut s;
        if let Some(text) = platform::clipboard_text() {
            let combined = format!("{}{}", w.global::<Compose>().get_compose_text(), text);
            let _ = w.as_weak().upgrade_in_event_loop(move |w| {
                w.global::<Compose>().set_compose_text(combined.clone().into());
                w.global::<Ui>().invoke_compose_changed();
            });
        }
    });

    cb!(ImportKey, on_import_file, |w, s| {
        let _ = &mut s;
        if let Some(path) = platform::pick_file(&[]) {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    println!("cb: import-file len={}", text.trim().len());
                    w.global::<ImportKey>().set_import_text(text.trim().into());
                    w.global::<ImportKey>().invoke_import_changed(text.trim().into());
                }
                Err(e) => {
                    w.global::<ImportKey>().set_import_feedback_ok(false);
                    w.global::<ImportKey>().set_import_feedback(format!("file: {e}").into());
                }
            }
        }
    });

    cb!(Ui, on_refresh, |w, s| {
        s.refresh_async(&w);
    });

    // Trampoline: a finished background scan invokes this from the event
    // loop; the UI thread applies it with full State access.
    cb!(Ui, on_apply_pending_refresh, |w, s| {
        s.apply_refresh_results(&w);
    });

    // Trampoline: an async compose send (notebook/spending/mixed) finished
    // building+broadcasting on a worker thread.
    cb!(Ui, on_apply_pending_compose, |w, s| {
        s.apply_compose_results(&w);
    });

    // Trampoline: an Activity Rebroadcast finished on a worker thread.
    cb!(Ui, on_apply_pending_act_retry, |w, s| {
        s.apply_act_retry_results(&w);
    });

    // Trampoline: `on_act_retry`'s sub-case (b) raw-hex fetch (chain-
    // recovered/watch record, no local hex) landed on a worker thread.
    cb!(Ui, on_apply_pending_rebroadcast_fetch, |w, s| {
        s.apply_pending_rebroadcast_fetch_results(&w);
    });

    // Trampoline: an Activity Speed-up (RBF) broadcast finished on a worker
    // thread (the re-sign itself stays synchronous — fast, no network; only
    // the broadcast POST is async).
    cb!(Ui, on_apply_pending_act_bump, |w, s| {
        s.apply_act_bump_results(&w);
    });

    // Trampoline: an async consolidate/sweep/wallet-consolidate/psbt
    // broadcast (CHANGE 4) finished on a worker thread.
    cb!(Ui, on_apply_pending_wallet_tx, |w, s| {
        s.apply_pending_wallet_tx_results(&w);
    });

    // Trampoline: a finished spending-wallet scan (funding-unification M3)
    // landed — same pattern as apply-pending-refresh.
    cb!(Ui, on_apply_pending_spending_refresh, |w, s| {
        s.apply_spending_refresh_results(&w);
    });

    // Trampoline: a finished wallet-wide rescan (Coins screen / notebook-
    // list ↻, watchdog fix 2026-07-20) landed — same pattern as
    // apply-pending-refresh.
    cb!(Ui, on_apply_pending_wallet_stores_refresh, |w, s| {
        s.apply_wallet_stores_refresh_results(&w);
    });

    // Trampoline: an iCloud KV notification (a contacts change synced in
    // from the user's OTHER device) landed — re-merge the freshly-synced
    // blob into the live device-level contacts list and refresh the
    // picker so the change appears without restarting the app.
    cb!(Ui, on_apply_pending_icloud_contacts, |w, s| {
        s.apply_icloud_contacts_merge(&w);
    });

    // Trampoline: worker-thread used/new probes for the create-notebook
    // picker landed — fill in the pills/balances without having blocked the
    // tap. Guarded by account/page/screen so a stale probe (user paged or
    // left) is dropped.
    cb!(Ui, on_apply_pending_picker_probe, |w, s| {
        let results: Vec<PickerProbeResult> =
            PICKER_PROBE_RESULTS.lock().expect("picker probe mutex").drain(..).collect();
        for r in results {
            if s.account != r.account
                || w.global::<AccountPicker>().get_account_page() != r.page as i32
                || w.global::<Ui>().get_screen() != Screen::AccountPicker
            {
                println!("cb: picker-probe stale-drop");
                continue;
            }
            let model = w.global::<AccountPicker>().get_accounts();
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

    // Trampoline: a finished Bitcoin Core preflight check (`refresh_node_health`).
    // Dropped when stale — the network or the configured node changed since
    // the check started (e.g. the user switched networks, or edited the
    // node URL again before the first check returned).
    cb!(Ui, on_apply_pending_node_health, |w, s| {
        let results: Vec<NodeHealthResult> =
            NODE_HEALTH_RESULTS.lock().expect("node health mutex").drain(..).collect();
        for r in results {
            if s.network != r.network || s.base_url().as_deref() != Some(r.base.as_str()) {
                println!("cb: node-health stale-drop");
                continue;
            }
            w.global::<Settings>().set_node_health_text(r.text);
            w.global::<Ui>().set_node_health_warn(r.warn);
        }
    });

    // Trampoline: a finished notebook gap-discovery walk (seed re-import).
    // Discovery is the sanctioned exception to deliberate notebook
    // creation — every found index has on-chain history, so recovering it
    // is what the user meant by importing the seed.
    // Deferred auto-unlock landed. Mirrors read_saved_material's error
    // handling, but on the UI thread with the result already in hand.
    cb!(Ui, on_apply_pending_unlock, |w, s| {
        let taken = UNLOCK_RESULT.lock().expect("unlock result mutex").take();
        match taken {
            // Boot path, not onboarding: never create a notebook here.
            Some(Ok(Some(m))) => s.activate_restored(&w, m, false),
            Some(Ok(None)) => {
                println!("cb: unlock none");
                s.saved_key_present = false;
                w.global::<Onboarding>().set_saved_key_present(false);
            }
            // Both failure branches REVEAL the door. The auto-unlock branch
            // never runs the `identity_exists` probe (it went straight for the
            // key), so `saved_key_present` is still false here — and the status
            // line tells the user to "tap Restore" on a door that isn't
            // rendered. We know an item exists: that is why we tried to unlock
            // it. (Until 2026-07-26 the separate "Restore from iCloud" door
            // accidentally covered this, but only for a SYNCED key.)
            Some(Err(e)) if e == "cancelled" => {
                // Left on onboarding with the door there, so a mis-tapped or
                // timed-out prompt is one tap from retrying.
                println!("cb: unlock cancelled");
                s.saved_key_present = true;
                w.global::<Onboarding>().set_saved_key_present(true);
                w.global::<Ui>().set_status("unlock cancelled — tap Restore to try again".into());
            }
            Some(Err(e)) => {
                println!("cb: unlock err={e}");
                s.saved_key_present = true;
                w.global::<Onboarding>().set_saved_key_present(true);
                w.global::<Ui>().set_status(format!("keychain: {e}").into());
            }
            None => {}
        }
    });

    cb!(Ui, on_apply_pending_discovery, |w, s| {
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
                    s.ensure_notebook(*index);
                    added += 1;
                }
            }
            println!("cb: notebook-discovery found={} added={added}", r.found.len());
            if added > 0 {
                s.update_notebook_list(&w);
            }
        }
    });

    cb!(Home, on_open_note, |w, s, id: SharedString| {
        let Some(store) = &s.store else { return };
        if let Some(n) = store.notes.iter().find(|n| n.note_id.as_str() == id.as_str()) {
            println!("cb: open-note id={} status={:?}", n.note_id, n.status);
            let watch = s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
            // PLAN-pnte-redesign.md: the note id IS the txid now (64 hex
            // chars, not the old synthetic hex8) — the inline "id:" quick-
            // view line shows just the first 8 chars, same footprint as
            // before; the full id is still available verbatim via the
            // "Copy text" button (copies this whole block) and the
            // dedicated "Copy txid" button (`note-txid`, set below).
            let detail = format_note_detail(n, watch, None);
            w.global::<Note>().set_note_detail(detail.into());
            w.global::<Ui>().set_note_view_id(n.note_id.clone().into());
            w.global::<Note>().set_note_pending(n.status == NoteStatus::Pending && n.raw_hex.is_some());
            w.global::<Note>().set_note_txid(n.txids.last().cloned().unwrap_or_default().into());
            refresh_note_unlock_ui(&w, n);
            // Reply-all set ({sender} ∪ recipients minus me) — meaningful
            // for both a received note (sender + other recipients) and an
            // OWN directed note (a shortcut to write the same people again;
            // Sal 2026-07-19). Self-notes have an empty set → no buttons.
            let my_addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
            let full_set = n.reply_set(&my_addr);
            // Reply = the single counterparty: the sender of a received note,
            // or the sole recipient of an own single-recipient directed note.
            // An own multi-recipient note has no single counterparty — it
            // gets Reply all only.
            let reply_addr = if n.received {
                n.sender.clone().unwrap_or_default()
            } else if full_set.len() == 1 {
                full_set[0].clone()
            } else {
                String::new()
            };
            w.global::<Note>().set_note_reply_address(reply_addr.into());
            let reply_rows: Vec<ContactItem> = full_set
                .iter()
                .map(|a| {
                    let name = s
                        .contacts
                        .iter()
                        .find(|c| &c.address == a && !c.name.is_empty())
                        .map(|c| c.name.clone())
                        .unwrap_or_default();
                    ContactItem { address: a.clone().into(), name: name.into(), synced: false, sync_status: 0, pq: false }
                })
                .collect();
            w.global::<Note>().set_note_reply_set(VecModel::from_slice(&reply_rows));
            let web = match s.network {
                Network::Regtest => String::new(),
                net => {
                    let addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
                    format!(
                        "https://byteapps.com/graffito/companion/note.html?address={addr}&network={}&note={}",
                        net.as_str(),
                        n.note_id
                    )
                }
            };
            w.global::<Note>().set_note_web_url(web.into());
            w.global::<Ui>().set_screen(Screen::Note);
        }
    });

    // Screen 5's "Unlock" tap. Never logs the typed passphrase — only
    // ok/err, matching the `cb:` log contract's "no secrets in logs" rule.
    cb!(Note, on_unlock_note, |w, s| {
        // User-initiated tap — the LAUNCH-PATH rule's other sanctioned door
        // (besides opening the Quantum keys screen, and — since
        // PLAN-graffito-self-pw.md — the Security panel's own header tap)
        // for loading an imported ML-KEM secret from the Keychain this
        // session. Runs before the borrows below so it never conflicts
        // with them.
        s.ensure_pq_imported_loaded();
        let note_id = w.global::<Ui>().get_note_view_id().to_string();
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        let identity = identity.clone_fields();
        let password = w.global::<Note>().get_note_unlock_passphrase().to_string();
        w.global::<Note>().set_note_unlock_busy(true);

        // A SELF-note's locked body goes through the VIEW-ONLY path
        // (PLAN-graffito-self-pw.md): `unlock_note`/`unlock_sent` refuse it
        // outright (`is_self()` discriminates in notes-core), so this check
        // must happen before picking which store fn to call at all.
        let is_self = s
            .store
            .as_ref()
            .and_then(|store| store.notes.iter().find(|n| n.note_id == note_id))
            .and_then(|n| n.locked.as_ref())
            .map(app_core::notes_core::pq::LockedBody::is_self)
            .unwrap_or(false);

        if is_self {
            // View-only: NEVER persisted, and `locked` never clears — every
            // future open asks again (the whole point of the second
            // factor). `unlock_note_view` takes `&self`, so nothing here
            // mutates the store — no `save_store()`, unlike the directed
            // path below.
            let mlkem_secret = s.pq_imported.as_ref().map(|kp| kp.secret());
            let result = match s.store.as_ref() {
                Some(store) => store.unlock_note_view(
                    &note_id,
                    &identity,
                    mlkem_secret.as_ref(),
                    Some(password.as_str()),
                ),
                None => Err(app_core::Error::Store("no store".into())),
            };
            w.global::<Note>().set_note_unlock_busy(false);
            match result {
                Ok(text) => {
                    println!("cb: unlock-note ok view-only");
                    let watch = s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
                    if let Some(n) =
                        s.store.as_ref().and_then(|store| store.notes.iter().find(|n| n.note_id == note_id))
                    {
                        let detail = format_note_detail(n, watch, Some(text.as_str()));
                        w.global::<Note>().set_note_detail(detail.into());
                    }
                    w.global::<Ui>().set_note_locked(false);
                    w.global::<Note>().set_note_unlock_needs_password(false);
                    w.global::<Ui>().set_note_unlock_show_button(false);
                    w.global::<Ui>().set_note_unlock_caption("".into());
                    w.global::<Note>().set_note_unlock_passphrase("".into());
                }
                Err(e) => {
                    println!("cb: unlock-note err={e}");
                    w.global::<Ui>().set_status(format!("couldn't unlock: {e}").into());
                }
            }
            return;
        }

        let secrets = mlkem_secrets_for(s.ident.as_ref().unwrap(), s.pq_imported.as_ref());
        let result = match s.store.as_mut() {
            Some(store) => store.unlock_note(&note_id, &identity, &secrets, Some(password.as_str())),
            None => Err(app_core::Error::Store("no store".into())),
        };
        w.global::<Note>().set_note_unlock_busy(false);
        match result {
            Ok(_text) => {
                println!("cb: unlock-note ok");
                s.save_store();
                s.update_home(&w);
                w.global::<Home>().invoke_open_note(note_id.into());
            }
            Err(e) => {
                println!("cb: unlock-note err={e}");
                w.global::<Ui>().set_status(format!("couldn't unlock: {e}").into());
            }
        }
    });

    cb!(Note, on_open_note_web, |w, s| {
        let _ = &mut s;
        let url = w.global::<Note>().get_note_web_url().to_string();
        if url.is_empty() {
            return;
        }
        println!("cb: open-note-web url={url}");
        let _ = platform::open_url(&url);
    });

    cb!(Ui, on_copy_text, |w, s, kind: SharedString, text: SharedString| {
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

    cb!(Compose, on_set_fee_tier, |w, s, tier: i32| {
        let f = s.fees.clone().unwrap_or_default();
        let rate = match tier {
            0 => f.economy,
            2 => f.fastest,
            _ => f.hour,
        }
        .max(1.0);
        w.global::<Compose>().set_fee_tier(tier);
        // Custom (tier 3, also reached by editing the always-visible rate
        // box) keeps whatever the field already holds — Rust never
        // overwrites it while tier == 3 (same rule as sweep's
        // on_set_sweep_tier), so auto-selecting custom on edit can't fight
        // the user's typing.
        if tier != 3 {
            w.global::<Compose>().set_rate_text(format!("{rate}").into());
        }
        println!("cb: fee-tier {tier} rate={rate}");
        s.refresh_compose(&w);
    });

    cb!(Settings, on_open_coins, |w, s| {
        println!("cb: open-coins");
        s.update_home(&w);
        s.update_spending_ui(&w);
        if w.global::<Ui>().get_coins_segment() == "spending" && s.spending_capable && !s.spending_scanned {
            s.spending_refresh_async(&w);
        }
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::Coins);
    });

    // Coins screen "spending" segment: scan on first view (data otherwise
    // stays "as of the last scan", matching the notebook segment's rule).
    cb!(Ui, on_set_coins_segment, |w, s, seg: SharedString| {
        w.global::<Ui>().set_coins_segment(seg.clone());
        if seg.as_str() == "spending" && s.spending_capable && !s.spending_scanned {
            s.spending_refresh_async(&w);
        }
    });

    cb!(Ui, on_open_activity, |w, s| {
        println!("cb: open-activity");
        w.global::<Ui>().set_return_screen(if w.global::<Ui>().get_screen() == Screen::Notebooks { Screen::Notebooks } else { Screen::Home });
        s.update_activity(&w);
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::Activity);
    });

    // Universal confirm screen (2026-07-17): stage A resolves the raw hex
    // (locally cached, or fetched) and hands off to screen 26 —
    // `act_pending_ref` is no longer set here for the broadcast itself
    // (moved to stage B, `on_confirm_broadcast`/`PendingPayload::
    // Rebroadcast`, mirroring `on_act_bump_confirm` below); it's only
    // touched transiently to guard sub-case (b)'s own network fetch
    // against a double-tap, cleared the moment the fetch result lands.
    cb!(Ui, on_act_retry, |w, s, ref_id: SharedString, is_note: bool| {
        if s.act_pending_ref.is_some() || s.wallet_tx_busy || s.pending_broadcast.is_some() {
            return;
        }
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
        let ref_id_s = ref_id.to_string();
        if let Some(r) = raw.filter(|r| !r.is_empty()) {
            // Case (a): raw hex cached locally — summarize + show_confirm
            // right now, no network round trip needed.
            s.enter_rebroadcast_confirm(&w, ref_id_s, is_note, r);
            return;
        }
        // Case (b): chain-recovered record (watch mode, or any record with
        // no cached hex) — the node that already knows the tx is the
        // keyless rebroadcast source. Never block the UI thread on the
        // fetch; land on the confirm screen from the fetch-result
        // trampoline (mirrors `spending_refresh_async`).
        let Some(base) = s.base_url() else {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let net = s.network;
        let identity_addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
        let creds = s.core_rpc_creds_for(&base, net);
        s.act_pending_ref = Some(ref_id_s.clone());
        s.update_activity(&w);
        let weak = w.as_weak();
        std::thread::spawn(move || {
            let _net_guard = NetOpGuard::new(weak.clone());
            let client = open_client(&base, net, creds).map_err(|e| e.to_string());
            let result = last_txid
                .ok_or_else(|| "nothing to rebroadcast".to_string())
                .and_then(|t| client.and_then(|c| c.fetch_tx_hex(&t).map_err(|e| format!("{e}"))));
            REBROADCAST_FETCH_RESULTS.lock().expect("rebroadcast fetch results mutex").push(
                RebroadcastFetchResult { ref_id: ref_id_s, is_note, identity_addr, result },
            );
            let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_rebroadcast_fetch());
        });
    });

    cb!(Activity, on_act_bump_open, |w, s, ref_id: SharedString, is_note: bool| {
        // The bump dialog prices off `st.fees.fastest` — lazily (re)fetch
        // before either branch below reads it (network-efficiency,
        // 2026-07-23). `watch_bump_open` also calls this — the 60s cache
        // makes the second call here-or-there free either way.
        s.refresh_fees_price(&w);
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            s.watch_bump_open(&w, ref_id.to_string(), is_note);
            return;
        }
        let Some(store) = &s.store else { return };
        // CHANGE 2 defense-in-depth: the UI already hides Speed-up for a
        // mixed record (`ActivityItem.bumpable`), but refuse here too
        // rather than trust the tap origin.
        if !is_note && store.txs.iter().any(|t| t.txids.iter().any(|x| x == ref_id.as_str()) && t.mixed_inputs) {
            w.global::<Ui>().set_status("this sweep mixed notebook + spending coins — it can't be sped up (rebroadcast still works)".into());
            return;
        }
        let Some((old_rate, fee, vsize)) = tx_rate(store, ref_id.as_str(), is_note) else {
            w.global::<Ui>().set_status("can't determine current fee rate".into());
            return;
        };
        // BIP-125: the replacement must add at least 1 sat/vB (incremental
        // relay) over the original, and pay a strictly higher total fee.
        let min_rate = old_rate + 1.0;
        let fast = s.fees.as_ref().map(|f| f.fastest).unwrap_or(min_rate);
        let recommended = fast.max(min_rate);
        println!("cb: bump-open ref={ref_id} old={old_rate:.1} min={min_rate:.1}");
        w.global::<Ui>().set_bump_ref(ref_id.clone());
        w.global::<Ui>().set_bump_is_note(is_note);
        w.global::<Modals>().set_bump_kind(if is_note { "Note transaction" } else { "Sweep / consolidate" }.into());
        w.global::<Modals>().set_bump_current(format!("Currently {old_rate:.1} sat/vB · {fee} sats fee").into());
        w.global::<Modals>().set_bump_min(format!("Minimum {min_rate:.1} sat/vB — RBF must add ≥1 sat/vB.").into());
        w.global::<Modals>().set_bump_error("".into());
        w.global::<Modals>().set_bump_rate(format!("{recommended:.1}").into());
        w.global::<Modals>().set_bump_new_fee(new_fee_line(recommended, vsize, fee).into());
        w.global::<Ui>().set_show_bump_dialog(true);
    });

    cb!(Modals, on_act_bump_rate_changed, |w, s, rate_s: SharedString| {
        let ref_id = w.global::<Ui>().get_bump_ref().to_string();
        let is_note = w.global::<Ui>().get_bump_is_note();
        if let Some(wb) =
            s.watch_bump.as_ref().filter(|wb| wb.ref_id == ref_id && wb.is_note == is_note)
        {
            match rate_s.trim().parse::<f64>() {
                Ok(r) if r > 0.0 => w.global::<Modals>().set_bump_new_fee(new_fee_line(r, wb.vsize, wb.old_fee).into()),
                _ => w.global::<Modals>().set_bump_new_fee("".into()),
            }
            return;
        }
        let Some((_, old_fee, vsize)) = s.store.as_ref().and_then(|st| tx_rate(st, &ref_id, is_note))
        else {
            return;
        };
        match rate_s.trim().parse::<f64>() {
            Ok(r) if r > 0.0 => w.global::<Modals>().set_bump_new_fee(new_fee_line(r, vsize, old_fee).into()),
            _ => w.global::<Modals>().set_bump_new_fee("".into()),
        }
    });

    // Universal confirm screen (2026-07-17): the dialog stays for rate
    // entry only — its primary button ("Sign…") now BUILDS + SIGNS the
    // replacement (stage A) and hands off to screen 26 instead of
    // broadcasting directly. `act_pending_ref` moves to stage B
    // (`on_confirm_broadcast`/`PendingPayload::Bump`, the actual
    // broadcast POST) — NOT set here, so it must never gate stage A;
    // `pending_broadcast`/`wallet_tx_busy` are the re-entrancy guard for
    // the build+navigate step instead.
    cb!(Modals, on_act_bump_confirm, |w, s| {
        if s.act_pending_ref.is_some() || s.wallet_tx_busy || s.pending_broadcast.is_some() {
            return;
        }
        let ref_id = w.global::<Ui>().get_bump_ref().to_string();
        let is_note = w.global::<Ui>().get_bump_is_note();
        let Ok(new_rate) = w.global::<Modals>().get_bump_rate().trim().parse::<f64>() else {
            w.global::<Modals>().set_bump_error("enter a number".into());
            return;
        };
        let net = s.network;
        if s.base_url().is_none() {
            w.global::<Modals>().set_bump_error("no Bitcoin node — set one in Settings".into());
            return;
        }
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            s.watch_bump_confirm(&w, new_rate);
            return;
        }
        // CHANGE 2 defense-in-depth (see on_act_bump_open).
        if !is_note
            && s.store.as_ref().map(|st| st.txs.iter().any(|t| t.txids.iter().any(|x| x == &ref_id) && t.mixed_inputs)).unwrap_or(false)
        {
            w.global::<Modals>().set_bump_error("this sweep mixed notebook + spending coins — it can't be sped up".into());
            return;
        }
        let min_rate = match s.store.as_ref().and_then(|st| tx_rate(st, &ref_id, is_note)) {
            Some((old_rate, _, _)) => old_rate + 1.0,
            None => {
                w.global::<Modals>().set_bump_error("transaction no longer pending".into());
                return;
            }
        };
        if new_rate + 1e-9 < min_rate {
            w.global::<Modals>().set_bump_error(format!("below the {min_rate:.1} sat/vB minimum").into());
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.global::<Modals>().set_bump_error("no identity".into());
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
        // PURE builds only (zero-trace cancel): the store is not touched
        // — no txid append, no fee/raw_hex update, no ledger swap, no
        // save — until the Broadcast tap runs `record_bumped_*` in stage
        // B. Cancel on screen 26 leaves the original pending tx exactly
        // as it was.
        let result: Result<BumpedBuild, app_core::Error> = if is_note {
            app_core::compose::bump_fee_build(
                s.store.as_ref().unwrap(),
                &identity,
                net,
                &ref_id,
                new_rate,
                None, // device default — no override control on the bump dialog
            )
            .map(BumpedBuild::Note)
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
                app_core::compose::bump_raw_tx_multi_build(
                    s.store.as_ref().unwrap(),
                    &idents,
                    &ref_id,
                    new_rate,
                    None, // device default — no override control on the bump dialog
                )
                .map(BumpedBuild::Tx)
            })
        } else {
            app_core::compose::bump_raw_tx_build(
                s.store.as_ref().unwrap(),
                &identity,
                &ref_id,
                new_rate,
                None, // device default — no override control on the bump dialog
            )
            .map(BumpedBuild::Tx)
        };
        match result {
            Ok(bumped) => {
                let (raw, txid, fee, vsize) = match &bumped {
                    BumpedBuild::Note(c) => {
                        (c.tx.raw_hex.clone(), c.tx.txid_hex.clone(), c.tx.fee, c.tx.vsize)
                    }
                    BumpedBuild::Tx(tx) => {
                        (tx.raw_hex.clone(), tx.txid_hex.clone(), tx.fee, tx.vsize)
                    }
                };
                // NOTHING is recorded or saved here — hand the signed
                // replacement to the universal confirm screen; stage B
                // (`on_confirm_broadcast`) applies `record_bumped_*` +
                // `save_store()` at the Broadcast tap, re-arms
                // `act_pending_ref` right before the POST, and spawns the
                // SAME worker pushing `ActBumpResult`.
                w.global::<Ui>().set_show_bump_dialog(false);
                let prevouts = s.stored_record_prevouts(&ref_id, is_note);
                let expected_change = s.stored_record_expected_change(&ref_id, is_note);
                let (self_spks, spending_spks) = s.confirm_self_spks();
                let ctx = app_core::confirm::ConfirmCtx {
                    network: app_core::derive::btc_network(net),
                    prevouts,
                    self_spks,
                    spending_spks,
                    expected_change,
                    recipient: None,
                    recipient_name: None,
                    recipients: Vec::new(),
                    note_preview: None,
                    tip_height: s.confirm_tip_height(),
                };
                let pending = PendingBroadcast {
                    kind: "bump",
                    raw_hex: raw,
                    txid,
                    vsize,
                    context: format!("Speed-up · {}", net.as_str()),
                    return_screen: Screen::Activity, // overwritten by show_confirm
                    payload: PendingPayload::Bump { ref_id: ref_id.clone(), fee, new_rate, bumped },
                };
                s.show_confirm(&w, pending, ctx);
            }
            Err(e) => {
                println!("cb: act-bump ref={ref_id} err={e}");
                w.global::<Modals>().set_bump_error(format!("{e}").into());
            }
        }
    });

    cb!(Ui, on_act_explorer, |w, s, url: SharedString| {
        let _ = &mut s;
        if url.is_empty() {
            return;
        }
        println!("cb: act-explorer");
        let _ = platform::open_url(url.as_str());
    });

    cb!(Settings, on_open_source, |w, s| {
        let _ = (&w, &mut s);
        println!("cb: open-source");
        let _ = platform::open_url(SOURCE_URL);
    });

    cb!(Home, on_open_note_web_url, |w, s, url: SharedString| {
        let _ = &mut s;
        if url.is_empty() {
            return;
        }
        println!("cb: open-note-web-url");
        let _ = platform::open_url(url.as_str());
    });

    cb!(Home, on_compose_open, |w, s| {
        println!("cb: compose-open");
        w.global::<Ui>().set_pick_mode("compose".into());
        s.pull_icloud_contacts_on_open(&w);
        w.global::<Ui>().set_contact_input("".into());
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::Contacts);
    });

    // Send-to picker header "Sync now" (sync-status UI, 2026-07-20).
    cb!(Contacts, on_sync_contacts_now, |w, s| {
        s.sync_contacts_now(&w);
    });

    cb!(Settings, on_sweep_open, |w, s| {
        println!("cb: sweep-open");
        // The send-to picker's sweep entry lands on screen 16 (fee tiers
        // shown) once a destination is picked — lazily (re)fetch here so
        // it's ready by then (network-efficiency, 2026-07-23).
        s.refresh_fees_price(&w);
        s.pending_spending_sweep_index = None; // a fresh manual pick, not the spending-wallet shortcut
        // A wallet sweep's inputs include spending-wallet coins — ALWAYS kick
        // a fresh scan here (not just when never-scanned). A prior scan can be
        // stale: coins may have arrived since, or gap-discovery may not have
        // reached the funded index yet, which showed ONLY notebook coins in
        // the sweep preview until the user backed out and re-entered. The scan
        // runs while the user is on the picker; apply_spending_refresh_results
        // repaints screen 16 with the spending coins when it lands.
        if s.spending_capable
            && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false)
        {
            s.spending_refresh_async(&w);
        }
        w.global::<Ui>().set_sweep_kind("sweep".into());
        w.global::<Ui>().set_pick_mode("sweep".into());
        s.pull_icloud_contacts_on_open(&w);
        w.global::<Ui>().set_contact_input("".into());
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::Contacts);
    });

    // Funding-unification M3: Settings spending-wallet card "Sweep notebook
    // funds here…" — routes through the EXISTING sweep flow (screen 7 →
    // 16), just pre-picking the destination = the spending wallet's next
    // receive address. `pending_spending_sweep_index` tells on_sweep's
    // success handler to mark that address used (fresh-address discipline).
    cb!(Settings, on_spending_sweep_here, |w, s| {
        s.ensure_spending_source();
        let Some(src) = s.spending_source.clone() else {
            w.global::<Ui>().set_status("spending wallet unavailable for this identity".into());
            return;
        };
        let Some(idx) = s.store.as_ref().map(|st| st.spending.next_receive) else { return };
        let Ok(d) = src.derive(0, idx) else { return };
        s.pending_spending_sweep_index = Some(idx);
        w.global::<Ui>().set_sweep_kind("sweep".into());
        w.global::<Ui>().set_pick_mode("sweep".into());
        s.set_sweep_dest(&w, d.address);
    });

    // CHANGE 3 (2026-07-17) / universal confirm screen follow-up: the
    // Coins screen's spending segment "Consolidate spending coins…"
    // button IS the trigger now (the confirm modal is gone) — build +
    // sign the all-P2WPKH merge directly (byte-exact mixed estimator, one
    // P2WPKH output at the next fresh spending receive address) and hand
    // off to the universal confirm screen. Stage B
    // (`on_confirm_broadcast`/`PendingPayload::SpendingConsolidate`) is
    // the pre-existing thread-spawn, moved verbatim.
    cb!(Coins, on_spending_consolidate_open, |w, s| {
        if s.wallet_tx_busy || s.pending_broadcast.is_some() {
            return;
        }
        // The fee rate used to build this tx comes from `s.fees.hour`
        // below — lazily (re)fetch first (network-efficiency, 2026-07-23).
        s.refresh_fees_price(&w);
        s.ensure_spending_source();
        let Some(src) = s.spending_source.clone() else {
            w.global::<Ui>().set_status("spending wallet unavailable for this identity".into());
            return;
        };
        let coins = s.spending_coins.clone();
        if coins.len() < 2 {
            w.global::<Ui>().set_status("nothing to consolidate (need 2+ spending coins)".into());
            return;
        }
        if s.base_url().is_none() {
            w.global::<Ui>().set_status("no Bitcoin node for this network — set one in Settings".into());
            return;
        }
        let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        let net = s.network;
        let Ok(material) = parse_key_material(&material_str, net) else { return };
        let Some(next_receive) = s.store.as_ref().map(|st| st.spending.next_receive) else { return };
        let Ok(dest) = src.derive(0, next_receive) else {
            w.global::<Ui>().set_status("couldn't derive the destination address".into());
            return;
        };
        let rate = s.fees.as_ref().map(|f| f.hour).unwrap_or(1.0).max(1.0);
        let account = s.account;
        // Deliberately the device default, not `effective_lock_time()`:
        // this is the Coins screen's direct "Consolidate spending coins…"
        // shortcut, not compose (6) or sweep/consolidate (16) — nothing
        // resets the per-tx override before it runs (see
        // `build_wconsol_confirm`'s doc comment for the same reasoning).
        let built = app_core::mixed::build_wallet_sweep_mixed(
            &[],
            Some((&material, net, account, &coins)),
            dest.spk.clone(),
            rate,
            s.lock_time(),
        );
        match built {
            Ok(tx) => {
                let spent: Vec<(String, u32, u64)> =
                    coins.iter().map(|c| (c.txid.clone(), c.vout, c.value)).collect();
                let snap = SpendingConsolidateSnapshot {
                    fp8: s.notebooks_fp8.clone().unwrap_or_default(),
                    network: net,
                    account,
                    dest_index: next_receive,
                    dest_addr: dest.address.clone(),
                    dest_spk_hex: hex::encode(&dest.spk),
                    value: tx.tx.outputs[0].value,
                    fee: tx.fee,
                    vsize: tx.vsize as u64,
                    raw_hex: tx.raw_hex.clone(),
                    spent,
                };
                let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
                for c in &coins {
                    prevouts.insert(
                        format!("{}:{}", c.txid, c.vout),
                        app_core::confirm::PrevoutInfo {
                            value: c.value,
                            address: Some(c.address.clone()),
                            source: "Spending wallet".to_string(),
                        },
                    );
                }
                let (mut self_spks, mut spending_spks) = s.confirm_self_spks();
                // Fresh spending receive address, not yet "used" bookkeeping
                // — push its spk on top so it classifies "self".
                self_spks.push(dest.spk.clone());
                spending_spks.push(dest.spk.clone());
                let ctx = app_core::confirm::ConfirmCtx {
                    network: app_core::derive::btc_network(net),
                    prevouts,
                    self_spks,
                    spending_spks,
                    expected_change: None,
                    recipient: None,
                    recipient_name: None,
                    recipients: Vec::new(),
                    note_preview: None,
                    tip_height: s.confirm_tip_height(),
                };
                let pending = PendingBroadcast {
                    kind: "spending-consolidate",
                    raw_hex: tx.raw_hex.clone(),
                    txid: tx.txid_hex.clone(),
                    vsize: tx.vsize,
                    context: format!("Consolidate spending coins · {}", net.as_str()),
                    return_screen: Screen::Coins, // overwritten by show_confirm
                    payload: PendingPayload::SpendingConsolidate { snap },
                };
                s.show_confirm(&w, pending, ctx);
            }
            Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
        }
    });

    cb!(Ui, on_consolidate_open, |w, s| {
        s.open_notebook_consolidate(&w);
    });

    cb!(Coins, on_consolidate_wallet_open, |w, s| {
        // The destination-pick handler prices the tx off `s.fees.hour`
        // shortly after this opens the account picker — lazily (re)fetch
        // now so it's ready (network-efficiency, 2026-07-23).
        s.refresh_fees_price(&w);
        // Keyed AND watch identities take the same wallet-level flow
        // (rev-3 follow-up 1): snapshot every active notebook's coins,
        // pick the destination notebook, confirm. Watch identities sign
        // the one resulting PSBT externally (screens 13/14).
        let Some(ix) = &s.notebooks else { return };
        let mut sources: Vec<(u32, Vec<app_core::notes_core::tx::Utxo>, u64)> = Vec::new();
        let mut coins_total = 0usize;
        for m in ix.active(s.account) {
            let Some(store) = s.notebook_store(m.index) else { continue };
            let coins = store.available_utxos();
            if coins.is_empty() {
                continue;
            }
            coins_total += coins.len();
            let value: u64 = coins.iter().map(|u| u.value).sum();
            sources.push((m.index, coins, value));
        }
        if coins_total < 2 {
            w.global::<Ui>().set_status("nothing to consolidate (need 2+ coins across the wallet)".into());
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
        w.global::<AccountPicker>().set_nb_create_name("".into());
        s.show_notebook_picker(&w, 0, "wconsol");
    });

    cb!(Sweep, on_set_sweep_tier, |w, s, tier: i32| {
        w.global::<Sweep>().set_sweep_tier(tier);
        let f = s.fees.clone().unwrap_or_default();
        let rate = match tier {
            0 => f.economy,
            2 => f.fastest,
            _ => f.hour,
        }
        .max(1.0);
        if tier != 3 {
            w.global::<Sweep>().set_sweep_rate_text(format!("{rate}").into());
        }
        println!("cb: sweep-tier {tier} rate={rate}");
        s.update_sweep_screen(&w);
    });

    cb!(Sweep, on_sweep_rate_changed, |w, s| {
        s.update_sweep_screen(&w);
    });

    cb!(Sweep, on_toggle_sweep_fund_external, |w, s, on: bool| {
        println!("cb: sweep-fund-external {on}");
        w.global::<Ui>().set_status("".into());
        if on && s.funding.is_none() {
            // No funding wallet active yet — pick one; Back returns here.
            w.global::<Ui>().set_funding_return(Screen::Sweep);
            s.refresh_funding_list(&w);
            w.global::<Ui>().set_screen(Screen::FundingWallets);
            return;
        }
        s.update_sweep_screen(&w);
    });

    cb!(Sweep, on_sweep_send, |w, s| {
        // Scan-freshness gate (belt to the UI button's braces — an e2e tap
        // or a race can land on a just-disabled button): never build a
        // sweep/consolidate off a coin cache a scan is about to replace.
        if w.global::<Ui>().get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=sweep");
            w.global::<Ui>().set_status("still syncing — one moment".into());
            return;
        }
        let dest = w.global::<Ui>().get_sweep_dest().to_string();
        let net = s.network;
        let Ok(recipient) = Recipient::parse(net, &dest) else {
            w.global::<Ui>().set_status(format!("not a valid {} address", net.as_str()).into());
            return;
        };
        let rate = s.resolve_sweep_rate(&w);
        if rate <= 0.0 {
            w.global::<Ui>().set_status("enter a fee rate".into());
            return;
        }
        if w.global::<Sweep>().get_sweep_fund_external() {
            // Fee from the funding wallet: the FULL balance rides to the
            // destination, funding change returns to the funding wallet.
            let Some(fund_src) = s.funding.clone() else {
                w.global::<Ui>().set_status("set a funding wallet first".into());
                return;
            };
            if s.funding_coins.is_empty() {
                w.global::<Ui>().set_status("funding wallet has no spendable coins".into());
                return;
            }
            // Watch identities sweep the whole WALLET (every active
            // notebook's coins, per-index key origins); a keyed identity
            // signs its own inputs with the one active key, so it stays on
            // the active store.
            let watch = s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false);
            let notes_coins: Vec<WatchCoin> = if watch {
                s.watch_wallet_coins()
            } else {
                let nb = s.ident.as_ref().map(|i| i.index).unwrap_or(0);
                s.store
                    .as_ref()
                    .map(|store| {
                        store
                            .utxos
                            .iter()
                            .filter(|u| !u.pending_spend)
                            .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, chain: 0, index: nb })
                            .collect()
                    })
                    .unwrap_or_default()
            };
            if notes_coins.is_empty() {
                w.global::<Ui>().set_status("nothing to sweep".into());
                return;
            }
            let inputs: Vec<app_core::store::TxInput> = notes_coins
                .iter()
                .map(|c| app_core::store::TxInput { txid: c.txid.clone(), vout: c.vout, value: c.value })
                .collect();
            let input_indexes: Vec<u32> = notes_coins.iter().map(|c| c.index).collect();
            // Unit 6: the watch branch's `notes_coins` (from `watch_wallet_coins`)
            // may include chain-1 change coins riding in this fee-external-
            // funded sweep too — same non-bumpable + prune-on-success
            // treatment as the self-paid watch sweep.
            let change_spent: Vec<(String, u32)> =
                notes_coins.iter().filter(|c| c.chain == 1).map(|c| (c.txid.clone(), c.vout)).collect();
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
                s.effective_lock_time(),
            ) {
                Ok(mut built) => {
                    // Keyed identity: the app signs its own inputs here and
                    // now — only the funding wallet still needs to sign.
                    if let Some(id) = s.ident.as_ref().and_then(|i| i.full()) {
                        match sign_own_taproot_inputs(&mut built.psbt, &id.output_x, &id.tweaked_seckey) {
                            Ok(k) => println!("cb: sweep-own-signed inputs={k}"),
                            Err(e) => {
                                w.global::<Ui>().set_status(format!("{e}").into());
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
                        kind: if w.global::<Ui>().get_sweep_kind().as_str() == "consolidate" { "consolidate" } else { "sweep" },
                        dest: dest.clone(),
                        dest_spk_hex: hex::encode(&recipient.spk),
                        value: built.sent_to_recipient,
                        fee: built.fee,
                        inputs,
                        input_indexes,
                        dest_index: None,
                        bump_ref: None,
                        change_spent: change_spent.clone(),
                    });
                    println!(
                        "cb: sweep-build funded=1 txid={} fee={} notes_in={} fund_in={}{}",
                        built.txid,
                        built.fee,
                        notes_coins.len(),
                        fund_coins.len(),
                        if change_spent.is_empty() { String::new() } else { format!(" change={}", change_spent.len()) }
                    );
                    s.show_psbt_sign_screen(&w, built, cost);
                }
                Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
            }
            return;
        }
        let consolidate = w.global::<Ui>().get_sweep_kind().as_str() == "consolidate";
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            let kind = if consolidate { "consolidate" } else { "sweep" };
            s.watch_spend_build(&w, kind, dest, recipient.spk.clone(), rate);
            return;
        }
        // Keyed, self-paid: build + sign now (stage A) and hand off to the
        // universal confirm screen — the (removed) sweep/consolidate
        // confirm modals used to gate this; Broadcast on screen 26 is the
        // only way out now (`on_confirm_broadcast`, kind "sweep"/
        // "consolidate").
        if s.wallet_tx_busy || s.pending_broadcast.is_some() {
            return;
        }
        if consolidate {
            s.build_consolidate_confirm(&w, rate);
        } else {
            s.build_sweep_confirm(&w, dest, rate);
        }
    });

    cb!(Contacts, on_pick_contact, |w, s, addr: SharedString| {
        // Sweep mode: the picker chooses the sweep DESTINATION, then opens
        // the compose-like sweep screen (16) instead of compose.
        if w.global::<Ui>().get_pick_mode().as_str() == "sweep" {
            let mut a = normalize_addr(addr.as_str());
            if a == "self" || a.is_empty() {
                w.global::<Ui>().set_status("pick a destination address".into());
                return;
            }
            if Recipient::parse(s.network, &a).is_err() {
                let lower = a.to_lowercase();
                if Recipient::parse(s.network, &lower).is_ok() {
                    a = lower;
                } else {
                    println!("cb: sweep-pick err=bad-address");
                    w.global::<Ui>().set_status(format!("not a valid {} address", s.network.as_str()).into());
                    return;
                }
            }
            // A manual pick here always replaces whatever destination was
            // set before (including the spending-wallet shortcut) — don't
            // mark a stale index used for an address the user didn't pick.
            s.pending_spending_sweep_index = None;
            s.set_sweep_dest(&w, a);
            return;
        }
        // Multi-select: the picker was reopened via compose's "+ Add
        // recipient" — append instead of replacing the primary recipient.
        if s.picking_extra {
            s.add_recipient_chip(&w, addr.as_str());
            return;
        }
        w.global::<Ui>().set_compose_return(Screen::Contacts);
        s.pick_contact_core(&w, addr.as_str());
    });

    cb!(Note, on_reply_to_note, |w, s| {
        let addr = w.global::<Note>().get_note_reply_address().to_string();
        if addr.is_empty() {
            return;
        }
        println!("cb: reply to={addr}");
        w.global::<Ui>().set_compose_return(Screen::Note);
        s.pick_contact_core(&w, &addr);
    });

    cb!(Note, on_reply_all_to_note, |w, s| {
        let addrs: Vec<String> = w.global::<Note>().get_note_reply_set().iter().map(|c| c.address.to_string()).collect();
        let Some((first, rest)) = addrs.split_first() else { return };
        println!("cb: reply-all to={} n={}", addrs.join(","), addrs.len());
        w.global::<Ui>().set_compose_return(Screen::Note);
        // pick_contact_core resets the compose session (clearing any prior
        // to_addresses_extra) before we seed the rest as extra chips.
        s.pick_contact_core(&w, first);
        s.to_addresses_extra = rest.to_vec();
        s.refresh_to_chips(&w);
        s.refresh_compose(&w);
    });

    cb!(Compose, on_add_recipient_open, |w, s| {
        // Multi-select stays notebook-funded-compose only (watch-only has
        // no multi-recipient PSBT builder yet — a later unit).
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            return;
        }
        let total = 1 + s.to_addresses_extra.len();
        if total >= 255 {
            w.global::<Ui>().set_status("recipient limit reached (255)".into());
            return;
        }
        println!("cb: add-recipient-open");
        s.picking_extra = true;
        w.global::<Ui>().set_picking_extra(true);
        w.global::<Ui>().set_contact_input("".into());
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_pick_mode("compose".into());
        s.pull_icloud_contacts_on_open(&w);
        w.global::<Ui>().set_screen(Screen::Contacts);
    });

    cb!(Compose, on_remove_chip, |w, s, addr: SharedString| {
        let a = addr.to_string();
        s.to_addresses_extra.retain(|x| x != &a);
        println!("cb: remove-chip n={}", s.to_addresses_extra.len() + 1);
        s.refresh_to_chips(&w);
        s.refresh_compose(&w);
    });

    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.global::<Contacts>().on_contact_scan(move || {
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
                    w.global::<Ui>().set_scanning(false);
                    if text.is_empty() {
                        w.global::<Ui>().set_status("scan: no QR seen".into());
                    } else {
                        println!("cb: contact-scan ok");
                        let a = normalize_addr(&text);
                        // Prefill so a failed validation leaves it editable,
                        // then pick directly — a valid scan goes straight
                        // to Compose (the Prime picker behavior).
                        w.global::<Ui>().set_contact_input(a.clone().into());
                        w.global::<Contacts>().invoke_pick_contact(a.into());
                    }
                });
            });
        });
    }

    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.global::<Change>().on_change_scan(move || {
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
                    w.global::<Ui>().set_scanning(false);
                    if text.is_empty() {
                        w.global::<Ui>().set_status("scan: no QR seen".into());
                    } else {
                        println!("cb: change-scan ok");
                        w.global::<Ui>().set_change_address(normalize_addr(&text).into());
                        w.global::<Ui>().set_change_expanded(true);
                        w.global::<Ui>().invoke_compose_changed();
                    }
                });
            });
        });
    }

    // Scan a funding descriptor / xpub / account-UR QR → prefill + validate.
    {
        let weak = window.as_weak();
        let scan_cancel = scan_cancel.clone();
        window.global::<FundingWalletScreen>().on_funding_scan(move || {
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
                        let _ = pweak.upgrade_in_event_loop(move |w| w.global::<Modals>().set_scan_progress(p));
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
                    w.global::<Ui>().set_scanning(false);
                    match result {
                        Some(Err(ur)) => {
                            println!("cb: funding-scan ur (multi-frame)");
                            w.global::<Ui>().invoke_funding_import_ur(ur.into());
                        }
                        Some(Ok(desc)) => {
                            println!("cb: funding-scan ok");
                            let t: SharedString = extract_descriptor(&desc).into();
                            w.global::<FundingWalletScreen>().set_funding_descriptor(t.clone());
                            w.global::<FundingWalletScreen>().invoke_funding_changed(t);
                        }
                        None => w.global::<Ui>().set_status("scan: no complete QR seen".into()),
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
        window.global::<ImportSignedPsbt>().on_psbt_import_scan(move || {
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
                        let _ = pweak.upgrade_in_event_loop(move |w| w.global::<Modals>().set_scan_progress(p));
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
                    w.global::<Ui>().set_scanning(false);
                    match result {
                        Some(text) => {
                            println!("cb: psbt-scan ok");
                            w.global::<Ui>().invoke_psbt_loaded(text.into());
                        }
                        None => w.global::<Ui>().set_status("scan: no complete PSBT seen".into()),
                    }
                });
            });
        });
    }

    cb!(Ui, on_start_rename, |w, s, addr: SharedString, name: SharedString, synced: bool| {
        let _ = &mut s;
        println!("cb: rename-start addr={addr}");
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_rename_address(addr.clone());
        w.global::<Modals>().set_rename_input(name);
        w.global::<Modals>().set_rename_synced(synced);
        w.global::<Modals>().set_rename_pq_input("".into());
        w.global::<Modals>().set_rename_pq_error("".into());
        w.global::<Ui>().set_rename_pq_display(s.contact_pq_display_for(addr.as_str()).into());
    });

    cb!(Modals, on_save_rename, |w, s, name: SharedString| {
        let addr = w.global::<Ui>().get_rename_address().to_string();
        let synced = w.global::<Modals>().get_rename_synced();
        s.name_contact(&addr, name.trim(), synced);
        s.save_contacts();
        println!("cb: save-contact addr={addr} name-len={}", name.trim().len());
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_rename_address("".into());
        w.global::<Modals>().set_rename_input("".into());
        w.global::<Modals>().set_rename_synced(false);
        w.global::<Modals>().set_rename_pq_input("".into());
        w.global::<Ui>().set_rename_pq_display("".into());
        w.global::<Modals>().set_rename_pq_error("".into());
        s.update_home(&w);
    });

    cb!(Ui, on_cancel_rename, |w, s| {
        let _ = &mut s;
        w.global::<Ui>().set_rename_address("".into());
        w.global::<Modals>().set_rename_input("".into());
        w.global::<Modals>().set_rename_synced(false);
        w.global::<Modals>().set_rename_pq_input("".into());
        w.global::<Ui>().set_rename_pq_display("".into());
        w.global::<Modals>().set_rename_pq_error("".into());
    });

    // Contact quantum key: paste/file -> `pqkeys::set_contact_pq_key` ->
    // persist through the normal contacts save path (the field already
    // rides `Contact` serde + the iCloud blob). Applied immediately (not
    // deferred to the dialog's own Save), same as the "Save to iCloud"
    // checkbox — both are contact-record edits independent of the name.
    cb!(Ui, on_contact_pq_set, |w, s, input: SharedString| {
        let addr = w.global::<Ui>().get_rename_address().to_string();
        if addr.is_empty() {
            return;
        }
        let net = s.network.as_str().to_string();
        let Some(contact) = s
            .contacts
            .iter_mut()
            .find(|c| c.address == addr && (c.network == net || c.network.is_empty()))
        else {
            return;
        };
        match app_core::pqkeys::set_contact_pq_key(contact, input.trim()) {
            Ok(fp) => {
                s.save_contacts();
                println!("cb: contact-pq-key ok fp={fp}");
                w.global::<Modals>().set_rename_pq_error("".into());
                w.global::<Modals>().set_rename_pq_input("".into());
                w.global::<Ui>().set_rename_pq_display(s.contact_pq_display_for(&addr).into());
                s.refresh_contacts(&w);
            }
            Err(e) => {
                println!("cb: contact-pq-key err={e}");
                w.global::<Modals>().set_rename_pq_error(e.to_string().into());
            }
        }
    });

    cb!(Ui, on_contact_pq_remove, |w, s| {
        let addr = w.global::<Ui>().get_rename_address().to_string();
        if addr.is_empty() {
            return;
        }
        let net = s.network.as_str().to_string();
        if let Some(contact) = s
            .contacts
            .iter_mut()
            .find(|c| c.address == addr && (c.network == net || c.network.is_empty()))
        {
            contact.mlkem_ek = None;
            s.save_contacts();
            println!("cb: contact-pq-key removed");
            w.global::<Ui>().set_rename_pq_display("".into());
            s.refresh_contacts(&w);
        }
    });

    cb!(Modals, on_contact_pq_file, |w, s| {
        let _ = &mut s;
        if let Some(path) = platform::pick_file(&[("Key", &["asc", "txt", "pgp", "gpg"])]) {
            match std::fs::read_to_string(&path) {
                Ok(text) => w.global::<Modals>().set_rename_pq_input(text.trim().into()),
                Err(e) => w.global::<Modals>().set_rename_pq_error(format!("file: {e}").into()),
            }
        }
    });

    cb!(Contacts, on_confirm_remove, |w, s, addr: SharedString, name: SharedString| {
        let _ = &mut s;
        println!("cb: confirm-remove addr={addr}");
        w.global::<Modals>().set_confirm_remove_name(name);
        w.global::<Ui>().set_confirm_remove_address(addr);
    });

    cb!(Ui, on_cancel_remove, |w, s| {
        let _ = &mut s;
        w.global::<Ui>().set_confirm_remove_address("".into());
    });

    cb!(Modals, on_remove_contact, |w, s, addr: SharedString| {
        s.remove_contact(addr.as_str());
        s.save_contacts();
        println!("cb: remove-contact addr={addr}");
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_confirm_remove_address("".into());
        if w.global::<Ui>().get_rename_address() == addr {
            w.global::<Ui>().set_rename_address("".into());
        }
        s.update_home(&w);
    });

    cb!(Ui, on_compose_changed, |w, s| {
        s.refresh_compose(&w);
    });

    // Post-quantum "Security" section (compose screen 6). The Generate
    // button is the ONLY door to a verified (certified quantum-resistant)
    // passphrase — see passphrase::generate's doc and the
    // SecurityChoice::passphrase_verified rule it exists to satisfy.
    cb!(Compose, on_pq_generate_passphrase, |w, s| {
        match app_core::passphrase::generate() {
            Ok((phrase, bits)) => {
                w.global::<Compose>().set_pq_passphrase_text(phrase.clone().into());
                s.pq_passphrase_generated = Some(phrase);
                s.pq_passphrase_verified = true;
                println!("cb: pq-generate bits={}", bits as u64);
                s.refresh_compose(&w);
            }
            Err(e) => {
                w.global::<Ui>().set_status(format!("couldn't generate a passphrase: {e}").into());
            }
        }
    });

    // Any edit — typed, pasted, or a generated phrase touched afterward —
    // is verified only when it EXACTLY matches the last generated text;
    // anything else (including reverting back to a substring of it) reads
    // as unverified, matching `passphrase_verified`'s doc: "unedited
    // since".
    cb!(Compose, on_pq_passphrase_changed, |w, s, text: SharedString| {
        let text = text.to_string();
        s.pq_passphrase_verified = s.pq_passphrase_generated.as_deref() == Some(text.as_str());
        s.refresh_compose(&w);
    });

    cb!(Compose, on_pq_mlkem_toggled, |w, s, _on: bool| {
        s.refresh_compose(&w);
    });

    // Security panel opened (Sal 2026-08-22, PLAN-graffito-self-pw.md): the
    // sanctioned user-initiated door for lazily loading a SELF-note's
    // imported quantum key this session — the ML-KEM switch itself starts
    // disabled (`pq-mlkem-available` false) until `State.pq_imported` is
    // populated, so it can't be the trigger; opening the panel is the
    // earliest tap available. A no-op on every OTHER repaint path (already
    // cached, or a directed note that never needs this key at all) —
    // `ensure_pq_imported_loaded` itself short-circuits once loaded. Never
    // called on close (LAUNCH-PATH rule: only ever from a deliberate tap).
    cb!(Compose, on_pq_panel_toggled, |w, s, opened: bool| {
        if opened {
            s.ensure_pq_imported_loaded();
            s.refresh_compose(&w);
        }
    });

    // Independent-expand rework (2026-07-18): `source` is now passed
    // explicitly by the tapped panel itself (each of the 3 CoinListPanel
    // instances on screen 20 forwards its OWN "notebook"/"spending"/
    // "wallet:<id>" — see app.slint) rather than read from a single
    // "currently expanded" variable, since multiple sections can be
    // expanded at once now. The cross-wallet selection memory
    // (`mixed_selected`) is authoritative; notebook/spending also mirror
    // into the legacy `selected_coins` scratch so their existing fee/
    // change-preview math keeps reading it directly. A coin tap — and ONLY
    // a coin tap, never a header tap — also makes its wallet the compose
    // engine's active/primary pay-from source (Sal's rule: only an
    // explicit pick may do that).
    cb!(PayFrom, on_toggle_coin, |w, s, source: SharedString, outpoint: SharedString| {
        let source = source.to_string();
        let op = outpoint.as_str();
        if let Some((txid, vout)) = op.rsplit_once(':') {
            if let Ok(vout) = vout.parse::<u32>() {
                // Taproot CHANGE-chain coins (unit 5, see
                // `../PLAN-chain-notes-app-taproot-change.md`) render folded
                // into the "notebook" panel (`payfrom_panel_coins`), so the
                // slint call site always passes source="notebook" for their
                // rows too — resolve the TRUE source from the outpoint
                // itself (globally unique) rather than trusting the caller,
                // so a change coin is tracked under its own "change" key.
                let source = if s.change_coins.iter().any(|c| c.txid == txid && c.vout == vout) {
                    "change".to_string()
                } else {
                    source
                };
                let mut coins = s.mixed_coins_for(&source);
                let key = (txid.to_string(), vout);
                if let Some(i) = coins.iter().position(|c| c == &key) {
                    coins.remove(i);
                } else {
                    coins.push(key);
                }
                s.mixed_sync_source(&source, &coins);
                s.payfrom_manual = true; // explicit pick — CHANGE 5 stops re-defaulting it
                s.payfrom_active_source = source.clone();
                if source == "notebook" || source == "spending" {
                    s.selected_coins = coins.clone();
                    s.coins_overridden = true;
                    s.apply_pay_from(&w, source.as_str());
                } else if let Some(id) = source.strip_prefix("wallet:") {
                    s.promote_wallet_active(&w, id);
                }
                println!("cb: toggle-coin selected={}", coins.len());
                s.refresh_compose(&w);
                s.update_payfrom_panels(&w);
                s.refresh_funding_list(&w);
            }
        }
    });

    cb!(PayFrom, on_set_coin_strategy, |w, s, strategy: i32| {
        // 0 = fewest coins (largest-first), 1 = consolidate (smallest-first).
        // Re-applies the suggestion (clears any manual override).
        s.consolidate_coins = strategy == 1;
        s.coins_overridden = false;
        w.global::<PayFrom>().set_coin_strategy(strategy);
        println!("cb: coin-strategy {}", if strategy == 1 { "consolidate" } else { "fewest" });
        s.refresh_compose(&w);
    });

    // Watchdog fix (2026-07-20): both ↻ taps used to rescan every active
    // notebook synchronously on the UI thread — see
    // `wallet_stores_refresh_async`'s doc comment. The spending-wallet
    // kickoff + notebook-list rebuild now happen in
    // `apply_wallet_stores_refresh_results` once the scan actually lands.
    cb!(Ui, on_refresh_coins, |w, s| {
        s.wallet_stores_refresh_async(&w, WalletStoresPurpose::Coins);
    });

    // Notebook-list (main screen) header ↻: rescan every active notebook and
    // rebuild the list so balances / note counts / unread badges are current.
    cb!(Ui, on_refresh_notebooks, |w, s| {
        s.wallet_stores_refresh_async(&w, WalletStoresPurpose::Notebooks);
    });

    // First-run disclaimer accepted → persist + reveal the real first screen.
    cb!(Terms, on_accept_terms, |w, s| {
        s.terms_accepted = true;
        s.save_config();
        // `target` stays the old int purely for the log line below, which is
        // NOT part of U2's log-contract change (only `cb: sys-back` is) —
        // `target_screen` is the real Screen value passed to the window.
        let target = if s.material.is_some() { 17 } else { 0 };
        let target_screen = if s.material.is_some() { Screen::Notebooks } else { Screen::Onboarding };
        w.global::<Ui>().set_terms_accept_mode(false);
        w.global::<Ui>().set_screen(target_screen);
        println!("cb: accept-terms target={target}");
    });

    // About / Privacy / Help / Q&A — one info screen, content set per button.
    cb!(Settings, on_open_info, |w, s, kind: slint::SharedString| {
        let _ = &mut s;
        let (title, body): (&str, String) = match kind.as_str() {
            "about" => ("About", about_body()),
            "privacy" => ("Privacy", PRIVACY.to_string()),
            "help" => ("Help", HELP.to_string()),
            "faq" => ("Q & A", FAQ.to_string()),
            // Terms & disclaimer re-views through the SAME info screen (25) as
            // the others, so Settings sub-screens share one scroll-top UX. The
            // centered screen 24 is now purely the first-run accept gate.
            "terms" => ("Terms & disclaimer", DISCLAIMER.to_string()),
            _ => return,
        };
        w.global::<Info>().set_info_title(title.into());
        w.global::<Info>().set_info_body(body.as_str().into());
        // The Slint attribution rides the About entry only. Section 2 of the
        // Slint Royalty-free license makes it a condition of the grant, so
        // this flag is load-bearing, not cosmetic — see THIRD-PARTY.md.
        w.global::<Info>().set_info_show_slint(kind.as_str() == "about");
        w.global::<Ui>().set_screen(Screen::Info);
        println!("cb: open-info {kind}");
    });

    // ---------- external funding (PSBT) ----------
    cb!(Ui, on_toggle_fund_external, |w, s, on: bool| {
        println!("cb: fund-external {on}");
        if !on {
            s.funding_coins.clear();
        }
        w.global::<Ui>().set_status("".into());
        s.refresh_compose(&w);
        // Turning it on with no wallet active → go to the saved-wallets list.
        if on && s.funding.is_none() {
            w.global::<Ui>().set_funding_return(Screen::Compose);
            s.refresh_funding_list(&w);
            w.global::<Ui>().set_screen(Screen::FundingWallets);
        }
    });

    // Funding-unification M3: compose "Pay from" picker — "notebook" or
    // "spending". External wallets are picked via use-funding-wallet
    // directly (they need a scan first, same as before this milestone).
    cb!(Ui, on_set_pay_from, |w, s, kind: SharedString| {
        println!("cb: pay-from {kind}");
        s.payfrom_manual = true; // explicit pick — CHANGE 5 stops re-defaulting it
        s.apply_pay_from(&w, kind.as_str());
        s.refresh_compose(&w);
    });

    cb!(Ui, on_open_funding, |w, s| {
        println!("cb: open-funding");
        w.global::<Ui>().set_status("".into());
        s.refresh_funding_list(&w);
        w.global::<Ui>().set_screen(Screen::FundingWallets);
    });

    // funding-unification: compose's compact "Pay from" row → the dedicated
    // picker/coin-control/change-address screen (20). Independent-expand
    // rework (2026-07-18, Sal's iPhone feedback #3): on EVERY open, re-derive
    // which sections start expanded from what's actually selected right now
    // (never persisted across visits) — every source holding at least one
    // selected coin starts open so the user sees it, the rest start
    // collapsed. This is the ONLY place auto-selection-driven expansion
    // happens; a header tap thereafter only shows/hides (`on_payfrom_expand`).
    cb!(Compose, on_open_funding_screen, |w, s| {
        println!("cb: funding-open");
        // Screen 20 (pay-from) shows fee tiers via the compose cost line —
        // lazily (re)fetch (network-efficiency, 2026-07-23).
        s.refresh_fees_price(&w);
        w.global::<Ui>().set_status("".into());
        s.nb_expanded = !s.mixed_coins_for("notebook").is_empty();
        s.sp_expanded = !s.mixed_coins_for("spending").is_empty();
        w.global::<PayFrom>().set_nb_expanded(s.nb_expanded);
        w.global::<PayFrom>().set_sp_expanded(s.sp_expanded);
        println!("cb: payfrom expand wallet=notebook expanded={}", s.nb_expanded);
        println!("cb: payfrom expand wallet=spending expanded={}", s.sp_expanded);
        let wallet_open = s
            .funding_wallets
            .iter()
            .find(|fw| !s.mixed_coins_for(&format!("wallet:{}", fw.id)).is_empty())
            .map(|fw| format!("wallet:{}", fw.id))
            .unwrap_or_default();
        s.payfrom_expanded_source = wallet_open;
        w.global::<Ui>().set_payfrom_expanded_source(s.payfrom_expanded_source.clone().into());
        if !s.payfrom_expanded_source.is_empty() {
            println!("cb: payfrom expand wallet={} expanded=true", s.payfrom_expanded_source);
        }
        s.update_funding_screen_ui(&w);
        s.update_payfrom_panels(&w);
        s.refresh_funding_list(&w);
        w.global::<Ui>().set_screen(Screen::PayFrom);
    });

    // Independent-expand rework (2026-07-18, Sal's iPhone feedback #1/#3): a
    // wallet-row tap ONLY toggles that section's visibility — it never
    // selects/deselects coins or changes which source is the compose
    // engine's active pay-from (that's `on_toggle_coin`'s job, triggered by
    // an actual coin tap, or the on-open auto-selection above). Notebook and
    // Spending expand/collapse fully independently of each other and of the
    // external-wallet row(s): opening one never hides another's selection.
    // External wallets stay an accordion AMONG THEMSELVES only — this app
    // only ever keeps ONE external wallet's coins scanned/cached live at a
    // time (`payfrom_wallet_coins`/`funding_coins`, a pre-existing scope
    // boundary) — but expanding one never touches Notebook/Spending.
    cb!(PayFrom, on_payfrom_expand, |w, s, source: SharedString| {
        let key = source.to_string();
        match key.as_str() {
            "notebook" => {
                s.nb_expanded = !s.nb_expanded;
                w.global::<PayFrom>().set_nb_expanded(s.nb_expanded);
                println!("cb: payfrom expand wallet=notebook expanded={}", s.nb_expanded);
            }
            "spending" => {
                s.sp_expanded = !s.sp_expanded;
                w.global::<PayFrom>().set_sp_expanded(s.sp_expanded);
                println!("cb: payfrom expand wallet=spending expanded={}", s.sp_expanded);
                if s.sp_expanded && !s.spending_scanned {
                    s.spending_refresh_async(&w);
                }
            }
            _ => {
                let collapsing = s.payfrom_expanded_source == key;
                s.payfrom_expanded_source = if collapsing { String::new() } else { key.clone() };
                w.global::<Ui>().set_payfrom_expanded_source(s.payfrom_expanded_source.clone().into());
                println!("cb: payfrom expand wallet={key} expanded={}", !collapsing);
                if !collapsing {
                    if let Some(id) = key.strip_prefix("wallet:") {
                        s.payfrom_scan_wallet_for_display(&w, id);
                    }
                }
            }
        }
        s.update_payfrom_panels(&w);
        s.refresh_funding_list(&w);
    });

    // Change now lives on its own screen (21), reached from a second
    // compose nav row below "Pay from" (funding-unification UI rework).
    cb!(Compose, on_change_open, |w, s| {
        w.global::<Ui>().set_status("".into());
        s.refresh_funding_list(&w);
        s.update_change_label(&w);
        // Logged AFTER resolution so `default=<choice>` reflects the
        // effective destination (an explicit pick if one was made this
        // session, else app-core's resolved default) — a screenshot-
        // independent way to assert change-default behavior in e2e.
        println!("cb: change-open default={}", w.global::<Ui>().get_change_choice());
        w.global::<Ui>().set_screen(Screen::Change);
    });

    cb!(Change, on_change_pick, |w, s, choice: SharedString| {
        println!("cb: change-pick {choice}");
        s.change_choice = choice.to_string();
        w.global::<Ui>().set_change_choice(choice.clone());
        if choice.as_str() != "custom" {
            w.global::<Ui>().set_change_address("".into());
            w.global::<Change>().set_change_error("".into());
        }
        s.update_change_label(&w);
        s.refresh_compose(&w);
        if choice.as_str() != "custom" {
            w.global::<Ui>().set_screen(Screen::Compose);
        }
    });

    // Screen 20's header ↻: re-scan the notebook + (if enabled) the spending
    // wallet on worker threads, same async/trampoline pattern as
    // refresh_async/spending_refresh_async — never blocks the UI thread.
    // Each landing logs its own `cb: funding-refresh …` (see
    // apply_refresh_results / apply_spending_refresh_results).
    cb!(PayFrom, on_funding_refresh, |w, s| {
        s.refresh_async(&w);
        if s.spending_capable && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false) {
            s.spending_refresh_async(&w);
        }
    });

    cb!(FundingWallets, on_add_funding_wallet, |w, s| {
        let _ = &mut s;
        w.global::<Ui>().set_status("".into());
        w.global::<FundingWalletScreen>().set_funding_descriptor("".into());
        w.global::<FundingWalletScreen>().set_funding_feedback("".into());
        w.global::<FundingWalletScreen>().set_funding_valid(false);
        w.global::<Ui>().set_screen(Screen::FundingWallet);
    });

    cb!(FundingWallets, on_use_funding_wallet, |w, s, id: SharedString| {
        s.activate_funding_wallet(&w, id.as_str());
    });

    cb!(FundingWallets, on_remove_funding_wallet, |w, s, id: SharedString| {
        println!("cb: remove-funding-wallet");
        s.funding_wallets.retain(|fw| fw.id != id.as_str());
        if s.active_funding_id.as_deref() == Some(id.as_str()) {
            s.active_funding_id = None;
            s.funding = None;
            s.funding_coins.clear();
        }
        s.save_funding_wallets();
        s.refresh_funding_list(&w);
    });

    cb!(FundingWallets, on_refresh_funding_wallet, |w, s, id: SharedString| {
        let net = s.network;
        let Some(idx) = s.funding_wallets.iter().position(|fw| fw.id == id.as_str()) else { return };
        let descriptor = s.funding_wallets[idx].descriptor.clone();
        let Some(base) = s.base_url() else {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let Ok(src) = FundingSource::parse(&descriptor, net) else { return };
        w.global::<Ui>().set_status("scanning…".into());
        let creds = s.core_rpc_creds_for(&base, net);
        if let Ok(client) = open_client(&base, net, creds) {
            if let Ok(scan) = client.scan_funding(&src, 20) {
                s.funding_wallets[idx].balance = scan.utxos.iter().map(|c| c.value).sum();
                s.funding_wallets[idx].coins = scan.utxos.len();
                s.funding_wallets[idx].scanned = true;
                s.funding_wallets[idx].next_change_index = scan.next_change_index;
                s.save_funding_wallets();
            }
        }
        w.global::<Ui>().set_status("".into());
        s.refresh_funding_list(&w);
    });

    cb!(FundingWallets, on_fund_rename_start, |w, s, id: SharedString, label: SharedString| {
        let _ = &mut s;
        w.global::<Modals>().set_fund_rename_input(label);
        w.global::<Ui>().set_fund_rename_id(id);
    });

    cb!(Modals, on_fund_rename_save, |w, s, text: SharedString| {
        let id = w.global::<Ui>().get_fund_rename_id().to_string();
        let name = text.trim();
        if !name.is_empty() {
            if let Some(fw) = s.funding_wallets.iter_mut().find(|fw| fw.id == id) {
                fw.label = name.to_string();
            }
            s.save_funding_wallets();
        }
        w.global::<Ui>().set_fund_rename_id("".into());
        s.refresh_funding_list(&w);
    });

    cb!(Ui, on_fund_rename_cancel, |w, s| {
        let _ = &mut s;
        w.global::<Ui>().set_fund_rename_id("".into());
    });

    cb!(FundingWalletScreen, on_funding_changed, |w, s, text: SharedString| {
        let net = s.network;
        let _ = &mut s;
        let t = text.trim();
        if t.is_empty() {
            w.global::<FundingWalletScreen>().set_funding_feedback("".into());
            w.global::<FundingWalletScreen>().set_funding_valid(false);
            return;
        }
        if t.to_lowercase().starts_with("ur:") {
            w.global::<FundingWalletScreen>().set_funding_feedback("Hardware-wallet export (UR) — press Save & use to import.".into());
            w.global::<FundingWalletScreen>().set_funding_valid(true);
            return;
        }
        match FundingSource::parse(&extract_descriptor(t), net) {
            Ok(src) => {
                let a0 = src.derive(0, 0).map(|d| d.address).unwrap_or_default();
                w.global::<FundingWalletScreen>().set_funding_feedback(format!("{} wallet · first address\n{a0}", src.kind.label()).into());
                w.global::<FundingWalletScreen>().set_funding_valid(true);
            }
            Err(e) => {
                w.global::<FundingWalletScreen>().set_funding_feedback(format!("{e}").into());
                w.global::<FundingWalletScreen>().set_funding_valid(false);
            }
        }
    });

    cb!(FundingWalletScreen, on_funding_use, |w, s| {
        // A UR hardware-wallet export imports its account(s) into the list.
        if s.try_import_ur_account(&w, &w.global::<FundingWalletScreen>().get_funding_descriptor()) {
            return;
        }
        // Otherwise: validate the descriptor, save to the list if new, activate.
        let input = extract_descriptor(&w.global::<FundingWalletScreen>().get_funding_descriptor());
        let net = s.network;
        let wallet = match FundingWallet::create(&input, "", net) {
            Ok(fw) => fw,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        if !s.funding_wallets.iter().any(|x| x.id == wallet.id) {
            s.funding_wallets.push(wallet.clone());
            s.save_funding_wallets();
        }
        s.activate_funding_wallet(&w, &wallet.id);
    });

    cb!(FundingWalletScreen, on_funding_file, |w, s| {
        if let Some(path) =
            platform::pick_file(&[("Descriptor / wallet export", &["txt", "json", "desc", "ur"])])
        {
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    if s.try_import_ur_account(&w, &content) {
                        return;
                    }
                    // A wallet-export file can list several script-type descriptors.
                    let descs = extract_all_descriptors(&content);
                    if descs.len() > 1 {
                        let added = s.save_funding_descriptors(&w, &descs);
                        w.global::<Ui>().set_status(format!("imported {added} wallet(s) from file — pick one").into());
                    } else {
                        let d = descs.into_iter().next().unwrap_or_default();
                        w.global::<FundingWalletScreen>().set_funding_descriptor(d.clone().into());
                        w.global::<FundingWalletScreen>().invoke_funding_changed(d.into());
                    }
                }
                Err(e) => w.global::<Ui>().set_status(format!("read failed: {e}").into()),
            }
        }
    });

    cb!(Ui, on_funding_import_ur, |w, s, text: SharedString| {
        s.try_import_ur_account(&w, text.as_str());
    });

    cb!(Ui, on_funding_clear, |w, s| {
        s.funding = None;
        s.funding_coins.clear();
        s.built_psbt = None;
        s.signed_psbt = None;
        w.global::<FundingWalletScreen>().set_funding_descriptor("".into());
        w.global::<FundingWalletScreen>().set_funding_feedback("".into());
        w.global::<FundingWalletScreen>().set_funding_valid(false);
        s.refresh_compose(&w);
    });

    cb!(Compose, on_fund_build, |w, s| {
        let text = w.global::<Compose>().get_compose_text().to_string();
        let private = w.global::<Compose>().get_compose_private();
        let rate: f64 = w.global::<Compose>().get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.global::<Ui>().set_status("empty note or bad fee rate".into());
            return;
        }
        if s.funding.is_none() || s.funding_coins.is_empty() {
            w.global::<Ui>().set_status("set a funding wallet first".into());
            return;
        }
        let net = s.network;
        let to = s.to_address.clone();
        let recipient = match to.as_deref() {
            Some(a) => match Recipient::parse(net, a) {
                Ok(r) => Some(r),
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            },
            None => None,
        };
        // Change destination: blank field = the funding wallet's own change
        // address; a valid custom address overrides it.
        let change_raw = normalize_addr(w.global::<Ui>().get_change_address().as_str());
        let change_override = if change_raw.is_empty() {
            None
        } else {
            match Recipient::parse(net, &change_raw) {
                Ok(r) => Some(r.spk),
                Err(_) => {
                    w.global::<Ui>().set_status(format!("change address isn't a valid {} address", net.as_str()).into());
                    return;
                }
            }
        };
        let src = s.funding.clone().unwrap();
        let coins = s.funding_coins.clone();
        let change_index = s.funding_change_index;
        let plan =
            FundingPlan { source: &src, coins: &coins, change_index, fee_rate: rate, change_override };
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            // Watch identity + funding wallet: PUBLIC note paid entirely by
            // the funding coins; both signatures happen externally. Frozen-
            // scan caveat: a rescan attributes an externally funded PUBLIC
            // note as received-from-funder — the local record keeps it own.
            if private {
                w.global::<Ui>().set_status("watch-only identities can only compose public notes".into());
                return;
            }
            let output_x = s.ident.as_ref().map(|i| i.output_x()).unwrap_or_default();
            let gift = if recipient.is_some() {
                w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
            } else {
                0
            };
            // Multi-recipient: the compose screen's extra To-chips — same
            // treatment as `on_compose_send`'s watch branch.
            let extra_recipients: Vec<&str> = s.to_addresses_extra.iter().map(String::as_str).collect();
            let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
                Ok(rc) => rc,
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            };
            let recipients_out: Vec<(Vec<u8>, u64)> = recipients.iter().map(|rc| (rc.spk.clone(), gift)).collect();
            let recipient_addrs: Vec<String> =
                if recipients.len() >= 2 { recipients.iter().map(|rc| rc.address.clone()).collect() } else { Vec::new() };
            let chunk = s.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);
            match app_core::psbt_build::build_watch_funded_note_psbt_multi(
                &output_x, &plan, &text, &recipients_out, chunk, s.effective_lock_time(),
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
                        text: text.clone(),
                        recipient: to.clone(),
                        recipients: recipient_addrs,
                        gift,
                        chunks: payload_outputs,
                        fee: built.fee,
                        change: 0, // funding change isn't an own coin
                        spent: Vec::new(),
                        funded: s.active_funding_pill(),
                        is_watch: true,
                        private: false,
                        dust_to_self: false,
                        change_spent: Vec::new(), // watch compose never spends change coins
                    });
                    let n = coins.len();
                    let nr = recipients.len();
                    let cost = format!(
                        "public note · fee {} sats · {n} funding input{} · sign with your external wallet{}",
                        built.fee,
                        if n == 1 { "" } else { "s" },
                        gift_cost_suffix(nr, gift),
                    );
                    // PLAN-pnte-redesign.md: the note id IS the txid.
                    println!(
                        "cb: watch-note-build id={} txid={} fee={} chunks={payload_outputs} funded=1{}",
                        built.txid,
                        built.txid,
                        built.fee,
                        if nr >= 2 { format!(" recipients={nr}") } else { String::new() }
                    );
                    s.show_psbt_sign_screen(&w, built, cost);
                }
                Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
            }
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        let np = NoteParams {
            identity: &identity,
            text: &text,
            private,
            recipient: recipient.as_ref(),
            max_op_return_bytes: DEFAULT_CHUNK,
            network: net,
        };
        match build_funding_psbt(&plan, &np, s.effective_lock_time()) {
            Ok(built) => {
                let n = coins.len();
                let cost =
                    format!("fee {} sats · {n} input{}", built.fee, if n == 1 { "" } else { "s" });
                s.watch_spend = None; // this sign screen serves external funding
                s.watch_note = None;
                s.show_psbt_sign_screen(&w, built, cost);
                println!("cb: fund-build ok");
            }
            Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
        }
    });

    cb!(ExportPsbt, on_psbt_save, |w, s| {
        let Some(built) = s.built_psbt.as_ref() else { return };
        let bytes = built.to_bytes();
        if let Some(path) = platform::save_file("note.psbt") {
            match std::fs::write(&path, &bytes) {
                Ok(()) => w.global::<Ui>().set_status("saved .psbt".into()),
                Err(e) => w.global::<Ui>().set_status(format!("save failed: {e}").into()),
            }
        }
    });

    cb!(Ui, on_psbt_copy, |w, s| {
        let b64 = s.built_psbt.as_ref().map(|b| b.to_base64()).unwrap_or_default();
        if b64.is_empty() {
            return;
        }
        let ok = platform::set_clipboard_text(&b64);
        if !ok {
            w.global::<Ui>().set_status("copy failed".into());
        }
        show_toast(&w, if ok { "PSBT copied" } else { "Copy failed" });
    });

    cb!(ExportPsbt, on_psbt_goto_import, |w, s| {
        let _ = &mut s;
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::ImportSignedPsbt);
    });

    cb!(Ui, on_psbt_loaded, |w, s, text: SharedString| {
        s.load_signed_psbt(&w, text.as_bytes());
    });

    cb!(ImportSignedPsbt, on_psbt_import_file, |w, s| {
        if let Some(path) = platform::pick_file(&[("PSBT", &["psbt", "txt"])]) {
            match std::fs::read(&path) {
                Ok(bytes) => s.load_signed_psbt(&w, &bytes),
                Err(e) => w.global::<Ui>().set_status(format!("read failed: {e}").into()),
            }
        }
    });

    cb!(Ui, on_psbt_broadcast, |w, s| {
        if s.wallet_tx_busy {
            return;
        }
        let Some(psbt) = s.signed_psbt.clone() else {
            w.global::<Ui>().set_status("no signed PSBT".into());
            return;
        };
        let Some(base) = s.base_url() else {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        };
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let net = s.network;
        let snap = PsbtBroadcastSnapshot {
            identity_addr: s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default(),
            txid,
            raw: raw.clone(),
            vsize,
        };
        s.wallet_tx_busy = true;
        w.global::<Confirm>().set_wallet_tx_busy(true);
        let creds = s.core_rpc_creds_for(&base, net);
        let weak = w.as_weak();
        std::thread::spawn(move || {
            let _net_guard = NetOpGuard::new(weak.clone());
            let result = open_client(&base, net, creds)
                .map_err(|e| e.to_string())
                .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
            PSBT_BROADCAST_RESULTS
                .lock()
                .expect("psbt broadcast results mutex")
                .push(PsbtBroadcastResult { snap, result });
            let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_wallet_tx());
        });
    });

    // ---- Universal confirm screen (26) — stage B ----
    //
    // Every broadcast path lands here now: stage A (each compose/sign
    // callback above) builds + signs synchronously and hands the result to
    // `show_confirm`, which stashes it as `State.pending_broadcast` and
    // navigates to screen 26. Tapping Broadcast there runs stage B: for
    // "psbt" that's the pre-existing `on_psbt_broadcast` handler above,
    // invoked verbatim (`invoke_psbt_broadcast`) — it already manages its
    // own `wallet_tx_busy` and reads `State.signed_psbt`/`watch_note`/
    // `watch_spend`, none of which the confirm screen touched. For the
    // three compose kinds, stage B is the exact record/spawn tail their
    // Stage-A callbacks used to run immediately after signing — moved here
    // so a Cancel tap (before Broadcast) never runs it at all.
    cb!(Confirm, on_confirm_broadcast, |w, s| {
        if s.wallet_tx_busy {
            return;
        }
        let Some(pending) = s.pending_broadcast.clone() else { return };
        println!("cb: confirm broadcast kind={} txid={}", pending.kind, pending.txid);
        match pending.payload {
            PendingPayload::Psbt => {
                // Self-managed: reads State.signed_psbt directly, sets its
                // own wallet_tx_busy, pushes PSBT_BROADCAST_RESULTS. Leaving
                // `pending_broadcast` in place lets a failed POST be retried
                // by tapping Broadcast again (re-invokes this same path).
                // `on_psbt_broadcast` takes its own `st.borrow_mut()` — drop
                // ours first or the shared RefCell double-borrows and panics.
                drop(s);
                w.global::<Ui>().invoke_psbt_broadcast();
            }
            PendingPayload::Compose { composed, text, private, change_to, created_at, to } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                // Record-before-POST, moved here from stage A: exactly what
                // `compose_and_record` used to do before its own broadcast
                // call. Recording is one-shot, so drop `pending_broadcast`
                // now — a failed POST is retried from Activity's
                // Rebroadcast (existing `apply_notebook_compose_result`
                // behavior, unchanged), never by re-tapping this button.
                if let Some(store) = s.store.as_mut() {
                    app_core::compose::record_composed_note(
                        store,
                        &text,
                        private,
                        change_to.as_deref(),
                        created_at,
                        &composed,
                    );
                }
                s.save_store();
                // Device-level contacts (iCloud-contacts feature): touch
                // every recipient here too — `record_composed_note` still
                // touches the per-notebook `Store.contacts` internally (kept
                // for serde back-compat; no longer read anywhere), but the
                // recents list the picker actually shows now lives on
                // `State.contacts`.
                if composed.recipients.is_empty() {
                    if let Some(addr) = &to {
                        s.touch_contact(addr);
                    }
                } else {
                    for addr in &composed.recipients {
                        s.touch_contact(addr);
                    }
                }
                s.save_contacts();
                s.pending_broadcast = None;
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let note_id = composed.note_id.clone();
                let fee = composed.tx.fee;
                let vsize = composed.tx.vsize;
                let pq_flags = composed.pq_flags;
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    NOTEBOOK_COMPOSE_RESULTS.lock().expect("notebook compose results mutex").push(
                        NotebookComposeResult { note_id, fee, vsize, to, private, pq_flags, result },
                    );
                    let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_compose());
                });
            }
            PendingPayload::ComposeSpending {
                text,
                private,
                to,
                recipients,
                gift,
                built_fee,
                built_change,
                spent_outpoints,
                change_index,
                change_raw,
                source,
            } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let txid = pending.txid.clone();
                let vsize = pending.vsize;
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    SPENDING_COMPOSE_RESULTS.lock().expect("spending compose results mutex").push(
                        SpendingComposeResult {
                            text,
                            private,
                            to,
                            recipients,
                            gift,
                            raw,
                            txid,
                            vsize,
                            built_fee,
                            built_change,
                            spent_outpoints,
                            change_index,
                            change_raw,
                            source,
                            result,
                        },
                    );
                    let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_compose());
                });
            }
            PendingPayload::ComposeMixed {
                text,
                private,
                to,
                recipients,
                gift,
                built_fee,
                built_change,
                change_default,
                notebook_spent,
                spent_spending,
                change_spent,
                payloads_len,
                recipient_count,
                change_index,
                spending_source,
            } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let txid = pending.txid.clone();
                let vsize = pending.vsize;
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    MIXED_COMPOSE_RESULTS.lock().expect("mixed compose results mutex").push(
                        MixedComposeResult {
                            text,
                            private,
                            to,
                            recipients,
                            gift,
                            raw,
                            txid,
                            vsize,
                            built_fee,
                            built_change,
                            change_default,
                            notebook_spent,
                            spent_spending,
                            change_spent,
                            payloads_len,
                            recipient_count,
                            change_index,
                            spending_source,
                            result,
                        },
                    );
                    let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_compose());
                });
            }
            // ---- sweep / consolidate / wconsol / spending-consolidate:
            // stage A already built + signed (see `build_sweep_confirm`
            // et al.); stage B synchronously returns to the ORIGIN screen
            // (`pending.return_screen`) — mirroring the removed confirm
            // modals, which closed in place while the broadcast ran in the
            // background — then spawns the pre-existing thread-spawn
            // verbatim, pushing into the SAME result queue their (UNTOUCHED)
            // `apply_*_broadcast_result` already drains via the shared
            // `apply-pending-wallet-tx` trampoline.
            PendingPayload::Sweep { snap } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    SWEEP_BROADCAST_RESULTS
                        .lock()
                        .expect("sweep broadcast results mutex")
                        .push(SweepBroadcastResult { snap, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_wallet_tx());
                });
            }
            PendingPayload::Consolidate { snap } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    CONSOLIDATE_BROADCAST_RESULTS
                        .lock()
                        .expect("consolidate broadcast results mutex")
                        .push(ConsolidateBroadcastResult { snap, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_wallet_tx());
                });
            }
            PendingPayload::WConsol { snap } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node for this network — set one in Settings".into());
                    return;
                };
                let net = snap.network;
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    WCONSOL_BROADCAST_RESULTS
                        .lock()
                        .expect("wconsol broadcast results mutex")
                        .push(WConsolBroadcastResult { snap, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_wallet_tx());
                });
            }
            PendingPayload::SpendingConsolidate { snap } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node for this network — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.wallet_tx_busy = true;
                w.global::<Confirm>().set_wallet_tx_busy(true);
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    SPENDING_CONSOLIDATE_RESULTS
                        .lock()
                        .expect("spending consolidate results mutex")
                        .push(SpendingConsolidateResult { snap, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_wallet_tx());
                });
            }
            // ---- bump / rebroadcast: stage B re-arms `act_pending_ref`
            // (the Activity row's own busy guard — screen 26 briefly, then
            // back on the Activity screen while the POST runs) and spawns
            // the SAME broadcast worker their (UNTOUCHED) apply_act_*
            // functions already drain.
            PendingPayload::Bump { ref_id, fee, new_rate, bumped } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                // Record-before-POST, moved here from stage A (zero-trace
                // cancel fix): apply the exact mutation the one-shot
                // bump_* functions used to make — replacement txid append,
                // fee/vsize/raw_hex update, and (notes) the ledger change
                // swap — then save, exactly like the Compose arm. A failed
                // POST leaves a retryable record with the replacement hex
                // in hand (`apply_act_bump_results` behavior, unchanged).
                // PLAN-pnte-redesign.md: a note bump RENAMES the record's
                // id to the replacement's txid (the note id IS the txid),
                // so the busy-row marker below must follow the rename — a
                // sweep/consolidate bump keeps using `ref_id` (its identity
                // is the whole `txids` history, never renamed).
                let mut renamed_note_id: Option<String> = None;
                if let Some(store) = s.store.as_mut() {
                    match &bumped {
                        BumpedBuild::Note(c) => {
                            renamed_note_id = app_core::compose::record_bumped_note(store, &ref_id, c);
                        }
                        BumpedBuild::Tx(tx) => {
                            app_core::compose::record_bumped_tx(store, &ref_id, tx)
                        }
                    }
                }
                s.save_store();
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.act_pending_ref = Some(renamed_note_id.clone().unwrap_or_else(|| ref_id.clone()));
                s.update_activity(&w);
                let raw = pending.raw_hex.clone();
                let txid = pending.txid.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    ACT_BUMP_RESULTS
                        .lock()
                        .expect("act-bump results mutex")
                        .push(ActBumpResult { ref_id, txid, fee, new_rate, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_act_bump());
                });
            }
            PendingPayload::Rebroadcast { ref_id } => {
                let Some(base) = s.base_url() else {
                    w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
                    return;
                };
                let net = s.network;
                s.pending_broadcast = None;
                w.global::<Ui>().set_screen(pending.return_screen);
                s.act_pending_ref = Some(ref_id.clone());
                s.update_activity(&w);
                let raw = pending.raw_hex.clone();
                let creds = s.core_rpc_creds_for(&base, net);
                let weak = w.as_weak();
                std::thread::spawn(move || {
                    let _net_guard = NetOpGuard::new(weak.clone());
                    let result = open_client(&base, net, creds)
                        .map_err(|e| e.to_string())
                        .and_then(|client| client.broadcast(&raw).map_err(|e| format!("{e}")));
                    ACT_RETRY_RESULTS
                        .lock()
                        .expect("act-retry results mutex")
                        .push(ActRetryResult { ref_id, result });
                    let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_act_retry());
                });
            }
        }
    });

    cb!(Ui, on_confirm_cancel, |w, s| {
        // Busy-guard: a broadcast already in flight can't be canceled out
        // from under itself (mirrors the Broadcast-tap guard above) — the
        // psbt kind in particular delegates to on_psbt_broadcast's own
        // wallet_tx_busy management, so this is the same flag either way.
        if s.wallet_tx_busy {
            return;
        }
        let kind = s.pending_broadcast.as_ref().map(|p| p.kind).unwrap_or("?");
        println!("cb: confirm cancel kind={kind}");
        let return_screen = s.pending_broadcast.take().map(|p| p.return_screen).unwrap_or(Screen::Home);
        w.global::<Ui>().set_confirm_warn("".into());
        w.global::<Confirm>().set_confirm_txid("".into());
        w.global::<Confirm>().set_confirm_context("".into());
        w.global::<Confirm>().set_confirm_note("".into());
        w.global::<Confirm>().set_confirm_inputs(VecModel::<PsbtRow>::from_slice(&[]));
        w.global::<Confirm>().set_confirm_outputs(VecModel::<PsbtRow>::from_slice(&[]));
        w.global::<Ui>().set_status("".into());
        if kind == "psbt" {
            // Zero-trace for the PSBT path means discarding the loaded
            // signed PSBT too — nothing was recorded, and re-showing a
            // stale confirm screen next load would be wrong. The unsigned
            // built PSBT / UR export (screen 13) is untouched, so backing
            // further out and re-exporting still works.
            s.signed_psbt = None;
            w.global::<Ui>().set_psbt_signed(false);
        }
        w.global::<Ui>().set_screen(return_screen);
    });

    cb!(Compose, on_compose_send, |w, s| {
        // Async sign+broadcast (2026-07-16): re-entrancy guard so a
        // double-tap on Sign can't double-broadcast.
        if s.compose_busy {
            return;
        }
        // Scan-freshness gate — see on_sweep_send.
        if w.global::<Ui>().get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=compose");
            w.global::<Ui>().set_status("still syncing — one moment".into());
            return;
        }
        let text = w.global::<Compose>().get_compose_text().to_string();
        let private = w.global::<Compose>().get_compose_private();
        let rate: f64 = w.global::<Compose>().get_rate_text().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.global::<Ui>().set_status("empty note or bad fee rate".into());
            return;
        }
        // Optional custom change address (empty = back to self).
        let change_addr = normalize_addr(w.global::<Ui>().get_change_address().as_str());
        if !change_addr.is_empty() && Recipient::parse(s.network, &change_addr).is_err() {
            w.global::<Ui>().set_status(format!("change address isn't a valid {} address", s.network.as_str()).into());
            return;
        }
        let net = s.network;
        let to = s.to_address.clone();
        if s.base_url().is_none() {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        }
        if !w.global::<Ui>().get_spend_enough() {
            w.global::<Ui>().set_status("selected coins don't cover the note + fee".into());
            return;
        }
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            // Watch compose: PUBLIC note as an external-sign PSBT over the
            // selected coins; recorded on broadcast like a keyed compose.
            if private {
                w.global::<Ui>().set_status("watch-only identities can only compose public notes".into());
                return;
            }
            let Some(src) = s.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
            let recipient = match to.as_deref() {
                Some(a) => match Recipient::parse(net, a) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        w.global::<Ui>().set_status(format!("{e}").into());
                        return;
                    }
                },
                None => None,
            };
            let gift = if recipient.is_some() {
                w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
            } else {
                0
            };
            // Multi-recipient: the compose screen's extra To-chips, exactly
            // like the notebook path — a watch identity can't compose
            // PRIVATE notes at all (checked above), so no content-key/ECDH
            // concerns here; `public_multi_payloads`/`build_watch_note_psbt_
            // multi` hand-frame the same FLAG_MULTI body a keyed identity's
            // sealer would produce.
            let extra_recipients: Vec<&str> = s.to_addresses_extra.iter().map(String::as_str).collect();
            let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
                Ok(r) => r,
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            };
            let recipients_out: Vec<(Vec<u8>, u64)> = recipients.iter().map(|r| (r.spk.clone(), gift)).collect();
            let recipient_addrs: Vec<String> =
                if recipients.len() >= 2 { recipients.iter().map(|r| r.address.clone()).collect() } else { Vec::new() };
            let Some(store) = s.store.as_ref() else { return };
            let sel: std::collections::HashSet<(String, u32)> =
                s.selected_coins.iter().cloned().collect();
            let nb = s.ident.as_ref().map(|i| i.index).unwrap_or(0);
            let coins: Vec<WatchCoin> = store
                .utxos
                .iter()
                .filter(|u| !u.pending_spend && sel.contains(&(u.txid.clone(), u.vout)))
                .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, chain: 0, index: nb })
                .collect();
            if coins.is_empty() {
                println!("cb: compose-send bail=no-coins src=watch");
                w.global::<Ui>().set_status("no coins selected".into());
                return;
            }
            let chunk = store.chunk_size;
            match build_watch_note_psbt_multi(
                &src, &coins, &text, &recipients_out, chunk, rate, s.effective_lock_time(),
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
                        text: text.clone(),
                        recipient: to.clone(),
                        recipients: recipient_addrs,
                        gift,
                        chunks: payload_outputs,
                        fee: built.fee,
                        change: built.change,
                        spent: coins
                            .iter()
                            .map(|c| app_core::store::OutPointRef { txid: c.txid.clone(), vout: c.vout })
                            .collect(),
                        funded: None, // spends the notebook's own coins
                        is_watch: true,
                        private: false,
                        dust_to_self: false,
                        change_spent: Vec::new(), // watch compose never spends change coins
                    });
                    let n = recipients.len();
                    let cost = format!(
                        "public note · fee {} sats{} · sign with your external wallet",
                        built.fee,
                        gift_cost_suffix(n, gift)
                    );
                    // PLAN-pnte-redesign.md: the note id IS the txid.
                    println!(
                        "cb: watch-note-build id={} txid={} fee={} chunks={payload_outputs}{}",
                        built.txid,
                        built.txid,
                        built.fee,
                        if n >= 2 { format!(" recipients={n}") } else { String::new() }
                    );
                    s.show_psbt_sign_screen(&w, built, cost);
                }
                Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
            }
            return;
        }
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        // Universal confirm screen (2026-07-17): stage A builds + signs
        // via the PURE `compose_note` (split out of `compose_and_record` —
        // see app-core/src/compose.rs) — no store mutation, so a Cancel on
        // screen 26 leaves zero trace. Stage B (`on_confirm_broadcast`)
        // calls `record_composed_note` + `save_store()` at the Broadcast
        // tap — exactly what `compose_and_record` used to do before its
        // own POST — then spawns the SAME broadcast worker below.
        let coins_vec = s.selected_coins.clone();
        let created_at = now();
        let gift_amount = to
            .as_ref()
            .map(|_| w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS));
        let change_to = (!change_addr.is_empty()).then(|| change_addr.clone());
        // Multi-recipient (notebook-funded compose only, see State::
        // to_addresses_extra): the compose screen's removable To-chips,
        // beyond the primary `to`. Empty for every other pay-from source
        // and for watch-only (the picker's "+ Add recipient" affordance is
        // hidden there) — so this stays the exact single-recipient flow,
        // byte-identical, for every path but this one.
        let extra_recipients: Vec<&str> = s.to_addresses_extra.iter().map(String::as_str).collect();
        // Post-quantum layers (compose screen 6's Security section). Only
        // reachable when the section could even be showing — re-check
        // `pq_compose_eligible` rather than trusting the toggles blindly,
        // since Sign is a separate tap that could race a recipient/private
        // change made after the section last repainted.
        let pq_eligible = s.pq_compose_eligible(&w);
        let pq_password = if pq_eligible && w.global::<Compose>().get_pq_passphrase_enabled() {
            let p = w.global::<Compose>().get_pq_passphrase_text().to_string();
            if p.trim().is_empty() {
                w.global::<Ui>().set_status("enter a passphrase, or turn off the passphrase layer".into());
                return;
            }
            Some(p)
        } else {
            None
        };
        let pq_mlkem = if pq_eligible && w.global::<Compose>().get_pq_mlkem_enabled() {
            match to.as_deref() {
                Some(addr) => {
                    let net_str = s.network.as_str();
                    let armor = s
                        .contacts
                        .iter()
                        .find(|c| c.address == addr && (c.network == net_str || c.network.is_empty()))
                        .and_then(|c| c.mlkem_ek.clone());
                    match armor.as_deref().map(app_core::notes_core::pq::import_public) {
                        Some(Ok(pair)) => Some(pair),
                        _ => {
                            w.global::<Ui>().set_status(
                                "couldn't read this contact's quantum key — try again, or turn off quantum encryption".into(),
                            );
                            return;
                        }
                    }
                }
                // Self-note (PLAN-graffito-self-pw.md): the imported quantum
                // key ONLY — never the notebook's seed-derived receive key
                // (see `pq_compose_eligible`'s doc). `ensure_pq_imported_
                // loaded` already ran when the Security panel was opened
                // (`on_pq_panel_toggled`); Sign is a separate tap that could
                // race the key being removed since, so re-check here rather
                // than trusting the toggle blindly.
                None => match s.pq_imported.as_ref() {
                    Some(kp) => Some((kp.alg(), kp.ek().to_vec())),
                    None => {
                        w.global::<Ui>().set_status(
                            "no quantum key — add one in Settings, or turn off quantum encryption".into(),
                        );
                        return;
                    }
                },
            }
        } else {
            None
        };
        let req = ComposeRequest {
            text: &text,
            private,
            recipient: to.as_deref(),
            extra_recipients: &extra_recipients,
            change_to: change_to.as_deref(),
            coins: (!coins_vec.is_empty()).then_some(coins_vec.as_slice()),
            fee_rate: rate,
            gift_amount,
            lock_time: s.lock_time_override_value(),
            now: created_at,
            pq_password,
            pq_mlkem,
        };
        let Some(store) = s.store.as_ref() else {
            w.global::<Ui>().set_status("no store".into());
            return;
        };
        match app_core::compose::compose_note(store, &identity, net, &req) {
            Ok(composed) => {
                let name = s.notebook_display_name(s.nb_index);
                let identity_addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
                let prevouts = notebook_prevouts(
                    s.store.as_ref().unwrap(),
                    &identity_addr,
                    &name,
                    &composed.tx.spent_outpoints,
                );
                let (self_spks, spending_spks) = s.confirm_self_spks();
                let contact_name = |a: &str| -> Option<String> {
                    s.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
                };
                let recipient_name = to.as_deref().and_then(contact_name);
                // Multi-recipient: `composed.recipients` is only populated
                // (2+ entries) for an actual multi-recipient note — every
                // other compose (self or ordinary single-recipient) keeps
                // this empty and relies on `recipient`/`recipient_name`
                // above, unchanged.
                let recipients: Vec<(String, Option<String>)> =
                    composed.recipients.iter().map(|a| (a.clone(), contact_name(a))).collect();
                let ctx = app_core::confirm::ConfirmCtx {
                    network: app_core::derive::btc_network(net),
                    prevouts,
                    self_spks,
                    spending_spks,
                    expected_change: change_to.clone(),
                    recipient: to.clone(),
                    recipient_name,
                    recipients,
                    note_preview: Some(if private { "Private note (encrypted)".to_string() } else { text.clone() }),
                    tip_height: s.confirm_tip_height(),
                };
                let (fchange, ffee, fvsize) = (composed.tx.change, composed.tx.fee, composed.tx.vsize);
                let pending = PendingBroadcast {
                    kind: "compose",
                    raw_hex: composed.tx.raw_hex.clone(),
                    txid: composed.tx.txid_hex.clone(),
                    vsize: composed.tx.vsize,
                    context: note_context(to.is_some(), private, net),
                    return_screen: Screen::Compose, // overwritten by show_confirm
                    payload: PendingPayload::Compose {
                        composed,
                        text: text.clone(),
                        private,
                        change_to,
                        created_at,
                        to: to.clone(),
                    },
                };
                s.show_confirm(&w, pending, ctx);
                note_subdust_fold_warn(&w, fchange, ffee, fvsize as u64, rate);
            }
            Err(e) => {
                println!("cb: compose err={e}");
                w.global::<Ui>().set_status(format!("{e}").into());
            }
        }
    });

    // Funding-unification M3: the internal spending-wallet compose path —
    // build the SAME funded-note shape the external path uses
    // (`build_funding_psbt_amount`), sign every P2WPKH input in-process
    // (`sign_own_wpkh_inputs` — no PSBT export/import round trip), and
    // broadcast in one tap. Mirrors `examples/cli.rs`'s `note-spend-funded`
    // recipe exactly.
    cb!(Compose, on_spending_compose_send, |w, s| {
        if s.compose_busy {
            return;
        }
        // Scan-freshness gate — see on_sweep_send.
        if w.global::<Ui>().get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=spending-compose");
            w.global::<Ui>().set_status("still syncing — one moment".into());
            return;
        }
        let text = w.global::<Compose>().get_compose_text().to_string();
        let private = w.global::<Compose>().get_compose_private();
        let rate: f64 = w.global::<Compose>().get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.global::<Ui>().set_status("empty note or bad fee rate".into());
            return;
        }
        let net = s.network;
        if s.base_url().is_none() {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        }
        let to = s.to_address.clone();
        let recipient = match to.as_deref() {
            Some(a) => match Recipient::parse(net, a) {
                Ok(r) => Some(r),
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            },
            None => None,
        };
        // Multi-recipient: the compose screen's extra To-chips — dropped
        // silently on this path before (Sal's report); now built the SAME
        // way the notebook path builds them (`compose::compose_note`).
        let extra_recipients: Vec<&str> = s.to_addresses_extra.iter().map(String::as_str).collect();
        let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
            Ok(r) => r,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let recipient_addrs: Vec<String> =
            if recipients.len() >= 2 { recipients.iter().map(|r| r.address.clone()).collect() } else { Vec::new() };
        let change_raw = normalize_addr(w.global::<Ui>().get_change_address().as_str());
        let change_override = if change_raw.is_empty() {
            None
        } else {
            match Recipient::parse(net, &change_raw) {
                Ok(r) => Some(r.spk),
                Err(_) => {
                    w.global::<Ui>().set_status(format!("change address isn't a valid {} address", net.as_str()).into());
                    return;
                }
            }
        };
        let Some(source) = s.spending_source.clone() else {
            w.global::<Ui>().set_status("spending wallet not scanned yet".into());
            return;
        };
        if s.spending_coins.is_empty() {
            w.global::<Ui>().set_status("spending wallet has no coins — fund it from Settings".into());
            return;
        }
        // Spend exactly the coins selected in the funding screen's coin
        // control — same `selected_coins`/`coins_overridden` state the
        // notebook path uses; unselected defaults to every scanned coin
        // (matches the live preview in `spending_compose_ui`).
        let spending_sel: std::collections::HashSet<(String, u32)> = if s.coins_overridden {
            s.selected_coins.iter().cloned().collect()
        } else {
            s.spending_coins.iter().map(|c| (c.txid.clone(), c.vout)).collect()
        };
        let selected_spending_coins: Vec<app_core::funding::FundingUtxo> = s
            .spending_coins
            .iter()
            .filter(|c| spending_sel.contains(&(c.txid.clone(), c.vout)))
            .cloned()
            .collect();
        if selected_spending_coins.is_empty() {
            println!("cb: compose-send bail=no-coins src=spending");
            w.global::<Ui>().set_status("no coins selected".into());
            return;
        }
        let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        let Ok(key_material) = parse_key_material(&material_str, net) else {
            w.global::<Ui>().set_status("identity parse failed".into());
            return;
        };
        let account = s.account;
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        let Some(change_index) = s.store.as_ref().map(|st| st.spending.next_change) else { return };
        let chunk = s.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);
        let gift = if recipient.is_some() {
            w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
        } else {
            0
        };
        let plan = FundingPlan {
            source: &source,
            coins: &selected_spending_coins,
            change_index,
            fee_rate: rate,
            change_override,
        };
        let np = NoteParams {
            identity: &identity,
            text: &text,
            private,
            recipient: recipient.as_ref(),
            max_op_return_bytes: chunk,
            network: net,
        };
        let built = if recipients.len() >= 2 {
            app_core::psbt_build::build_funding_psbt_multi(&plan, &np, &recipients, gift, s.effective_lock_time())
        } else {
            app_core::psbt_build::build_funding_psbt_amount(&plan, &np, gift, s.effective_lock_time())
        };
        let built = match built {
            Ok(b) => b,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let mut psbt = built.psbt.clone();
        match app_core::psbt_build::sign_own_wpkh_inputs(
            &mut psbt,
            &key_material,
            net,
            account,
            &selected_spending_coins,
        ) {
            Ok(n) if n > 0 => {}
            Ok(_) => {
                w.global::<Ui>().set_status("no spending-wallet inputs signed".into());
                return;
            }
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        // Captured before `finalize_extract` consumes the PSBT — used below
        // to drop the just-spent coins from the runtime cache the moment the
        // broadcast succeeds (finding 1: a second compose in the same
        // session must never see an already-spent UTXO).
        let spent_outpoints: Vec<(String, u32)> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|inp| (inp.previous_output.txid.to_string(), inp.previous_output.vout))
            .collect();
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        // Universal confirm screen (2026-07-17): nothing is recorded here —
        // that was already true before this refactor (unlike the notebook
        // path) — so stage A just hands the signed tx to the confirm
        // screen. Stage B (`on_confirm_broadcast`) is this exact
        // thread-spawn, moved verbatim to the Broadcast tap.
        let built_fee = built.fee;
        let built_change = built.change;
        let (mut self_spks, mut spending_spks) = s.confirm_self_spks();
        // A custom change override leaves the wallet entirely (classified
        // via `expected_change`, not self); the default spending-wallet
        // change address is freshly derived and not yet "used" bookkeeping,
        // so it must be added on top of `confirm_self_spks`'s set.
        let expected_change = if !change_raw.is_empty() {
            Some(change_raw.clone())
        } else {
            if built_change > 0 {
                if let Ok(d) = source.derive(1, change_index) {
                    self_spks.push(d.spk.clone());
                    spending_spks.push(d.spk);
                }
            }
            None
        };
        let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
        for c in &selected_spending_coins {
            prevouts.insert(
                format!("{}:{}", c.txid, c.vout),
                app_core::confirm::PrevoutInfo {
                    value: c.value,
                    address: Some(c.address.clone()),
                    source: "Spending wallet".to_string(),
                },
            );
        }
        let recipient_name = to.as_deref().and_then(|a| {
            s.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        });
        let contact_name = |a: &str| -> Option<String> {
            s.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        };
        let confirm_recipients: Vec<(String, Option<String>)> =
            recipient_addrs.iter().map(|a| (a.clone(), contact_name(a))).collect();
        let ctx = app_core::confirm::ConfirmCtx {
            network: app_core::derive::btc_network(net),
            prevouts,
            self_spks,
            spending_spks,
            expected_change,
            recipient: to.clone(),
            recipient_name,
            recipients: confirm_recipients,
            note_preview: Some(if private { "Private note (encrypted)".to_string() } else { text.clone() }),
            tip_height: s.confirm_tip_height(),
        };
        let pending = PendingBroadcast {
            kind: "compose-spending",
            raw_hex: raw,
            txid,
            vsize,
            context: note_context(to.is_some(), private, net),
            return_screen: Screen::Compose, // overwritten by show_confirm
            payload: PendingPayload::ComposeSpending {
                text: text.clone(),
                private,
                to: to.clone(),
                recipients: recipient_addrs,
                gift,
                built_fee,
                built_change,
                spent_outpoints,
                change_index,
                change_raw,
                source,
            },
        };
        s.show_confirm(&w, pending, ctx);
        note_subdust_fold_warn(&w, built_change, built_fee, vsize as u64, rate);
    });

    // Funding-unification UI rework (2026-07-16): the selection on the
    // Pay-from screen spans more than one wallet — assemble ONE mixed-
    // source PSBT (notebook + spending + at most one external wallet),
    // sign our own inputs in-app, and either broadcast directly (no
    // external coin involved) or route the partially-signed PSBT through
    // the existing external-sign screens 13/14 (the funded-sweep test in
    // app-core's psbt_build already proves that pattern: our own
    // signatures plus an external signer's, on one PSBT).
    cb!(Compose, on_compose_send_mixed, |w, s| {
        if s.compose_busy {
            return;
        }
        // Scan-freshness gate — see on_sweep_send.
        if w.global::<Ui>().get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=mixed-compose");
            w.global::<Ui>().set_status("still syncing — one moment".into());
            return;
        }
        let text = w.global::<Compose>().get_compose_text().to_string();
        let private = w.global::<Compose>().get_compose_private();
        let rate: f64 = w.global::<Compose>().get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.global::<Ui>().set_status("empty note or bad fee rate".into());
            return;
        }
        if s.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            w.global::<Ui>().set_status("watch-only identities can't mix sources".into());
            return;
        }
        let net = s.network;
        if s.base_url().is_none() {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        }
        let to = s.to_address.clone();
        let recipient = match to.as_deref() {
            Some(a) => match Recipient::parse(net, a) {
                Ok(r) => Some(r),
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            },
            None => None,
        };
        let gift = if recipient.is_some() {
            w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
        } else {
            0
        };
        // Multi-recipient: the compose screen's extra To-chips — dropped
        // silently on this path before (Sal's report); now built the SAME
        // way the notebook path builds them.
        let extra_recipients: Vec<&str> = s.to_addresses_extra.iter().map(String::as_str).collect();
        let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
            Ok(r) => r,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let recipient_addrs: Vec<String> =
            if recipients.len() >= 2 { recipients.iter().map(|r| r.address.clone()).collect() } else { Vec::new() };
        let Some(identity) = s.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        let notebook_spk = p2tr_script_pubkey(&identity.output_x);

        // Coins + wallets + change resolution come from the SAME args-builder
        // the compose preview (`mixed_compose_ui`) dry-runs — the shared seam
        // that makes preview and send structurally identical (TestFlight
        // build-20 fix, 2026-07-18).
        let MixedComposeArgs { coins, wallets_map, change_spks, change_default, change_override, change_index } =
            match s.mixed_compose_args(&w) {
                Ok(a) => a,
                Err(e) => {
                    w.global::<Ui>().set_status(e.into());
                    return;
                }
            };

        if coins.is_empty() {
            println!("cb: compose-send bail=no-coins src=mixed");
            w.global::<Ui>().set_status("no coins selected".into());
            return;
        }
        // A change-ONLY selection is single-source by `spans_multiple_wallets`'s
        // count (one distinct `CoinSource::Change`), but there IS no other
        // Sign button for it — taproot-change unit 5 — so it must still
        // route here rather than bounce with "use the Sign button on that
        // source instead".
        let has_change = coins.iter().any(|c| matches!(c.source, app_core::mixed::CoinSource::Change));
        if !has_change && !app_core::mixed::spans_multiple_wallets(&coins) {
            println!("cb: compose-send bail=single-source src=mixed");
            w.global::<Ui>().set_status("selection is single-source — use the Sign button on that source instead".into());
            return;
        }
        let chunk = s.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);

        // PLAN-pnte-redesign.md: a private body's AAD binds the tx's FIRST
        // input's outpoint, not a synthetic id — `coins[0]` becomes that
        // input by construction (`assemble_mixed_note_psbt_multi_ext`
        // iterates `coins` in caller order with no reordering), so it's
        // known before the tx itself is built. `coins` was checked
        // non-empty above.
        let outpoint: [u8; 36] = {
            let c = &coins[0];
            let mut txid = [0u8; 32];
            if let Err(e) = hex::decode_to_slice(&c.txid, &mut txid) {
                w.global::<Ui>().set_status(format!("bad coin txid: {e}").into());
                return;
            }
            txid.reverse();
            app_core::notes_core::tx::outpoint_bytes(&app_core::notes_core::tx::Utxo {
                txid,
                vout: c.vout,
                value: c.value,
            })
        };

        // Fresh one-shot content key for a private multi-recipient body
        // (notes-core's hybrid seal) — OS TRNG, never persisted/logged,
        // zeroized immediately after use, same convention `compose_note`
        // (the notebook path) follows. Unused (and not drawn) for 0/1
        // recipients — `sealed_note_payloads_multi` ignores it there too.
        let payloads_and_spks = if recipients.len() >= 2 {
            let content_key = match app_core::compose::fresh_content_key() {
                Ok(k) => k,
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            };
            let mut content_key = content_key;
            let result = app_core::notes_core::bundle::sealed_note_payloads_multi(
                &identity, &text, private, &recipients, outpoint, content_key, chunk,
            );
            content_key.zeroize();
            result.map_err(app_core::Error::from)
        } else {
            app_core::notes_core::bundle::sealed_note_payloads(
                &identity, &text, private, recipient.as_ref(), outpoint, chunk,
            )
            .map(|(p, spk)| (p, spk.into_iter().collect::<Vec<Vec<u8>>>()))
            .map_err(app_core::Error::from)
        };
        let (payloads, recipient_spks) = match payloads_and_spks {
            Ok(p) => p,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let recipients_out: Vec<(Vec<u8>, u64)> = recipient_spks.into_iter().map(|spk| (spk, gift)).collect();

        let mut built = match app_core::mixed::assemble_mixed_note_psbt_multi_ext(
            &coins,
            notebook_spk,
            s.spending_source.as_ref(),
            &wallets_map,
            &change_spks,
            &payloads,
            &recipients_out,
            &change_default,
            change_override,
            change_index,
            rate,
            s.effective_lock_time(),
        ) {
            Ok(b) => b,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };

        // Sign our own inputs regardless of kind — a no-op (Ok(0)) for
        // whichever kind isn't present in this selection.
        if let Err(e) =
            app_core::psbt_build::sign_own_taproot_inputs(&mut built.psbt, &identity.output_x, &identity.tweaked_seckey)
        {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
        // Taproot CHANGE-chain owners (unit 5): group the selected coins by
        // UNIQUE chain-1 index and sign each owner's inputs with its OWN
        // tweaked key — exactly unit 4's `build_sweep_confirm` change-idents
        // loop, at the PSBT level. `realize_change`'s `AppIdentity` (and its
        // `Zeroizing` leaf secret) drops — and zeroizes — at the end of each
        // loop iteration, never escaping this scope.
        if has_change {
            let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
                w.global::<Ui>().set_status("no identity".into());
                return;
            };
            let Ok(key_material) = parse_key_material(&material_str, net) else {
                w.global::<Ui>().set_status("identity parse failed".into());
                return;
            };
            let mut seen_idx: Vec<u32> = Vec::new();
            for c in coins.iter().filter(|c| matches!(c.source, app_core::mixed::CoinSource::Change)) {
                if seen_idx.contains(&c.index) {
                    continue;
                }
                seen_idx.push(c.index);
                let owner = match realize_change(&key_material, net, s.account, c.index) {
                    Ok(o) => o,
                    Err(e) => {
                        w.global::<Ui>().set_status(format!("{e}").into());
                        return;
                    }
                };
                let Some(owner_identity) = owner.full() else {
                    w.global::<Ui>().set_status("change-chain identity has no key".into());
                    return;
                };
                if let Err(e) = app_core::psbt_build::sign_own_taproot_inputs(
                    &mut built.psbt, &owner_identity.output_x, &owner_identity.tweaked_seckey,
                ) {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            }
        }
        let spending_funding_utxos = app_core::mixed::spending_funding_utxos(&coins);
        if !spending_funding_utxos.is_empty() {
            let Some(material_str) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
                w.global::<Ui>().set_status("no identity".into());
                return;
            };
            let Ok(key_material) = parse_key_material(&material_str, net) else {
                w.global::<Ui>().set_status("identity parse failed".into());
                return;
            };
            if let Err(e) = app_core::psbt_build::sign_own_wpkh_inputs(
                &mut built.psbt, &key_material, net, s.account, &spending_funding_utxos,
            ) {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        }

        let notebook_spent: Vec<app_core::store::OutPointRef> = coins
            .iter()
            .filter(|c| matches!(c.source, app_core::mixed::CoinSource::Notebook))
            .map(|c| app_core::store::OutPointRef { txid: c.txid.clone(), vout: c.vout })
            .collect();
        // Taproot CHANGE-chain coins ridden as inputs (unit 5): NOT part of
        // `store.utxos` (they live in `State.change_coins`, a separate
        // per-account pool), so they're tracked as their own (txid, vout)
        // list — same shape+timing as `SweepSnapshot.change_spent` (unit 4):
        // pruned from `State.change_coins` only on broadcast SUCCESS.
        let change_spent: Vec<(String, u32)> = coins
            .iter()
            .filter(|c| matches!(c.source, app_core::mixed::CoinSource::Change))
            .map(|c| (c.txid.clone(), c.vout))
            .collect();
        let has_external = coins.iter().any(|c| matches!(c.source, app_core::mixed::CoinSource::Wallet(_)));
        // Input-anchored skip (2026-07-18 dust-skip rework; extended to
        // Change by taproot-change unit 5): mirrors
        // `assemble_mixed_note_psbt`'s own `has_self_input` condition
        // exactly, so a bumped/re-read `WatchNote`'s change-vout math
        // (`wn.dust_to_self`) stays byte-true to what the built tx actually
        // contains.
        let has_notebook_input = !notebook_spent.is_empty() || !change_spent.is_empty();

        if has_external {
            // Our own inputs are already signed above; export for the
            // external wallet to complete its own via screens 13/14.
            s.watch_spend = None;
            s.watch_note = Some(WatchNote {
                text: text.clone(),
                recipient: to.clone(),
                recipients: recipient_addrs.clone(),
                gift,
                chunks: payloads.len(),
                fee: built.fee,
                change: built.change,
                spent: notebook_spent,
                funded: Some("mixed".to_string()),
                is_watch: false,
                private,
                dust_to_self: !has_notebook_input,
                change_spent: change_spent.clone(),
            });
            let n = coins.len();
            let nr = recipients.len();
            let sources: std::collections::HashSet<&str> =
                s.mixed_selected.iter().map(|(src, _, _)| src.as_str()).collect();
            println!(
                "cb: compose-mixed build txid={} fee={} inputs={n} sources={} external=1{}",
                built.txid,
                built.fee,
                sources.len(),
                if nr >= 2 { format!(" recipients={nr}") } else { String::new() }
            );
            // `today's copy` here never mentioned the gift at all (even for
            // a single recipient) — preserved for nr <= 1; nr >= 2 appends
            // the ×N total (Sal, 2026-07-19).
            let cost = format!(
                "mixed source · fee {} sats · {n} input{}{} · sign with your external wallet",
                built.fee,
                if n == 1 { "" } else { "s" },
                if nr >= 2 { gift_cost_suffix(nr, gift) } else { String::new() }
            );
            s.show_psbt_sign_screen(&w, built, cost);
            return;
        }

        // No external coin: finalize + hand off to the universal confirm
        // screen. Nothing is recorded here — same "safe to retry from
        // compose on failure" shape as the spending path; stage B
        // (`on_confirm_broadcast`) is this exact thread-spawn, moved
        // verbatim to the Broadcast tap.
        let psbt = built.psbt.clone();
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let spent_spending: Vec<(String, u32)> = coins
            .iter()
            .filter(|c| matches!(c.source, app_core::mixed::CoinSource::Spending))
            .map(|c| (c.txid.clone(), c.vout))
            .collect();
        let spending_source = s.spending_source.clone();
        let built_fee = built.fee;
        let built_change = built.change;
        let payloads_len = payloads.len();
        // `recipients` (the full parsed list, not the "empty means single"
        // `recipient_addrs`) already carries the exact recipient OUTPUT
        // count for every case (0 self-note / 1 ordinary / N multi).
        let recipient_count = recipients.len();

        let identity_addr = s.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
        let name = s.notebook_display_name(s.nb_index);
        let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
        for c in &coins {
            let key = format!("{}:{}", c.txid, c.vout);
            match &c.source {
                app_core::mixed::CoinSource::Notebook => {
                    prevouts.insert(
                        key,
                        app_core::confirm::PrevoutInfo {
                            value: c.value,
                            address: Some(identity_addr.clone()),
                            source: format!("Notebook · {name}"),
                        },
                    );
                }
                app_core::mixed::CoinSource::Spending => {
                    let addr = s
                        .spending_coins
                        .iter()
                        .find(|sc| sc.txid == c.txid && sc.vout == c.vout)
                        .map(|sc| sc.address.clone());
                    prevouts.insert(
                        key,
                        app_core::confirm::PrevoutInfo {
                            value: c.value,
                            address: addr,
                            source: "Spending wallet".to_string(),
                        },
                    );
                }
                // Taproot CHANGE-chain coin (unit 5): same account, chain 1
                // — tagged "Change" (mirrors the sweep confirm's own
                // `source: "Change"` label from unit 4).
                app_core::mixed::CoinSource::Change => {
                    let addr = s
                        .change_coins
                        .iter()
                        .find(|cc| cc.txid == c.txid && cc.vout == c.vout)
                        .map(|cc| cc.address.clone());
                    prevouts.insert(
                        key,
                        app_core::confirm::PrevoutInfo { value: c.value, address: addr, source: "Change".to_string() },
                    );
                }
                // Unreachable here: `has_external` (Wallet(_) coins present)
                // returned above via the external-sign screen instead.
                app_core::mixed::CoinSource::Wallet(_) => {}
            }
        }
        let (mut self_spks, mut spending_spks) = s.confirm_self_spks();
        // A custom change override (screen 21 "custom") leaves the wallet
        // entirely; the default spending-wallet change address is freshly
        // derived and not yet "used" bookkeeping, so — like the spending
        // path — it must be added on top of `confirm_self_spks`'s set. A
        // notebook-default change needs no augmentation (already covered).
        let choice = w.global::<Ui>().get_change_choice().to_string();
        let expected_change = if choice == "custom" {
            Some(normalize_addr(w.global::<Ui>().get_change_address().as_str()))
        } else {
            if change_default == app_core::mixed::ChangeDefault::Spending && built_change > 0 {
                if let Some(src) = s.spending_source.as_ref() {
                    if let Ok(d) = src.derive(1, change_index) {
                        self_spks.push(d.spk.clone());
                        spending_spks.push(d.spk);
                    }
                }
            }
            None
        };
        let recipient_name = to.as_deref().and_then(|a| {
            s.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        });
        let contact_name = |a: &str| -> Option<String> {
            s.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        };
        let confirm_recipients: Vec<(String, Option<String>)> =
            recipient_addrs.iter().map(|a| (a.clone(), contact_name(a))).collect();
        let ctx = app_core::confirm::ConfirmCtx {
            network: app_core::derive::btc_network(net),
            prevouts,
            self_spks,
            spending_spks,
            expected_change,
            recipient: to.clone(),
            recipient_name,
            recipients: confirm_recipients,
            note_preview: Some(if private { "Private note (encrypted)".to_string() } else { text.clone() }),
            tip_height: s.confirm_tip_height(),
        };
        let pending = PendingBroadcast {
            kind: "compose-mixed",
            raw_hex: raw,
            txid,
            vsize,
            context: note_context(to.is_some(), private, net),
            return_screen: Screen::Compose, // overwritten by show_confirm
            payload: PendingPayload::ComposeMixed {
                text: text.clone(),
                private,
                to: to.clone(),
                recipients: recipient_addrs,
                gift,
                built_fee,
                built_change,
                change_default,
                notebook_spent,
                spent_spending,
                change_spent,
                payloads_len,
                recipient_count,
                change_index,
                spending_source,
            },
        };
        s.show_confirm(&w, pending, ctx);
        note_subdust_fold_warn(&w, built_change, built_fee, vsize as u64, rate);
    });

    cb!(Notebooks, on_settings_open, |w, s| {
        w.global::<Ui>().set_return_screen(if w.global::<Ui>().get_screen() == Screen::Notebooks { Screen::Notebooks } else { Screen::Home });
        println!("cb: settings-open");
        s.clear_reveal(&w);
        w.global::<Ui>().set_status("".into());
        w.global::<Settings>().set_chunk_custom(false);
        s.load_backend_settings(&w);
        s.refresh_node_health(&w);
        // Settings shows identity/network/note-size fields that used to be set
        // only by update_home; onboarding now lands on the list (not a home),
        // so populate them here too or the "Change account…" row (gated on
        // settings-hierarchical) is missing on the first Settings visit.
        s.update_settings_identity(&w);
        s.update_spending_ui(&w);
        if s.spending_capable
            && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false)
            && !s.spending_scanned
        {
            s.spending_refresh_async(&w);
        }
        // Fresh entry from the list starts at the top; returning from a Settings
        // sub-screen (via nav-back, which doesn't call this) keeps its position.
        w.global::<Settings>().set_settings_scroll_y(0.0);
        w.global::<Ui>().set_screen(Screen::Settings);
    });

    cb!(Settings, on_open_account_picker, |w, s| {
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else { return };
        println!("cb: account-picker open");
        let page = s.account / 5;
        w.global::<AccountPicker>().set_account_pick_mode("switch".into());
        show_account_picker(&w, &material, s.network, page, Some(s.account));
    });

    cb!(AccountPicker, on_accounts_page, |w, s, delta: i32| {
        let page = (w.global::<AccountPicker>().get_account_page() + delta).max(0) as u32;
        let mode = w.global::<AccountPicker>().get_account_pick_mode();
        if mode == "notebook" || mode == "wconsol" {
            s.show_notebook_picker(&w, page, mode.as_str());
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

    cb!(AccountPicker, on_pick_account, |w, s, idx: i32| {
        if w.global::<AccountPicker>().get_account_pick_mode() == "wconsol" {
            if s.wallet_tx_busy || s.pending_broadcast.is_some() {
                return;
            }
            // Wallet consolidate: the pick is the DESTINATION — a notebook
            // address (receive index) of the active account. A non-
            // notebook address becomes a notebook (named inline) so the
            // gathered coin can never land somewhere invisible. Picking IS
            // the trigger now (the confirm modal is gone) — build + sign
            // (or, watch, build the external-sign PSBT) right here.
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
                // The picker has no name field in this mode, so the new
                // notebook takes the default name ("Notebook <index+1>")
                // until the user renames it from the list.
                s.ensure_notebook(index);
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
                w.global::<Ui>().set_status("not enough across the wallet to cover the fee".into());
                s.wconsol = None;
                return;
            }
            wc.dest_index = index;
            wc.dest_addr = addr;
            wc.rate = rate;
            wc.fee = fee;
            wc.vsize = vsize as u64;
            s.build_wconsol_confirm(&w, wc);
            return;
        }
        if w.global::<AccountPicker>().get_account_pick_mode() == "notebook" {
            // Create flow: the inline name field is already filled (or
            // left empty, taking the default "Notebook <index+1>") —
            // tapping an address creates right away.
            let index = idx.max(0) as u32;
            if s.notebooks.as_ref().and_then(|ix| ix.get(s.account, index)).is_some() {
                return; // row is disabled in the UI; never re-add
            }
            let name = w.global::<AccountPicker>().get_nb_create_name().trim().to_string();
            println!("cb: create-notebook index={index}");
            let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
                return;
            };
            s.nb_index = index;
            match s.activate(&material, false) {
                Ok(()) => {
                    s.ensure_notebook(index);
                    if !name.is_empty() {
                        let account = s.account;
                        if let Some(ix) = s.notebooks.as_mut() {
                            ix.rename(account, index, &name);
                            s.save_notebooks();
                            println!("cb: rename-notebook index={index}");
                        }
                    }
                    w.global::<AccountPicker>().set_account_pick_mode("switch".into());
                    w.global::<AccountPicker>().set_nb_create_name("".into());
                    w.global::<Ui>().set_status("".into());
                    s.update_notebook_list(&w);
                    w.global::<Ui>().set_screen(Screen::Notebooks);
                }
                Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
            }
            return;
        }
        // Sal 2026-07-22: this picker mode is now switch-only — imports
        // never set `pending_import` any more (removed in on_import_confirm),
        // so this always falls back to the current identity's material.
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
        match s.activate(&material, false) {
            Ok(()) => {
                // Settings account switch: the account is a wallet — land on
                // ITS notebook list. A fresh/empty account (no notebooks at
                // all) auto-creates its first one so the switch never lands
                // on an empty list (Sal 2026-07-22); an account that already
                // has notebooks (even if all archived) is left untouched.
                let empty =
                    s.notebooks.as_ref().map(|ix| ix.active(s.account).count() == 0).unwrap_or(true);
                if empty {
                    s.ensure_first_onboarded_notebook();
                }
                w.global::<Ui>().set_status("".into());
                s.update_notebook_list(&w);
                w.global::<Ui>().set_screen(Screen::Notebooks);
                s.refresh_async(&w);
                s.spending_refresh_async(&w);
            }
            Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
        }
    });

    cb!(Ui, on_account_cancel, |w, s| {
        if w.global::<AccountPicker>().get_account_pick_mode() == "wconsol" {
            // Abandon wallet consolidate: back to settings, untouched.
            w.global::<AccountPicker>().set_account_pick_mode("switch".into());
            w.global::<AccountPicker>().set_nb_create_name("".into());
            s.wconsol = None;
            w.global::<Ui>().set_status("".into());
            w.global::<Ui>().set_screen(Screen::Settings);
            return;
        }
        if w.global::<AccountPicker>().get_account_pick_mode() == "notebook" {
            // Abandon create → back to the notebook list, untouched.
            w.global::<AccountPicker>().set_account_pick_mode("switch".into());
            w.global::<AccountPicker>().set_nb_create_name("".into());
            w.global::<Ui>().set_status("".into());
            s.update_notebook_list(&w);
            w.global::<Ui>().set_screen(Screen::Notebooks);
            return;
        }
        if s.pending_import.take().is_some() {
            w.global::<Ui>().set_screen(Screen::ImportKey); // abandon import → back to the import form
        } else {
            s.update_home(&w);
            w.global::<Ui>().set_screen(Screen::Settings); // came from settings
        }
    });

    cb!(Modals, on_reset_identity, |w, s| {
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
        s.to_addresses_extra.clear();
        s.picking_extra = false;
        w.global::<Ui>().set_picking_extra(false);
        s.icloud_backup = false;
        w.global::<Ui>().set_icloud_backup(false);
        // The key is gone, so there is nothing to restore and nothing to
        // auto-unlock — leaving either set would show a "Restore saved key"
        // door pointing at an item we just deleted.
        s.auto_unlock = false;
        s.saved_key_present = false;
        w.global::<Onboarding>().set_saved_key_present(false);
        s.save_config();
        w.global::<Ui>().set_show_reset_confirm(false);
        s.clear_reveal(&w);
        w.global::<Ui>().set_status("".into());
        w.global::<ImportKey>().set_import_text("".into());
        w.global::<Ui>().set_screen(Screen::Onboarding);
    });

    cb!(Ui, on_reveal_hide, |w, s| {
        s.clear_reveal(&w);
        println!("cb: hide-reveal");
    });

    cb!(Settings, on_set_network, |w, s, net: SharedString| {
        let Some(n) = Network::from_str_opt(net.as_str()) else { return };
        if n == s.network {
            return;
        }
        s.network = n;
        println!("cb: set-network {}", s.network.as_str());
        s.save_config();
        // Notebooks are PER-NETWORK (`notebooks-<net>-<fp8>.json`), so a
        // network is a wallet context exactly like an account is — reset to
        // notebook 0 the same way the Settings account switch does, or the
        // active index would carry over to a chain that may not list it.
        s.nb_index = 0;
        // Same key material, new network: re-derive + reload store.
        let material = std::env::var("APP_KEY")
            .ok()
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())));
        if let Some(m) = material {
            match s.activate(&m, false) {
                Ok(()) => {
                    // A network this key has never touched starts with an
                    // EMPTY index, so the switch used to land on an empty
                    // notebook list (Sal 2026-08-01). Auto-create its first
                    // notebook, same guard and same wording as the account
                    // switch above. Safe w.r.t. gap discovery: activate()
                    // already decided `discovery_pending` from whether the
                    // index FILE existed, so writing an entry now cannot
                    // suppress the probe that recovers a used seed's other
                    // notebooks — it just means index 0 is listed first.
                    let empty = s
                        .notebooks
                        .as_ref()
                        .map(|ix| ix.active(s.account).count() == 0)
                        .unwrap_or(true);
                    if empty {
                        s.ensure_first_onboarded_notebook();
                    }
                    s.update_home(&w);
                    s.update_notebook_list(&w);
                    s.refresh_async(&w);
                    s.spending_refresh_async(&w); // CHANGE 5
                }
                Err(e) => w.global::<Ui>().set_status(format!("network switch: {e}").into()),
            }
        }
        w.global::<Settings>().set_settings_network(s.network.as_str().into());
    });

    cb!(Settings, on_set_chunk, |w, s, t: SharedString| {
        match t.trim().parse::<usize>() {
            Ok(n) if (20..=100_000).contains(&n) => {
                if let Some(store) = &mut s.store {
                    store.chunk_size = n;
                }
                s.save_store();
                s.chunk = Some(n); // device-level: every notebook, on activate
                s.save_config();
                println!("cb: set-chunk-size {n} ok");
                w.global::<Settings>().set_chunk_text(n.to_string().into());
                if n == 100_000 || n == 80 {
                    w.global::<Settings>().set_chunk_custom(false);
                }
                w.global::<Ui>().set_status("".into());
            }
            _ => {
                println!("cb: set-chunk-size err=range");
                w.global::<Ui>().set_status("chunk bytes must be 20..=100000".into());
            }
        }
    });

    cb!(Settings, on_set_locktime, |w, s, mode: SharedString, height: SharedString| {
        let policy = parse_locktime_mode(mode.as_str(), height.as_str());
        let Some(policy) = policy else {
            println!("cb: set-locktime err=range");
            w.global::<Ui>().set_status("locktime must be a block height below 500000000".into());
            return;
        };
        s.lock_time_policy = policy;
        if let Some(store) = &mut s.store {
            store.lock_time = policy; // device-level: every notebook, on activate
        }
        s.save_store();
        s.save_config();
        let effective = s.lock_time();
        println!("cb: set-locktime {} effective={effective} ok", policy.as_str());
        w.global::<Settings>().set_locktime_mode(policy.as_str().into());
        w.global::<Settings>().set_locktime_text(effective.to_string().into());
        w.global::<Settings>().set_locktime_effective(locktime_caption(policy, s.store.as_ref().map(|st| st.tip_height)).into());
        w.global::<Ui>().set_status("".into());
    });

    // Compose screen (6) locktime override panel — a per-tx override of
    // the device policy above, NOT a new setting: never written to
    // config.json/store, reset to the device default every time compose is
    // (re)opened (`pick_contact_core`). Shares `parse_locktime_mode`'s
    // validation and `locktime_caption`'s wording with Settings.
    cb!(Compose, on_set_compose_locktime, |w, s, mode: SharedString, height: SharedString| {
        let Some(policy) = parse_locktime_mode(mode.as_str(), height.as_str()) else {
            println!("cb: compose-locktime err=range");
            w.global::<Ui>().set_status("locktime must be a block height below 500000000".into());
            return;
        };
        s.tx_lock_time_override = Some(policy);
        let effective = s.effective_lock_time();
        println!("cb: compose-locktime {} effective={effective} ok", policy.as_str());
        s.refresh_compose_locktime_panel(&w);
        w.global::<Ui>().set_status("".into());
    });

    // Sweep/consolidate screen (16) locktime override panel — same
    // contract as the compose one above, reset on `set_sweep_dest`/
    // `open_notebook_consolidate`.
    cb!(Sweep, on_set_sweep_locktime, |w, s, mode: SharedString, height: SharedString| {
        let Some(policy) = parse_locktime_mode(mode.as_str(), height.as_str()) else {
            println!("cb: sweep-locktime err=range");
            w.global::<Ui>().set_status("locktime must be a block height below 500000000".into());
            return;
        };
        s.tx_lock_time_override = Some(policy);
        let effective = s.effective_lock_time();
        println!("cb: sweep-locktime {} effective={effective} ok", policy.as_str());
        s.refresh_sweep_locktime_panel(&w);
        w.global::<Ui>().set_status("".into());
    });

    // Compose "too large" dialog: raise the chunk size to Standard and reprice
    // the draft in place. Only offered when the note actually fits at Standard.
    cb!(Modals, on_oversize_bump, |w, s| {
        if let Some(store) = &mut s.store {
            store.chunk_size = DEFAULT_CHUNK;
        }
        s.save_store();
        println!("cb: set-chunk-size {DEFAULT_CHUNK} ok (oversize-bump)");
        w.global::<Settings>().set_chunk_text(DEFAULT_CHUNK.to_string().into());
        w.global::<Settings>().set_chunk_custom(false);
        w.global::<Ui>().set_show_oversize_modal(false);
        s.refresh_compose(&w);
    });

    // Bitcoin node dropdown: a preset row writes its base (None = network
    // default) to the device config for this network; the two trailing
    // UI-managed rows — "Bitcoin Core" then "Custom…" (U12) — just reveal
    // their own text field (the Slint side already moved node-index) and
    // write nothing yet; the value follows when the user submits it via
    // set-node-address / set-node-custom respectively.
    cb!(Settings, on_set_node_preset, |w, s, i: i32| {
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
        } else if i == presets.len() {
            println!("cb: set-node-preset core");
        } else {
            println!("cb: set-node-preset custom");
        }
        w.global::<Ui>().set_status("".into());
        // Every preset is Esplora — this both clears a previously-active
        // Core node's credential fields/health line and is a no-op (no
        // network call) whenever the picker was already on Esplora.
        s.refresh_node_health(&w);
    });

    // Bitcoin Core node-address field (U12): normalizes whatever a person
    // typed (bare host, host:port, http(s)://…, or a pasted `bitcoind+…`)
    // into the stored `bitcoind+http(s)://host:port` form via
    // `compose_core_url` — the `bitcoind+` scheme prefix is a storage
    // detail now, never something the user has to type or see. Inline
    // credentials are stripped and routed exactly like `set-node-custom`'s
    // paste path (never stored in the URL). On success the field is
    // rewritten to the canonical `display_core_url` form so what's on
    // screen always matches what got stored; on a malformed input nothing
    // is written and the field is left as typed so the user can fix it.
    cb!(Settings, on_set_node_address, |w, s, t: SharedString| {
        let net = s.network.as_str().to_string();
        match compose_core_url(t.trim(), s.network) {
            Ok((v, inline_creds)) => {
                s.node_urls.insert(net.clone(), v.clone());
                s.save_config();
                println!("cb: set-node-address {v}");
                if let Some((user, pass)) = &inline_creds {
                    let persist = s.core_rpc_should_persist(s.network);
                    let result = route_core_rpc_creds(
                        persist,
                        &net,
                        user,
                        pass,
                        &mut s.core_rpc_session_creds,
                        |u, p| keychain::store_rpc_creds(&net, u, p),
                        || keychain::delete_rpc_creds(&net),
                    );
                    match result {
                        Ok(()) => println!(
                            "cb: set-node-address inline-creds redacted stored=ok persist={persist}"
                        ),
                        Err(e) => {
                            println!("cb: set-node-address inline-creds redacted stored=err ({e})")
                        }
                    }
                }
                w.global::<Ui>().set_node_address_text(display_core_url(&v).into());
                w.global::<Ui>().set_status("".into());
            }
            Err(msg) => {
                println!("cb: set-node-address err={msg}");
                w.global::<Ui>().set_status(format!("Bitcoin node address: {msg}").into());
            }
        }
        s.refresh_node_health(&w);
    });

    cb!(Settings, on_set_node_custom, |w, s, t: SharedString| {
        let net = s.network.as_str().to_string();
        // Strip any inline `user:pass@` userinfo BEFORE it ever reaches
        // config.json or this `cb:` log line (plan §2.4 — "the stored node
        // URL must contain NO credentials"). A pasted
        // `bitcoind+http://user:pass@host:8332` is routed exactly like the
        // credential fields below (`route_core_rpc_creds` — Keychain when
        // the "Save credentials" switch is on, the session-only slot when
        // it's off, so a pasted credential can't become a persisted one
        // behind the user's back); the value that gets
        // stored/logged/displayed is always the creds-free form.
        let (v, inline_creds) = split_url_userinfo(t.trim());
        if v.is_empty() {
            s.node_urls.remove(&net);
        } else {
            s.node_urls.insert(net.clone(), v.clone());
        }
        s.save_config();
        println!("cb: set-node-custom {}", if v.is_empty() { "default" } else { &v });
        if let Some((user, pass)) = &inline_creds {
            let persist = s.core_rpc_should_persist(s.network);
            let result = route_core_rpc_creds(
                persist,
                &net,
                user,
                pass,
                &mut s.core_rpc_session_creds,
                |u, p| keychain::store_rpc_creds(&net, u, p),
                || keychain::delete_rpc_creds(&net),
            );
            match result {
                Ok(()) => println!(
                    "cb: set-node-custom inline-creds redacted stored=ok persist={persist}"
                ),
                Err(e) => println!("cb: set-node-custom inline-creds redacted stored=err ({e})"),
            }
        }
        w.global::<Ui>().set_status("".into());
        s.refresh_node_health(&w);
    });

    // Bitcoin Core RPC credentials (plan §2.4/U6, extended by U10's "Save
    // credentials" switch): persisted in the Keychain ONLY while the switch
    // is on for this network — `keychain::{store,load,delete}_rpc_creds`,
    // under a distinct account namespace from the identity key. Off routes
    // to the session-only slot instead (`route_core_rpc_creds`); the
    // Keychain is never touched in that branch. Never written to
    // config.json, never logged (length only). Clearing both fields
    // deletes/clears the stored or session credential instead of writing
    // an empty one.
    cb!(Settings, on_set_node_core_creds, |w, s, user: SharedString, pass: SharedString| {
        let net = s.network.as_str().to_string();
        let user = user.trim().to_string();
        let pass = pass.to_string();
        let persist = s.core_rpc_should_persist(s.network);
        let result = route_core_rpc_creds(
            persist,
            &net,
            &user,
            &pass,
            &mut s.core_rpc_session_creds,
            |u, p| keychain::store_rpc_creds(&net, u, p),
            || keychain::delete_rpc_creds(&net),
        );
        match &result {
            Ok(()) => println!(
                "cb: set-node-core-creds ok user_len={} pass_len={} persist={persist}",
                user.len(),
                pass.len()
            ),
            Err(e) => println!("cb: set-node-core-creds err={e}"),
        }
        w.global::<Ui>().set_status(if result.is_ok() { "".into() } else { "couldn't save RPC credentials".into() });
        s.refresh_node_health(&w);
        if result.is_err() {
            // A FAILED save stored nothing, so the refresh above resolves
            // this network's credentials as absent and empties the fields —
            // destroying what the user typed on top of not saving it. Put
            // it back so they can fix the cause and press Save again
            // (reproducible on any unsigned dev build, where SecItemAdd
            // returns -34018).
            w.global::<Settings>().set_node_core_user(user.as_str().into());
            w.global::<Settings>().set_node_core_pass(pass.as_str().into());
        }
    });

    // "Save credentials" switch (plan §2.4 / U10): default ON, so nobody who
    // already saved credentials sees a change. Turning it OFF immediately
    // deletes any stored Keychain item for this network — leaving a stale
    // secret behind after the user says "don't save" would be worse than
    // not having the feature — and keeps today's on-screen fields in the
    // session-only slot instead, so the user doesn't lose what they just
    // typed. Turning it back ON persists whatever is in hand (session slot
    // or the on-screen fields) and clears the session copy. A failed
    // Keychain op reverts the on-screen toggle rather than claiming
    // success.
    cb!(Settings, on_set_node_core_save_creds, |w, s, enabled: bool| {
        let net = s.network.as_str().to_string();
        let net_key = net.clone();
        let user = w.global::<Settings>().get_node_core_user().to_string();
        let pass = w.global::<Settings>().get_node_core_pass().to_string();
        let result = apply_core_rpc_persist_toggle(
            enabled,
            &user,
            &pass,
            || keychain::delete_rpc_creds(&net),
            |u, p| keychain::store_rpc_creds(&net, u, p),
        );
        match result {
            Ok(session) => {
                s.core_rpc_save_creds.insert(net_key.clone(), enabled);
                match session {
                    Some(entry) => {
                        s.core_rpc_session_creds.insert(net_key, entry);
                    }
                    None => {
                        s.core_rpc_session_creds.remove(&net_key);
                    }
                }
                s.save_config();
                println!("cb: set-node-core-save-creds {enabled} ok");
            }
            Err(e) => {
                w.global::<Settings>().set_node_core_save_creds(!enabled);
                println!("cb: set-node-core-save-creds {enabled} err={e}");
            }
        }
        s.update_node_backend_ui(&w);
        s.refresh_node_health(&w);
    });

    cb!(Settings, on_set_explorer_preset, |w, s, i: i32| {
        let net = s.network.as_str().to_string();
        let presets = explorer_presets(s.network);
        let i = i as usize;
        if i < presets.len() {
            match presets[i].1 {
                Some(url) => { s.explorers.insert(net, url.to_string()); }
                None => { s.explorers.remove(&net); }
            }
            s.save_config();
            s.update_activity(&w); // refresh live Explorer links
            println!("cb: set-explorer-preset {}", presets[i].0);
        } else {
            println!("cb: set-explorer-preset custom");
        }
        w.global::<Ui>().set_status("".into());
    });

    cb!(Settings, on_set_explorer_custom, |w, s, t: SharedString| {
        let net = s.network.as_str().to_string();
        let v = t.trim().to_string();
        if v.is_empty() {
            s.explorers.remove(&net);
        } else {
            s.explorers.insert(net, v.clone());
        }
        s.save_config();
        s.update_activity(&w); // refresh live Explorer links
        println!("cb: set-explorer-custom {}", if v.is_empty() { "default" } else { &v });
        w.global::<Ui>().set_status("".into());
    });

    // ---- Public keys (screen 18): derived from the SESSION-CACHED
    // material only — never a fresh biometric. Watch-only identities show
    // whatever public material `export_formats` yields (their `material`
    // IS the xpub/descriptor string itself, so this works unchanged).
    cb!(Settings, on_reveal_public, |w, s| {
        let material = std::env::var("APP_KEY")
            .ok()
            .or_else(|| s.material.as_ref().map(|z| String::from(z.as_str())));
        let Some(material) = material else {
            w.global::<PublicKeys>().set_reveal_public_rows(VecModel::from_slice(&Vec::<RevealRow>::new()));
            w.global::<Ui>().set_reveal_fingerprint("".into());
            w.global::<Ui>().set_reveal_public_hint(
                "No key material cached this session — open Private keys once (it re-authenticates), or restart the app."
                    .into(),
            );
            w.global::<Ui>().set_screen(Screen::PublicKeys);
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
                w.global::<Ui>().set_reveal_fingerprint(fp_line.into());
                w.global::<PublicKeys>().set_reveal_public_rows(VecModel::from_slice(&rows));
                // A single hex/WIF key import has a leaf key but no account
                // node — legitimately nothing public to export. Explain the
                // empty screen instead of leaving it blank.
                w.global::<Ui>().set_reveal_public_hint(if rows.is_empty() {
                    "This key has no account-level public material — a single hex/WIF import can't yield a watch-only xpub or descriptor.".into()
                } else {
                    "".into()
                });
            }
            Err(e) => {
                w.global::<PublicKeys>().set_reveal_public_rows(VecModel::from_slice(&Vec::<RevealRow>::new()));
                w.global::<Ui>().set_reveal_public_hint(format!("Couldn't derive public keys: {e}").into());
                println!("cb: reveal-public err");
            }
        }
        w.global::<Ui>().set_screen(Screen::PublicKeys);
    });

    // ---- Private keys (screen 19): ALWAYS a fresh biometric — never the
    // session cache. Only on success do we derive + navigate; failures
    // surface as a status message on Settings (screen stays 8). Every
    // format this identity supports is derived up front and cached in
    // `s.reveal_formats` so the picker (`private-select`) never re-prompts
    // — but nothing is shown until the user taps a pill (progressive
    // disclosure).
    cb!(Settings, on_reveal_private, |w, s| {
        match keychain::reveal_secret(KEYCHAIN_ACCOUNT, "reveal your keys") {
            Ok(Some(secret)) => {
                match app_core::keyexport::export_formats(&secret, s.network, s.account, s.nb_index)
                {
                    Ok(f) => {
                        let fp_line = match f.fingerprint.as_deref() {
                            Some(fp) => format!("{fp} · account {}", s.account),
                            None => format!("account {}", s.account),
                        };
                        w.global::<Ui>().set_reveal_fingerprint(fp_line.into());
                        w.global::<PrivateKeys>().set_reveal_has_recovery(f.mnemonic.is_some());
                        w.global::<PrivateKeys>().set_reveal_has_xprv(f.account_xprv.is_some());
                        w.global::<PrivateKeys>().set_reveal_has_hex(f.leaf_hex.is_some());
                        w.global::<PrivateKeys>().set_reveal_has_wif(f.leaf_wif.is_some());
                        // Nothing selected yet — the screen shows only the
                        // pills until one is tapped.
                        w.global::<Ui>().set_reveal_private_format("".into());
                        w.global::<PrivateKeys>().set_reveal_private_value("".into());
                        w.global::<PrivateKeys>().set_reveal_private_qr(slint::Image::default());
                        w.global::<PrivateKeys>().set_reveal_words_col1("".into());
                        w.global::<PrivateKeys>().set_reveal_words_col2("".into());
                        w.global::<PrivateKeys>().set_reveal_show_seedqr(false);
                        w.global::<PrivateKeys>().set_reveal_seedqr_image(slint::Image::default());
                        // Hex/WIF picker: the active account's notebooks,
                        // defaulting to the active notebook. Hidden in the UI
                        // for recovery/xprv, but harmless to populate always.
                        w.global::<PrivateKeys>().set_reveal_nb_rows(VecModel::from_slice(&s.private_nb_rows()));
                        w.global::<PrivateKeys>().set_reveal_nb_index(s.nb_index as i32);
                        println!("cb: reveal-private ok");
                        s.reveal_formats = Some(f);
                        w.global::<Ui>().set_status("".into());
                        w.global::<Ui>().set_screen(Screen::PrivateKeys);
                    }
                    Err(e) => {
                        println!("cb: reveal-private err");
                        w.global::<Ui>().set_status(format!("export: {e}").into());
                    }
                }
            }
            Ok(None) => {
                println!("cb: reveal-private no-key");
                w.global::<Ui>().set_status("(no key in keychain — APP_KEY env session?)".into());
            }
            Err(e) if e == "cancelled" => {
                println!("cb: reveal-private cancelled");
                w.global::<Ui>().set_status("authentication cancelled".into());
            }
            Err(e) => {
                println!("cb: reveal-private err");
                w.global::<Ui>().set_status(format!("keychain: {e}").into());
            }
        }
    });

    // Switch which single format is on screen (progressive disclosure —
    // only one value visible at a time). Reads the formats derived at
    // reveal-private time; never re-authenticates. Hex/WIF derive from
    // whichever notebook the picker currently has selected (not always
    // the active notebook) so switching back to a pill after picking a
    // different notebook shows the right value.
    cb!(PrivateKeys, on_private_select, |w, s, fmt: SharedString| {
        let fmt = fmt.as_str();
        if fmt == "hex" || fmt == "wif" {
            let Some(v) = s.derive_leaf_value(&w, fmt) else { return };
            w.global::<PrivateKeys>().set_reveal_show_seedqr(false);
            w.global::<PrivateKeys>().set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
            w.global::<PrivateKeys>().set_reveal_private_value(v.into());
            w.global::<Ui>().set_reveal_private_format(fmt.into());
            println!("cb: private-select fmt={fmt}");
            return;
        }
        let Some(f) = s.reveal_formats.as_ref() else { return };
        w.global::<PrivateKeys>().set_reveal_show_seedqr(false);
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
                w.global::<PrivateKeys>().set_reveal_words_col1(col(0..half).into());
                w.global::<PrivateKeys>().set_reveal_words_col2(col(half..list.len()).into());
                if let Ok(m) = bip39::Mnemonic::parse(&words) {
                    let digits = app_core::seedqr::encode_standard(&m);
                    w.global::<PrivateKeys>().set_reveal_seedqr_image(qr::qr_image(&digits).unwrap_or_default());
                }
                w.global::<PrivateKeys>().set_reveal_private_value(words.into());
                w.global::<PrivateKeys>().set_reveal_private_qr(slint::Image::default());
            }
            "xprv" => {
                let Some(v) = f.account_xprv.as_ref().map(|z| z.as_str().to_string()) else {
                    return;
                };
                w.global::<PrivateKeys>().set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
                w.global::<PrivateKeys>().set_reveal_private_value(v.into());
            }
            // hex/wif are handled above (picker-aware, returns early).
            _ => return,
        }
        w.global::<Ui>().set_reveal_private_format(fmt.into());
        println!("cb: private-select fmt={fmt}");
    });

    // Hex/WIF only: switch the picker's selected notebook and re-derive
    // its leaf key from the session-cached material — NO re-auth. A no-op
    // for recovery/xprv (the picker is hidden for those, and the shown
    // format is index-independent anyway).
    cb!(PrivateKeys, on_private_pick_notebook, |w, s, index: i32| {
        w.global::<PrivateKeys>().set_reveal_nb_index(index);
        println!("cb: private-pick-notebook index={index}");
        let fmt = w.global::<Ui>().get_reveal_private_format().to_string();
        if fmt != "hex" && fmt != "wif" {
            return;
        }
        let Some(v) = s.derive_leaf_value(&w, &fmt) else { return };
        w.global::<PrivateKeys>().set_reveal_private_qr(qr::qr_image(&v).unwrap_or_default());
        w.global::<PrivateKeys>().set_reveal_private_value(v.into());
    });

    // ---- Quantum keys (Settings -> screen 29) ----------------------------

    cb!(Settings, on_open_pq_keys, |w, s| {
        // User-initiated — the LAUNCH-PATH rule's other sanctioned door for
        // loading an imported ML-KEM secret from the Keychain this session
        // (a no-op once already cached).
        s.ensure_pq_imported_loaded();
        w.global::<QuantumKeys>().set_pq_import_text("".into());
        w.global::<QuantumKeys>().set_pq_import_error("".into());
        w.global::<Ui>().set_pq_import_source("".into());
        w.global::<Ui>().set_pq_show_backup_confirm(false);
        w.global::<QuantumKeys>().set_pq_gen_level("768".into());
        w.global::<QuantumKeys>().set_pq_gen_extra("".into());
        w.global::<Ui>().set_pq_show_replace_confirm(false);
        w.global::<Ui>().set_pq_show_export_private_confirm(false);
        w.global::<Modals>().set_pq_imported_private_value("".into());
        w.global::<Modals>().set_pq_imported_private_qr(slint::Image::default());
        s.pq_pending_replace = None;
        s.update_pq_keys_screen(&w);
        w.global::<Ui>().set_screen(Screen::QuantumKeys);
        // Log-contract landing signal (graffito-app-selfpq.sh) — emitted
        // LAST, after ensure_pq_imported_loaded (which blocks on a
        // SecurityAgent keychain prompt on a freshly-resigned debug build)
        // and set_screen, so it fires only once the screen is truly shown.
        println!("cb: pq-keys open");
    });

    cb!(QuantumKeys, on_pq_set_level, |w, s, level: SharedString| {
        let Some(level) = pq_level_from_str(level.as_str()) else { return };
        s.pq_level = level;
        s.save_config();
        println!("cb: pq-key level={}", pq_level_str(level));
        s.update_pq_keys_screen(&w);
    });

    cb!(QuantumKeys, on_pq_copy_public, |w, s| {
        let _ = &mut s;
        let Some(ls) = s.ident.as_ref().and_then(|i| i.leaf_secret()) else { return };
        let kp = app_core::pqkeys::derive_keypair(ls, app_core::pqkeys::pq_alg(s.pq_level));
        let armor = app_core::pqkeys::export_public_armor(&kp);
        let ok = platform::set_clipboard_text(&armor);
        println!("cb: pq-key-export public len={}", armor.len());
        show_toast(&w, if ok { "Copied" } else { "Copy failed" });
    });

    cb!(QuantumKeys, on_pq_save_public, |w, s| {
        let _ = &mut s;
        let Some(ls) = s.ident.as_ref().and_then(|i| i.leaf_secret()) else { return };
        let kp = app_core::pqkeys::derive_keypair(ls, app_core::pqkeys::pq_alg(s.pq_level));
        let armor = app_core::pqkeys::export_public_armor(&kp);
        if let Some(path) = platform::save_file("quantum-public-key.asc") {
            match std::fs::write(&path, armor.as_bytes()) {
                Ok(()) => {
                    println!("cb: pq-key-export public len={}", armor.len());
                    w.global::<Ui>().set_status("saved public key".into());
                }
                Err(e) => w.global::<Ui>().set_status(format!("save failed: {e}").into()),
            }
        }
    });

    cb!(Modals, on_pq_copy_private, |w, s| {
        let _ = &mut s;
        let Some(ls) = s.ident.as_ref().and_then(|i| i.leaf_secret()) else { return };
        let kp = app_core::pqkeys::derive_keypair(ls, app_core::pqkeys::pq_alg(s.pq_level));
        let armor = app_core::pqkeys::export_private_armor(&kp);
        let ok = platform::set_clipboard_secret(&armor);
        println!("cb: pq-key-export private len={}", armor.len());
        w.global::<Ui>().set_pq_show_backup_confirm(false);
        show_toast(&w, if ok { "Copied" } else { "Copy failed" });
    });

    cb!(Modals, on_pq_save_private, |w, s| {
        let _ = &mut s;
        let Some(ls) = s.ident.as_ref().and_then(|i| i.leaf_secret()) else { return };
        let kp = app_core::pqkeys::derive_keypair(ls, app_core::pqkeys::pq_alg(s.pq_level));
        let armor = app_core::pqkeys::export_private_armor(&kp);
        w.global::<Ui>().set_pq_show_backup_confirm(false);
        if let Some(path) = platform::save_file("quantum-private-key.asc") {
            match std::fs::write(&path, armor.as_bytes()) {
                Ok(()) => {
                    println!("cb: pq-key-export private len={}", armor.len());
                    w.global::<Ui>().set_status("saved private key".into());
                }
                Err(e) => w.global::<Ui>().set_status(format!("save failed: {e}").into()),
            }
        }
    });

    cb!(QuantumKeys, on_pq_import_paste, |w, s| {
        let _ = &mut s;
        match platform::clipboard_text() {
            Some(text) => w.global::<QuantumKeys>().set_pq_import_text(text.into()),
            None => w.global::<QuantumKeys>().set_pq_import_error("clipboard empty".into()),
        }
    });

    cb!(QuantumKeys, on_pq_import_file, |w, s| {
        let _ = &mut s;
        if let Some(path) = platform::pick_file(&[("Key", &["asc", "txt", "pgp", "gpg"])]) {
            match std::fs::read_to_string(&path) {
                Ok(text) => w.global::<QuantumKeys>().set_pq_import_text(text.trim().into()),
                Err(e) => w.global::<QuantumKeys>().set_pq_import_error(format!("file: {e}").into()),
            }
        }
    });

    // Generate/Import both route through the REPLACE GUARD when a "My
    // quantum key" is already present (PLAN-graffito-quantum-key.md — never
    // silently overwrite): the confirm modal opens instead of acting, and
    // `on_pq_replace_confirm` runs whichever action was pending. The
    // pending action's own input (gen level/extra, or import text) is left
    // untouched in the Slint properties across the round trip.
    cb!(QuantumKeys, on_pq_generate, |w, s| {
        if s.pq_imported.is_some() {
            s.pq_pending_replace = Some(PqReplaceKind::Generate);
            w.global::<Ui>().set_pq_show_replace_confirm(true);
            return;
        }
        s.do_pq_generate(&w);
    });

    cb!(QuantumKeys, on_pq_import_submit, |w, s| {
        if s.pq_imported.is_some() {
            s.pq_pending_replace = Some(PqReplaceKind::Import);
            w.global::<Ui>().set_pq_show_replace_confirm(true);
            return;
        }
        s.do_pq_import(&w);
    });

    cb!(Ui, on_pq_replace_confirm, |w, s| {
        w.global::<Ui>().set_pq_show_replace_confirm(false);
        match s.pq_pending_replace.take() {
            Some(PqReplaceKind::Generate) => s.do_pq_generate(&w),
            Some(PqReplaceKind::Import) => s.do_pq_import(&w),
            None => {}
        }
    });

    cb!(Modals, on_pq_replace_cancel, |w, s| {
        s.pq_pending_replace = None;
        w.global::<Ui>().set_pq_show_replace_confirm(false);
    });

    cb!(QuantumKeys, on_pq_import_remove, |w, s| {
        let _ = keychain::delete_secret(PQ_IMPORTED_ACCOUNT);
        s.pq_imported = None;
        w.global::<Ui>().set_pq_import_source("".into());
        w.global::<QuantumKeys>().set_pq_import_error("".into());
        println!("cb: pq-key-remove");
        s.update_pq_keys_screen(&w);
    });

    // ---- "My quantum key" export (item 3: public is a plain share, the
    // private armor sits behind an explicit reveal warning and copies via
    // the concealed/expiring clipboard, never the plain one) ----

    cb!(QuantumKeys, on_pq_imported_copy_public, |w, s| {
        let _ = &mut s;
        let Some(kp) = s.pq_imported.as_ref() else { return };
        let armor = app_core::notes_core::pq::export_public(kp.alg(), kp.ek());
        let ok = platform::set_clipboard_text(&armor);
        println!("cb: pq-key-export public len={}", armor.len());
        show_toast(&w, if ok { "Copied" } else { "Copy failed" });
    });

    cb!(Modals, on_pq_imported_reveal_private, |w, s| {
        let _ = &mut s;
        let Some(kp) = s.pq_imported.as_ref() else { return };
        let armor = app_core::pqkeys::export_private_armor(kp);
        w.global::<Modals>().set_pq_imported_private_qr(qr::qr_image(&armor).unwrap_or_default());
        w.global::<Modals>().set_pq_imported_private_value(armor.into());
        println!("cb: pq-key-export private-reveal");
    });

    cb!(Modals, on_pq_imported_copy_private, |w, s| {
        let _ = &mut s;
        let armor = w.global::<Modals>().get_pq_imported_private_value().to_string();
        if armor.is_empty() {
            return;
        }
        let ok = platform::set_clipboard_secret(&armor);
        println!("cb: pq-key-export private len={}", armor.len());
        show_toast(&w, if ok { "Copied" } else { "Copy failed" });
    });

    cb!(Ui, on_pq_imported_hide_private, |w, s| {
        let _ = &mut s;
        w.global::<Modals>().set_pq_imported_private_value("".into());
        w.global::<Modals>().set_pq_imported_private_qr(slint::Image::default());
    });

    cb!(Ui, on_copy_value, |w, s, value: SharedString| {
        let _ = &mut s;
        let ok = platform::set_clipboard_text(value.as_str());
        println!("cb: copy-value len={}", value.len());
        show_toast(&w, if ok { "Copied" } else { "Copy failed" });
    });

    // Spending material (audit M3) — concealed/local-only/expiring clipboard,
    // never the plain broadcast one. Length only, as ever; never the value.
    cb!(PrivateKeys, on_copy_secret, |w, s, value: SharedString| {
        let _ = &mut s;
        let ok = platform::set_clipboard_secret(value.as_str());
        println!("cb: copy-secret len={}", value.len());
        show_toast(&w, if ok { "Copied" } else { "Copy failed" });
    });

    cb!(Ui, on_go_home, |w, s| {
        s.clear_reveal(&w);
        s.go_home_or_list(&w);
    });

    cb!(Ui, on_open_notebooks, |w, s| {
        // Leaving the open notebook: everything that was on screen counts
        // as read, so the list badge only flags what arrived since.
        if let Some(store) = s.store.as_mut() {
            if store.mark_seen() > 0 {
                s.save_store();
            }
        }
        w.global::<Ui>().set_status("".into());
        s.update_notebook_list(&w);
        w.global::<Ui>().set_screen(Screen::Notebooks);
    });

    cb!(Notebooks, on_open_notebook, |w, s, index: i32| {
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        s.nb_index = index.max(0) as u32;
        println!("cb: open-notebook index={}", s.nb_index);
        match s.activate(&material, false) {
            Ok(()) => {
                s.update_home(&w);
                w.global::<Ui>().set_screen(Screen::Home); // paint first — the scan runs in the background
                s.refresh_async(&w);
                s.spending_refresh_async(&w); // CHANGE 5: was missing — Sal's finding
            }
            Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
        }
    });

    cb!(Notebooks, on_create_notebook, |w, s| {
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
        w.global::<AccountPicker>().set_nb_create_name("".into());
        s.show_notebook_picker(&w, 0, "notebook");
    });

    cb!(Notebooks, on_nb_rename_start, |w, s, index: i32, _display: SharedString| {
        let _ = &mut s;
        // Prefill the RAW local name (the display name may be the address
        // short form, which must not become a name by accident).
        let raw = s
            .notebooks
            .as_ref()
            .and_then(|ix| ix.get(s.account, index.max(0) as u32))
            .map(|m| m.name.clone())
            .unwrap_or_default();
        w.global::<Modals>().set_nb_rename_input(raw.into());
        w.global::<Ui>().set_nb_rename_index(index);
    });

    cb!(Modals, on_nb_rename_save, |w, s, name: SharedString| {
        let sel = w.global::<Ui>().get_nb_rename_index();
        if sel < 0 {
            return;
        }
        w.global::<Ui>().set_nb_rename_index(-1);
        w.global::<Modals>().set_nb_rename_input("".into());
        let index = sel as u32;
        let account = s.account;
        if let Some(ix) = s.notebooks.as_mut() {
            ix.rename(account, index, name.as_str());
            s.save_notebooks();
            println!("cb: rename-notebook index={index}");
        }
        s.update_notebook_list(&w);
        if s.ident.as_ref().map(|i| i.index) == Some(index) {
            w.global::<Home>().set_notebook_title(s.notebook_display_name(index).into());
        }
    });

    cb!(Ui, on_nb_rename_cancel, |w, s| {
        let _ = &mut s;
        w.global::<Ui>().set_nb_rename_index(-1);
        w.global::<Modals>().set_nb_rename_input("".into());
    });

    cb!(Notebooks, on_nb_archive, |w, s, index: i32, archived: bool| {
        let index = index.max(0) as u32;
        if s.notebooks.is_none() {
            return;
        }
        if archived {
            // One guard only: funds never disappear from view silently —
            // sweep first. Archiving EVERY notebook is allowed (the list
            // shows its empty state); Restore brings any of them back.
            let balance = s.notebook_store(index).map(|st2| st2.balance()).unwrap_or(0);
            if balance > 0 {
                w.global::<Ui>().set_status(
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
        w.global::<Ui>().set_status("".into());
        s.update_notebook_list(&w);
    });

    cb!(Home, on_toggle_sender, |w, s, key: SharedString, excluded: bool| {
        let Some(store) = s.store.as_mut() else { return };
        store.set_excluded(key.as_str(), excluded);
        let hidden = store.excluded_senders.len();
        println!("cb: toggle-sender excluded={excluded} hidden={hidden}");
        s.save_store();
        s.update_home(&w);
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
                    if w.global::<Ui>().get_screen() == Screen::Home {
                        let mut s = st.borrow_mut();
                        if s.ident.is_some() {
                            // MUST be the async refresh: slint timers keep
                            // firing while the app is BACKGROUNDED, and a
                            // blocking chain call here parks the main thread
                            // inside a timer callback — iOS's scene-update
                            // watchdog then kills the app (0x8BADF00D, the
                            // builds 3–9 "crashed in the background /
                            // after resuming" reports; root-caused from
                            // device .ips logs 2026-07-19).
                            println!("cb: auto-refresh");
                            s.refresh_async(&w);
                        }
                    }
                }
            },
        );
    }

    // Design-preview harness: `CN_PREVIEW=<screen-name>` boots straight into
    // a funding screen with mock data so the UI can be screenshotted and
    // iterated without wiring or clicking through onboarding. Dev-only.
    if let Ok(scr) = std::env::var("CN_PREVIEW") {
        if let Some(n) = screen_by_name(scr.trim()) {
            preview_mock(&window);
            window.global::<Ui>().set_screen(n);
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
                win.global::<Modals>().set_ready(true);
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

    // iCloud-contacts feature: live cross-device sync while this device is
    // already running (boot-time sync happened above, before the window
    // existed). A no-op registration off Apple platforms, or when the OS
    // has no entitlement/iCloud account (see icloud.rs) — the callback can
    // fire on any thread, so it only ever schedules the real work back onto
    // the UI thread via the same upgrade_in_event_loop trampoline every
    // other async result uses.
    {
        let weak = window.as_weak();
        icloud::start_observer(move || {
            let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_icloud_contacts());
        });
    }

    window.run().expect("event loop");
    let _ = safe_area_timer;
}

/// Populate every external-funding screen with representative mock data for
/// the `CN_PREVIEW` design harness.
fn preview_mock(w: &AppWindow) {
    // Screen 25 is content-driven, so without this it previews blank. Staged
    // as the About entry specifically, since that is the one the Slint
    // attribution rides on and the preview is how we check it still renders.
    w.global::<Info>().set_info_title("About".into());
    w.global::<Info>().set_info_body(about_body().as_str().into());
    w.global::<Info>().set_info_show_slint(true);
    w.global::<Ui>().set_directed(true);
    w.global::<Compose>().set_gift_sats("330".into());
    w.global::<Ui>().set_backup_words(
        " 1. legal      2. winner    3. thank\n 4. year       5. wave      6. sausage\n 7. worth      8. useful    9. dawn\n10. absorb    11. pledge   12. yellow\n"
            .into(),
    );
    w.global::<Ui>().set_fund_external(true);
    w.global::<Ui>().set_funding_ready(true);
    w.global::<Sweep>().set_funding_summary("taproot · bcrt1p2caq…6hrewe · 2 coins · 220,000 sats".into());
    w.global::<Ui>().set_change_amount("Change to funding wallet".into());
    w.global::<FundingWalletScreen>().set_funding_descriptor("tr([a1b2c3d4/86h/1h/0h]tpub…/<0;1>/*)".into());
    w.global::<FundingWalletScreen>().set_funding_feedback(
        "Taproot wallet · fingerprint a1b2c3d4 · first address\nbcrt1p2caqg0ht8m7dykfrx2lnrcc85kxs09m3vgur9fl6emljxktnu7es6hrewe"
            .into(),
    );
    w.global::<FundingWalletScreen>().set_funding_valid(true);
    w.global::<Ui>().set_to_label("bcrt1pxs94vakt8gnq…rqmeyu58".into());
    w.global::<Compose>().set_compose_text("Happy birthday! Paid from cold storage.".into());
    w.global::<Compose>().set_rate_text("2".into());
    // Worst case on purpose: EVERY row of the structured cost card
    // populated, including the dust-rule fold split (Sal's build-17
    // follow-up — the card replaced the long wrapped cost-line string).
    set_cost_card(
        w,
        "1 chunk · ~180 vB".to_string(),
        "~360 sats (~$0.26)".to_string(),
        "+330 sats".to_string(),
        "+330 sats".to_string(),
        Some((227, 587)),
    );

    let coins = [
        SpendCoin { outpoint: "aa:0".into(), value: "200,000".into(), confirmed: true, selected: true, txid_short: "aaaa…aaaa".into(), explorer: "".into(), tag: "".into() },
        SpendCoin { outpoint: "bb:1".into(), value: "20,000".into(), confirmed: false, selected: false, txid_short: "bbbb…bbbb".into(), explorer: "".into(), tag: "".into() },
    ];
    w.global::<Ui>().set_spend_coins(VecModel::from_slice(&coins));
    w.global::<Ui>().set_spend_title("Spending 1 coin · 200,000 sats".into());
    w.global::<Ui>().set_spend_expanded(true);

    w.global::<ExportPsbt>().set_psbt_qr(qr::qr_image("UR:CRYPTO-PSBT/1-1/HKADCSJNCPFGAXHDMOCKPREVIEWFRAME").unwrap_or_default());
    w.global::<ExportPsbt>().set_psbt_cost_line("fee 360 sats · 1 input · 180 vB".into());
    w.global::<ExportPsbt>().set_psbt_frame_label("frame 1 / 1".into());

    w.global::<Ui>().set_psbt_signed(true);
    w.global::<Confirm>().set_confirm_note("Happy birthday! Paid from cold storage.".into());
    w.global::<Confirm>().set_confirm_fee_line("360 sats · 2.0 sat/vB".into());
    w.global::<Confirm>().set_confirm_locktime_line("Locktime 146209 · block height".into());
    w.global::<Ui>().set_confirm_warn("".into());
    w.global::<Confirm>().set_confirm_txid("aaaaaaaabbbbbbbbccccccccddddddddaaaaaaaabbbbbbbbccccccccdddddddd".into());
    w.global::<Confirm>().set_confirm_context("Directed note · regtest".into());
    let ins = [PsbtRow {
        title: "bcrt1p2caqg0ht8m7dykfrx2lnrcc85kx…".into(),
        subtitle: "aaaaaaaa…aaaaaaaa : 0".into(),
        amount: "200,000".into(),
        kind: "input".into(),
    }];
    w.global::<Confirm>().set_confirm_inputs(VecModel::from_slice(&ins));
    let outs = [
        PsbtRow { title: "".into(), subtitle: "OP_RETURN · PNTE note".into(), amount: "0".into(), kind: "note".into() },
        PsbtRow { title: "bcrt1pxs94vakt8gnqrwhuxdscwkx5e…".into(), subtitle: "directed recipient".into(), amount: "330".into(), kind: "recipient".into() },
        PsbtRow { title: "bcrt1p8wpt9v4frpf3tkn0srd97pks…".into(), subtitle: "your notebook (keeps the note yours)".into(), amount: "330".into(), kind: "self".into() },
        PsbtRow { title: "bcrt1p2caqg0ht8m7dykfrx2lnrcc…".into(), subtitle: "change back to the funding wallet".into(), amount: "198,980".into(), kind: "change".into() },
    ];
    w.global::<Confirm>().set_confirm_outputs(VecModel::from_slice(&outs));

    let wallets = [
        FundingWalletRow { id: "aa".into(), label: "Signer · bc1p5cyxnux…".into(), meta: "taproot · 220,000 sats · 2 coins".into(), active: true, change_addr: "bc1p3qkhfe…uhk7".into(), coins: VecModel::from_slice(&[] as &[SpendCoin]), coin_title: "".into(), expanded: false },
        FundingWalletRow { id: "bb".into(), label: "Sparrow hot wallet".into(), meta: "segwit · 45,000 sats · 1 coin".into(), active: false, change_addr: "bc1qm34ls…dqfw".into(), coins: VecModel::from_slice(&[] as &[SpendCoin]), coin_title: "".into(), expanded: false },
        FundingWalletRow { id: "cc".into(), label: "segwit · tb1qr8k2p9…".into(), meta: "segwit · tap to scan for funds".into(), active: false, change_addr: "".into(), coins: VecModel::from_slice(&[] as &[SpendCoin]), coin_title: "".into(), expanded: false },
    ];
    w.global::<Ui>().set_funding_wallets(VecModel::from_slice(&wallets));
}

/// Render each screen to `<out_dir>/screen-<name>.png` via the software
/// renderer, with no on-screen window — for headless design iteration.
/// macOS-only.
#[cfg(target_os = "macos")]
fn render_previews(w: u32, h: u32, screens: &[Screen], out_dir: &str) {
    use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType, Rgb565Pixel};
    use std::rc::Rc;

    std::fs::create_dir_all(out_dir).expect("create out_dir");

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
    // No safe-area pass runs headless — lift the splash cover directly.
    app.global::<Modals>().set_ready(true);

    for &n in screens {
        let name = screen_name(n);
        preview_mock(&app);
        app.global::<Ui>().set_screen(n);
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
        let path = format!("{out_dir}/screen-{name}.png");
        let file = std::fs::File::create(&path).expect("create png");
        let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w, h);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        enc.write_header().unwrap().write_image_data(&rgb).unwrap();
        eprintln!("rendered screen {name} -> {path}");
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

#[cfg(test)]
mod tests;
