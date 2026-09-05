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
    /// Argon2id preset for the passphrase layer of the note being composed
    /// (the compose panel's "Unlock cost" pills). Persisted in config.json
    /// like `pq_level`; the note itself still records the parameters it was
    /// sealed with, so this is only the default for the NEXT note.
    pq_pw_cost: app_core::notes_core::pq::PwCost,
    /// The user switched the ML-KEM hybrid OFF by hand. The hybrid defaults
    /// ON whenever a quantum key is available (2026-09-05); this keeps a
    /// deliberate opt-out from being re-enabled on the next recipient change
    /// or the next run (persisted in config.json as `pq_mlkem_off`).
    pq_mlkem_user_off: bool,
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
    /// `apply_wallet_stores_refresh_result`'s own (fp8, network, account)
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
            "pq_pw_cost": self.pq_pw_cost.as_str(),
            "pq_mlkem_off": self.pq_mlkem_user_off,
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
            pq_pw_cost: app_core::notes_core::pq::PwCost::DEFAULT,
            pq_mlkem_user_off: false,
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













// Result of the deferred auto-unlock is posted straight to `post` (U5) —
// no intermediate static needed now that a job only ever exists once there
// IS a result.
















// ---- CHANGE 4: async wallet-tx broadcast (2026-07-17) ----
//
// consolidate / sweep / wallet-consolidate / psbt-broadcast all build+sign
// synchronously (fast, no network) exactly as before; only the
// `client.broadcast()` POST moves to a worker thread — the part that used
// to visibly freeze the confirm button on a slow connection. Each flow's
// `apply_*_result` replays its EXACT pre-existing Ok/Err bookkeeping, once,
// from the worker's result via `post` (U5), which also clears the shared
// busy flag (`State::clear_wallet_tx_busy`) — same shape every compose
// path uses (`State::clear_compose_busy`). `State.wallet_tx_busy` is the
// shared re-entrancy guard; every entry point returns early when it's set.


































// ---- Async compose send (2026-07-16) ----
//
// Each of the three compose send paths (notebook / spending / mixed) builds
// + signs synchronously (fast, no network) exactly as before, then hands
// ONLY the `client.broadcast()` POST to a worker thread — the part that
// used to visibly freeze the Sign button on a slow connection. The UI-
// thread `apply_*_compose_result` functions replay each path's EXACT
// pre-existing Ok/Err bookkeeping, now run once from the worker's result via
// `post` (U5), which also clears the shared busy/progress state
// (`State::clear_compose_busy`). The external/watch/fund-external route is
// untouched — it already hands off to the sign screen instead of
// broadcasting itself.








































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
    // Type scale: 1.0 on desktop, base × OS font scale on phones
    // (`platform::type_scale`; every font-size in the UI multiplies by it).
    apply_type_scale(&window);

    // Quantum keys (screen 29) level-picker captions — pinned copy from
    // `passphrase::MlKemLevel::describe()`, set once (never changes at
    // runtime, so no need to re-derive it on every screen open).
    window.global::<QuantumKeys>().set_pq_desc_512(app_core::passphrase::MlKemLevel::MlKem512.describe().into());
    window.global::<QuantumKeys>().set_pq_desc_768(app_core::passphrase::MlKemLevel::MlKem768.describe().into());
    window.global::<QuantumKeys>().set_pq_desc_1024(app_core::passphrase::MlKemLevel::MlKem1024.describe().into());

    // EditOps global wiring — src/editops.rs (U4, PLAN-graffito-app-arch.md).
    editops::wire(&window);
    // Capture-proof window while a secret is on screen (app.slint decides
    // which screens; this just applies it to the platform window).
    {
        let w = window.as_weak();
        window.global::<Ui>().on_secure_screen_changed(move |on| {
            if let Some(win) = w.upgrade() {
                platform::set_secure_screen(win.window(), on);
            }
        });
    }

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
            // result comes back via `post` (U5) — the same trampoline shape
            // the async scans use.
            let w = window.as_weak();
            slint::Timer::single_shot(std::time::Duration::from_millis(700), move || {
                let weak = w.clone();
                std::thread::spawn(move || {
                    let r = keychain::load_secret_protected(
                        KEYCHAIN_ACCOUNT,
                        "unlock your Graffito identity",
                    );
                    post(&weak, move |w, st| st.apply_unlock_result(w, r));
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
                let $w = weak.unwrap();
                let mut $s = st.borrow_mut();
                $body
            });
        }};
    }

    // Onboarding's "Restore saved key" door. This is the ONLY place a user
    // meets the Face ID prompt for the stored key on a cold start, and it is
    // reached by a tap — so it can block for as long as it likes.
    // Written out rather than via cb!: that macro takes a State borrow for the
    // whole body, and this body sits on a biometric prompt that can last as
    // long as the user does. The prompt waits on a WORKER thread — on Android
    // the native thread is also the input-draining thread, and blocking it
    // trips the 5 s input watchdog (2026-09-05) — and the State borrow happens
    // only in the posted continuation.
    {
        let weak = window.as_weak();
        window.global::<Onboarding>().on_restore_saved_key(move || {
            println!("cb: restore-saved-key");
            let weak = weak.clone();
            std::thread::spawn(move || {
                let r = keychain::load_secret_gated(KEYCHAIN_ACCOUNT, "unlock your Graffito identity");
                post(&weak, move |w, st| {
                    if let Some(m) = apply_restore_result(w, r) {
                        st.activate_restored(w, m, true); // onboarding exit
                    }
                });
            });
        });
    }

    cb!(Onboarding, on_door_import, |w, s| { s.on_door_import(&w) });

    // Creating a seed is now TWO steps: this door only records the length and
    // opens the entropy-source screen (27). Generating immediately would deny
    // the user the one choice they may actually care about — where the
    // randomness came from.
    cb!(Onboarding, on_door_create, |w, s, words: i32| { s.on_door_create(&w, words) });

    cb!(EntropySource, on_pick_entropy_source, |w, s, kind: SharedString| { s.on_pick_entropy_source(&w, kind) });

    cb!(Ui, on_dice_roll, |w, s, face: i32| { s.on_dice_roll(&w, face) });

    cb!(Dice, on_dice_undo, |w, s| { s.on_dice_undo(&w) });

    cb!(Ui, on_dice_clear, |w, s| { s.on_dice_clear(&w) });

    cb!(Dice, on_dice_continue, |w, s| { s.on_dice_continue(&w) });

    // "New words" (↻) on the backup screen: reroll a fresh mnemonic of the same
    // length, in case the user didn't like the ones shown.
    cb!(BackupWords, on_regenerate_words, |w, s| { s.on_regenerate_words(&w) });

    // iCloud backup toggle (backup screen + Settings). Sets the sync mode; if a
    // key is already stored this session, re-stores it with the new mode.
    cb!(Ui, on_set_icloud_backup, |w, s, enabled: bool| { s.on_set_icloud_backup(&w, enabled) });

    // Funding-unification M3: "Separate spending wallet" toggle. Persisted
    // per (identity, account) — M3.1: in the notebooks index, shared by
    // every notebook of the account — survives restarts, resets to off on
    // a fresh identity.
    cb!(Settings, on_set_spending_enabled, |w, s, on: bool| { s.on_set_spending_enabled(&w, on) });

    cb!(Settings, on_spending_refresh, |w, s| { s.on_spending_refresh(&w) });

    // "Scan for existing funds…" manual deep scan (network-efficiency
    // follow-up): gap-20 full discovery for a seed used elsewhere with gaps
    // the shallow automatic scan wouldn't reach.
    cb!(Coins, on_spending_scan_deep, |w, s| { s.on_spending_scan_deep(&w) });

    // (`on_restore_icloud` lived here until 2026-07-26. A synced key is a
    // saved key — the same `load_secret_protected` call behind the same
    // onboarding door — so the separate handler only duplicated the door and
    // left different state behind. See `activate_restored`.)

    cb!(BackupWords, on_backup_continue, |w, s| { s.on_backup_continue(&w) });

    cb!(Quiz, on_quiz_submit, |w, s, answer: SharedString| { s.on_quiz_submit(&w, answer) });

    cb!(ImportKey, on_import_changed, |w, s, text: SharedString| { s.on_import_changed(&w, text) });

    cb!(ImportKey, on_import_confirm, |w, s, text: SharedString| { s.on_import_confirm(&w, text) });

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
    cb!(ImportKey, on_paste_import, |w, s| { s.on_paste_import(&w) });

    // Paste into the compose note (appends clipboard to the current text).
    cb!(Ui, on_paste_compose, |w, s| { s.on_paste_compose(&w) });

    cb!(ImportKey, on_import_file, |w, s| { s.on_import_file(&w) });

    cb!(Ui, on_refresh, |w, s| { s.on_refresh(&w) });

    // The ONE async trampoline (U5, PLAN-graffito-app-arch.md): every
    // worker thread that finishes a background job — a scan, a broadcast,
    // a probe, the deferred auto-unlock, an iCloud-contacts merge — posts a
    // boxed closure onto the shared queue (`pending::post`) and invokes
    // this SAME callback from the event loop; `State::apply_pending` runs
    // every queued job in arrival order with full State access. Replaces
    // the 13 separate per-kind trampolines this used to be (one Slint
    // callback + one `on_apply_pending_<kind>` forwarder + one
    // `apply_<kind>_result(s)` drain each).
    cb!(Ui, on_apply_pending, |w, s| { s.apply_pending(&w) });

    cb!(Home, on_open_note, |w, s, id: SharedString| { s.on_open_note(&w, id) });

    // Screen 5's "Unlock" tap. Never logs the typed passphrase — only
    // ok/err, matching the `cb:` log contract's "no secrets in logs" rule.
    cb!(Note, on_unlock_note, |w, s| { s.on_unlock_note(&w) });

    cb!(Note, on_open_note_web, |w, s| { s.on_open_note_web(&w) });

    cb!(Ui, on_copy_text, |w, s, kind: SharedString, text: SharedString| { s.on_copy_text(&w, kind, text) });

    cb!(Compose, on_set_fee_tier, |w, s, tier: i32| { s.on_set_fee_tier(&w, tier) });

    cb!(Settings, on_open_coins, |w, s| { s.on_open_coins(&w) });

    // Coins screen "spending" segment: scan on first view (data otherwise
    // stays "as of the last scan", matching the notebook segment's rule).
    cb!(Ui, on_set_coins_segment, |w, s, seg: SharedString| { s.on_set_coins_segment(&w, seg) });

    cb!(Ui, on_open_activity, |w, s| { s.on_open_activity(&w) });

    // Universal confirm screen (2026-07-17): stage A resolves the raw hex
    // (locally cached, or fetched) and hands off to screen 26 —
    // `act_pending_ref` is no longer set here for the broadcast itself
    // (moved to stage B, `on_confirm_broadcast`/`PendingPayload::
    // Rebroadcast`, mirroring `on_act_bump_confirm` below); it's only
    // touched transiently to guard sub-case (b)'s own network fetch
    // against a double-tap, cleared the moment the fetch result lands.
    cb!(Ui, on_act_retry, |w, s, ref_id: SharedString, is_note: bool| { s.on_act_retry(&w, ref_id, is_note) });

    cb!(Activity, on_act_bump_open, |w, s, ref_id: SharedString, is_note: bool| { s.on_act_bump_open(&w, ref_id, is_note) });

    cb!(Modals, on_act_bump_rate_changed, |w, s, rate_s: SharedString| { s.on_act_bump_rate_changed(&w, rate_s) });

    // Universal confirm screen (2026-07-17): the dialog stays for rate
    // entry only — its primary button ("Sign…") now BUILDS + SIGNS the
    // replacement (stage A) and hands off to screen 26 instead of
    // broadcasting directly. `act_pending_ref` moves to stage B
    // (`on_confirm_broadcast`/`PendingPayload::Bump`, the actual
    // broadcast POST) — NOT set here, so it must never gate stage A;
    // `pending_broadcast`/`wallet_tx_busy` are the re-entrancy guard for
    // the build+navigate step instead.
    cb!(Modals, on_act_bump_confirm, |w, s| { s.on_act_bump_confirm(&w) });

    cb!(Ui, on_act_explorer, |w, s, url: SharedString| { s.on_act_explorer(&w, url) });

    cb!(Settings, on_open_source, |w, s| { s.on_open_source(&w) });

    cb!(Home, on_open_note_web_url, |w, s, url: SharedString| { s.on_open_note_web_url(&w, url) });

    cb!(Home, on_compose_open, |w, s| { s.on_compose_open(&w) });

    // Send-to picker header "Sync now" (sync-status UI, 2026-07-20).
    cb!(Contacts, on_sync_contacts_now, |w, s| { s.on_sync_contacts_now(&w) });

    cb!(Settings, on_sweep_open, |w, s| { s.on_sweep_open(&w) });

    // Funding-unification M3: Settings spending-wallet card "Sweep notebook
    // funds here…" — routes through the EXISTING sweep flow (screen 7 →
    // 16), just pre-picking the destination = the spending wallet's next
    // receive address. `pending_spending_sweep_index` tells on_sweep's
    // success handler to mark that address used (fresh-address discipline).
    cb!(Settings, on_spending_sweep_here, |w, s| { s.on_spending_sweep_here(&w) });

    // CHANGE 3 (2026-07-17) / universal confirm screen follow-up: the
    // Coins screen's spending segment "Consolidate spending coins…"
    // button IS the trigger now (the confirm modal is gone) — build +
    // sign the all-P2WPKH merge directly (byte-exact mixed estimator, one
    // P2WPKH output at the next fresh spending receive address) and hand
    // off to the universal confirm screen. Stage B
    // (`on_confirm_broadcast`/`PendingPayload::SpendingConsolidate`) is
    // the pre-existing thread-spawn, moved verbatim.
    cb!(Coins, on_spending_consolidate_open, |w, s| { s.on_spending_consolidate_open(&w) });

    cb!(Ui, on_consolidate_open, |w, s| { s.on_consolidate_open(&w) });

    cb!(Coins, on_consolidate_wallet_open, |w, s| { s.on_consolidate_wallet_open(&w) });

    cb!(Sweep, on_set_sweep_tier, |w, s, tier: i32| { s.on_set_sweep_tier(&w, tier) });

    cb!(Sweep, on_sweep_rate_changed, |w, s| { s.on_sweep_rate_changed(&w) });

    cb!(Sweep, on_toggle_sweep_fund_external, |w, s, on: bool| { s.on_toggle_sweep_fund_external(&w, on) });

    cb!(Sweep, on_sweep_send, |w, s| { s.on_sweep_send(&w) });

    cb!(Contacts, on_pick_contact, |w, s, addr: SharedString| { s.on_pick_contact(&w, addr) });

    cb!(Note, on_reply_to_note, |w, s| { s.on_reply_to_note(&w) });

    cb!(Note, on_reply_all_to_note, |w, s| { s.on_reply_all_to_note(&w) });

    cb!(Compose, on_add_recipient_open, |w, s| { s.on_add_recipient_open(&w) });

    cb!(Compose, on_remove_chip, |w, s, addr: SharedString| { s.on_remove_chip(&w, addr) });

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

    cb!(Ui, on_start_rename, |w, s, addr: SharedString, name: SharedString, synced: bool| { s.on_start_rename(&w, addr, name, synced) });

    cb!(Modals, on_save_rename, |w, s, name: SharedString| { s.on_save_rename(&w, name) });

    cb!(Ui, on_cancel_rename, |w, s| { s.on_cancel_rename(&w) });

    // Contact quantum key: paste/file -> `pqkeys::set_contact_pq_key` ->
    // persist through the normal contacts save path (the field already
    // rides `Contact` serde + the iCloud blob). Applied immediately (not
    // deferred to the dialog's own Save), same as the "Save to iCloud"
    // checkbox — both are contact-record edits independent of the name.
    cb!(Ui, on_contact_pq_set, |w, s, input: SharedString| { s.on_contact_pq_set(&w, input) });

    cb!(Ui, on_contact_pq_remove, |w, s| { s.on_contact_pq_remove(&w) });

    cb!(Modals, on_contact_pq_file, |w, s| { s.on_contact_pq_file(&w) });

    cb!(Contacts, on_confirm_remove, |w, s, addr: SharedString, name: SharedString| { s.on_confirm_remove(&w, addr, name) });

    cb!(Ui, on_cancel_remove, |w, s| { s.on_cancel_remove(&w) });

    cb!(Modals, on_remove_contact, |w, s, addr: SharedString| { s.on_remove_contact(&w, addr) });

    cb!(Ui, on_compose_changed, |w, s| { s.on_compose_changed(&w) });

    // Post-quantum "Security" section (compose screen 6). The Generate
    // button is the ONLY door to a verified (certified quantum-resistant)
    // passphrase — see passphrase::generate's doc and the
    // SecurityChoice::passphrase_verified rule it exists to satisfy.
    cb!(Compose, on_pq_generate_passphrase, |w, s| { s.on_pq_generate_passphrase(&w) });

    // Any edit — typed, pasted, or a generated phrase touched afterward —
    // is verified only when it EXACTLY matches the last generated text;
    // anything else (including reverting back to a substring of it) reads
    // as unverified, matching `passphrase_verified`'s doc: "unedited
    // since".
    cb!(Compose, on_pq_passphrase_changed, |w, s, text: SharedString| { s.on_pq_passphrase_changed(&w, text) });

    cb!(Compose, on_pq_mlkem_toggled, |w, s, _on: bool| { s.on_pq_mlkem_toggled(&w, _on) });
    cb!(Compose, on_pq_pw_cost_changed, |w, s, cost: SharedString| { s.on_pq_pw_cost_changed(&w, cost) });

    // Security panel opened (Sal 2026-08-22, PLAN-graffito-self-pw.md): the
    // sanctioned user-initiated door for lazily loading a SELF-note's
    // imported quantum key this session — the ML-KEM switch itself starts
    // disabled (`pq-mlkem-available` false) until `State.pq_imported` is
    // populated, so it can't be the trigger; opening the panel is the
    // earliest tap available. A no-op on every OTHER repaint path (already
    // cached, or a directed note that never needs this key at all) —
    // `ensure_pq_imported_loaded` itself short-circuits once loaded. Never
    // called on close (LAUNCH-PATH rule: only ever from a deliberate tap).
    cb!(Compose, on_pq_panel_toggled, |w, s, opened: bool| { s.on_pq_panel_toggled(&w, opened) });

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
    cb!(PayFrom, on_toggle_coin, |w, s, source: SharedString, outpoint: SharedString| { s.on_toggle_coin(&w, source, outpoint) });

    cb!(PayFrom, on_set_coin_strategy, |w, s, strategy: i32| { s.on_set_coin_strategy(&w, strategy) });

    // Watchdog fix (2026-07-20): both ↻ taps used to rescan every active
    // notebook synchronously on the UI thread — see
    // `wallet_stores_refresh_async`'s doc comment. The spending-wallet
    // kickoff + notebook-list rebuild now happen in
    // `apply_wallet_stores_refresh_result` once the scan actually lands.
    cb!(Ui, on_refresh_coins, |w, s| { s.on_refresh_coins(&w) });

    // Notebook-list (main screen) header ↻: rescan every active notebook and
    // rebuild the list so balances / note counts / unread badges are current.
    cb!(Ui, on_refresh_notebooks, |w, s| { s.on_refresh_notebooks(&w) });

    // First-run disclaimer accepted → persist + reveal the real first screen.
    cb!(Terms, on_accept_terms, |w, s| { s.on_accept_terms(&w) });

    // About / Privacy / Help / Q&A — one info screen, content set per button.
    cb!(Settings, on_open_info, |w, s, kind: slint::SharedString| { s.on_open_info(&w, kind) });

    // ---------- external funding (PSBT) ----------
    cb!(Ui, on_toggle_fund_external, |w, s, on: bool| { s.on_toggle_fund_external(&w, on) });

    // Funding-unification M3: compose "Pay from" picker — "notebook" or
    // "spending". External wallets are picked via use-funding-wallet
    // directly (they need a scan first, same as before this milestone).
    cb!(Ui, on_set_pay_from, |w, s, kind: SharedString| { s.on_set_pay_from(&w, kind) });

    cb!(Ui, on_open_funding, |w, s| { s.on_open_funding(&w) });

    // funding-unification: compose's compact "Pay from" row → the dedicated
    // picker/coin-control/change-address screen (20). Independent-expand
    // rework (2026-07-18, Sal's iPhone feedback #3): on EVERY open, re-derive
    // which sections start expanded from what's actually selected right now
    // (never persisted across visits) — every source holding at least one
    // selected coin starts open so the user sees it, the rest start
    // collapsed. This is the ONLY place auto-selection-driven expansion
    // happens; a header tap thereafter only shows/hides (`on_payfrom_expand`).
    cb!(Compose, on_open_funding_screen, |w, s| { s.on_open_funding_screen(&w) });

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
    cb!(PayFrom, on_payfrom_expand, |w, s, source: SharedString| { s.on_payfrom_expand(&w, source) });

    // Change now lives on its own screen (21), reached from a second
    // compose nav row below "Pay from" (funding-unification UI rework).
    cb!(Compose, on_change_open, |w, s| { s.on_change_open(&w) });

    cb!(Change, on_change_pick, |w, s, choice: SharedString| { s.on_change_pick(&w, choice) });

    // Screen 20's header ↻: re-scan the notebook + (if enabled) the spending
    // wallet on worker threads, same async/trampoline pattern as
    // refresh_async/spending_refresh_async — never blocks the UI thread.
    // Each landing logs its own `cb: funding-refresh …` (see
    // apply_refresh_result / apply_spending_refresh_result).
    cb!(PayFrom, on_funding_refresh, |w, s| { s.on_funding_refresh(&w) });

    cb!(FundingWallets, on_add_funding_wallet, |w, s| { s.on_add_funding_wallet(&w) });

    cb!(FundingWallets, on_use_funding_wallet, |w, s, id: SharedString| { s.on_use_funding_wallet(&w, id) });

    cb!(FundingWallets, on_remove_funding_wallet, |w, s, id: SharedString| { s.on_remove_funding_wallet(&w, id) });

    cb!(FundingWallets, on_refresh_funding_wallet, |w, s, id: SharedString| { s.on_refresh_funding_wallet(&w, id) });

    cb!(FundingWallets, on_fund_rename_start, |w, s, id: SharedString, label: SharedString| { s.on_fund_rename_start(&w, id, label) });

    cb!(Modals, on_fund_rename_save, |w, s, text: SharedString| { s.on_fund_rename_save(&w, text) });

    cb!(Ui, on_fund_rename_cancel, |w, s| { s.on_fund_rename_cancel(&w) });

    cb!(FundingWalletScreen, on_funding_changed, |w, s, text: SharedString| { s.on_funding_changed(&w, text) });

    cb!(FundingWalletScreen, on_funding_use, |w, s| { s.on_funding_use(&w) });

    cb!(FundingWalletScreen, on_funding_file, |w, s| { s.on_funding_file(&w) });

    cb!(Ui, on_funding_import_ur, |w, s, text: SharedString| { s.on_funding_import_ur(&w, text) });

    cb!(Ui, on_funding_clear, |w, s| { s.on_funding_clear(&w) });

    cb!(Compose, on_fund_build, |w, s| { s.on_fund_build(&w) });

    cb!(ExportPsbt, on_psbt_save, |w, s| { s.on_psbt_save(&w) });

    cb!(Ui, on_psbt_copy, |w, s| { s.on_psbt_copy(&w) });

    cb!(ExportPsbt, on_psbt_goto_import, |w, s| { s.on_psbt_goto_import(&w) });

    cb!(Ui, on_psbt_loaded, |w, s, text: SharedString| { s.on_psbt_loaded(&w, text) });

    cb!(ImportSignedPsbt, on_psbt_import_file, |w, s| { s.on_psbt_import_file(&w) });

    cb!(Ui, on_psbt_broadcast, |w, s| { s.on_psbt_broadcast(&w) });

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
    cb!(Confirm, on_confirm_broadcast, |w, s| { s.on_confirm_broadcast(&w) });

    cb!(Ui, on_confirm_cancel, |w, s| { s.on_confirm_cancel(&w) });

    cb!(Compose, on_compose_send, |w, s| { s.on_compose_send(&w) });

    // Funding-unification M3: the internal spending-wallet compose path —
    // build the SAME funded-note shape the external path uses
    // (`build_funding_psbt_amount`), sign every P2WPKH input in-process
    // (`sign_own_wpkh_inputs` — no PSBT export/import round trip), and
    // broadcast in one tap. Mirrors `examples/cli.rs`'s `note-spend-funded`
    // recipe exactly.
    cb!(Compose, on_spending_compose_send, |w, s| { s.on_spending_compose_send(&w) });

    // Funding-unification UI rework (2026-07-16): the selection on the
    // Pay-from screen spans more than one wallet — assemble ONE mixed-
    // source PSBT (notebook + spending + at most one external wallet),
    // sign our own inputs in-app, and either broadcast directly (no
    // external coin involved) or route the partially-signed PSBT through
    // the existing external-sign screens 13/14 (the funded-sweep test in
    // app-core's psbt_build already proves that pattern: our own
    // signatures plus an external signer's, on one PSBT).
    cb!(Compose, on_compose_send_mixed, |w, s| { s.on_compose_send_mixed(&w) });

    cb!(Notebooks, on_settings_open, |w, s| { s.on_settings_open(&w) });

    cb!(Settings, on_open_account_picker, |w, s| { s.on_open_account_picker(&w) });

    cb!(AccountPicker, on_accounts_page, |w, s, delta: i32| { s.on_accounts_page(&w, delta) });

    cb!(AccountPicker, on_pick_account, |w, s, idx: i32| { s.on_pick_account(&w, idx) });

    cb!(Ui, on_account_cancel, |w, s| { s.on_account_cancel(&w) });

    cb!(Modals, on_reset_identity, |w, s| { s.on_reset_identity(&w) });

    cb!(Ui, on_reveal_hide, |w, s| { s.on_reveal_hide(&w) });

    cb!(Settings, on_set_network, |w, s, net: SharedString| { s.on_set_network(&w, net) });

    cb!(Settings, on_set_chunk, |w, s, t: SharedString| { s.on_set_chunk(&w, t) });

    cb!(Settings, on_set_locktime, |w, s, mode: SharedString, height: SharedString| { s.on_set_locktime(&w, mode, height) });

    // Compose screen (6) locktime override panel — a per-tx override of
    // the device policy above, NOT a new setting: never written to
    // config.json/store, reset to the device default every time compose is
    // (re)opened (`pick_contact_core`). Shares `parse_locktime_mode`'s
    // validation and `locktime_caption`'s wording with Settings.
    cb!(Compose, on_set_compose_locktime, |w, s, mode: SharedString, height: SharedString| { s.on_set_compose_locktime(&w, mode, height) });

    // Sweep/consolidate screen (16) locktime override panel — same
    // contract as the compose one above, reset on `set_sweep_dest`/
    // `open_notebook_consolidate`.
    cb!(Sweep, on_set_sweep_locktime, |w, s, mode: SharedString, height: SharedString| { s.on_set_sweep_locktime(&w, mode, height) });

    // Compose "too large" dialog: raise the chunk size to Standard and reprice
    // the draft in place. Only offered when the note actually fits at Standard.
    cb!(Modals, on_oversize_bump, |w, s| { s.on_oversize_bump(&w) });

    // Bitcoin node dropdown: a preset row writes its base (None = network
    // default) to the device config for this network; the two trailing
    // UI-managed rows — "Bitcoin Core" then "Custom…" (U12) — just reveal
    // their own text field (the Slint side already moved node-index) and
    // write nothing yet; the value follows when the user submits it via
    // set-node-address / set-node-custom respectively.
    cb!(Settings, on_set_node_preset, |w, s, i: i32| { s.on_set_node_preset(&w, i) });

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
    cb!(Settings, on_set_node_address, |w, s, t: SharedString| { s.on_set_node_address(&w, t) });

    cb!(Settings, on_set_node_custom, |w, s, t: SharedString| { s.on_set_node_custom(&w, t) });

    // Bitcoin Core RPC credentials (plan §2.4/U6, extended by U10's "Save
    // credentials" switch): persisted in the Keychain ONLY while the switch
    // is on for this network — `keychain::{store,load,delete}_rpc_creds`,
    // under a distinct account namespace from the identity key. Off routes
    // to the session-only slot instead (`route_core_rpc_creds`); the
    // Keychain is never touched in that branch. Never written to
    // config.json, never logged (length only). Clearing both fields
    // deletes/clears the stored or session credential instead of writing
    // an empty one.
    cb!(Settings, on_set_node_core_creds, |w, s, user: SharedString, pass: SharedString| { s.on_set_node_core_creds(&w, user, pass) });

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
    cb!(Settings, on_set_node_core_save_creds, |w, s, enabled: bool| { s.on_set_node_core_save_creds(&w, enabled) });

    cb!(Settings, on_set_explorer_preset, |w, s, i: i32| { s.on_set_explorer_preset(&w, i) });

    cb!(Settings, on_set_explorer_custom, |w, s, t: SharedString| { s.on_set_explorer_custom(&w, t) });

    // ---- Public keys (screen 18): derived from the SESSION-CACHED
    // material only — never a fresh biometric. Watch-only identities show
    // whatever public material `export_formats` yields (their `material`
    // IS the xpub/descriptor string itself, so this works unchanged).
    cb!(Settings, on_reveal_public, |w, s| { s.on_reveal_public(&w) });

    // ---- Private keys (screen 19): ALWAYS a fresh biometric — never the
    // session cache. Only on success do we derive + navigate; failures
    // surface as a status message on Settings (screen stays 8). Every
    // format this identity supports is derived up front and cached in
    // `s.reveal_formats` so the picker (`private-select`) never re-prompts
    // — but nothing is shown until the user taps a pill (progressive
    // disclosure).
    cb!(Settings, on_reveal_private, |w, s| { s.on_reveal_private(&w) });

    // Switch which single format is on screen (progressive disclosure —
    // only one value visible at a time). Reads the formats derived at
    // reveal-private time; never re-authenticates. Hex/WIF derive from
    // whichever notebook the picker currently has selected (not always
    // the active notebook) so switching back to a pill after picking a
    // different notebook shows the right value.
    cb!(PrivateKeys, on_private_select, |w, s, fmt: SharedString| { s.on_private_select(&w, fmt) });

    // Hex/WIF only: switch the picker's selected notebook and re-derive
    // its leaf key from the session-cached material — NO re-auth. A no-op
    // for recovery/xprv (the picker is hidden for those, and the shown
    // format is index-independent anyway).
    cb!(PrivateKeys, on_private_pick_notebook, |w, s, index: i32| { s.on_private_pick_notebook(&w, index) });

    // ---- Quantum keys (Settings -> screen 29) ----------------------------

    cb!(Settings, on_open_pq_keys, |w, s| { s.on_open_pq_keys(&w) });

    cb!(QuantumKeys, on_pq_set_level, |w, s, level: SharedString| { s.on_pq_set_level(&w, level) });

    cb!(QuantumKeys, on_pq_copy_public, |w, s| { s.on_pq_copy_public(&w) });

    cb!(QuantumKeys, on_pq_save_public, |w, s| { s.on_pq_save_public(&w) });

    cb!(Modals, on_pq_copy_private, |w, s| { s.on_pq_copy_private(&w) });

    cb!(Modals, on_pq_save_private, |w, s| { s.on_pq_save_private(&w) });

    cb!(QuantumKeys, on_pq_import_paste, |w, s| { s.on_pq_import_paste(&w) });

    cb!(QuantumKeys, on_pq_import_file, |w, s| { s.on_pq_import_file(&w) });

    // Generate/Import both route through the REPLACE GUARD when a "My
    // quantum key" is already present (PLAN-graffito-quantum-key.md — never
    // silently overwrite): the confirm modal opens instead of acting, and
    // `on_pq_replace_confirm` runs whichever action was pending. The
    // pending action's own input (gen level/extra, or import text) is left
    // untouched in the Slint properties across the round trip.
    cb!(QuantumKeys, on_pq_generate, |w, s| { s.on_pq_generate(&w) });

    cb!(QuantumKeys, on_pq_import_submit, |w, s| { s.on_pq_import_submit(&w) });

    cb!(Ui, on_pq_replace_confirm, |w, s| { s.on_pq_replace_confirm(&w) });

    cb!(Modals, on_pq_replace_cancel, |w, s| { s.on_pq_replace_cancel(&w) });

    cb!(QuantumKeys, on_pq_import_remove, |w, s| { s.on_pq_import_remove(&w) });

    // ---- "My quantum key" export (item 3: public is a plain share, the
    // private armor sits behind an explicit reveal warning and copies via
    // the concealed/expiring clipboard, never the plain one) ----

    cb!(QuantumKeys, on_pq_imported_copy_public, |w, s| { s.on_pq_imported_copy_public(&w) });

    cb!(Modals, on_pq_imported_reveal_private, |w, s| { s.on_pq_imported_reveal_private(&w) });

    cb!(Modals, on_pq_imported_copy_private, |w, s| { s.on_pq_imported_copy_private(&w) });

    cb!(Ui, on_pq_imported_hide_private, |w, s| { s.on_pq_imported_hide_private(&w) });

    cb!(Ui, on_copy_value, |w, s, value: SharedString| { s.on_copy_value(&w, value) });

    // Spending material (audit M3) — concealed/local-only/expiring clipboard,
    // never the plain broadcast one. Length only, as ever; never the value.
    cb!(PrivateKeys, on_copy_secret, |w, s, value: SharedString| { s.on_copy_secret(&w, value) });

    cb!(Ui, on_go_home, |w, s| { s.on_go_home(&w) });

    cb!(Ui, on_open_notebooks, |w, s| { s.on_open_notebooks(&w) });

    cb!(Notebooks, on_open_notebook, |w, s, index: i32| { s.on_open_notebook(&w, index) });

    cb!(Notebooks, on_create_notebook, |w, s| { s.on_create_notebook(&w) });

    cb!(Notebooks, on_nb_rename_start, |w, s, index: i32, _display: SharedString| { s.on_nb_rename_start(&w, index, _display) });

    cb!(Modals, on_nb_rename_save, |w, s, name: SharedString| { s.on_nb_rename_save(&w, name) });

    cb!(Ui, on_nb_rename_cancel, |w, s| { s.on_nb_rename_cancel(&w) });

    cb!(Notebooks, on_nb_archive, |w, s, index: i32, archived: bool| { s.on_nb_archive(&w, index, archived) });

    cb!(Home, on_toggle_sender, |w, s, key: SharedString, excluded: bool| { s.on_toggle_sender(&w, key, excluded) });

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
    // the UI thread via the same `post` (U5) trampoline every other async
    // result uses — this one just has no payload (re-reads the KV store
    // itself once it runs).
    {
        let weak = window.as_weak();
        icloud::start_observer(move || {
            post(&weak, |w, st| st.apply_icloud_contacts_merge(w));
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
    // Through the real formatter so the phone column count previews too.
    set_backup_words(w, "legal winner thank year wave sausage worth useful dawn absorb pledge yellow");
    // Mixed word lengths on purpose: the reveal grid must keep its columns
    // aligned whatever the words are.
    set_reveal_word_list(w, "upset around cover chalk relief live multiply pool define police crouch exile");
    w.global::<Ui>().set_reveal_private_format("recovery".into());
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
    // `APP_TYPE_SCALE=1.6 scripts/render-all.sh out` previews every screen
    // at the phone type-scale cap on a Mac (unset = 1.0, the byte-identity
    // baseline).
    app.global::<Metrics>().set_type_scale(platform::type_scale());
    app.global::<Metrics>().set_word_columns(platform::word_columns());

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
static ANDROID_APP: std::sync::RwLock<Option<slint::android::AndroidApp>> = std::sync::RwLock::new(None);

/// The CURRENT `AndroidApp` handle, stashed by `android_main`, so `platform::
/// safe_area_insets` can read the window insets / content rect (status-bar
/// and nav-bar). A RwLock, not a OnceLock: `android_main` runs AGAIN, with a
/// NEW `AndroidApp`, every time the NativeActivity is recreated (a font-size
/// or other configuration change — `fontScale` is deliberately not in the
/// manifest's `configChanges`), and the old handle's activity reference is
/// dead after that — `getRootWindowInsets` on it is null forever and its
/// content rect reads (0, 0), which is how the header ended up under the
/// status bar after a font-size change (Sal's Pixel, 2026-09-05).
#[cfg(target_os = "android")]
pub(crate) fn android_app() -> Option<slint::android::AndroidApp> {
    ANDROID_APP.read().ok().and_then(|g| g.clone())
}

#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: slint::android::AndroidApp) {
    if let Some(path) = app.internal_data_path() {
        std::env::set_var("APP_DATA_DIR", path);
    }
    // Keep the CURRENT handle for safe-area insets (see `android_app`);
    // AndroidApp is a cheap clonable handle.
    *ANDROID_APP.write().expect("android app lock") = Some(app.clone());
    // Stash the JavaVM + Activity so the keystore/camera JNI backends can
    // reach them (ndk-context is populated by android-activity at startup;
    // this is a belt-and-suspenders no-op if already set).
    slint::android::init(app).expect("slint android init");
    run();
}

#[cfg(test)]
mod tests;
