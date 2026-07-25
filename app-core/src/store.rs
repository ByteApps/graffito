//! Local store: notes, UTXO ledger, contacts, settings — the Prime
//! state.json model, keyed by identity so switching identities can never
//! mix notebooks. JSON on disk, atomic save (tmp + rename).
//!
//! Merge discipline (the Prime plan's idempotency rule): applying a full
//! bundle plus overlapping incrementals must converge — notes dedupe by
//! (note_id, origin), chain data wins for heights/txids, extracted
//! plaintext wins over a missing cache, and re-applying the same bundle
//! is a no-op.

use notes_core::address::{p2tr_script_pubkey, taproot_address};
use notes_core::bundle::{
    extract_notes_multi_deduped, extract_notes_watch_multi_deduped, Identity, RecoveredNote, SyncBundle,
};
use notes_core::tx::Utxo;
use notes_core::Network;
use serde::{Deserialize, Serialize};

use crate::notebooks::{SpendingAddr, SpendingSection};
use crate::Error;

pub const DEFAULT_CHUNK: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutPointRef {
    pub txid: String, // display hex
    pub vout: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    /// Signed (and possibly broadcast); inputs locked, txid known.
    Pending,
    /// Seen on-chain with a height.
    Confirmed,
    /// A pending note whose inputs vanished from a full rescan without
    /// its txid appearing — spent elsewhere; user must recompose.
    Orphaned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteRecord {
    pub note_id: String, // hex8, canonical identity
    pub status: NoteStatus,
    pub text: Option<String>, // plaintext cache; None = undecryptable
    pub private: bool,
    pub directed: bool,
    pub received: bool,
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub recipient: Option<String>,
    /// Full recipient list of a MULTI-recipient directed note (FLAG_MULTI,
    /// 2+ recipients), in output order. Empty for a self-note or an
    /// ordinary single-recipient directed note — use `recipient` instead
    /// (mirrors notes-core's `RecoveredNote.recipients` convention
    /// exactly, including "empty means single"). Populated for BOTH own
    /// (compose-time) and received (scan-derived) multi notes.
    #[serde(default)]
    pub recipients: Vec<String>,
    pub txids: Vec<String>,
    #[serde(default)]
    pub height: Option<u64>,
    #[serde(default)]
    pub blocktime: Option<u64>,
    /// Local compose time (never chain-recovered; display falls back to
    /// blocktime).
    #[serde(default)]
    pub created_at: Option<u64>,
    /// Inputs this note's signed tx spends — pending bookkeeping only.
    #[serde(default)]
    pub spent: Vec<OutPointRef>,
    /// Raw signed tx hex while Pending — enables rebroadcast (and fee
    /// bumps) across app restarts. Cleared on confirmation.
    #[serde(default)]
    pub raw_hex: Option<String>,
    /// Fee (sats) of the current tx — for the activity view.
    #[serde(default)]
    pub fee: Option<u64>,
    /// vsize of the current tx — with fee gives the sat/vB rate.
    #[serde(default)]
    pub vsize: Option<u64>,
    /// Custom change destination (None = change returned to self).
    #[serde(default)]
    pub change_to: Option<String>,
    /// Directed notes: sats sent to the recipient (the "gift"). None for
    /// self-notes; preserved across RBF so a fee-bump keeps the same gift.
    #[serde(default)]
    pub gift_amount: Option<u64>,
    /// Funding-unification M3: who paid for this note besides the
    /// notebook itself — `Some("spending")` for the internal BIP-84
    /// spending wallet, `Some("wallet:<label>")` for an external funding
    /// wallet, `None` for the ordinary notebook-funded path (today's
    /// default — every pre-M3 record loads with `None`, so Activity shows
    /// no source pill for it, matching current behavior byte-for-byte).
    #[serde(default)]
    pub funded_by: Option<String>,
    /// Task #14 (dropped-pending detection): true once a PENDING record's
    /// tx lookup came back a definitive not-found AND its first spent
    /// input was verifiably still unspent — the mempool genuinely lost the
    /// broadcast (as opposed to Orphaned, where a DIFFERENT tx spent the
    /// inputs). Cleared the moment the tx is seen again. Never true for a
    /// Confirmed/Orphaned record. See [`resolve_dropped`].
    #[serde(default)]
    pub dropped: bool,
}

impl NoteRecord {
    /// `{sender} ∪ recipients` minus `my_address`, deduped, sender first
    /// then recipients in order — "who else was on this note", for a
    /// Reply-all picker. Mirrors notes-core's `bundle::reply_set` exactly
    /// (same rule), applied to the app's persisted `NoteRecord` instead of
    /// a freshly-scanned `RecoveredNote` — both carry the same
    /// sender/recipient/recipients shape. Falls back to the legacy
    /// singular `recipient` field when `recipients` is empty (an ordinary
    /// single-recipient directed note). A self-note (no sender, no
    /// recipients) returns an empty list.
    pub fn reply_set(&self, my_address: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let push = |addr: &str, out: &mut Vec<String>| {
            if addr != my_address && !out.iter().any(|a| a == addr) {
                out.push(addr.to_string());
            }
        };
        if let Some(s) = &self.sender {
            push(s, &mut out);
        }
        if self.recipients.is_empty() {
            if let Some(r) = &self.recipient {
                push(r, &mut out);
            }
        } else {
            for r in &self.recipients {
                push(r, &mut out);
            }
        }
        out
    }
}

/// One input spent by a sweep/consolidate tx — kept for RBF re-signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub txid: String, // display hex
    pub vout: u32,
    pub value: u64,
}

/// A non-note transaction the app broadcast (sweep or consolidate).
/// Notes track their own lifecycle in `NoteRecord`; this ledger gives
/// sweeps/consolidations the same pending → confirmed tracking plus
/// rebroadcast and RBF, so a stuck admin tx isn't lost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    pub kind: String, // "sweep" | "consolidate"
    pub txids: Vec<String>,
    pub status: NoteStatus,
    pub value: u64, // output value (sats delivered)
    pub fee: u64,
    #[serde(default)]
    pub vsize: u64,
    #[serde(default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub raw_hex: Option<String>,
    /// Destination label for display (address or "self").
    #[serde(default)]
    pub dest: String,
    /// Exact inputs + destination script, so an RBF bump re-signs the
    /// same spend at a higher rate.
    pub inputs: Vec<TxInput>,
    pub dest_spk_hex: String,
    /// Owning account per input (parallel to `inputs`) for MULTI-KEY
    /// records (wallet sweep/consolidate) — a bump must re-sign each
    /// input with its own account's key. Empty = single-key record
    /// (every legacy record), bumped with the active identity.
    /// LEGACY (pre-rev-3): implies notebook index 0 for every input.
    #[serde(default)]
    pub input_accounts: Vec<u32>,
    /// Rev 3: owning NOTEBOOK INDEX per input (parallel to `inputs`),
    /// within the record's account — wallet ops never span accounts now.
    /// Empty on legacy records (see `input_accounts`).
    #[serde(default)]
    pub input_indexes: Vec<u32>,
    /// CHANGE 2 (funding-unification wallet-level flows, 2026-07-17): true
    /// when this record's inputs mix notebook (taproot) coins with
    /// spending-wallet (P2WPKH) coins — `build_wallet_sweep_mixed`'s
    /// output. `input_accounts`/`input_indexes` are left EMPTY on a mixed
    /// record (no single per-input owner scheme covers both kinds), so the
    /// existing multi-key bump path (`bump_raw_tx_multi`, taproot-only)
    /// must never be reached for one — the UI hides Speed-up
    /// (`ActivityItem.bumpable`) and `on_act_bump_open`/`_confirm` refuse
    /// defensively too. Rebroadcast still works (`raw_hex` is kept exactly
    /// like any other pending record) — only RBF re-signing is unavailable.
    /// Default false: every pre-existing record (single-key or
    /// taproot-only multi-key) is unaffected and stays bumpable.
    #[serde(default)]
    pub mixed_inputs: bool,
    /// Task #14 (dropped-pending detection): see `NoteRecord::dropped` —
    /// same meaning, same [`resolve_dropped`] state machine, applied to
    /// sweep/consolidate records via [`Store::resolve_dropped_tx`].
    #[serde(default)]
    pub dropped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerUtxo {
    pub txid: String, // display hex
    pub vout: u32,
    pub value: u64,
    #[serde(default)]
    pub height: Option<u64>,
    /// Locked by a signed-but-not-yet-confirmed note.
    #[serde(default)]
    pub pending_spend: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub address: String,
    #[serde(default)]
    pub name: String,
    /// Which network this address belongs to (`Network::as_str()` —
    /// "mainnet"/"testnet4"/"signet"/"regtest"). Needed because testnet4
    /// and signet addresses share the SAME `tb1…` HRP, so the address
    /// string alone can't distinguish them — this tag is the disambiguator
    /// for the device-level global contacts list (iCloud-contacts feature,
    /// 2026-07-20), which spans every network on the device.
    /// `#[serde(default)]` = "" for every contact that existed before this
    /// field shipped; an empty tag is treated as a wildcard (matches any
    /// network) everywhere it's read, until the contact is next
    /// touched/renamed, which stamps it with a real network and ends the
    /// wildcard treatment for that entry. A `Store`'s own `contacts` field
    /// is single-network by construction (one store = one network), so
    /// `Store::touch_contact` always stamps `self.network` here — the
    /// (address, network) identity distinction only matters once contacts
    /// are merged into the device-level list.
    #[serde(default)]
    pub network: String,
    /// Unix MILLISECONDS the contact was last added/touched/renamed —
    /// tombstone-based cross-device deletion's last-write-wins clock
    /// (contacts-tombstones feature, 2026-07-20). `#[serde(default)]` = 0
    /// for every contact that existed before this field shipped, which
    /// makes a legacy entry lose any conflict against a genuinely-timed
    /// one from either device (0 is always the oldest possible value) —
    /// the desired behavior, since a legacy entry carries no real
    /// evidence of when it was last touched. Produced ONLY by the impure
    /// app crate (`std::time::SystemTime::now()`); every pure `app-core`
    /// function here takes timestamps as parameters so merge stays
    /// host-testable without a clock. Conflict resolution across devices
    /// relies on their wall clocks being roughly NTP-synced — a device
    /// with a badly skewed clock can lose a genuinely-later edit/deletion
    /// to a genuinely-earlier one from another device (documented
    /// tradeoff, not solved here; a vector clock would remove the
    /// assumption but is overkill for a 2-device contacts list).
    #[serde(default)]
    pub updated_at: u64,
    /// Whether this contact is pushed to iCloud — per-contact opt-in
    /// (2026-07-20), replacing the old all-contacts-sync behavior.
    /// `#[serde(default)] = false` so every contact created before this
    /// field shipped, and any brand-new contact, starts UNSYNCED (opt-in,
    /// not opt-out) until the user explicitly checks "Save to iCloud" when
    /// naming it.
    #[serde(default)]
    pub synced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub version: u32,
    pub network: String,
    /// Hex of the identity's output x-only key — a guard, not a secret:
    /// applying data for a different identity is a hard error.
    pub identity_fingerprint: String,
    pub address: String,
    #[serde(default)]
    pub notes: Vec<NoteRecord>,
    #[serde(default)]
    pub utxos: Vec<LedgerUtxo>,
    /// Recents-ordered, front = latest use (the Prime contacts rule).
    #[serde(default)]
    pub contacts: Vec<Contact>,
    /// Sweep/consolidate transactions (newest last).
    #[serde(default)]
    pub txs: Vec<TxRecord>,
    #[serde(default)]
    pub tip_height: u64,
    #[serde(default)]
    pub last_scan_time: u64,
    /// "Did anything change since last scan" fingerprint (task: 429
    /// throttling) — the address's chain+mempool stats as of the last
    /// successful scan. `#[serde(default)]` so existing store files
    /// (which predate this field) load with `None`, tolerantly, and a
    /// later wiring pass short-circuits a refresh when a fresh
    /// `ChainClient::address_stats` call comes back unchanged.
    #[serde(default)]
    pub addr_stats: Option<crate::chain::AddrStats>,
    #[serde(default = "default_chunk")]
    pub chunk_size: usize,
    /// Legacy per-identity Bitcoin-node URL (shipped as `esplora`). The node
    /// and block-explorer choices are now device-level (config.json, keyed by
    /// network); this field is kept only to migrate old stores on load and is
    /// dropped on the next save (`skip_serializing_if`).
    #[serde(default, alias = "esplora", skip_serializing_if = "Option::is_none")]
    pub node_url: Option<String>,
    /// Sender filter: sender keys (addresses) hidden from this notebook's
    /// view. The EXCLUSION set is what persists — everything not listed is
    /// visible, so a brand-new sender always shows up by default.
    #[serde(default)]
    pub excluded_senders: Vec<String>,
    /// Unread tracking: `"<note_id>:<sender>"` keys of received notes the
    /// user has already had on screen (marked when the notebook opens).
    #[serde(default)]
    pub seen_received: Vec<String>,
    /// RUNTIME cache of the identity's spending wallet (funding-
    /// unification M2/M3.1). `#[serde(skip)]` — this field never
    /// round-trips with the store file: the section is per (network,
    /// identity, ACCOUNT), shared by every notebook of the account, so it
    /// now persists in the per-identity notebooks index
    /// (`NotebookIndex.spending`, see `notebooks.rs`) instead. Whatever
    /// loads a store for the active (account, notebook) must stamp this
    /// field from `NotebookIndex::spending_for(account)`, and every
    /// mutation (`spending_mark_used` etc.) must be written back through
    /// `NotebookIndex::set_spending` + save — the [`Store`] methods below
    /// only touch the in-memory copy. Defaults empty/disabled until
    /// stamped.
    #[serde(skip)]
    pub spending: SpendingSection,
}

fn default_chunk() -> usize {
    DEFAULT_CHUNK
}

/// Task #14 (dropped-pending detection): the pure state-machine core —
/// no I/O, so it's host-testable with canned inputs. Decides the NEXT
/// `dropped` flag for one PENDING record from its tx-lookup result and
/// (lazily — only evaluated when the lookup is `NotFound`) whether its
/// first spent input is still sitting unspent.
///
/// - `Found(_)`            → false. The tx is back (still there, or newly
///   seen) — clears a stale `dropped` from an earlier flaky lookup.
/// - `Unknown`              → unchanged. A transient error (offline,
///   non-404 HTTP failure, bad body) must NEVER move the flag either way.
/// - `NotFound` + unspent   → true. The node has no record of the tx AND
///   the coin it was supposed to spend never left — the broadcast
///   genuinely evaporated (as opposed to Orphaned, where something ELSE
///   spent the input).
/// - `NotFound` + spent, or unspent-check itself inconclusive → unchanged
///   (never guess a positive from a `NotFound` alone — the coin may have
///   been consumed by an RBF replacement or a different owner entirely;
///   the caller's own orphan-detection pass handles the "spent by
///   something else" case separately).
pub fn resolve_dropped(
    was_dropped: bool,
    lookup: crate::chain::TxLookupStatus,
    first_input_unspent: impl FnOnce() -> Option<bool>,
) -> bool {
    use crate::chain::TxLookupStatus;
    match lookup {
        TxLookupStatus::Found(_) => false,
        TxLookupStatus::Unknown => was_dropped,
        TxLookupStatus::NotFound => match first_input_unspent() {
            Some(true) => true,
            _ => was_dropped,
        },
    }
}

impl Store {
    pub fn new(output_x: &[u8; 32], network: Network) -> Self {
        Store {
            version: 1,
            network: network.as_str().to_string(),
            identity_fingerprint: hex::encode(output_x),
            address: taproot_address(network, output_x),
            notes: Vec::new(),
            utxos: Vec::new(),
            contacts: Vec::new(),
            txs: Vec::new(),
            tip_height: 0,
            last_scan_time: 0,
            addr_stats: None,
            chunk_size: DEFAULT_CHUNK,
            node_url: None,
            excluded_senders: Vec::new(),
            seen_received: Vec::new(),
            spending: SpendingSection::default(),
        }
    }

    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::Store(e.to_string()))?;
        serde_json::from_str(&text).map_err(|e| Error::Store(e.to_string()))
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), Error> {
        let text = serde_json::to_string_pretty(self).map_err(|e| Error::Store(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| Error::Store(e.to_string()))?;
        std::fs::rename(&tmp, path).map_err(|e| Error::Store(e.to_string()))
    }

    /// UTXOs compose may spend: confirmed or own unconfirmed change, not
    /// locked by a pending note. Internal byte order, largest handled by
    /// notes-core's selector.
    pub fn available_utxos(&self) -> Vec<Utxo> {
        self.utxos
            .iter()
            .filter(|u| !u.pending_spend)
            .filter_map(|u| {
                let mut txid = [0u8; 32];
                hex::decode_to_slice(&u.txid, &mut txid).ok()?;
                txid.reverse();
                Some(Utxo { txid, vout: u.vout, value: u.value })
            })
            .collect()
    }

    pub fn balance(&self) -> u64 {
        self.utxos.iter().filter(|u| !u.pending_spend).map(|u| u.value).sum()
    }

    pub fn note_id_taken(&self, id: &[u8; 4]) -> bool {
        let hex_id = hex::encode(id);
        self.notes.iter().any(|n| n.note_id == hex_id)
    }

    /// Record a freshly signed note: note enters Pending, its inputs are
    /// locked, and its change (if any) becomes spendable unconfirmed —
    /// several notes can queue between scans.
    pub fn record_signed(&mut self, record: NoteRecord, change: Option<LedgerUtxo>) {
        for spent in &record.spent {
            if let Some(u) =
                self.utxos.iter_mut().find(|u| u.txid == spent.txid && u.vout == spent.vout)
            {
                u.pending_spend = true;
            }
        }
        if let Some(c) = change {
            self.utxos.push(c);
        }
        self.notes.push(record);
    }

    /// Merge a scan into the store. `bundle` must be for our address;
    /// full bundles are authoritative for the UTXO set and run orphan
    /// detection, incrementals only add. The self-spk SET (funding-
    /// unification M2) is the notebook's own spk plus the spending
    /// wallet's used addresses — empty `spending.used` (every pre-M2 store,
    /// or the setting left off) makes this byte-identical to the old
    /// singleton-spk `extract_notes` call.
    ///
    /// `notebook_spks` (2026-07-18, notes-core rev 6e36a23) is the DISPLAY-
    /// OWNER anchor set: the p2tr scriptPubKeys of every ACTIVE notebook of
    /// this identity's account, in index order — see
    /// `identity::active_notebook_spks`, the caller's usual source. An
    /// empty slice is a strict no-op (byte-identical to the pre-dedup
    /// `extract_notes_multi` call), so old callers/tests are unaffected.
    ///
    /// `extra_spending_spks` (spending-self-notes fix, Unit A / RC1) is
    /// UNIONED (deduped) with [`Self::spending_self_spks`] into the self-spk
    /// SET — it does not replace the recorded-`used` snapshot, it widens it.
    /// The usual source is a derived spending-address window
    /// (`spending::window_spks`), which fixes classification for a note
    /// funded from a spending address the recorded snapshot doesn't (yet, or
    /// ever, on a disk-loaded non-active store) know about. An empty slice
    /// is a strict no-op — byte-identical to before this parameter existed.
    pub fn apply_bundle(
        &mut self,
        bundle: &SyncBundle,
        identity: &Identity,
        network: Network,
        notebook_spks: &[Vec<u8>],
        extra_spending_spks: &[Vec<u8>],
    ) -> Result<ApplyStats, Error> {
        self.check_identity(&identity.output_x)?;
        let mut self_spks = vec![p2tr_script_pubkey(&identity.output_x)];
        self_spks.extend(self.spending_self_spks());
        for spk in extra_spending_spks {
            if !self_spks.contains(spk) {
                self_spks.push(spk.clone());
            }
        }
        self.apply_recovered(
            bundle,
            extract_notes_multi_deduped(bundle, identity, network, &self_spks, notebook_spks),
        )
    }

    /// Watch-only [`Self::apply_bundle`]: same merge, but notes extract
    /// without keys — every private body stays sealed (text: None). Watch
    /// identities have no spending wallet (PLAN decision 7), so
    /// `spending_self_spks` is always empty here, and callers must pass an
    /// empty `extra_spending_spks` too (no spending wallet to derive a
    /// window from) — this stays byte-identical to the old
    /// `extract_notes_watch` call. `notebook_spks`: see
    /// [`Self::apply_bundle`] — this scan's own notebook spk (derived from
    /// `output_x`) is the anchor identity compared against.
    pub fn apply_bundle_watch(
        &mut self,
        bundle: &SyncBundle,
        output_x: &[u8; 32],
        network: Network,
        notebook_spks: &[Vec<u8>],
        extra_spending_spks: &[Vec<u8>],
    ) -> Result<ApplyStats, Error> {
        self.check_identity(output_x)?;
        let own_spk = p2tr_script_pubkey(output_x);
        let mut self_spks = self.spending_self_spks();
        for spk in extra_spending_spks {
            if !self_spks.contains(spk) {
                self_spks.push(spk.clone());
            }
        }
        self.apply_recovered(
            bundle,
            extract_notes_watch_multi_deduped(bundle, network, &self_spks, notebook_spks, &own_spk),
        )
    }

    fn check_identity(&self, output_x: &[u8; 32]) -> Result<(), Error> {
        if hex::encode(output_x) != self.identity_fingerprint {
            return Err(Error::Store("bundle applied to a different identity".into()));
        }
        Ok(())
    }

    fn apply_recovered(
        &mut self,
        bundle: &SyncBundle,
        recovered: Vec<RecoveredNote>,
    ) -> Result<ApplyStats, Error> {
        let mut stats = ApplyStats::default();
        for note in &recovered {
            stats.notes_seen += 1;
            if self.upsert_note(note) {
                stats.notes_new += 1;
            }
        }

        // Spending-self-notes fix, Unit B / RC2: an authoritative scan can
        // now recover as OWN a note that a PAST scan (running with a
        // too-narrow self-spk set, RC1) stored as `received`/"unknown" —
        // `upsert_note` keys on (note_id, received, sender), so that stale
        // record would otherwise linger forever beside the freshly-correct
        // one. Only `bundle.full` runs this (an incremental bundle is a
        // partial view and must never delete anything it didn't fully see).
        if bundle.full {
            self.prune_stale_received_twins(&recovered, &mut stats);
        }

        // Confirm pending notes whose txid surfaced with a height even if
        // (unexpectedly) their payload didn't extract.
        let confirmed_txids: std::collections::HashMap<&str, (Option<u64>, Option<u64>)> = bundle
            .notes_onchain
            .iter()
            .filter(|t| t.height.is_some())
            .map(|t| (t.txid.as_str(), (t.height, t.blocktime)))
            .collect();
        for n in &mut self.notes {
            if n.status == NoteStatus::Pending {
                if let Some((h, bt)) =
                    n.txids.iter().find_map(|t| confirmed_txids.get(t.as_str()))
                {
                    n.status = NoteStatus::Confirmed;
                    n.height = *h;
                    n.blocktime = *bt;
                    n.raw_hex = None; // on-chain now — no rebroadcast needed
                    n.dropped = false; // it reappeared — task #14
                }
            }
        }

        if bundle.full {
            self.reconcile_utxos_full(bundle, &mut stats);
            // Sweep/consolidate records do NOT confirm here: their inputs
            // vanish from the UTXO set on mere mempool acceptance (esplora
            // drops mempool-spent coins immediately), which is not
            // finality. The caller resolves them against real tx statuses
            // via [`Self::resolve_spend_statuses`] after every scan.
        } else {
            self.merge_utxos_incremental(bundle);
        }

        self.tip_height = self.tip_height.max(bundle.tip_height);
        self.last_scan_time = bundle.bundle_time;
        Ok(stats)
    }

    /// Spending-self-notes fix, Unit B / RC2: remove any stored `received`
    /// record whose `note_id` + at least one `txid` matches a note THIS
    /// batch recovered as OWN. `recovered` is the just-extracted batch (the
    /// same one `apply_recovered`'s upsert loop just applied), so an OWN
    /// entry here is provably, freshly re-derived from `self_spks` — the
    /// caller only reaches this when `bundle.full` (an authoritative scan).
    ///
    /// SAFETY (one-directional): a `received` record is pruned ONLY when
    /// the SAME transaction ALSO recovers as own in THIS scan — i.e. it
    /// provably spends our (possibly just-widened) self-spk set. A
    /// genuinely third-party received note's tx never recovers as own (its
    /// inputs are never ours, however wide the self-spk set gets), so it is
    /// never touched. This preserves the received/own bucket split's
    /// security property in the OTHER direction (a tx that merely PAYS us
    /// must never become — or stay disguised as — an own note): this
    /// function only ever deletes `received` rows, never touches or creates
    /// an own one, and only in response to independently-proven ownership.
    fn prune_stale_received_twins(&mut self, recovered: &[RecoveredNote], stats: &mut ApplyStats) {
        let own: Vec<(String, &[String])> = recovered
            .iter()
            .filter(|n| !n.received)
            .map(|n| (hex::encode(n.note_id), n.txids.as_slice()))
            .collect();
        if own.is_empty() {
            return;
        }
        let before = self.notes.len();
        self.notes.retain(|n| {
            if !n.received {
                return true; // only ever prunes the received bucket
            }
            !own.iter().any(|(id, txids)| {
                *id == n.note_id && n.txids.iter().any(|t| txids.contains(t))
            })
        });
        stats.reclassified += before - self.notes.len();
    }

    /// Resolve pending sweep/consolidate records against REAL tx statuses.
    /// `lookup(txid)` returns Some(confirmed?) from the node, or None when
    /// the txid is unknown there (evicted/replaced, or transport error).
    /// A record settles when ANY of its txids (original or RBF bumps —
    /// they accumulate in `txids`) is in a block; while every known txid
    /// is only in the mempool it stays Pending, keeping Speed-up and
    /// Rebroadcast available exactly when RBF is still possible. Returns
    /// how many records confirmed.
    pub fn resolve_spend_statuses(&mut self, lookup: impl Fn(&str) -> Option<bool>) -> usize {
        let mut confirmed = 0;
        for t in &mut self.txs {
            if t.status != NoteStatus::Pending {
                continue;
            }
            if t.txids.iter().any(|x| lookup(x) == Some(true)) {
                t.status = NoteStatus::Confirmed;
                t.raw_hex = None; // on-chain now — no rebroadcast needed
                t.dropped = false; // it reappeared — task #14
                confirmed += 1;
            }
        }
        confirmed
    }

    /// Task #14 (dropped-pending detection): resolve `dropped` for every
    /// PENDING sweep/consolidate record, same pass as
    /// [`Self::resolve_spend_statuses`] (both run from the async refresh's
    /// pending-status sweep, fed by the same node round trip). `lookup`
    /// gives the CURRENT (latest RBF bump) txid's definitive-vs-transient
    /// status; `unspent(address, txid, vout)` is called ONLY when `lookup`
    /// says `NotFound`, checking whether the record's first spent input is
    /// still sitting unspent at the store's own address (the common case —
    /// see [`resolve_dropped`]'s doc for the mixed/spending-wallet-funded
    /// caveat). Returns the CURRENT txid of every record that just
    /// transitioned INTO dropped (for the caller's one-line-per-transition
    /// log) — a record clearing back to not-dropped isn't included (no log
    /// line asked for that direction).
    pub fn resolve_dropped_tx(
        &mut self,
        lookup: impl Fn(&str) -> crate::chain::TxLookupStatus,
        unspent: impl Fn(&str, &str, u32) -> Option<bool>,
    ) -> Vec<String> {
        let address = self.address.clone();
        let mut newly_dropped = Vec::new();
        for t in &mut self.txs {
            if t.status != NoteStatus::Pending {
                continue;
            }
            let Some(current) = t.txids.last() else { continue };
            let Some(first) = t.inputs.first() else { continue };
            let status = lookup(current);
            let next = resolve_dropped(t.dropped, status, || {
                unspent(&address, &first.txid, first.vout)
            });
            if next && !t.dropped {
                newly_dropped.push(current.clone());
            }
            t.dropped = next;
        }
        newly_dropped
    }

    /// Task #14: the note-record twin of [`Self::resolve_dropped_tx`] — a
    /// note's own broadcast can go missing exactly the same way a sweep's
    /// can. Same signature/semantics; `t.spent` (the note's locked inputs)
    /// stands in for `TxRecord.inputs`.
    pub fn resolve_dropped_notes(
        &mut self,
        lookup: impl Fn(&str) -> crate::chain::TxLookupStatus,
        unspent: impl Fn(&str, &str, u32) -> Option<bool>,
    ) -> Vec<String> {
        let address = self.address.clone();
        let mut newly_dropped = Vec::new();
        for n in &mut self.notes {
            if n.status != NoteStatus::Pending {
                continue;
            }
            let Some(current) = n.txids.last() else { continue };
            let Some(first) = n.spent.first() else { continue };
            let status = lookup(current);
            let next = resolve_dropped(n.dropped, status, || {
                unspent(&address, &first.txid, first.vout)
            });
            if next && !n.dropped {
                newly_dropped.push(current.clone());
            }
            n.dropped = next;
        }
        newly_dropped
    }

    /// Record a broadcast sweep/consolidate for the activity view + RBF.
    #[allow(clippy::too_many_arguments)]
    pub fn record_tx(
        &mut self,
        kind: &str,
        txid: String,
        value: u64,
        fee: u64,
        vsize: u64,
        raw_hex: String,
        dest: String,
        inputs: Vec<TxInput>,
        dest_spk_hex: String,
        now: u64,
    ) {
        self.txs.push(TxRecord {
            kind: kind.to_string(),
            txids: vec![txid],
            status: NoteStatus::Pending,
            value,
            fee,
            vsize,
            created_at: Some(now),
            raw_hex: Some(raw_hex),
            dest,
            inputs,
            dest_spk_hex,
            input_accounts: Vec::new(),
            input_indexes: Vec::new(),
            mixed_inputs: false,
            dropped: false,
        });
    }

    /// Returns true if the note was new.
    fn upsert_note(&mut self, note: &RecoveredNote) -> bool {
        let id = hex::encode(note.note_id);
        let existing = self
            .notes
            .iter_mut()
            .find(|n| n.note_id == id && n.received == note.received && n.sender == note.sender);
        match existing {
            Some(n) => {
                for t in &note.txids {
                    if !n.txids.contains(t) {
                        n.txids.push(t.clone());
                    }
                }
                if note.height.is_some() {
                    n.status = NoteStatus::Confirmed;
                    n.height = note.height;
                    n.blocktime = note.blocktime;
                    n.raw_hex = None;
                }
                // A FRESH successful decode wins over a stale cache — a
                // failed one (None) never clobbers a good cache. Fill-if-
                // empty alone left poisoned text stuck forever: a scan run
                // by an older binary (e.g. pre-FLAG_MULTI, which kept the
                // raw count-prefixed body as "text") cached its bad decode,
                // and no later, smarter rescan could ever correct it (Sal's
                // "␂public note…" artifact, 2026-07-19).
                if note.text.is_some() && n.text != note.text {
                    n.text = note.text.clone();
                }
                if n.recipient.is_none() {
                    n.recipient = note.recipient.clone();
                }
                if n.recipients.is_empty() {
                    n.recipients = note.recipients.clone();
                }
                false
            }
            None => {
                self.notes.push(NoteRecord {
                    note_id: id,
                    status: if note.height.is_some() {
                        NoteStatus::Confirmed
                    } else {
                        NoteStatus::Pending
                    },
                    text: note.text.clone(),
                    private: note.private,
                    directed: note.directed,
                    received: note.received,
                    sender: note.sender.clone(),
                    recipient: note.recipient.clone(),
                    recipients: note.recipients.clone(),
                    txids: note.txids.clone(),
                    height: note.height,
                    blocktime: note.blocktime,
                    created_at: None,
                    spent: Vec::new(),
                    raw_hex: None,
                    fee: None,
                    vsize: None,
                    change_to: None,
                    gift_amount: None,
                    funded_by: None,
                    dropped: false,
                });
                true
            }
        }
    }

    /// Full bundle: chain UTXO set is authoritative. Keep pending locks
    /// where the outpoint survives; keep unconfirmed change belonging to
    /// still-pending notes; orphan pending notes whose inputs vanished
    /// without their txid appearing.
    fn reconcile_utxos_full(&mut self, bundle: &SyncBundle, stats: &mut ApplyStats) {
        let known_txids: std::collections::HashSet<&str> = bundle
            .notes_onchain
            .iter()
            .map(|t| t.txid.as_str())
            .chain(bundle.utxos.iter().map(|u| u.txid.as_str()))
            .collect();

        let pending_txids: Vec<String> = self
            .notes
            .iter()
            .filter(|n| n.status == NoteStatus::Pending)
            .flat_map(|n| n.txids.iter().cloned())
            .collect();

        let mut next: Vec<LedgerUtxo> = bundle
            .utxos
            .iter()
            .map(|u| LedgerUtxo {
                txid: u.txid.clone(),
                vout: u.vout,
                value: u.value,
                height: u.height,
                pending_spend: self
                    .utxos
                    .iter()
                    .any(|l| l.pending_spend && l.txid == u.txid && l.vout == u.vout),
            })
            .collect();

        // Unconfirmed change of still-pending (unbroadcast) notes isn't on
        // chain yet — carry it over.
        for l in &self.utxos {
            let carried = pending_txids.contains(&l.txid)
                && !next.iter().any(|n| n.txid == l.txid && n.vout == l.vout);
            if carried {
                next.push(l.clone());
            }
        }

        let vanished: Vec<String> = self
            .utxos
            .iter()
            .filter(|l| {
                l.pending_spend && !next.iter().any(|n| n.txid == l.txid && n.vout == l.vout)
            })
            .map(|l| l.txid.clone())
            .collect();
        let _ = vanished; // inputs consumed on-chain — expected once confirmed

        self.utxos = next;

        // Orphan detection: a Pending note whose every spent input is gone
        // from the authoritative set AND whose txid the chain has never
        // seen was double-spent elsewhere. Inputs may legitimately be
        // "gone" because an EARLIER queued note produced them (change
        // chaining) — those stay Pending. Decide immutably, apply after.
        let orphans: Vec<String> = self
            .notes
            .iter()
            .filter(|n| {
                n.status == NoteStatus::Pending
                    && !n.spent.is_empty()
                    && !n.txids.iter().any(|t| known_txids.contains(t.as_str()))
                    && n.spent.iter().all(|s| {
                        !self.utxos.iter().any(|u| u.txid == s.txid && u.vout == s.vout)
                    })
                    && !self
                        .notes
                        .iter()
                        .filter(|o| o.status == NoteStatus::Pending && o.note_id != n.note_id)
                        .flat_map(|o| o.txids.iter())
                        .any(|t| n.spent.iter().any(|s| &s.txid == t))
            })
            .map(|n| n.note_id.clone())
            .collect();
        for n in &mut self.notes {
            if orphans.contains(&n.note_id) {
                n.status = NoteStatus::Orphaned;
                stats.orphaned += 1;
            }
        }
        // An orphaned tx never made it on-chain: its change is phantom —
        // drop every ledger entry that tx produced.
        if !orphans.is_empty() {
            let orphan_txids: std::collections::HashSet<&str> = self
                .notes
                .iter()
                .filter(|n| n.status == NoteStatus::Orphaned)
                .flat_map(|n| n.txids.iter().map(String::as_str))
                .collect();
            self.utxos.retain(|u| !orphan_txids.contains(u.txid.as_str()));
        }
    }

    fn merge_utxos_incremental(&mut self, bundle: &SyncBundle) {
        for u in &bundle.utxos {
            if let Some(l) = self.utxos.iter_mut().find(|l| l.txid == u.txid && l.vout == u.vout)
            {
                l.height = u.height;
            } else {
                self.utxos.push(LedgerUtxo {
                    txid: u.txid.clone(),
                    vout: u.vout,
                    value: u.value,
                    height: u.height,
                    pending_spend: false,
                });
            }
        }
    }

    /// The sender-filter key of a note: the counterparty address for
    /// received notes, the notebook's own address for everything it
    /// authored — so "own notes" is one filterable stream like any other.
    pub fn sender_key(&self, n: &NoteRecord) -> String {
        if n.received {
            n.sender.clone().unwrap_or_else(|| "unknown".into())
        } else {
            self.address.clone()
        }
    }

    /// Distinct sender keys with note counts, newest activity first (the
    /// order the filter panel lists them in).
    pub fn senders(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = Vec::new();
        for n in self.notes.iter().rev() {
            let key = self.sender_key(n);
            match out.iter_mut().find(|(k, _)| *k == key) {
                Some((_, count)) => *count += 1,
                None => out.push((key, 1)),
            }
        }
        out
    }

    pub fn is_excluded(&self, key: &str) -> bool {
        self.excluded_senders.iter().any(|s| s == key)
    }

    pub fn set_excluded(&mut self, key: &str, excluded: bool) {
        if excluded {
            if !self.is_excluded(key) {
                self.excluded_senders.push(key.to_string());
            }
        } else {
            self.excluded_senders.retain(|s| s != key);
        }
    }

    /// Notes the sender filter lets through, in store order.
    pub fn visible_notes(&self) -> impl Iterator<Item = &NoteRecord> {
        self.notes.iter().filter(|n| !self.is_excluded(&self.sender_key(n)))
    }

    fn seen_key(n: &NoteRecord) -> String {
        format!("{}:{}", n.note_id, n.sender.as_deref().unwrap_or(""))
    }

    /// Received notes not yet marked seen — the notebook row's unread badge.
    pub fn unread_count(&self) -> usize {
        self.notes
            .iter()
            .filter(|n| n.received && !self.seen_received.contains(&Self::seen_key(n)))
            .count()
    }

    /// [`Self::unread_count`] restricted to senders the filter shows — the
    /// notebook row's badge (the preview must match what opening reveals).
    pub fn unread_visible_count(&self) -> usize {
        self.notes
            .iter()
            .filter(|n| {
                n.received
                    && !self.is_excluded(&self.sender_key(n))
                    && !self.seen_received.contains(&Self::seen_key(n))
            })
            .count()
    }

    /// Opening the notebook marks every current received note seen.
    /// Returns how many were newly marked (0 = nothing to persist).
    pub fn mark_seen(&mut self) -> usize {
        let mut newly = 0;
        let keys: Vec<String> = self
            .notes
            .iter()
            .filter(|n| n.received)
            .map(Self::seen_key)
            .collect();
        for k in keys {
            if !self.seen_received.contains(&k) {
                self.seen_received.push(k);
                newly += 1;
            }
        }
        newly
    }

    /// Contacts, Prime rules: front = latest use, dedupe by address,
    /// cap 20; naming does not bump recency. LEGACY / no longer the source
    /// of truth for the app (see `Contact::network`'s doc comment) — kept
    /// only so old `store-*.json` files still round-trip and can still
    /// feed the device-level contacts migration. A `Store`'s own
    /// `contacts` is single-network by construction, so this always
    /// stamps `self.network` (no cross-network ambiguity within one
    /// store — the (address, network) identity only matters once merged
    /// into the device-level list). Never participates in tombstone sync
    /// (that's the device-level list's job) — `updated_at` is left 0 here.
    pub fn touch_contact(&mut self, address: &str) {
        let name = self
            .contacts
            .iter()
            .position(|c| c.address == address)
            .map(|i| self.contacts.remove(i).name)
            .unwrap_or_default();
        self.contacts.insert(
            0,
            Contact {
                address: address.to_string(),
                name,
                network: self.network.clone(),
                updated_at: 0,
                // Device-local legacy contact creation never talks to
                // iCloud — this list is no longer the device-level source
                // of truth (see `Contact::network`'s doc comment), so a
                // touched entry here starts unsynced like every other
                // fresh contact.
                synced: false,
            },
        );
        self.contacts.truncate(20);
    }

    pub fn name_contact(&mut self, address: &str, name: &str) {
        if let Some(c) = self.contacts.iter_mut().find(|c| c.address == address) {
            c.name = name.to_string();
        }
    }

    pub fn remove_contact(&mut self, address: &str) {
        self.contacts.retain(|c| c.address != address);
    }

    /// Merge a freshly derived spending address into the used list
    /// (idempotent by (chain, index)) and bump the matching next-index
    /// past it — fresh-address discipline (funding-unification PLAN): the
    /// NEXT unused index always comes after every address actually handed
    /// out or discovered. Mutates only the in-memory runtime cache — the
    /// caller must write it back through `NotebookIndex::set_spending` +
    /// save so the rest of the account's notebooks see the update.
    pub fn spending_mark_used(&mut self, addr: SpendingAddr) {
        self.spending.mark_used(addr);
    }

    /// The spending wallet's self-spk SET: every used address's
    /// scriptPubKey — fed to `extract_notes_multi`/`_watch_multi` alongside
    /// the notebook's own spk so a spending-wallet-funded note scans back
    /// as OWN. Empty when the section has never been used (or the runtime
    /// cache hasn't been stamped), which keeps scan behavior identical to
    /// pre-M2 stores.
    pub fn spending_self_spks(&self) -> Vec<Vec<u8>> {
        self.spending.self_spks()
    }

    /// Merge a gap-scan's findings (`chain::discover_spending`) into the
    /// section: every discovered used address, plus each chain's next-
    /// unused index raised (never lowered — an unconfirmed local spend the
    /// scan can't see yet must not un-advance the index). Same write-back
    /// caveat as [`Self::spending_mark_used`].
    pub fn spending_apply_discovery(
        &mut self,
        used: Vec<SpendingAddr>,
        next_receive: u32,
        next_change: u32,
    ) {
        self.spending.apply_discovery(used, next_receive, next_change);
    }

    /// Same write-back caveat as [`Self::spending_mark_used`].
    pub fn spending_set_enabled(&mut self, on: bool) {
        self.spending.enabled = on;
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ApplyStats {
    pub notes_seen: usize,
    pub notes_new: usize,
    pub orphaned: usize,
    /// Stale `received` twins pruned this apply (spending-self-notes fix,
    /// Unit B / RC2) — a note that a past, too-narrow scan filed as
    /// received/"unknown" and THIS scan re-derived as OWN. Always 0 on an
    /// incremental (non-`full`) bundle; only ever counts a `received` row
    /// removed in favor of an independently-proven own one, never the
    /// reverse.
    pub reclassified: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(id: &str, received: bool, sender: Option<&str>) -> NoteRecord {
        NoteRecord {
            note_id: id.into(),
            status: NoteStatus::Confirmed,
            text: Some("t".into()),
            private: false,
            directed: received,
            received,
            sender: sender.map(String::from),
            recipient: None,
            recipients: vec![],
            txids: vec![],
            height: Some(1),
            blocktime: Some(1),
            created_at: None,
            spent: vec![],
            raw_hex: None,
            fee: None,
            vsize: None,
            change_to: None,
            gift_amount: None,
            funded_by: None,
            dropped: false,
        }
    }

    fn store_with_notes() -> Store {
        let mut s = Store::new(&[7u8; 32], Network::Regtest);
        s.notes.push(note("aa", false, None)); // own
        s.notes.push(note("bb", true, Some("tb1p-alice")));
        s.notes.push(note("cc", true, Some("tb1p-alice")));
        s.notes.push(note("dd", true, Some("tb1p-bob")));
        s
    }

    #[test]
    fn sender_keys_and_ordering() {
        let s = store_with_notes();
        // Own notes key by the notebook's own address.
        assert_eq!(s.sender_key(&s.notes[0]), s.address);
        // Newest activity first: bob (last note) → alice → self.
        let senders = s.senders();
        assert_eq!(
            senders,
            vec![("tb1p-bob".into(), 1), ("tb1p-alice".into(), 2), (s.address.clone(), 1)]
        );
    }

    #[test]
    fn exclusion_set_filters_and_persists_only_exclusions() {
        let mut s = store_with_notes();
        assert_eq!(s.visible_notes().count(), 4);
        s.set_excluded("tb1p-alice", true);
        s.set_excluded("tb1p-alice", true); // no dupes
        assert_eq!(s.excluded_senders, vec!["tb1p-alice".to_string()]);
        assert_eq!(s.visible_notes().count(), 2);
        // A brand-new sender is visible without any state change.
        s.notes.push(note("ee", true, Some("tb1p-carol")));
        assert_eq!(s.visible_notes().count(), 3);
        s.set_excluded("tb1p-alice", false);
        assert!(s.excluded_senders.is_empty());
        assert_eq!(s.visible_notes().count(), 5);
    }

    #[test]
    fn unread_counts_received_until_marked_seen() {
        let mut s = store_with_notes();
        assert_eq!(s.unread_count(), 3); // own note never counts
        assert_eq!(s.mark_seen(), 3);
        assert_eq!(s.unread_count(), 0);
        assert_eq!(s.mark_seen(), 0); // idempotent
        s.notes.push(note("ee", true, Some("tb1p-carol")));
        assert_eq!(s.unread_count(), 1);
    }

    #[test]
    fn spending_section_defaults_empty_and_disabled() {
        let s = Store::new(&[7u8; 32], Network::Regtest);
        assert!(!s.spending.enabled);
        assert_eq!(s.spending.next_receive, 0);
        assert_eq!(s.spending.next_change, 0);
        assert!(s.spending.used.is_empty());
        assert!(s.spending_self_spks().is_empty());
    }

    #[test]
    fn spending_mark_used_advances_indexes_and_dedupes() {
        let mut s = Store::new(&[7u8; 32], Network::Regtest);
        s.spending_mark_used(SpendingAddr {
            chain: 0,
            index: 0,
            address: "bc1qreceive0".into(),
            script_pubkey_hex: "0014aa".into(),
        });
        s.spending_mark_used(SpendingAddr {
            chain: 1,
            index: 2,
            address: "bc1qchange2".into(),
            script_pubkey_hex: "0014bb".into(),
        });
        assert_eq!(s.spending.next_receive, 1);
        assert_eq!(s.spending.next_change, 3);
        assert_eq!(s.spending.used.len(), 2);
        assert_eq!(s.spending_self_spks(), vec![hex::decode("0014aa").unwrap(), hex::decode("0014bb").unwrap()]);

        // Re-marking the same (chain, index) is idempotent and never
        // lowers an index a later observation already advanced past.
        s.spending_mark_used(SpendingAddr {
            chain: 0,
            index: 0,
            address: "bc1qreceive0".into(),
            script_pubkey_hex: "0014aa".into(),
        });
        assert_eq!(s.spending.used.len(), 2);
        assert_eq!(s.spending.next_receive, 1);
    }

    #[test]
    fn spending_apply_discovery_merges_and_never_lowers_indexes() {
        let mut s = Store::new(&[7u8; 32], Network::Regtest);
        // Local state already advanced past index 5 on an unconfirmed
        // change spend the discovery scan below can't see yet.
        s.spending.next_change = 5;

        s.spending_apply_discovery(
            vec![
                SpendingAddr { chain: 0, index: 0, address: "r0".into(), script_pubkey_hex: "00".into() },
                SpendingAddr { chain: 0, index: 2, address: "r2".into(), script_pubkey_hex: "01".into() },
            ],
            3,
            1,
        );
        assert_eq!(s.spending.used.len(), 2);
        assert_eq!(s.spending.next_receive, 3);
        // Discovery's next_change=1 must not un-advance the local 5.
        assert_eq!(s.spending.next_change, 5);
    }

    #[test]
    fn spending_field_is_runtime_only_and_never_round_trips_via_store() {
        // Funding-unification M3.1: the spending section moved to the
        // per-identity notebooks index (account-level), so `Store.spending`
        // is now `#[serde(skip)]` — a populated cache must NOT survive a
        // plain store save/load cycle, and the saved JSON must carry no
        // "spending" key at all (requirement: no stale field in per-
        // notebook store files).
        let dir = std::env::temp_dir().join(format!("cn-store-spending-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("store-regtest-aabbccdd.json");
        let mut s = Store::new(&[7u8; 32], Network::Regtest);
        s.spending_set_enabled(true);
        s.spending_mark_used(SpendingAddr {
            chain: 0,
            index: 0,
            address: "bc1qreceive0".into(),
            script_pubkey_hex: "0014aa".into(),
        });
        s.save(&path).unwrap();
        let back = Store::load(&path).unwrap();
        assert!(!back.spending.enabled);
        assert!(back.spending.used.is_empty());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("\"spending\""));

        // A STALE store file left over from an M2/M3 build (spending key
        // still in the JSON) loads fine — the field is simply ignored, not
        // adopted and not an error.
        let legacy_path = dir.join("store-regtest-legacy.json");
        std::fs::write(
            &legacy_path,
            r#"{
                "version": 1,
                "network": "regtest",
                "identity_fingerprint": "aa",
                "address": "bcrt1paaaa",
                "notes": [],
                "utxos": [],
                "contacts": [],
                "txs": [],
                "spending": {"enabled": true, "next_receive": 3, "next_change": 1, "used": []}
            }"#,
        )
        .unwrap();
        let legacy = Store::load(&legacy_path).unwrap();
        assert!(!legacy.spending.enabled);
        assert!(legacy.spending_self_spks().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spending_shared_across_notebooks_via_notebook_index() {
        use crate::notebooks::NotebookIndex;
        // Simulates the app's stamp-then-write-back pattern (`activate()` /
        // `State::save_spending`): load a store for a notebook, stamp its
        // `spending` runtime cache from the ACCOUNT-level `NotebookIndex`,
        // mutate, write back — proving two notebooks of the same account
        // (different leaves, so different store files) never diverge, and
        // that a mark-used via either one advances the index the other
        // sees (fresh-address discipline across the whole account).
        let mut ix = NotebookIndex::new();
        let mut store_a = Store::new(&[1u8; 32], Network::Regtest); // notebook 0
        let mut store_b = Store::new(&[2u8; 32], Network::Regtest); // notebook 1, same account

        store_a.spending = ix.spending_for(0);
        store_a.spending_set_enabled(true);
        store_a.spending_mark_used(SpendingAddr {
            chain: 0,
            index: 0,
            address: "a0".into(),
            script_pubkey_hex: "00".into(),
        });
        ix.set_spending(0, store_a.spending.clone());

        // Notebook B stamps FRESH from the account-level section and sees
        // notebook A's enabled flag + index — not independent, empty state.
        store_b.spending = ix.spending_for(0);
        assert!(store_b.spending.enabled);
        assert_eq!(store_b.spending.next_receive, 1);

        // A mark-used via B advances the SAME index A will see next.
        store_b.spending_mark_used(SpendingAddr {
            chain: 0,
            index: 1,
            address: "a1".into(),
            script_pubkey_hex: "01".into(),
        });
        ix.set_spending(0, store_b.spending.clone());
        store_a.spending = ix.spending_for(0);
        assert_eq!(store_a.spending.next_receive, 2);
        assert_eq!(store_a.spending.used.len(), 2);
        // Feeds the self-spk SCAN SET identically for every notebook of
        // the account (requirement: apply_bundle recognizes the account's
        // spending spks for every notebook).
        assert_eq!(store_a.spending_self_spks().len(), 2);
    }

    // ---- task #14: dropped-pending detection — the pure state machine
    // (`resolve_dropped`) plus its two Store-level wirings. ----

    use crate::chain::TxLookupStatus;

    #[test]
    fn resolve_dropped_marks_notfound_plus_unspent_as_dropped() {
        assert!(resolve_dropped(false, TxLookupStatus::NotFound, || Some(true)));
    }

    #[test]
    fn resolve_dropped_transient_error_never_changes_state() {
        // Not-yet-dropped stays not-dropped...
        assert!(!resolve_dropped(false, TxLookupStatus::Unknown, || {
            panic!("must not evaluate the unspent check on a transient error")
        }));
        // ...and an already-dropped record STAYS dropped through a blip
        // (a transient error must never clear it either — that would need
        // a real reappearance).
        assert!(resolve_dropped(true, TxLookupStatus::Unknown, || {
            panic!("must not evaluate the unspent check on a transient error")
        }));
    }

    #[test]
    fn resolve_dropped_reappearing_tx_clears_the_flag() {
        assert!(!resolve_dropped(true, TxLookupStatus::Found(false), || {
            panic!("Found must never consult the unspent check")
        }));
        assert!(!resolve_dropped(true, TxLookupStatus::Found(true), || {
            panic!("Found must never consult the unspent check")
        }));
    }

    #[test]
    fn resolve_dropped_notfound_but_input_spent_stays_unchanged() {
        // NotFound alone is not enough — the coin being gone too (spent by
        // something else, or just an inconclusive check) must never flip
        // an un-dropped record to dropped.
        assert!(!resolve_dropped(false, TxLookupStatus::NotFound, || Some(false)));
        assert!(!resolve_dropped(false, TxLookupStatus::NotFound, || None));
    }

    fn tx_input(txid: &str, vout: u32, value: u64) -> TxInput {
        TxInput { txid: txid.into(), vout, value }
    }

    fn pending_tx(txid: &str, first_input: &str) -> TxRecord {
        TxRecord {
            kind: "sweep".into(),
            txids: vec![txid.into()],
            status: NoteStatus::Pending,
            value: 1000,
            fee: 100,
            vsize: 150,
            created_at: Some(1),
            raw_hex: Some("00".into()),
            dest: "ext".into(),
            inputs: vec![tx_input(first_input, 0, 2000)],
            dest_spk_hex: "51".into(),
            input_accounts: vec![0],
            input_indexes: vec![0],
            mixed_inputs: false,
            dropped: false,
        }
    }

    #[test]
    fn resolve_dropped_tx_marks_and_logs_the_transition() {
        let mut store = Store::new(&[3u8; 32], Network::Regtest);
        store.txs.push(pending_tx("deadbeef", "coin1"));

        let newly = store.resolve_dropped_tx(
            |txid| if txid == "deadbeef" { TxLookupStatus::NotFound } else { TxLookupStatus::Unknown },
            |_addr, txid, _vout| if txid == "coin1" { Some(true) } else { None },
        );
        assert_eq!(newly, vec!["deadbeef".to_string()]);
        assert!(store.txs[0].dropped);

        // A second pass with the SAME inputs is not a new transition (the
        // record is already dropped) — the caller must not re-log it.
        let newly2 = store.resolve_dropped_tx(
            |_| TxLookupStatus::NotFound,
            |_addr, txid, _vout| if txid == "coin1" { Some(true) } else { None },
        );
        assert!(newly2.is_empty());
        assert!(store.txs[0].dropped);

        // The tx reappears (found in the mempool again) — cleared.
        let newly3 = store.resolve_dropped_tx(|_| TxLookupStatus::Found(false), |_, _, _| None);
        assert!(newly3.is_empty()); // "cleared" isn't a "newly dropped" transition
        assert!(!store.txs[0].dropped);
    }

    #[test]
    fn resolve_dropped_tx_transient_error_never_marks_dropped() {
        let mut store = Store::new(&[4u8; 32], Network::Regtest);
        store.txs.push(pending_tx("cafef00d", "coin2"));
        let newly = store.resolve_dropped_tx(
            |_| TxLookupStatus::Unknown,
            |_, _, _| panic!("must not be called on a non-NotFound lookup"),
        );
        assert!(newly.is_empty());
        assert!(!store.txs[0].dropped);
    }

    #[test]
    fn resolve_dropped_tx_ignores_confirmed_and_orphaned_records() {
        let mut store = Store::new(&[5u8; 32], Network::Regtest);
        let mut t = pending_tx("11111111", "coin3");
        t.status = NoteStatus::Confirmed;
        store.txs.push(t);
        let newly = store.resolve_dropped_tx(
            |_| TxLookupStatus::NotFound,
            |_, _, _| panic!("a Confirmed record must never reach the unspent check"),
        );
        assert!(newly.is_empty());
        assert!(!store.txs[0].dropped);
    }

    #[test]
    fn resolve_dropped_notes_mirrors_the_tx_state_machine() {
        let mut store = Store::new(&[6u8; 32], Network::Regtest);
        let mut n = note("aa", false, None);
        n.status = NoteStatus::Pending;
        n.txids = vec!["notetxid".into()];
        n.spent = vec![OutPointRef { txid: "notecoin".into(), vout: 0 }];
        store.notes.push(n);

        let newly = store.resolve_dropped_notes(
            |txid| if txid == "notetxid" { TxLookupStatus::NotFound } else { TxLookupStatus::Unknown },
            |_addr, txid, _vout| if txid == "notecoin" { Some(true) } else { None },
        );
        assert_eq!(newly, vec!["notetxid".to_string()]);
        assert!(store.notes[0].dropped);

        // Reappears — cleared.
        store.resolve_dropped_notes(|_| TxLookupStatus::Found(true), |_, _, _| None);
        assert!(!store.notes[0].dropped);
    }

    /// A rescan whose decoder improved must CORRECT a poisoned text cache
    /// (an older binary cached a raw count-prefixed multi body as "text"),
    /// while a failed decode (None) must never clobber a good cache.
    #[test]
    fn fresh_decode_corrects_stale_text_cache() {
        let mut store = Store::new(&[7u8; 32], Network::Testnet4);
        let mut poisoned = note("aaaa1111", true, Some("tb1p-sender"));
        poisoned.text = Some("\u{2}public note to many".into());
        store.notes.push(poisoned);

        let mut rec = RecoveredNote {
            note_id: [0xaa, 0xaa, 0x11, 0x11],
            txids: vec!["t1".into()],
            height: None,
            blocktime: None,
            private: false,
            directed: true,
            received: true,
            sender: Some("tb1p-sender".into()),
            recipient: None,
            recipients: vec![],
            text: Some("public note to many".into()),
        };
        // Fresh scan decodes correctly -> cache corrected.
        store.upsert_note(&rec);
        assert_eq!(store.notes[0].text.as_deref(), Some("public note to many"));

        // A later failed decode (None) never clobbers the good cache.
        rec.text = None;
        store.upsert_note(&rec);
        assert_eq!(store.notes[0].text.as_deref(), Some("public note to many"));
    }

    /// `NoteRecord::reply_set` mirrors notes-core's `bundle::reply_set`:
    /// sender first, then recipients, minus me, deduped; falls back to the
    /// singular `recipient` when `recipients` is empty; a self-note yields
    /// nothing.
    #[test]
    fn reply_set_covers_sender_recipients_self_and_dedup() {
        let me = "tb1p-me";

        // Received single-recipient note: just the sender.
        let mut n = note("aa", true, Some("tb1p-alice"));
        n.recipient = Some(me.to_string());
        assert_eq!(n.reply_set(me), vec!["tb1p-alice".to_string()]);

        // Received MULTI-recipient note: sender first, then every OTHER
        // recipient (me excluded), in order.
        let mut n = note("bb", true, Some("tb1p-alice"));
        n.recipients = vec![me.to_string(), "tb1p-carol".to_string(), "tb1p-dave".to_string()];
        assert_eq!(n.reply_set(me), vec!["tb1p-alice".to_string(), "tb1p-carol".to_string(), "tb1p-dave".to_string()]);

        // Sender appearing again as a recipient (edge case) dedupes.
        let mut n = note("cc", true, Some("tb1p-alice"));
        n.recipients = vec![me.to_string(), "tb1p-alice".to_string()];
        assert_eq!(n.reply_set(me), vec!["tb1p-alice".to_string()]);

        // A self-note (no sender, no recipients) has nothing to reply to.
        let n = note("dd", false, None);
        assert!(n.reply_set(me).is_empty());
    }

    // ---- addr_stats: the 429-throttling task's scan-fingerprint field ----

    #[test]
    fn addr_stats_round_trips_through_save_and_load() {
        use crate::chain::AddrStats;

        let dir = std::env::temp_dir().join(format!("cn-store-addrstats-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store-regtest-addrstats.json");

        let mut s = Store::new(&[7u8; 32], Network::Regtest);
        assert!(s.addr_stats.is_none(), "a fresh store has no stamped fingerprint yet");
        s.addr_stats = Some(AddrStats {
            chain_tx_count: 4,
            chain_funded: 150000,
            chain_spent: 50000,
            mempool_tx_count: 1,
            mempool_funded: 900,
            mempool_spent: 0,
        });
        s.save(&path).unwrap();

        let back = Store::load(&path).unwrap();
        assert_eq!(back.addr_stats, s.addr_stats);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn addr_stats_absent_field_loads_as_none() {
        // A store file saved before this field existed must still load —
        // `#[serde(default)]` tolerance, not a hard error.
        let dir =
            std::env::temp_dir().join(format!("cn-store-addrstats-legacy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store-regtest-legacy-addrstats.json");
        std::fs::write(
            &path,
            r#"{
                "version": 1,
                "network": "regtest",
                "identity_fingerprint": "aa",
                "address": "bcrt1paaaa",
                "notes": [],
                "utxos": [],
                "contacts": [],
                "txs": []
            }"#,
        )
        .unwrap();

        let s = Store::load(&path).unwrap();
        assert!(s.addr_stats.is_none());

        std::fs::remove_dir_all(&dir).ok();
    }
}
