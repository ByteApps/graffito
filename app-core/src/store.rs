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
use notes_core::bundle::{extract_notes_multi, extract_notes_watch_multi, Identity, RecoveredNote, SyncBundle};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub address: String,
    #[serde(default)]
    pub name: String,
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
    pub fn apply_bundle(
        &mut self,
        bundle: &SyncBundle,
        identity: &Identity,
        network: Network,
    ) -> Result<ApplyStats, Error> {
        self.check_identity(&identity.output_x)?;
        let mut self_spks = vec![p2tr_script_pubkey(&identity.output_x)];
        self_spks.extend(self.spending_self_spks());
        self.apply_recovered(bundle, extract_notes_multi(bundle, identity, network, &self_spks))
    }

    /// Watch-only [`Self::apply_bundle`]: same merge, but notes extract
    /// without keys — every private body stays sealed (text: None). Watch
    /// identities have no spending wallet (PLAN decision 7), so
    /// `spending_self_spks` is always empty here — this stays byte-
    /// identical to the old `extract_notes_watch` call.
    pub fn apply_bundle_watch(
        &mut self,
        bundle: &SyncBundle,
        output_x: &[u8; 32],
        network: Network,
    ) -> Result<ApplyStats, Error> {
        self.check_identity(output_x)?;
        self.apply_recovered(bundle, extract_notes_watch_multi(bundle, network, &self.spending_self_spks()))
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
                confirmed += 1;
            }
        }
        confirmed
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
                if n.text.is_none() {
                    n.text = note.text.clone();
                }
                if n.recipient.is_none() {
                    n.recipient = note.recipient.clone();
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
    /// cap 20; naming does not bump recency.
    pub fn touch_contact(&mut self, address: &str) {
        let name = self
            .contacts
            .iter()
            .position(|c| c.address == address)
            .map(|i| self.contacts.remove(i).name)
            .unwrap_or_default();
        self.contacts.insert(0, Contact { address: address.to_string(), name });
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
}
