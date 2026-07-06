//! Local store: notes, UTXO ledger, contacts, settings — the Prime
//! state.json model, keyed by identity so switching identities can never
//! mix notebooks. JSON on disk, atomic save (tmp + rename).
//!
//! Merge discipline (the Prime plan's idempotency rule): applying a full
//! bundle plus overlapping incrementals must converge — notes dedupe by
//! (note_id, origin), chain data wins for heights/txids, extracted
//! plaintext wins over a missing cache, and re-applying the same bundle
//! is a no-op.

use notes_core::bundle::{extract_notes, Identity, RecoveredNote, SyncBundle};
use notes_core::tx::Utxo;
use notes_core::Network;
use serde::{Deserialize, Serialize};

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
    #[serde(default)]
    pub tip_height: u64,
    #[serde(default)]
    pub last_scan_time: u64,
    #[serde(default = "default_chunk")]
    pub chunk_size: usize,
    /// Custom esplora base URL (Settings); None = network default.
    #[serde(default)]
    pub esplora: Option<String>,
}

fn default_chunk() -> usize {
    DEFAULT_CHUNK
}

impl Store {
    pub fn new(identity: &Identity, network: Network) -> Self {
        Store {
            version: 1,
            network: network.as_str().to_string(),
            identity_fingerprint: hex::encode(identity.output_x),
            address: identity.address(network),
            notes: Vec::new(),
            utxos: Vec::new(),
            contacts: Vec::new(),
            tip_height: 0,
            last_scan_time: 0,
            chunk_size: DEFAULT_CHUNK,
            esplora: None,
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
    /// detection, incrementals only add.
    pub fn apply_bundle(
        &mut self,
        bundle: &SyncBundle,
        identity: &Identity,
        network: Network,
    ) -> Result<ApplyStats, Error> {
        if hex::encode(identity.output_x) != self.identity_fingerprint {
            return Err(Error::Store("bundle applied to a different identity".into()));
        }

        let mut stats = ApplyStats::default();
        let recovered = extract_notes(bundle, identity, network);
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
        } else {
            self.merge_utxos_incremental(bundle);
        }

        self.tip_height = self.tip_height.max(bundle.tip_height);
        self.last_scan_time = bundle.bundle_time;
        Ok(stats)
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
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ApplyStats {
    pub notes_seen: usize,
    pub notes_new: usize,
    pub orphaned: usize,
}
