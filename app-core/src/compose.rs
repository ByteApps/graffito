//! Compose orchestration: build via notes-core compose (the ONLY producer
//! of on-chain bytes) → record pending in the store, keyed by the just-
//! built tx's txid (PLAN-pnte-redesign.md: the note id IS the txid — there
//! is no synthetic id to generate up front any more). Broadcast is the
//! caller's step (chain.rs), so a failed POST leaves a retryable Pending
//! note with the tx hex still in hand.

use notes_core::address::Recipient;
use notes_core::address::address_to_script_pubkey;
use notes_core::bundle::{
    compose_directed_note_multi_exact, compose_directed_note_multi_with_change,
    compose_directed_note_pq_exact_amount, compose_directed_note_pq_with_change_amount,
    compose_directed_note_with_change_amount, compose_note_exact, compose_note_with_change, Identity,
};
use notes_core::keys::generate_aux_rand;
use notes_core::pq::SealLayers;
use notes_core::tx::NoteTx;
use notes_core::Network;
use zeroize::Zeroize;

use crate::store::{LedgerUtxo, NoteRecord, NoteStatus, OutPointRef, Store};
use crate::Error;

/// Fresh 32-byte OS-TRNG content key for a multi-recipient private compose
/// (notes-core's `multi_body` hybrid seal, dm.rs) — same one-shot,
/// never-persisted handling as aux-rand: generated fresh per
/// compose attempt, never stored, never logged, and zeroized by the caller
/// immediately after the notes-core call returns. `pub` (not just used
/// internally by [`compose_note`]) — every externally-assembled
/// multi-recipient path (mixed/spending/watch PSBT builders in
/// `psbt_build.rs`/`mixed.rs`, and `on_compose_send_mixed` in the app's own
/// `src/lib.rs`) needs the SAME fresh-per-attempt, zeroize-after convention
/// when it calls notes-core's `sealed_note_payloads_multi` directly.
pub fn fresh_content_key() -> Result<[u8; 32], Error> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).map_err(|_| Error::Entropy)?;
    Ok(key)
}

/// Parse + dedupe a primary + extra recipient address list (first
/// occurrence wins, order preserved) — the same convention notes-core's own
/// internal `dedupe_recipients`/`sealed_note_payloads_multi` use, exposed
/// here so every externally-assembled (mixed/spending/watch) compose path
/// builds its recipient list identically to this module's own
/// [`compose_note`] (whose inline dedupe loop mirrors this exactly).
/// `primary: None` (a self-note) always returns an empty list — extras are
/// only meaningful for a directed note.
pub fn parse_dedupe_recipients(
    network: Network,
    primary: Option<&str>,
    extra: &[&str],
) -> Result<Vec<Recipient>, Error> {
    let mut recipients: Vec<Recipient> = Vec::new();
    if let Some(addr) = primary {
        recipients.push(Recipient::parse(network, addr)?);
        for e in extra {
            let r = Recipient::parse(network, e)?;
            if !recipients.iter().any(|existing| existing.address == r.address) {
                recipients.push(r);
            }
        }
    }
    Ok(recipients)
}

pub struct ComposeRequest<'a> {
    pub text: &'a str,
    pub private: bool,
    /// None = self-note; Some = directed note (dust output).
    pub recipient: Option<&'a str>,
    /// Multi-recipient directed notes: EXTRA recipient addresses beyond
    /// `recipient` (the multi-select contact picker's chips minus the
    /// first). Empty = today's exact single-recipient flow, byte-
    /// identical on the wire — notes-core's multi-recipient entry points
    /// dedupe-then-delegate to the single-recipient builders for exactly
    /// one unique address, so this app only bothers routing through them
    /// at all when there's more than one distinct chip. Every recipient
    /// (primary + extras) gets the SAME `gift_amount` (uniform gift per
    /// recipient — the existing collapsible "Gift · N sats" panel value).
    /// Ignored when `recipient` is None (self-notes never have extras).
    pub extra_recipients: &'a [&'a str],
    /// Where the change goes. None = back to the notes address (default).
    /// Some = a custom address; that change is NOT tracked as a spendable
    /// coin (it leaves this wallet).
    pub change_to: Option<&'a str>,
    /// Coin control: exact inputs to spend as (display-txid, vout).
    /// None = auto-select (largest-first).
    pub coins: Option<&'a [(String, u32)]>,
    pub fee_rate: f64,
    /// Directed notes only: sats to send EACH recipient (the "gift"). None =
    /// DUST_LIMIT (the minimum, and the default). Ignored for self-notes.
    pub gift_amount: Option<u64>,
    /// Per-tx `nLockTime` override (compose screen's collapsible locktime
    /// panel): `None` = fall back to `store.lock_time()` (the device
    /// policy), exactly like `gift_amount`'s `None` = DUST_LIMIT. `Some(h)`
    /// is used VERBATIM — never re-resolved against the device policy —
    /// same "the caller's choice, passed through untouched" rule
    /// `LockTimePolicy::Custom` documents. Never persisted: this is a
    /// transient per-attempt override, not a new setting.
    pub lock_time: Option<u32>,
    /// Local wall-clock seconds for created_at (display only).
    pub now: u64,
    /// Post-quantum: an Argon2id passphrase layer over a directed-private
    /// note (`notes_core::pq::SealLayers::password`), composable with
    /// `pq_mlkem`. Requires a single-recipient DIRECTED PRIVATE note —
    /// `compose_note` errors otherwise (mirrors notes-core's own
    /// `SealLayers`/envelope validity rule: no public/self-note/multi-
    /// recipient pq notes). `None` = no passphrase layer (the ordinary v1
    /// path, byte-identical to before this field existed).
    pub pq_password: Option<String>,
    /// Post-quantum: an ML-KEM hybrid layer sealed to the recipient's
    /// encapsulation key — `(alg, ek_bytes)`. The caller resolves `ek`
    /// (from a `Contact::mlkem_ek` or a freshly imported key) before
    /// calling; this module never looks it up itself. Same single-
    /// recipient directed-PRIVATE requirement as `pq_password`, and the
    /// two compose together (hybrid, never exclusive). `None` = no ML-KEM
    /// layer.
    pub pq_mlkem: Option<(notes_core::pq::MlKemAlg, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct ComposedNote {
    /// PLAN-pnte-redesign.md: the note id IS the txid of the tx this
    /// compose just built — always equal to `tx.txid_hex`. No longer a
    /// synthetic 4-byte id chosen before signing (there is nothing left to
    /// generate — the id only exists once the tx does).
    pub note_id: String,
    pub tx: NoteTx,
    /// The directed-note recipient's address, if any (the FIRST recipient
    /// for a multi-recipient note) — carried alongside the built tx so a
    /// deferred recording step (the universal confirm screen's stage B)
    /// doesn't need to re-parse `req.recipient`.
    pub recipient_address: Option<String>,
    /// Full recipient list, ONLY populated (2+ entries) for a multi-
    /// recipient note — empty for a self-note or an ordinary single-
    /// recipient directed note (mirrors notes-core's/`NoteRecord`'s "empty
    /// means single" convention exactly).
    pub recipients: Vec<String>,
    /// Whether change (if any) returns to the notes address (true) or a
    /// custom `req.change_to` destination (false) — mirrors the
    /// `change_spk.is_none()` check `compose_and_record` used to make
    /// inline before it split into `compose_note` + `record_composed_note`.
    pub change_is_self: bool,
    /// Post-quantum sealing flags this note carries
    /// (`notes_core::envelope::FLAG_PW`/`FLAG_MLKEM`) — 0 for an ordinary
    /// v1 note (every non-pq compose path, and `bump_fee_build`, which
    /// refuses to rebuild a pq note rather than silently drop its layers —
    /// see its doc comment). See [`ComposeRequest::pq_password`]/
    /// [`ComposeRequest::pq_mlkem`].
    pub pq_flags: u8,
}

/// Build + sign ONLY — no store mutation. The paranoid "cancel leaves zero
/// trace" seam: this is everything `compose_and_record` used to do up to
/// the point notes-core hands back a signed [`NoteTx`]. Callers that want
/// the original build-then-record behavior in one step should call
/// [`compose_and_record`]; the universal confirm screen calls this alone at
/// build time and defers [`record_composed_note`] to the user's Broadcast
/// tap.
pub fn compose_note(
    store: &Store,
    identity: &Identity,
    network: Network,
    req: &ComposeRequest,
) -> Result<ComposedNote, Error> {
    let utxos = store.available_utxos();
    // Every recipient (primary `req.recipient` + `req.extra_recipients`,
    // parsed in that order), each paired with the SAME gift amount —
    // empty for a self-note.
    let gift = req.gift_amount.unwrap_or(notes_core::DUST_LIMIT);
    let lock_time = req.lock_time.unwrap_or_else(|| store.lock_time());
    let mut recipients: Vec<(Recipient, u64)> = Vec::new();
    if let Some(addr) = req.recipient {
        recipients.push((Recipient::parse(network, addr)?, gift));
        for extra in req.extra_recipients {
            let r = Recipient::parse(network, extra)?;
            // Dedupe by address (first occurrence wins) BEFORE deciding
            // single-vs-multi — mirrors notes-core's own
            // `dedupe_recipients` so a UI double-pick of the same address
            // (chip re-added, or the primary re-selected as an extra)
            // collapses to a genuine single-recipient note here too, not
            // just at the wire-format layer.
            if !recipients.iter().any(|(existing, _)| existing.address == r.address) {
                recipients.push((r, gift));
            }
        }
    }
    let recipient_address = recipients.first().map(|(r, _)| r.address.clone());
    let recipient_addresses: Vec<String> =
        if recipients.len() >= 2 { recipients.iter().map(|(r, _)| r.address.clone()).collect() } else { Vec::new() };
    // Custom change destination (leaves this wallet, so not ledger-tracked).
    let change = match req.change_to {
        Some(addr) => Some(Recipient::parse(network, addr)?),
        None => None,
    };
    let change_spk = change.as_ref().map(|c| c.spk.as_slice());

    // Coin control: resolve the selected outpoints to spendable inputs.
    let selected: Option<Vec<notes_core::tx::Utxo>> = match req.coins {
        Some(sel) => {
            let mut v = Vec::with_capacity(sel.len());
            for (txid_disp, vout) in sel {
                let l = store
                    .utxos
                    .iter()
                    .find(|u| &u.txid == txid_disp && u.vout == *vout && !u.pending_spend)
                    .ok_or(Error::Store("selected coin is not spendable".into()))?;
                let mut t = [0u8; 32];
                hex::decode_to_slice(&l.txid, &mut t)
                    .map_err(|_| Error::Store("bad coin txid".into()))?;
                t.reverse();
                v.push(notes_core::tx::Utxo { txid: t, vout: l.vout, value: l.value });
            }
            Some(v)
        }
        None => None,
    };

    // Post-quantum layers (Argon2id password / ML-KEM hybrid, notes-core's
    // pq.rs): additive over the ordinary compose path, so this branches out
    // BEFORE the existing self/multi dispatch below rather than threading
    // pq state through it. Structural requirement mirrors notes-core's own
    // `SealLayers`/envelope validity rule: a pq note is always directed,
    // private, and single-recipient — no public/self-note/multi-recipient
    // pq notes exist. `req.private` false, a self-note (`recipients`
    // empty), or a multi-recipient pick (`recipients.len() > 1`) with a pq
    // layer set is refused loudly rather than silently dropping the layer.
    if req.pq_password.is_some() || req.pq_mlkem.is_some() {
        if !req.private || recipients.len() != 1 {
            return Err(Error::Store(
                "post-quantum layers require a single-recipient directed private note".into(),
            ));
        }
        let layers = SealLayers {
            mlkem_ek: req.pq_mlkem.as_ref().map(|(alg, ek)| (*alg, ek.as_slice())),
            password: req.pq_password.as_deref(),
        };
        let pq_flags = layers.flags();
        let (recipient, gift) = &recipients[0];
        let tx = match &selected {
            Some(ins) => compose_directed_note_pq_exact_amount(
                identity, ins, req.text, recipient, *gift, layers,
                change_spk, store.chunk_size, req.fee_rate, lock_time, generate_aux_rand,
            ),
            None => compose_directed_note_pq_with_change_amount(
                identity, &utxos, req.text, recipient, *gift, layers,
                change_spk, store.chunk_size, req.fee_rate, lock_time, generate_aux_rand,
            ),
        }?;
        return Ok(ComposedNote {
            note_id: tx.txid_hex.clone(),
            recipient_address,
            recipients: recipient_addresses,
            change_is_self: change_spk.is_none(),
            pq_flags,
            tx,
        });
    }

    let tx = if recipients.is_empty() {
        match &selected {
            Some(ins) => compose_note_exact(
                identity, ins, req.text, req.private, change_spk,
                store.chunk_size, req.fee_rate, lock_time, generate_aux_rand,
            ),
            None => compose_note_with_change(
                identity, &utxos, req.text, req.private, change_spk,
                store.chunk_size, req.fee_rate, lock_time, generate_aux_rand,
            ),
        }
    } else {
        // Always the MULTI notes-core entry points, even for exactly one
        // recipient: they dedupe-then-delegate to the single-recipient
        // builders in that case, so the wire bytes stay byte-identical to
        // the legacy path — see `compose_directed_note_multi_with_change`'s
        // doc comment. This keeps ONE call site instead of branching the
        // single/multi builders here too.
        let mut content_key = fresh_content_key()?;
        let result = match &selected {
            Some(ins) => compose_directed_note_multi_exact(
                identity, ins, req.text, req.private, &recipients, content_key,
                change_spk, store.chunk_size, req.fee_rate, lock_time, generate_aux_rand,
            ),
            None => compose_directed_note_multi_with_change(
                identity, &utxos, req.text, req.private, &recipients, content_key,
                change_spk, store.chunk_size, req.fee_rate, lock_time, generate_aux_rand,
            ),
        };
        content_key.zeroize();
        result
    }?;

    Ok(ComposedNote {
        note_id: tx.txid_hex.clone(),
        recipient_address,
        recipients: recipient_addresses,
        change_is_self: change_spk.is_none(),
        pq_flags: 0,
        tx,
    })
}

/// Record an already-built [`ComposedNote`] (see [`compose_note`]) into the
/// store: note Pending, inputs locked, change spendable (unconfirmed
/// chaining), contact touched. Split out of `compose_and_record` so the
/// universal confirm screen can defer this — the only store-mutating half
/// of composing a note — to the user's explicit Broadcast tap.
pub fn record_composed_note(
    store: &mut Store,
    text: &str,
    private: bool,
    change_to: Option<&str>,
    created_at: u64,
    composed: &ComposedNote,
) {
    let tx = &composed.tx;
    let spent: Vec<OutPointRef> = tx
        .spent_outpoints
        .iter()
        .map(|(txid, vout)| {
            let mut display = *txid;
            display.reverse();
            OutPointRef { txid: hex::encode(display), vout: *vout }
        })
        .collect();

    // Only track change as our own coin when it returns to the notes
    // address. Custom change leaves the wallet (re-discovered by a scan
    // only if it happens to pay us).
    let change_utxo = (tx.change > 0 && composed.change_is_self).then(|| LedgerUtxo {
        txid: tx.txid_hex.clone(),
        vout: (tx.tx.outputs.len() - 1) as u32,
        value: tx.change,
        height: None,
        pending_spend: false,
    });

    let record = NoteRecord {
        note_id: composed.note_id.clone(),
        status: NoteStatus::Pending,
        text: Some(text.to_string()),
        private,
        directed: composed.recipient_address.is_some(),
        received: false,
        sender: None,
        recipient: composed.recipient_address.clone(),
        recipients: composed.recipients.clone(),
        txids: vec![tx.txid_hex.clone()],
        height: None,
        blocktime: None,
        created_at: Some(created_at),
        spent,
        raw_hex: Some(tx.raw_hex.clone()),
        fee: Some(tx.fee),
        vsize: Some(tx.vsize as u64),
        change_to: change_to.map(str::to_string),
        gift_amount: composed.recipient_address.as_ref().map(|_| tx.sent),
        funded_by: None,
        dropped: false,
        pq_flags: composed.pq_flags,
        // We composed this note ourselves — the plaintext is right there in
        // `text`, so there is nothing to unlock later. `locked` is only
        // ever populated for a RECEIVED pq note the scanner couldn't
        // decrypt yet (see `store::extract_and_apply_pq`/`unlock_note`).
        locked: None,
    };
    store.record_signed(record, change_utxo);

    // Touch every recipient (multi-recipient: all of them; single: just
    // the one) so the contacts "recents" list reflects the whole To list.
    if composed.recipients.is_empty() {
        if let Some(addr) = &composed.recipient_address {
            store.touch_contact(addr);
        }
    } else {
        for addr in &composed.recipients {
            store.touch_contact(addr);
        }
    }
}

/// Build + sign + record in one call — `compose_note` then
/// `record_composed_note` back to back. Kept for every pre-existing caller
/// (the CLI, host tests) so their behavior is byte-identical to before this
/// split.
pub fn compose_and_record(
    store: &mut Store,
    identity: &Identity,
    network: Network,
    req: &ComposeRequest,
) -> Result<ComposedNote, Error> {
    let composed = compose_note(store, identity, network, req)?;
    record_composed_note(store, req.text, req.private, req.change_to, req.now, &composed);
    Ok(composed)
}

/// Build + sign an RBF fee-bump replacement for a Pending note — PURE, no
/// store mutation (the universal confirm screen's stage-A seam, same
/// pattern as [`compose_note`] / [`record_composed_note`]): re-sign the
/// SAME inputs at a higher rate. PLAN-pnte-redesign.md: the note id IS
/// the txid, so a replacement (different fee, different outputs) has a
/// DIFFERENT id from the note it replaces — [`record_bumped_note`] is
/// what actually renames the stored record so the next scan re-matches
/// whichever tx confirms. Callers that want the original build-then-record behavior in
/// one step call [`bump_fee`]; the universal confirm screen calls this
/// alone at Sign time and defers [`record_bumped_note`] to the user's
/// Broadcast tap — a Cancel then leaves the store byte-identical.
/// `lock_time`: `None` = re-resolve the device policy against the store's
/// last-scanned tip (a replacement is the same logical transaction, so a
/// fresher height just buys a bit more anti-fee-sniping protection) —
/// `Some(h)` overrides it verbatim, same convention as
/// [`ComposeRequest::lock_time`]. No caller passes `Some` today (the
/// compose/sweep panels' override doesn't extend to fee-bumping in this
/// milestone); the parameter exists so it can without another signature
/// change.
pub fn bump_fee_build(
    store: &Store,
    identity: &Identity,
    network: Network,
    note_id_hex: &str,
    new_rate: f64,
    lock_time: Option<u32>,
) -> Result<ComposedNote, Error> {
    let rec = store
        .notes
        .iter()
        .find(|n| n.note_id == note_id_hex && n.status == crate::store::NoteStatus::Pending)
        .ok_or(Error::Store("only pending notes can be fee-bumped".into()))?;
    let text = rec.text.clone().ok_or(Error::Store("no cached text".into()))?;
    let private = rec.private;
    let recipient_addr = rec.recipient.clone();
    // Multi-recipient RBF isn't built yet (would need to re-run the whole
    // recipient list + a fresh content_key through the multi builder) —
    // refuse loudly rather than silently rebuild a replacement that drops
    // every recipient but the first.
    if rec.recipients.len() > 1 {
        return Err(Error::Store("fee-bumping a multi-recipient note isn't supported yet".into()));
    }
    // Same reasoning: rebuilding a pq-layered note's replacement would need
    // its original password/ML-KEM ek re-supplied (never persisted, and
    // not threaded through this signature) — refuse rather than silently
    // rebuild a plain v1 replacement that drops both layers.
    if rec.pq_flags != 0 {
        return Err(Error::Store("fee-bumping a post-quantum note isn't supported yet".into()));
    }
    let gift = rec.gift_amount.unwrap_or(notes_core::DUST_LIMIT);
    let change_to = rec.change_to.clone();
    let spent = rec.spent.clone();

    // Rebuild the exact input set (values from the ledger, which retains
    // pending-locked entries).
    let utxos: Vec<notes_core::tx::Utxo> = spent
        .iter()
        .map(|op| {
            let l = store
                .utxos
                .iter()
                .find(|u| u.txid == op.txid && u.vout == op.vout)
                .ok_or(Error::Store("bumped input missing from ledger".into()))?;
            let mut txid = [0u8; 32];
            hex::decode_to_slice(&l.txid, &mut txid).map_err(|_| Error::Store("bad txid".into()))?;
            txid.reverse();
            Ok(notes_core::tx::Utxo { txid, vout: l.vout, value: l.value })
        })
        .collect::<Result<_, Error>>()?;

    let recipient = match &recipient_addr {
        Some(a) => Some(Recipient::parse(network, a)?),
        None => None,
    };
    let change_spk_vec = match &change_to {
        Some(a) => Some(address_to_script_pubkey(network, a)?),
        None => None,
    };
    let change_spk = change_spk_vec.as_deref();
    let lock_time = lock_time.unwrap_or_else(|| store.lock_time());
    let tx = match &recipient {
        Some(r) => compose_directed_note_with_change_amount(
            identity, &utxos, &text, private, r, gift, change_spk,
            store.chunk_size, new_rate, lock_time, generate_aux_rand,
        ),
        None => compose_note_with_change(
            identity, &utxos, &text, private, change_spk,
            store.chunk_size, new_rate, lock_time, generate_aux_rand,
        ),
    }?;

    // PLAN-pnte-redesign.md: the replacement is a DIFFERENT tx (same
    // inputs, different fee/outputs), so it has a DIFFERENT txid — the
    // note's new canonical id. `record_bumped_note` is what actually
    // renames the stored record; this just reports it, same as
    // `compose_note` reporting the freshly-built tx's id.
    Ok(ComposedNote {
        note_id: tx.txid_hex.clone(),
        recipient_address: recipient_addr,
        recipients: Vec::new(),
        change_is_self: change_spk.is_none(),
        pq_flags: 0,
        tx,
    })
}

/// Apply EXACTLY the store mutation the one-shot [`bump_fee`] makes after
/// building: swap the ledger change (drop the replaced tx's outputs,
/// re-add only if change returns to self), append the replacement txid +
/// update raw_hex/fee/vsize on the note record, and — PLAN-pnte-
/// redesign.md — RENAME the record's `note_id` to the replacement's txid
/// (the note id IS the txid now, and a fee-bump is a different tx with a
/// different txid; a Confirmed record's id never changes again, but a
/// Pending one's does on every bump). `old_note_id` is the id
/// [`bump_fee_build`] was called with — the record's CURRENT (about to be
/// superseded) id, needed to find it since building was pure and never
/// touched the store. Returns the record's new id (== `composed.note_id`)
/// on success, so a caller tracking "which row is busy" by id can follow
/// the rename — `None` when the record vanished (e.g. it confirmed
/// between build and record), a quiet no-op the one-shot path can never
/// hit.
pub fn record_bumped_note(
    store: &mut Store,
    old_note_id: &str,
    composed: &ComposedNote,
) -> Option<String> {
    let rec = store.notes.iter().find(|n| n.note_id == old_note_id)?;
    let old_txids = rec.txids.clone();
    store.utxos.retain(|u| !old_txids.contains(&u.txid));
    if composed.tx.change > 0 && composed.change_is_self {
        store.utxos.push(crate::store::LedgerUtxo {
            txid: composed.tx.txid_hex.clone(),
            vout: (composed.tx.tx.outputs.len() - 1) as u32,
            value: composed.tx.change,
            height: None,
            pending_spend: false,
        });
    }
    let rec = store
        .notes
        .iter_mut()
        .find(|n| n.note_id == old_note_id)
        .expect("checked above");
    rec.note_id = composed.tx.txid_hex.clone();
    rec.txids.push(composed.tx.txid_hex.clone());
    rec.raw_hex = Some(composed.tx.raw_hex.clone());
    rec.fee = Some(composed.tx.fee);
    rec.vsize = Some(composed.tx.vsize as u64);
    Some(rec.note_id.clone())
}

/// RBF fee-bump a Pending note: [`bump_fee_build`] then
/// [`record_bumped_note`] back to back — kept for every pre-existing
/// caller (CLI, host tests) so their behavior is byte-identical to before
/// this split (same pattern as [`compose_and_record`]).
pub fn bump_fee(
    store: &mut Store,
    identity: &Identity,
    network: Network,
    note_id_hex: &str,
    new_rate: f64,
) -> Result<ComposedNote, Error> {
    let composed = bump_fee_build(store, identity, network, note_id_hex, new_rate, None)?;
    record_bumped_note(store, note_id_hex, &composed);
    Ok(composed)
}

/// Build + sign an RBF-bump replacement for a pending sweep/consolidate —
/// PURE, no store mutation (universal confirm stage-A seam): re-sign the
/// SAME inputs to the SAME destination at a higher rate. The one-shot
/// [`bump_raw_tx`] is build + [`record_bumped_tx`] back to back.
/// `lock_time`: `None` = re-resolve the device policy (same "fresher
/// height" reasoning as [`bump_fee_build`]); `Some(h)` overrides it
/// verbatim. No caller passes `Some` today — see `bump_fee_build`'s doc
/// comment.
pub fn bump_raw_tx_build(
    store: &Store,
    identity: &Identity,
    txid: &str,
    new_rate: f64,
    lock_time: Option<u32>,
) -> Result<notes_core::tx::NoteTx, Error> {
    let rec = store
        .txs
        .iter()
        .find(|t| {
            t.txids.iter().any(|x| x == txid) && t.status == crate::store::NoteStatus::Pending
        })
        .ok_or(Error::Store("only pending sweeps/consolidations can be bumped".into()))?;
    let inputs: Vec<notes_core::tx::Utxo> = rec
        .inputs
        .iter()
        .map(|i| {
            let mut t = [0u8; 32];
            hex::decode_to_slice(&i.txid, &mut t).map_err(|_| Error::Store("bad txid".into()))?;
            t.reverse();
            Ok(notes_core::tx::Utxo { txid: t, vout: i.vout, value: i.value })
        })
        .collect::<Result<_, Error>>()?;
    let dest_spk =
        hex::decode(&rec.dest_spk_hex).map_err(|_| Error::Store("bad dest spk".into()))?;
    notes_core::tx::build_sweep_tx(
        &inputs,
        &identity.output_x,
        dest_spk,
        new_rate,
        // A replacement is the same logical transaction; re-resolving the
        // policy just gives it a fresher anti-fee-sniping height.
        lock_time.unwrap_or_else(|| store.lock_time()),
        &identity.tweaked_seckey,
        generate_aux_rand,
    )
    .map_err(Into::into)
}

/// Apply EXACTLY the store mutation the one-shot [`bump_raw_tx`] /
/// [`bump_raw_tx_multi`] make after building: append the replacement txid
/// + update raw_hex/fee/vsize/value on the tx record — nothing more or
/// less. `txid` is the SAME reference the build step looked the record up
/// by (any txid in its chain). A vanished record is a quiet no-op; the
/// one-shot paths can never hit that.
pub fn record_bumped_tx(store: &mut Store, txid: &str, tx: &notes_core::tx::NoteTx) {
    let Some(rec) = store.txs.iter_mut().find(|t| t.txids.iter().any(|x| x == txid)) else {
        return;
    };
    rec.txids.push(tx.txid_hex.clone());
    rec.raw_hex = Some(tx.raw_hex.clone());
    rec.fee = tx.fee;
    rec.vsize = tx.vsize as u64;
    rec.value = tx.tx.outputs[0].value;
}

/// RBF-bump a pending sweep/consolidate: [`bump_raw_tx_build`] then
/// [`record_bumped_tx`] back to back — kept for every pre-existing caller
/// so behavior is byte-identical to before this split.
pub fn bump_raw_tx(
    store: &mut Store,
    identity: &Identity,
    txid: &str,
    new_rate: f64,
) -> Result<notes_core::tx::NoteTx, Error> {
    let tx = bump_raw_tx_build(store, identity, txid, new_rate, None)?;
    record_bumped_tx(store, txid, &tx);
    Ok(tx)
}

/// [`bump_raw_tx`] for MULTI-KEY records (wallet sweep/consolidate): the
/// record's per-input owner list — `input_indexes` (rev 3, notebook
/// indexes within the record's account) or `input_accounts` (legacy
/// accounts-as-notebooks records) — says which owner key signs each
/// input, and `identities` supplies each owner's keys under the SAME
/// u32 keying the caller resolved — every input is re-signed by its
/// owner via `build_sweep_tx_multi`, same inputs, same destination,
/// higher rate.
pub fn bump_raw_tx_multi(
    store: &mut Store,
    identities: &[(u32, Identity)],
    txid: &str,
    new_rate: f64,
) -> Result<notes_core::tx::NoteTx, Error> {
    let tx = bump_raw_tx_multi_build(store, identities, txid, new_rate, None)?;
    record_bumped_tx(store, txid, &tx);
    Ok(tx)
}

/// [`bump_raw_tx_multi`]'s PURE build half (universal confirm stage-A
/// seam) — no store mutation; the one-shot wrapper above records via the
/// shared [`record_bumped_tx`]. `lock_time`: `None` = re-resolve the
/// device policy; `Some(h)` overrides it verbatim — see `bump_fee_build`'s
/// doc comment.
pub fn bump_raw_tx_multi_build(
    store: &Store,
    identities: &[(u32, Identity)],
    txid: &str,
    new_rate: f64,
    lock_time: Option<u32>,
) -> Result<notes_core::tx::NoteTx, Error> {
    let rec = store
        .txs
        .iter()
        .find(|t| {
            t.txids.iter().any(|x| x == txid) && t.status == crate::store::NoteStatus::Pending
        })
        .ok_or(Error::Store("only pending sweeps/consolidations can be bumped".into()))?;
    let owners: &[u32] = if !rec.input_indexes.is_empty() {
        &rec.input_indexes
    } else {
        &rec.input_accounts
    };
    if owners.len() != rec.inputs.len() {
        return Err(Error::Store("record has no per-input owners".into()));
    }
    // Group inputs per owner, preserving first-seen order (the
    // original build was source-grouped the same way).
    let mut groups: Vec<(u32, Vec<notes_core::tx::Utxo>)> = Vec::new();
    for (i, acct) in rec.inputs.iter().zip(owners) {
        let mut t = [0u8; 32];
        hex::decode_to_slice(&i.txid, &mut t).map_err(|_| Error::Store("bad txid".into()))?;
        t.reverse();
        let u = notes_core::tx::Utxo { txid: t, vout: i.vout, value: i.value };
        match groups.iter_mut().find(|(a, _)| a == acct) {
            Some((_, v)) => v.push(u),
            None => groups.push((*acct, vec![u])),
        }
    }
    let dest_spk =
        hex::decode(&rec.dest_spk_hex).map_err(|_| Error::Store("bad dest spk".into()))?;
    let sources: Vec<notes_core::tx::SweepSource> = groups
        .iter()
        .map(|(acct, coins)| {
            let (_, id) = identities
                .iter()
                .find(|(a, _)| a == acct)
                .ok_or(Error::Store(format!("no key for account {acct}")))?;
            Ok(notes_core::tx::SweepSource {
                utxos: coins,
                output_x: id.output_x,
                tweaked_seckey: &id.tweaked_seckey,
            })
        })
        .collect::<Result<_, Error>>()?;
    notes_core::tx::build_sweep_tx_multi(
        &sources,
        dest_spk,
        new_rate,
        lock_time.unwrap_or_else(|| store.lock_time()),
        generate_aux_rand,
    )
        .map_err(Into::into)
}

#[cfg(test)]
mod bump_tests {
    use super::*;
    use crate::store::{NoteStatus, Store, TxInput, TxRecord};
    use notes_core::Network;

    /// Multi-key RBF: a wallet sweep/consolidate record carrying
    /// per-input owners re-signs EACH input with its own account's key at
    /// the higher rate — rust-bitcoin recomputes both sighashes and
    /// verifies every signature against the matching owner key.
    #[test]
    fn bump_raw_tx_multi_resigns_per_owner() {
        use bitcoin::consensus::encode::deserialize;
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::{Amount, ScriptBuf, TxOut};

        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let b = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let dest_spk = notes_core::address::p2tr_script_pubkey(
            &Identity::from_app_seed(&[11u8; 32]).unwrap().output_x,
        );

        let mut store = Store::new(&a.output_x, Network::Regtest);
        store.txs.push(TxRecord {
            kind: "sweep".into(),
            txids: vec!["00".repeat(32)],
            status: NoteStatus::Pending,
            value: 69_000,
            fee: 100,
            vsize: 160,
            created_at: Some(1),
            raw_hex: Some(String::new()),
            dest: "ext".into(),
            inputs: vec![
                TxInput { txid: "11".repeat(32), vout: 0, value: 40_000 },
                TxInput { txid: "22".repeat(32), vout: 1, value: 30_000 },
            ],
            dest_spk_hex: hex::encode(&dest_spk),
            // Legacy accounts-as-notebooks owner list — rev-3 records
            // carry input_indexes instead (same re-sign path, owner u32s
            // resolved by the caller).
            input_accounts: vec![0, 3],
            input_indexes: Vec::new(),
            mixed_inputs: false,
            dropped: false,
        });

        fn dup(i: &Identity) -> Identity {
            Identity {
                internal_x: i.internal_x,
                output_x: i.output_x,
                tweaked_seckey: i.tweaked_seckey,
                enc_key: i.enc_key,
            }
        }
        let idents = vec![(0u32, dup(&a)), (3u32, dup(&b))];
        let bumped =
            bump_raw_tx_multi(&mut store, &idents, &"00".repeat(32), 5.0).unwrap();
        assert!(bumped.fee > 100, "fee must rise");
        assert_eq!(bumped.tx.inputs.len(), 2);

        // The record swapped to the replacement.
        let rec = &store.txs[0];
        assert_eq!(rec.txids.len(), 2);
        assert_eq!(rec.fee, bumped.fee);

        // rust-bitcoin verifies each input against ITS OWNER's key.
        let raw = hex::decode(&bumped.raw_hex).unwrap();
        let btx: bitcoin::Transaction = deserialize(&raw).unwrap();
        let spk_a = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&a.output_x));
        let spk_b = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&b.output_x));
        let prevouts = vec![
            TxOut { value: Amount::from_sat(40_000), script_pubkey: spk_a },
            TxOut { value: Amount::from_sat(30_000), script_pubkey: spk_b },
        ];
        let secp = Secp256k1::verification_only();
        let keys = [
            XOnlyPublicKey::from_slice(&a.output_x).unwrap(),
            XOnlyPublicKey::from_slice(&b.output_x).unwrap(),
        ];
        let mut cache = SighashCache::new(&btx);
        for (index, witness) in (0..btx.input.len()).zip(&bumped.tx.witnesses) {
            let sighash = cache
                .taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                )
                .unwrap();
            secp.verify_schnorr(
                &Signature::from_slice(&witness[0]).unwrap(),
                &Message::from_digest(sighash.to_byte_array()),
                &keys[index],
            )
            .expect("each input re-signed by its own owner");
        }

        // A record WITHOUT owners must refuse the multi path (legacy →
        // single-key bump_raw_tx).
        store.txs[0].input_accounts.clear();
        store.txs[0].status = NoteStatus::Pending;
        let last = store.txs[0].txids.last().unwrap().clone();
        assert!(bump_raw_tx_multi(&mut store, &idents, &last, 9.0).is_err());
    }

    /// Universal-confirm split (zero-trace cancel): the `_build` halves
    /// must not touch the store AT ALL, and build + record must land the
    /// store in the same state the original one-shot functions produce.
    /// Raw hex is the one field that can't be byte-compared across two
    /// independent signing runs (schnorr aux-rand randomizes the witness;
    /// the txid — non-witness serialization — IS deterministic), so each
    /// store's raw_hex is checked against its own returned tx instead.
    #[test]
    fn bump_builds_are_pure_and_build_plus_record_matches_one_shot() {
        let id = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let dest_spk = notes_core::address::p2tr_script_pubkey(
            &Identity::from_app_seed(&[11u8; 32]).unwrap().output_x,
        );

        // ---- TxRecord (sweep/consolidate) case: bump_raw_tx ----
        let mut base = Store::new(&id.output_x, Network::Regtest);
        base.txs.push(TxRecord {
            kind: "sweep".into(),
            txids: vec!["00".repeat(32)],
            status: NoteStatus::Pending,
            value: 69_000,
            fee: 100,
            vsize: 160,
            created_at: Some(1),
            raw_hex: Some(String::new()),
            dest: "ext".into(),
            inputs: vec![
                TxInput { txid: "11".repeat(32), vout: 0, value: 40_000 },
                TxInput { txid: "22".repeat(32), vout: 1, value: 30_000 },
            ],
            dest_spk_hex: hex::encode(&dest_spk),
            input_accounts: Vec::new(),
            input_indexes: Vec::new(),
            mixed_inputs: false,
            dropped: false,
        });
        let mut one_shot = base.clone();
        let mut split = base.clone();

        // Purity: a build-only call leaves the store byte-identical.
        let before = serde_json::to_string(&split).unwrap();
        let built = bump_raw_tx_build(&split, &id, &"00".repeat(32), 5.0, None).unwrap();
        assert_eq!(
            serde_json::to_string(&split).unwrap(),
            before,
            "bump_raw_tx_build must not mutate the store"
        );

        // Build + record == one-shot on every deterministic field.
        let one = bump_raw_tx(&mut one_shot, &id, &"00".repeat(32), 5.0).unwrap();
        record_bumped_tx(&mut split, &"00".repeat(32), &built);
        let (ra, rb) = (&one_shot.txs[0], &split.txs[0]);
        assert_eq!(ra.txids, rb.txids, "same replacement txid appended");
        assert_eq!(ra.fee, rb.fee);
        assert_eq!(ra.vsize, rb.vsize);
        assert_eq!(ra.value, rb.value);
        assert_eq!(ra.raw_hex.as_deref(), Some(one.raw_hex.as_str()));
        assert_eq!(rb.raw_hex.as_deref(), Some(built.raw_hex.as_str()));

        // ---- NoteRecord case: bump_fee (record step also swaps the
        // ledger change UTXO) ----
        let mut note_base = Store::new(&id.output_x, Network::Regtest);
        note_base.utxos.push(crate::store::LedgerUtxo {
            txid: "33".repeat(32),
            vout: 0,
            value: 80_000,
            height: Some(1),
            pending_spend: false,
        });
        let composed = compose_and_record(
            &mut note_base,
            &id,
            Network::Regtest,
            &ComposeRequest {
                text: "bump me",
                private: false,
                recipient: None,
                extra_recipients: &[],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: None,
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();
        let note_id = composed.note_id.clone();
        let mut one_shot = note_base.clone();
        let mut split = note_base.clone();

        let before = serde_json::to_string(&split).unwrap();
        let built = bump_fee_build(&split, &id, Network::Regtest, &note_id, 5.0, None).unwrap();
        assert_eq!(
            serde_json::to_string(&split).unwrap(),
            before,
            "bump_fee_build must not mutate the store"
        );

        let one = bump_fee(&mut one_shot, &id, Network::Regtest, &note_id, 5.0).unwrap();
        record_bumped_note(&mut split, &note_id, &built);
        let (na, nb) = (&one_shot.notes[0], &split.notes[0]);
        assert_eq!(na.txids, nb.txids, "same replacement txid appended");
        assert_eq!(na.note_id, nb.note_id, "both rename to the same replacement txid");
        assert_eq!(na.note_id, na.txids.last().cloned().unwrap(), "renamed id IS the current txid");
        assert_ne!(na.note_id, note_id, "the bumped note's id changed from the original txid");
        assert_eq!(na.fee, nb.fee);
        assert_eq!(na.vsize, nb.vsize);
        assert_eq!(na.raw_hex.as_deref(), Some(one.tx.raw_hex.as_str()));
        assert_eq!(nb.raw_hex.as_deref(), Some(built.tx.raw_hex.as_str()));
        // Ledger change swap matches too: old change gone, the same new
        // change UTXO (deterministic txid/vout/value) in both stores.
        let utxo_key = |s: &Store| -> Vec<(String, u32, u64, bool)> {
            s.utxos.iter().map(|u| (u.txid.clone(), u.vout, u.value, u.pending_spend)).collect()
        };
        assert_eq!(utxo_key(&one_shot), utxo_key(&split));
        assert!(
            split.utxos.iter().any(|u| u.txid == built.tx.txid_hex),
            "replacement change UTXO tracked"
        );
    }
}

#[cfg(test)]
mod multi_recipient_tests {
    use super::*;
    use crate::store::Store;
    use notes_core::Network;

    const NET: Network = Network::Regtest;

    fn funded_store(identity: &Identity) -> Store {
        let mut store = Store::new(&identity.output_x, NET);
        store.utxos.push(LedgerUtxo {
            txid: "aa".repeat(32),
            vout: 0,
            value: 100_000,
            height: Some(100),
            pending_spend: false,
        });
        store
    }

    /// A directed note with `extra_recipients` empty (the ordinary single-
    /// recipient flow) must stay byte-identical to notes-core's own
    /// single-recipient builder — proves this app's new multi-aware branch
    /// in `compose_note` didn't change the legacy wire format.
    #[test]
    fn single_recipient_via_multi_branch_is_byte_identical() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let bob_addr = bob.address(NET);
        let store = funded_store(&a);

        let composed = compose_note(
            &store,
            &a,
            NET,
            &ComposeRequest {
                text: "hi bob",
                private: false,
                recipient: Some(&bob_addr),
                extra_recipients: &[],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: None,
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();
        assert_eq!(composed.recipient_address.as_deref(), Some(bob_addr.as_str()));
        assert!(composed.recipients.is_empty(), "single recipient: plural list stays empty");

        // Rebuild directly through notes-core's single-recipient entry
        // point over the SAME inputs (there is no more note_id to line up —
        // PLAN-pnte-redesign.md dropped it entirely) and compare txids
        // (non-witness bytes — schnorr aux-rand makes the witness itself
        // non-deterministic across two independent runs).
        let recipient = notes_core::address::Recipient::parse(NET, &bob_addr).unwrap();
        let direct = notes_core::bundle::compose_directed_note_with_change_amount(
            &a,
            &store.available_utxos(),
            "hi bob",
            false,
            &recipient,
            notes_core::DUST_LIMIT,
            None,
            store.chunk_size,
            1.0,
            0,
            notes_core::keys::generate_aux_rand,
        )
        .unwrap();
        assert_eq!(composed.tx.txid_hex, direct.txid_hex);
        assert_eq!(composed.tx.raw_hex.len(), direct.raw_hex.len(), "same shape/size");
    }

    /// `extra_recipients` with the SAME address as `recipient` (a UI
    /// double-pick) dedupes down to one unique address — the plural
    /// `recipients` list stays empty, same as any other single-recipient
    /// compose (notes-core's `dedupe_recipients` + 1-entry delegation).
    #[test]
    fn duplicate_recipient_dedupes_to_single() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let bob_addr = bob.address(NET);
        let store = funded_store(&a);

        let composed = compose_note(
            &store,
            &a,
            NET,
            &ComposeRequest {
                text: "hi bob",
                private: false,
                recipient: Some(&bob_addr),
                extra_recipients: &[&bob_addr],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: None,
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();
        assert!(composed.recipients.is_empty());
        // Exactly one recipient output at the dust gift, not two.
        let gift_outputs =
            composed.tx.tx.outputs.iter().filter(|o| o.value == notes_core::DUST_LIMIT).count();
        assert_eq!(gift_outputs, 1);
    }

    /// A public note to 3 distinct recipients: three DUST_LIMIT outputs
    /// (uniform gift), `recipients` carries all three in order, and
    /// `record_composed_note` persists the plural list + touches every
    /// recipient as a recent contact.
    #[test]
    fn multi_recipient_public_note_builds_and_records() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let carol = Identity::from_app_seed(&[11u8; 32]).unwrap();
        let dave = Identity::from_app_seed(&[13u8; 32]).unwrap();
        let (bob_addr, carol_addr, dave_addr) = (bob.address(NET), carol.address(NET), dave.address(NET));
        let mut store = funded_store(&a);

        let composed = compose_and_record(
            &mut store,
            &a,
            NET,
            &ComposeRequest {
                text: "group note",
                private: false,
                recipient: Some(&bob_addr),
                extra_recipients: &[&carol_addr, &dave_addr],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: None,
                now: 42,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();

        assert_eq!(composed.recipient_address.as_deref(), Some(bob_addr.as_str()));
        assert_eq!(composed.recipients, vec![bob_addr.clone(), carol_addr.clone(), dave_addr.clone()]);
        let gift_outputs: Vec<u64> = composed
            .tx
            .tx
            .outputs
            .iter()
            .filter(|o| o.value == notes_core::DUST_LIMIT)
            .map(|o| o.value)
            .collect();
        assert_eq!(gift_outputs.len(), 3, "one dust output per recipient");

        let rec = store.notes.iter().find(|n| n.note_id == composed.note_id).unwrap();
        assert_eq!(rec.recipient.as_deref(), Some(bob_addr.as_str()));
        assert_eq!(rec.recipients, vec![bob_addr.clone(), carol_addr.clone(), dave_addr.clone()]);
        assert!(rec.directed);

        // All three landed as recent contacts.
        for addr in [&bob_addr, &carol_addr, &dave_addr] {
            assert!(store.contacts.iter().any(|c| &c.address == addr), "{addr} touched as contact");
        }
    }

    /// A custom (uniform) gift applies to EVERY recipient, not just the
    /// first.
    #[test]
    fn multi_recipient_gift_is_uniform() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let carol = Identity::from_app_seed(&[11u8; 32]).unwrap();
        let (bob_addr, carol_addr) = (bob.address(NET), carol.address(NET));
        let store = funded_store(&a);

        let composed = compose_note(
            &store,
            &a,
            NET,
            &ComposeRequest {
                text: "gift for both",
                private: false,
                recipient: Some(&bob_addr),
                extra_recipients: &[&carol_addr],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: Some(5_000),
                lock_time: None,
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();
        let gift_outputs: Vec<u64> =
            composed.tx.tx.outputs.iter().map(|o| o.value).filter(|&v| v == 5_000).collect();
        assert_eq!(gift_outputs.len(), 2, "both recipients get the SAME 5,000-sat gift");
    }

    /// Private + a non-taproot recipient among the extras errors BEFORE
    /// any signing happens — same `RecipientNotTaproot` notes-core raises
    /// for the single-recipient path today, just reached through the
    /// multi entry point.
    #[test]
    fn private_multi_recipient_requires_every_recipient_taproot() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let bob_addr = bob.address(NET);
        // A P2WPKH (non-taproot) segwit address on regtest.
        let non_taproot = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let store = funded_store(&a);

        let err = compose_note(
            &store,
            &a,
            NET,
            &ComposeRequest {
                text: "secret",
                private: true,
                recipient: Some(&bob_addr),
                extra_recipients: &[non_taproot],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: None,
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("taproot"), "got: {err}");
    }

    /// Fee-bumping a multi-recipient note is refused (not silently rebuilt
    /// with only the first recipient) — `bump_fee_build` checks the
    /// stored record's `recipients` list.
    #[test]
    fn bump_fee_refuses_multi_recipient_record() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let carol = Identity::from_app_seed(&[11u8; 32]).unwrap();
        let (bob_addr, carol_addr) = (bob.address(NET), carol.address(NET));
        let mut store = funded_store(&a);

        let composed = compose_and_record(
            &mut store,
            &a,
            NET,
            &ComposeRequest {
                text: "group note",
                private: false,
                recipient: Some(&bob_addr),
                extra_recipients: &[&carol_addr],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: None,
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();

        let err = bump_fee_build(&store, &a, NET, &composed.note_id, 5.0, None).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("multi-recipient"), "got: {err}");
    }
}

/// Mutation-test target: the per-tx locktime override must reach the
/// SIGNED TRANSACTION BYTES, decoded independently via rust-bitcoin — not
/// merely "the value was passed to a function somewhere". Dropping
/// `req.lock_time` (or wiring it to the wrong builder parameter, e.g. the
/// old bare `store.lock_time()` call) must fail these tests.
#[cfg(test)]
mod lock_time_tests {
    use super::*;
    use crate::store::{NoteStatus, Store, TxInput, TxRecord};
    use bitcoin::consensus::encode::deserialize;
    use notes_core::tx::LockTimePolicy;
    use notes_core::Network;

    const NET: Network = Network::Regtest;

    fn funded_store(identity: &Identity) -> Store {
        let mut store = Store::new(&identity.output_x, NET);
        store.utxos.push(LedgerUtxo {
            txid: "aa".repeat(32),
            vout: 0,
            value: 100_000,
            height: Some(100),
            pending_spend: false,
        });
        store
    }

    /// Decode nLockTime from raw signed tx hex via rust-bitcoin, completely
    /// independent of whatever the app's own builders computed — this is
    /// the byte-truth check, same discipline as `confirm.rs`.
    fn decoded_lock_time(raw_hex: &str) -> u32 {
        let bytes = hex::decode(raw_hex).unwrap();
        let tx: bitcoin::Transaction = deserialize(&bytes).unwrap();
        tx.lock_time.to_consensus_u32()
    }

    /// `ComposeRequest.lock_time: Some(h)` reaches the raw tx bytes exactly.
    #[test]
    fn compose_lock_time_override_reaches_raw_tx_bytes() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let store = funded_store(&a);
        let composed = compose_note(
            &store,
            &a,
            NET,
            &ComposeRequest {
                text: "override test",
                private: false,
                recipient: None,
                extra_recipients: &[],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: Some(777_777),
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();
        assert_eq!(decoded_lock_time(&composed.tx.raw_hex), 777_777);
    }

    /// `lock_time: None` still resolves to `store.lock_time()` — default
    /// behavior is UNCHANGED when no override is present. Uses a
    /// non-default store policy so the assertion can't pass by coincidence
    /// (e.g. both happening to be the Tip-with-no-scan 0 fallback).
    #[test]
    fn compose_lock_time_none_falls_back_to_store_default() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let mut store = funded_store(&a);
        store.lock_time = LockTimePolicy::Custom { height: 555_555 };
        let composed = compose_note(
            &store,
            &a,
            NET,
            &ComposeRequest {
                text: "default test",
                private: false,
                recipient: None,
                extra_recipients: &[],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: None,
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();
        assert_eq!(decoded_lock_time(&composed.tx.raw_hex), 555_555);
        assert_eq!(decoded_lock_time(&composed.tx.raw_hex), store.lock_time());
    }

    /// The override WINS over a differing store default — proves it isn't
    /// merely equal by coincidence (the previous test's default happened to
    /// resolve to a fixed height too).
    #[test]
    fn compose_lock_time_override_wins_over_differing_store_default() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let mut store = funded_store(&a);
        store.lock_time = LockTimePolicy::Zero; // the default would be 0
        let composed = compose_note(
            &store,
            &a,
            NET,
            &ComposeRequest {
                text: "override wins",
                private: false,
                recipient: None,
                extra_recipients: &[],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: Some(123_456),
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();
        assert_eq!(decoded_lock_time(&composed.tx.raw_hex), 123_456);
        assert_ne!(decoded_lock_time(&composed.tx.raw_hex), store.lock_time());
    }

    /// The coin-control (`compose_note_exact`) branch honors the override
    /// too — a second builder path, so the plumbing at BOTH of
    /// `compose_note`'s call sites is covered, not just the auto-select one.
    #[test]
    fn compose_lock_time_override_reaches_exact_coin_control_branch() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let store = funded_store(&a);
        let picks = vec![("aa".repeat(32), 0u32)];
        let composed = compose_note(
            &store,
            &a,
            NET,
            &ComposeRequest {
                text: "coin control override",
                private: false,
                recipient: None,
                extra_recipients: &[],
                change_to: None,
                coins: Some(&picks),
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: Some(444_444),
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();
        assert_eq!(decoded_lock_time(&composed.tx.raw_hex), 444_444);
    }

    /// The RBF bump build (`bump_raw_tx_build`, sweep/consolidate
    /// speed-up) accepts the same override-or-fallback contract.
    #[test]
    fn bump_raw_tx_build_override_reaches_raw_tx_bytes() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let dest_spk = notes_core::address::p2tr_script_pubkey(
            &Identity::from_app_seed(&[11u8; 32]).unwrap().output_x,
        );
        let mut store = Store::new(&a.output_x, NET);
        store.txs.push(TxRecord {
            kind: "sweep".into(),
            txids: vec!["00".repeat(32)],
            status: NoteStatus::Pending,
            value: 69_000,
            fee: 100,
            vsize: 160,
            created_at: Some(1),
            raw_hex: Some(String::new()),
            dest: "ext".into(),
            inputs: vec![TxInput { txid: "11".repeat(32), vout: 0, value: 40_000 }],
            dest_spk_hex: hex::encode(&dest_spk),
            input_accounts: Vec::new(),
            input_indexes: Vec::new(),
            mixed_inputs: false,
            dropped: false,
        });
        let built = bump_raw_tx_build(&store, &a, &"00".repeat(32), 5.0, Some(999_999)).unwrap();
        assert_eq!(decoded_lock_time(&built.raw_hex), 999_999);

        // None still falls back to the store default.
        store.lock_time = LockTimePolicy::Custom { height: 222_222 };
        let built_default = bump_raw_tx_build(&store, &a, &"00".repeat(32), 5.0, None).unwrap();
        assert_eq!(decoded_lock_time(&built_default.raw_hex), 222_222);
    }

    /// The note-fee-bump build (`bump_fee_build`) accepts the same
    /// override-or-fallback contract.
    #[test]
    fn bump_fee_build_override_reaches_raw_tx_bytes() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let mut store = funded_store(&a);
        let composed = compose_and_record(
            &mut store,
            &a,
            NET,
            &ComposeRequest {
                text: "bump me",
                private: false,
                recipient: None,
                extra_recipients: &[],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: None,
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();
        let built = bump_fee_build(&store, &a, NET, &composed.note_id, 5.0, Some(333_333)).unwrap();
        assert_eq!(decoded_lock_time(&built.tx.raw_hex), 333_333);
    }

    /// Round-trip half of the invariant: the per-tx override must NEVER
    /// touch the persisted store policy. `compose_and_record` mutates the
    /// store in plenty of ways (records the note, locks the spent coin) —
    /// but its `lock_time` field, the ONE thing that would end up written
    /// to `store-<net>-<fp8>.json` on the next save, stays byte-identical
    /// to what it was before this compose, even though the compose itself
    /// used a wildly different overridden height. If a future change ever
    /// threaded the override into `Store.lock_time` instead of just the
    /// one transaction, this test would catch it.
    #[test]
    fn compose_override_never_persists_into_store_policy() {
        let a = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let mut store = funded_store(&a);
        store.lock_time = LockTimePolicy::Tip; // the device default in force
        let _composed = compose_and_record(
            &mut store,
            &a,
            NET,
            &ComposeRequest {
                text: "override must not persist",
                private: false,
                recipient: None,
                extra_recipients: &[],
                change_to: None,
                coins: None,
                fee_rate: 1.0,
                gift_amount: None,
                lock_time: Some(999_999),
                now: 1,
                pq_password: None,
                pq_mlkem: None,
            },
        )
        .unwrap();
        assert_eq!(store.lock_time, LockTimePolicy::Tip, "device policy field must be untouched");
        // The store's serialized shape carries only the device policy — no
        // second locktime-shaped field exists for an override to hide in.
        let policy_json = serde_json::to_value(store.lock_time).unwrap();
        assert_eq!(policy_json, serde_json::json!({"mode": "tip"}));
    }
}
