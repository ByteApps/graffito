//! Compose orchestration: unique note_id → notes-core compose (the ONLY
//! producer of on-chain bytes) → record pending in the store. Broadcast
//! is the caller's step (chain.rs), so a failed POST leaves a retryable
//! Pending note with the tx hex still in hand.

use notes_core::address::Recipient;
use notes_core::bundle::{compose_directed_note, compose_note, Identity};
use notes_core::keys::{generate_aux_rand, generate_note_id, pick_unique_note_id};
use notes_core::tx::NoteTx;
use notes_core::Network;

use crate::store::{LedgerUtxo, NoteRecord, NoteStatus, OutPointRef, Store};
use crate::Error;

pub struct ComposeRequest<'a> {
    pub text: &'a str,
    pub private: bool,
    /// None = self-note; Some = directed note (dust output).
    pub recipient: Option<&'a str>,
    pub fee_rate: f64,
    /// Local wall-clock seconds for created_at (display only).
    pub now: u64,
}

pub struct ComposedNote {
    pub note_id: String, // hex8
    pub tx: NoteTx,
}

/// Build + sign + record. The store afterwards: note Pending, inputs
/// locked, change spendable (unconfirmed chaining).
pub fn compose_and_record(
    store: &mut Store,
    identity: &Identity,
    network: Network,
    req: &ComposeRequest,
) -> Result<ComposedNote, Error> {
    let note_id =
        pick_unique_note_id(generate_note_id, |id| store.note_id_taken(id))?;

    let utxos = store.available_utxos();
    let recipient = match req.recipient {
        Some(addr) => Some(Recipient::parse(network, addr)?),
        None => None,
    };

    let tx = match &recipient {
        Some(r) => compose_directed_note(
            identity,
            &utxos,
            req.text,
            req.private,
            note_id,
            r,
            store.chunk_size,
            req.fee_rate,
            generate_aux_rand,
        ),
        None => compose_note(
            identity,
            &utxos,
            req.text,
            req.private,
            note_id,
            store.chunk_size,
            req.fee_rate,
            generate_aux_rand,
        ),
    }?;

    let spent: Vec<OutPointRef> = tx
        .spent_outpoints
        .iter()
        .map(|(txid, vout)| {
            let mut display = *txid;
            display.reverse();
            OutPointRef { txid: hex::encode(display), vout: *vout }
        })
        .collect();

    let change = (tx.change > 0).then(|| LedgerUtxo {
        txid: tx.txid_hex.clone(),
        vout: (tx.tx.outputs.len() - 1) as u32,
        value: tx.change,
        height: None,
        pending_spend: false,
    });

    let record = NoteRecord {
        note_id: hex::encode(note_id),
        status: NoteStatus::Pending,
        text: Some(req.text.to_string()),
        private: req.private,
        directed: recipient.is_some(),
        received: false,
        sender: None,
        recipient: recipient.as_ref().map(|r| r.address.clone()),
        txids: vec![tx.txid_hex.clone()],
        height: None,
        blocktime: None,
        created_at: Some(req.now),
        spent,
        raw_hex: Some(tx.raw_hex.clone()),
    };
    store.record_signed(record, change);

    if let Some(r) = &recipient {
        store.touch_contact(&r.address);
    }

    Ok(ComposedNote { note_id: hex::encode(note_id), tx })
}

/// RBF fee-bump a Pending note: re-sign the SAME note_id spending the
/// SAME inputs at a higher rate. The envelope's note_id is unchanged, so
/// the next scan re-matches whichever tx confirms; the store keeps both
/// txids and swaps the change UTXO.
pub fn bump_fee(
    store: &mut Store,
    identity: &Identity,
    network: Network,
    note_id_hex: &str,
    new_rate: f64,
) -> Result<ComposedNote, Error> {
    let rec = store
        .notes
        .iter()
        .find(|n| n.note_id == note_id_hex && n.status == crate::store::NoteStatus::Pending)
        .ok_or(Error::Store("only pending notes can be fee-bumped".into()))?;
    let text = rec.text.clone().ok_or(Error::Store("no cached text".into()))?;
    let private = rec.private;
    let recipient_addr = rec.recipient.clone();
    let old_txids = rec.txids.clone();
    let spent = rec.spent.clone();

    let mut note_id = [0u8; 4];
    hex::decode_to_slice(note_id_hex, &mut note_id).map_err(|_| Error::Store("bad id".into()))?;

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
    let tx = match &recipient {
        Some(r) => compose_directed_note(
            identity, &utxos, &text, private, note_id, r,
            store.chunk_size, new_rate, generate_aux_rand,
        ),
        None => compose_note(
            identity, &utxos, &text, private, note_id,
            store.chunk_size, new_rate, generate_aux_rand,
        ),
    }?;

    // Swap ledger change: drop the replaced tx's outputs, add the new one.
    store.utxos.retain(|u| !old_txids.contains(&u.txid));
    if tx.change > 0 {
        store.utxos.push(crate::store::LedgerUtxo {
            txid: tx.txid_hex.clone(),
            vout: (tx.tx.outputs.len() - 1) as u32,
            value: tx.change,
            height: None,
            pending_spend: false,
        });
    }
    let rec = store
        .notes
        .iter_mut()
        .find(|n| n.note_id == note_id_hex)
        .expect("checked above");
    rec.txids.push(tx.txid_hex.clone());
    rec.raw_hex = Some(tx.raw_hex.clone());

    Ok(ComposedNote { note_id: note_id_hex.to_string(), tx })
}
