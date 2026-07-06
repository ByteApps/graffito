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
    };
    store.record_signed(record, change);

    if let Some(r) = &recipient {
        store.touch_contact(&r.address);
    }

    Ok(ComposedNote { note_id: hex::encode(note_id), tx })
}
