//! Compose orchestration: unique note_id → notes-core compose (the ONLY
//! producer of on-chain bytes) → record pending in the store. Broadcast
//! is the caller's step (chain.rs), so a failed POST leaves a retryable
//! Pending note with the tx hex still in hand.

use notes_core::address::Recipient;
use notes_core::address::address_to_script_pubkey;
use notes_core::bundle::{
    compose_directed_note_exact_amount, compose_directed_note_with_change_amount,
    compose_note_exact, compose_note_with_change, Identity,
};
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
    /// Where the change goes. None = back to the notes address (default).
    /// Some = a custom address; that change is NOT tracked as a spendable
    /// coin (it leaves this wallet).
    pub change_to: Option<&'a str>,
    /// Coin control: exact inputs to spend as (display-txid, vout).
    /// None = auto-select (largest-first).
    pub coins: Option<&'a [(String, u32)]>,
    pub fee_rate: f64,
    /// Directed notes only: sats to send the recipient (the "gift"). None =
    /// DUST_LIMIT (the minimum, and the default). Ignored for self-notes.
    pub gift_amount: Option<u64>,
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

    let gift = req.gift_amount.unwrap_or(notes_core::DUST_LIMIT);
    let tx = match (&recipient, &selected) {
        (Some(r), Some(ins)) => compose_directed_note_exact_amount(
            identity, ins, req.text, req.private, note_id, r, gift, change_spk,
            store.chunk_size, req.fee_rate, generate_aux_rand,
        ),
        (Some(r), None) => compose_directed_note_with_change_amount(
            identity, &utxos, req.text, req.private, note_id, r, gift, change_spk,
            store.chunk_size, req.fee_rate, generate_aux_rand,
        ),
        (None, Some(ins)) => compose_note_exact(
            identity, ins, req.text, req.private, note_id, change_spk,
            store.chunk_size, req.fee_rate, generate_aux_rand,
        ),
        (None, None) => compose_note_with_change(
            identity, &utxos, req.text, req.private, note_id, change_spk,
            store.chunk_size, req.fee_rate, generate_aux_rand,
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

    // Only track change as our own coin when it returns to the notes
    // address. Custom change leaves the wallet (re-discovered by a scan
    // only if it happens to pay us).
    let change_utxo = (tx.change > 0 && change_spk.is_none()).then(|| LedgerUtxo {
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
        fee: Some(tx.fee),
        vsize: Some(tx.vsize as u64),
        change_to: req.change_to.map(str::to_string),
        gift_amount: recipient.as_ref().map(|_| tx.sent),
    };
    store.record_signed(record, change_utxo);

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
    let gift = rec.gift_amount.unwrap_or(notes_core::DUST_LIMIT);
    let change_to = rec.change_to.clone();
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
    let change_spk_vec = match &change_to {
        Some(a) => Some(address_to_script_pubkey(network, a)?),
        None => None,
    };
    let change_spk = change_spk_vec.as_deref();
    let tx = match &recipient {
        Some(r) => compose_directed_note_with_change_amount(
            identity, &utxos, &text, private, note_id, r, gift, change_spk,
            store.chunk_size, new_rate, generate_aux_rand,
        ),
        None => compose_note_with_change(
            identity, &utxos, &text, private, note_id, change_spk,
            store.chunk_size, new_rate, generate_aux_rand,
        ),
    }?;

    // Swap ledger change: drop the replaced tx's outputs; re-add only if
    // change returns to self.
    store.utxos.retain(|u| !old_txids.contains(&u.txid));
    if tx.change > 0 && change_spk.is_none() {
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
    rec.fee = Some(tx.fee);
    rec.vsize = Some(tx.vsize as u64);

    Ok(ComposedNote { note_id: note_id_hex.to_string(), tx })
}

/// RBF-bump a pending sweep/consolidate: re-sign the SAME inputs to the
/// SAME destination at a higher rate. Returns the new signed tx; the
/// caller broadcasts it and the store swaps txids/raw_hex/fee.
pub fn bump_raw_tx(
    store: &mut Store,
    identity: &Identity,
    txid: &str,
    new_rate: f64,
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
    let tx = notes_core::tx::build_sweep_tx(
        &inputs,
        &identity.output_x,
        dest_spk,
        new_rate,
        &identity.tweaked_seckey,
        generate_aux_rand,
    )?;
    let rec = store
        .txs
        .iter_mut()
        .find(|t| t.txids.iter().any(|x| x == txid))
        .expect("checked above");
    rec.txids.push(tx.txid_hex.clone());
    rec.raw_hex = Some(tx.raw_hex.clone());
    rec.fee = tx.fee;
    rec.vsize = tx.vsize as u64;
    rec.value = tx.tx.outputs[0].value;
    Ok(tx)
}
