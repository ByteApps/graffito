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
        funded_by: None,
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
    let tx = notes_core::tx::build_sweep_tx_multi(&sources, dest_spk, new_rate, generate_aux_rand)?;
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
}
