//! Assemble the UNSIGNED funding PSBT for a note paid by an external wallet.
//!
//! Output order (matches the note-ownership decision — the note stays in the
//! app identity's notebook via a dust-to-self output):
//!   1. OP_RETURN(payload) for each PNTE chunk   (value 0)
//!   2. dust → recipient                          (330, directed notes only)
//!   3. dust → our identity address               (330, discoverability)
//!   4. change → the funding wallet's change addr (when ≥ dust)
//!
//! Inputs are the selected funding UTXOs (RBF sequence). Each PSBT input gets
//! its `witness_utxo` plus BIP-32 / taproot key origins from the descriptor,
//! so a hardware wallet recognises and signs its own inputs. Note bytes come
//! from `notes_core::bundle::sealed_note_payloads`, so the on-chain note is
//! byte-identical to an on-device compose.

use std::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::transaction::{predict_weight, InputWeightPrediction, Version};
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use miniscript::psbt::PsbtInputExt;
use notes_core::address::Recipient;
use notes_core::bundle::{sealed_note_payloads, Identity};
use notes_core::tx::op_return_script;
use notes_core::{Network, DUST_LIMIT};
use zeroize::Zeroize;

use crate::funding::{FundingSource, FundingUtxo};
use crate::identity::KeyMaterial;
use crate::Error;

/// The funding side of a build request: which source, which coins, where
/// change goes, and the fee rate.
pub struct FundingPlan<'a> {
    pub source: &'a FundingSource,
    pub coins: &'a [FundingUtxo],
    pub change_index: u32,
    pub fee_rate: f64,
    /// Custom change scriptPubKey. `None` = the funding wallet's own next
    /// change address (`source`'s change chain at `change_index`).
    pub change_override: Option<Vec<u8>>,
}

/// The note side of a build request.
pub struct NoteParams<'a> {
    pub identity: &'a Identity,
    pub text: &'a str,
    pub private: bool,
    /// `Some` = directed note (dust to the recipient); `None` = self-note.
    pub recipient: Option<&'a Recipient>,
    pub note_id: [u8; 4],
    pub max_op_return_bytes: usize,
    pub network: Network,
}

/// A built unsigned PSBT plus its accounting, for the confirmation UI.
pub struct BuiltPsbt {
    pub psbt: Psbt,
    pub fee: u64,
    pub change: u64,
    pub sent_to_recipient: u64,
    pub dust_to_self: u64,
    /// txid of the unsigned tx (unchanged by segwit signing).
    pub txid: String,
}

impl BuiltPsbt {
    /// Base64 for `.psbt` file / clipboard export.
    pub fn to_base64(&self) -> String {
        self.psbt.to_string()
    }

    /// Raw serialized PSBT bytes (for binary `.psbt` files and UR framing).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.psbt.serialize()
    }
}

/// A coin a watch identity spends — at the descriptor's `chain/{index}` leaf
/// (rev 3: each notebook is one receive (chain 0) index; pre-rev-3 coins are
/// all index 0, the original notes address). Taproot change-chain unit 6:
/// `chain` also carries 1 for the account's own CHANGE-chain coins
/// (`m/86'/…/1/{index}`, [`crate::identity::realize_change`]'s watch-only
/// sibling) — every existing caller constructs `chain: 0`, so a chain-0 coin
/// behaves byte-identically to before the field existed.
#[derive(Debug, Clone)]
pub struct WatchCoin {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    /// 0 = receive/notebook chain, 1 = change chain.
    pub chain: u32,
    pub index: u32,
}

/// Predicted vsize of an all-taproot-keyspend tx with these output script
/// lengths — what the watch bump dialog prices old/new rates against.
pub fn predict_keyspend_vsize(n_inputs: usize, out_lens: impl Iterator<Item = usize>) -> u64 {
    predict_weight(
        std::iter::repeat(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH).take(n_inputs),
        out_lens,
    )
    .to_vbytes_ceil()
}

fn taproot_keyspend_inputs(
    source: &FundingSource,
    coins: &[WatchCoin],
) -> Result<(Vec<TxIn>, Vec<TxOut>, Vec<InputWeightPrediction>), Error> {
    let mut inputs = Vec::with_capacity(coins.len());
    let mut prevouts = Vec::with_capacity(coins.len());
    let mut weights = Vec::with_capacity(coins.len());
    for coin in coins {
        // Unit 6: each coin's OWN chain (0 = receive/notebook, 1 = change) —
        // a chain-0 coin derives exactly as before (byte-identical no-op).
        let leaf_spk = ScriptBuf::from_bytes(source.derive(coin.chain as usize, coin.index)?.spk);
        let txid = Txid::from_str(&coin.txid).map_err(|e| Error::Funding(format!("bad txid: {e}")))?;
        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout: coin.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        prevouts.push(TxOut { value: Amount::from_sat(coin.value), script_pubkey: leaf_spk });
        weights.push(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH);
    }
    Ok((inputs, prevouts, weights))
}

fn assemble_watch_psbt(
    source: &FundingSource,
    coins: &[WatchCoin],
    inputs: Vec<TxIn>,
    prevouts: Vec<TxOut>,
    outputs: Vec<TxOut>,
    lock_time: u32,
) -> Result<(Psbt, String), Error> {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(lock_time),
        input: inputs,
        output: outputs,
    };
    let txid = tx.compute_txid().to_string();
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| Error::Funding(format!("psbt: {e}")))?;
    for (i, coin) in coins.iter().enumerate() {
        // Per-coin definite descriptor: key origins carry each input's own
        // chain+index (unit 6: notebook coins at 0/{index}, change coins at
        // 1/{index}), so a signer recognizes every notebook's AND the
        // account's change coins.
        let def = source.definite(coin.chain as usize, coin.index)?;
        psbt.inputs[i].witness_utxo = Some(prevouts[i].clone());
        psbt.inputs[i]
            .update_with_descriptor_unchecked(&def)
            .map_err(|e| Error::Funding(format!("psbt key origins: {e}")))?;
    }
    Ok((psbt, txid))
}

/// Sweep/consolidate for a WATCH identity: spend `coins` (all at the notes
/// leaf) into ONE `dest_spk` output carrying total − fee, RBF-enabled.
/// An external wallet signs; key origins come from the identity descriptor.
pub fn build_watch_spend_psbt(
    source: &FundingSource,
    coins: &[WatchCoin],
    dest_spk: Vec<u8>,
    fee_rate: f64,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    if coins.is_empty() {
        return Err(Error::Funding("no coins to spend".into()));
    }
    let (inputs, prevouts, weights) = taproot_keyspend_inputs(source, coins)?;
    let weight = predict_weight(weights.iter().copied(), std::iter::once(dest_spk.len()));
    let fee = (weight.to_vbytes_ceil() as f64 * fee_rate).ceil() as u64;
    let in_value: u64 = coins.iter().map(|c| c.value).sum();
    if in_value <= fee || in_value - fee < DUST_LIMIT {
        return Err(Error::Funding("not enough to cover the fee".into()));
    }
    let out_value = in_value - fee;
    let outputs = vec![TxOut {
        value: Amount::from_sat(out_value),
        script_pubkey: ScriptBuf::from_bytes(dest_spk),
    }];
    let (psbt, txid) = assemble_watch_psbt(source, coins, inputs, prevouts, outputs, lock_time)?;
    Ok(BuiltPsbt { psbt, fee, change: 0, sent_to_recipient: out_value, dust_to_self: 0, txid })
}

/// RBF replacement for a WATCH identity's pending tx: identical inputs and
/// outputs, fee raised to `new_rate` sat/vB, the delta taken from the
/// output at `reduce_vout` (the caller picks it — normally the own-address
/// change/consolidation output, or the destination on a sweep).
pub fn build_watch_bump_psbt(
    source: &FundingSource,
    coins: &[WatchCoin],
    prev_outputs: &[(Vec<u8>, u64)],
    reduce_vout: usize,
    new_rate: f64,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    if coins.is_empty() || prev_outputs.is_empty() {
        return Err(Error::Funding("nothing to bump".into()));
    }
    if reduce_vout >= prev_outputs.len() {
        return Err(Error::Funding("bad output index".into()));
    }
    let (inputs, prevouts, weights) = taproot_keyspend_inputs(source, coins)?;
    let weight =
        predict_weight(weights.iter().copied(), prev_outputs.iter().map(|(spk, _)| spk.len()));
    let new_fee = (weight.to_vbytes_ceil() as f64 * new_rate).ceil() as u64;
    let in_value: u64 = coins.iter().map(|c| c.value).sum();
    let out_value: u64 = prev_outputs.iter().map(|(_, v)| v).sum();
    let old_fee = in_value.saturating_sub(out_value);
    if new_fee <= old_fee {
        return Err(Error::Funding("new fee must exceed the current fee (BIP-125)".into()));
    }
    let delta = new_fee - old_fee;
    let (_, reduce_value) = &prev_outputs[reduce_vout];
    if *reduce_value < delta + DUST_LIMIT {
        return Err(Error::Funding("output too small to absorb the fee bump".into()));
    }
    let outputs: Vec<TxOut> = prev_outputs
        .iter()
        .enumerate()
        .map(|(i, (spk, v))| TxOut {
            value: Amount::from_sat(if i == reduce_vout { v - delta } else { *v }),
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        })
        .collect();
    let (psbt, txid) = assemble_watch_psbt(source, coins, inputs, prevouts, outputs, lock_time)?;
    Ok(BuiltPsbt {
        psbt,
        fee: new_fee,
        change: 0,
        sent_to_recipient: out_value - delta,
        dust_to_self: 0,
        txid,
    })
}

/// Keyless PUBLIC multi-recipient note body: the exact `FLAG_DIRECTED |
/// FLAG_MULTI` framing `notes_core::bundle::sealed_note_payloads_multi`
/// produces for a PUBLIC (non-private) note — `count(u8) || utf8 text`,
/// unsealed, since a public body needs no key at all (see notes-core's
/// `multi_body`, the `!private` branch). Watch identities have no key
/// material to hand notes-core's identity-keyed entry point, so this
/// hand-frames the same bytes directly; `count` is `recipients.len()`
/// (2..=255, enforced by the caller routing here only when `len() >= 2`).
/// Byte-parity against a keyed `sealed_note_payloads_multi` call (same
/// text/count/note_id) is asserted in this module's tests.
fn public_multi_payloads(
    text: &str,
    recipient_count: usize,
    note_id: [u8; 4],
    max_op_return_bytes: usize,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut body = Vec::with_capacity(1 + text.len());
    body.push(recipient_count as u8);
    body.extend_from_slice(text.as_bytes());
    let flags = notes_core::envelope::FLAG_DIRECTED | notes_core::envelope::FLAG_MULTI;
    notes_core::envelope::encode_chunks(note_id, flags, &body, max_op_return_bytes).map_err(Into::into)
}

/// A WATCH identity's self-funded PUBLIC note: OP_RETURN chunks + an
/// optional directed-recipient output (`recipient_amount` ≥ dust, the
/// gift) + change back to the notes address, spending the identity's own
/// coins — the tx spends from self, so the own-note rule holds on scan.
/// Output order matches the on-device compose (OP_RETURNs, recipient,
/// change), keeping the ledger's change-vout convention. PUBLIC only:
/// sealing needs the enc/DM keys, which a watch device doesn't hold.
pub fn build_watch_note_psbt(
    source: &FundingSource,
    coins: &[WatchCoin],
    text: &str,
    recipient_spk: Option<Vec<u8>>,
    recipient_amount: u64,
    note_id: [u8; 4],
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    let recipients: Vec<(Vec<u8>, u64)> =
        recipient_spk.map(|spk| vec![(spk, recipient_amount)]).unwrap_or_default();
    build_watch_note_psbt_multi(
        source, coins, text, &recipients, note_id, max_op_return_bytes, fee_rate, lock_time,
    )
}

/// Multi-recipient generalization of [`build_watch_note_psbt`]: `recipients`
/// carries EVERY recipient's (scriptPubKey, amount) pair in output order.
/// A watch identity has no key material, so a PUBLIC multi-recipient body
/// can't go through notes-core's identity-keyed `sealed_note_payloads_multi`
/// — [`public_multi_payloads`] hand-frames the SAME `FLAG_MULTI` body
/// (`count(u8) || utf8 text`, unsealed since it's public) that function
/// would produce for a public note, and byte-parity with a keyed call is
/// asserted in this module's tests. 0 recipients = self-note, 1 = ordinary
/// directed note (byte-identical to [`build_watch_note_psbt`], which
/// delegates here), 2+ = genuine multi-recipient.
#[allow(clippy::too_many_arguments)]
pub fn build_watch_note_psbt_multi(
    source: &FundingSource,
    coins: &[WatchCoin],
    text: &str,
    recipients: &[(Vec<u8>, u64)],
    note_id: [u8; 4],
    max_op_return_bytes: usize,
    fee_rate: f64,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    if coins.is_empty() {
        return Err(Error::Funding("no coins selected".into()));
    }
    if text.is_empty() {
        return Err(Error::Funding("empty note".into()));
    }
    if recipients.len() > 255 {
        return Err(Error::Funding("recipients: 1..=255".into()));
    }
    for (_, amount) in recipients {
        if *amount < DUST_LIMIT {
            return Err(Error::Funding(format!("gift below dust ({DUST_LIMIT} sats minimum)")));
        }
    }
    let payloads = if recipients.len() >= 2 {
        public_multi_payloads(text, recipients.len(), note_id, max_op_return_bytes)?
    } else {
        let flags = if !recipients.is_empty() { notes_core::envelope::FLAG_DIRECTED } else { 0 };
        notes_core::envelope::encode_chunks(note_id, flags, text.as_bytes(), max_op_return_bytes)?
    };
    let (inputs, prevouts, weights) = taproot_keyspend_inputs(source, coins)?;
    let self_spk = ScriptBuf::from_bytes(source.derive(0, 0)?.spk);

    let mut outputs: Vec<TxOut> = payloads
        .iter()
        .map(|p| TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(op_return_script(p)) })
        .collect();
    let mut sent_to_recipient = 0u64;
    for (spk, amount) in recipients {
        outputs.push(TxOut {
            value: Amount::from_sat(*amount),
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        });
        sent_to_recipient += amount;
    }

    // Fee/change: prefer change back to self; a sub-dust remainder folds
    // into the fee (build_funding_psbt's policy).
    let in_value: u64 = coins.iter().map(|c| c.value).sum();
    let base_lens: Vec<usize> = outputs.iter().map(|o| o.script_pubkey.len()).collect();
    let mut selected: Option<(u64, u64, bool)> = None;
    for with_change in [true, false] {
        let mut lens = base_lens.clone();
        if with_change {
            lens.push(self_spk.len());
        }
        let vsize = predict_weight(weights.iter().copied(), lens.iter().copied()).to_vbytes_ceil();
        let fee = (vsize as f64 * fee_rate).ceil() as u64;
        if in_value < sent_to_recipient + fee {
            continue;
        }
        let change = in_value - sent_to_recipient - fee;
        if with_change {
            if change >= DUST_LIMIT {
                selected = Some((fee, change, true));
                break;
            }
        } else {
            selected = Some((in_value - sent_to_recipient, 0, false));
            break;
        }
    }
    let (fee, change, with_change) =
        selected.ok_or_else(|| Error::Funding("selected coins don't cover the note + fee".into()))?;
    let mut outputs = outputs;
    if with_change {
        outputs.push(TxOut { value: Amount::from_sat(change), script_pubkey: self_spk });
    }

    let (psbt, txid) = assemble_watch_psbt(source, coins, inputs, prevouts, outputs, lock_time)?;
    Ok(BuiltPsbt { psbt, fee, change, sent_to_recipient, dust_to_self: 0, txid })
}

/// Sweep where an EXTERNAL wallet pays the fee: every notes coin rides in
/// FULL to `dest_spk`, the fee comes out of the funding coins, and change
/// (when ≥ dust) returns to the funding wallet. `identity_source` adds key
/// origins to the notes inputs for watch identities (their signer must
/// recognize them); keyed identities pass None and sign their own inputs
/// via [`sign_own_taproot_inputs`].
pub fn build_funded_sweep_psbt(
    identity_spk: Vec<u8>,
    identity_source: Option<&FundingSource>,
    notes_coins: &[WatchCoin],
    plan: &FundingPlan,
    dest_spk: Vec<u8>,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    if notes_coins.is_empty() {
        return Err(Error::Funding("nothing to sweep".into()));
    }
    if plan.coins.is_empty() {
        return Err(Error::Funding("no funding coins selected".into()));
    }
    let notes_spk = ScriptBuf::from_bytes(identity_spk);
    let mut inputs = Vec::new();
    let mut prevouts = Vec::new();
    let mut weights = Vec::new();
    for coin in notes_coins {
        let txid = Txid::from_str(&coin.txid).map_err(|e| Error::Funding(format!("bad txid: {e}")))?;
        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout: coin.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        // Watch identities may sweep several notebooks (AND the account's
        // change chain, unit 6) at once — each coin sits at its own
        // `chain/{index}` leaf. Keyed identities pass identity_source = None
        // and one spk (they sign their own inputs).
        let spk = match identity_source {
            Some(src) => ScriptBuf::from_bytes(src.derive(coin.chain as usize, coin.index)?.spk),
            None => notes_spk.clone(),
        };
        prevouts.push(TxOut { value: Amount::from_sat(coin.value), script_pubkey: spk });
        weights.push(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH);
    }
    let funding_weight = match plan.source.kind {
        crate::funding::FundingKind::Taproot => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
        crate::funding::FundingKind::Wpkh => InputWeightPrediction::P2WPKH_MAX,
    };
    for coin in plan.coins {
        let txid = Txid::from_str(&coin.txid).map_err(|e| Error::Funding(format!("bad txid: {e}")))?;
        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout: coin.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        let spk = ScriptBuf::from_bytes(plan.source.derive(coin.chain, coin.index)?.spk);
        prevouts.push(TxOut { value: Amount::from_sat(coin.value), script_pubkey: spk });
        weights.push(funding_weight);
    }

    let notes_total: u64 = notes_coins.iter().map(|c| c.value).sum();
    let funding_total: u64 = plan.coins.iter().map(|c| c.value).sum();
    let mut outputs =
        vec![TxOut { value: Amount::from_sat(notes_total), script_pubkey: ScriptBuf::from_bytes(dest_spk) }];
    let change_spk = match &plan.change_override {
        Some(spk) => ScriptBuf::from_bytes(spk.clone()),
        None => ScriptBuf::from_bytes(plan.source.derive(1, plan.change_index)?.spk),
    };
    // Fee entirely from the funding side: prefer a change output, else fold
    // the sub-dust remainder into the fee (same policy as build_funding_psbt).
    let base_lens: Vec<usize> = outputs.iter().map(|o| o.script_pubkey.len()).collect();
    let mut selected: Option<(u64, u64, bool)> = None;
    for with_change in [true, false] {
        let mut lens = base_lens.clone();
        if with_change {
            lens.push(change_spk.len());
        }
        let vsize = predict_weight(weights.iter().copied(), lens.iter().copied()).to_vbytes_ceil();
        let fee = (vsize as f64 * plan.fee_rate).ceil() as u64;
        if funding_total < fee {
            continue;
        }
        let change = funding_total - fee;
        if with_change {
            if change >= DUST_LIMIT {
                selected = Some((fee, change, true));
                break;
            }
        } else {
            selected = Some((funding_total, 0, false));
            break;
        }
    }
    let (fee, change, with_change) = selected
        .ok_or_else(|| Error::Funding("funding coins don't cover the sweep fee".into()))?;
    if with_change {
        outputs.push(TxOut { value: Amount::from_sat(change), script_pubkey: change_spk });
    }

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(lock_time),
        input: inputs,
        output: outputs,
    };
    let txid = tx.compute_txid().to_string();
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| Error::Funding(format!("psbt: {e}")))?;
    for (i, prevout) in prevouts.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(prevout.clone());
    }
    if let Some(src) = identity_source {
        for (i, coin) in notes_coins.iter().enumerate() {
            // Per-coin definite descriptor: each input's key origin carries
            // its own chain+index, so the signer recognizes every notebook's
            // AND the account's change coins (the assemble_watch_psbt rule,
            // unit 6).
            let def = src.definite(coin.chain as usize, coin.index)?;
            psbt.inputs[i]
                .update_with_descriptor_unchecked(&def)
                .map_err(|e| Error::Funding(format!("identity key origins: {e}")))?;
        }
    }
    for (j, coin) in plan.coins.iter().enumerate() {
        let i = notes_coins.len() + j;
        let def = plan.source.definite(coin.chain, coin.index)?;
        psbt.inputs[i]
            .update_with_descriptor_unchecked(&def)
            .map_err(|e| Error::Funding(format!("funding key origins: {e}")))?;
    }
    Ok(BuiltPsbt { psbt, fee, change, sent_to_recipient: notes_total, dust_to_self: 0, txid })
}

/// Sign every PSBT input whose prevout is `p2tr(output_x)` with the
/// identity's tweaked key (BIP-341 key-path, ALL-prevouts, default
/// sighash) — the app's half of a mixed sweep (its own coins + an
/// external fee wallet's). Returns how many inputs it signed.
pub fn sign_own_taproot_inputs(
    psbt: &mut Psbt,
    output_x: &[u8; 32],
    tweaked_seckey: &[u8; 32],
) -> Result<usize, Error> {
    use bitcoin::sighash::{Prevouts, SighashCache};
    use bitcoin::TapSighashType;
    let self_spk = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(output_x));
    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().ok_or_else(|| Error::Funding("input missing witness_utxo".into())))
        .collect::<Result<_, _>>()?;
    let tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&tx);
    let mut signed = 0;
    for (i, pin) in psbt.inputs.iter_mut().enumerate() {
        if prevouts[i].script_pubkey != self_spk {
            continue;
        }
        let sighash = cache
            .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
            .map_err(|e| Error::Funding(format!("sighash: {e}")))?;
        let msg: [u8; 32] = *sighash.as_ref();
        let aux = notes_core::keys::generate_aux_rand()
            .map_err(|_| Error::Funding("aux randomness unavailable".into()))?;
        let sig = notes_core::sign::schnorr_sign(tweaked_seckey, &msg, &aux)?;
        pin.tap_key_sig = Some(bitcoin::taproot::Signature {
            signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&sig)
                .map_err(|e| Error::Funding(e.to_string()))?,
            sighash_type: TapSighashType::Default,
        });
        signed += 1;
    }
    Ok(signed)
}

/// `psbt`'s inputs/outputs recast as a `notes_core::tx::Transaction` — the
/// shape `notes_core::wpkh`'s BIP143 sighash needs. Pure data marshalling
/// (outpoints, values from `witness_utxo`, output scripts/values); no
/// crypto happens here. Every input must already carry a `witness_utxo`
/// (true of every funding input `assemble_funded_note_psbt` builds).
fn to_notes_tx(psbt: &Psbt) -> Result<notes_core::tx::Transaction, Error> {
    let mut inputs = Vec::with_capacity(psbt.unsigned_tx.input.len());
    for (i, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        // notes-core's Transaction model has no per-input sequence — its
        // BIP143 sighash hardcodes the RBF sequence every builder here
        // uses. A different sequence would make the sighash (and thus the
        // signature) silently invalid, so refuse loudly instead.
        if txin.sequence != Sequence::ENABLE_RBF_NO_LOCKTIME {
            return Err(Error::Funding(format!(
                "input {i} sequence {:#010x} unsupported (wpkh sighash assumes RBF 0xfffffffd)",
                txin.sequence.0
            )));
        }
        let value = psbt
            .inputs
            .get(i)
            .and_then(|pin| pin.witness_utxo.as_ref())
            .ok_or_else(|| Error::Funding("input missing witness_utxo".into()))?
            .value
            .to_sat();
        inputs.push(notes_core::tx::Utxo {
            txid: txin.previous_output.txid.to_byte_array(),
            vout: txin.previous_output.vout,
            value,
        });
    }
    let outputs = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| notes_core::tx::TxOut {
            value: o.value.to_sat(),
            script_pubkey: o.script_pubkey.to_bytes(),
        })
        .collect();
    Ok(notes_core::tx::Transaction {
        version: psbt.unsigned_tx.version.0,
        lock_time: psbt.unsigned_tx.lock_time.to_consensus_u32(),
        inputs,
        outputs,
        witnesses: Vec::new(),
    })
}

/// Sign every PSBT input that is a P2WPKH output of the identity's OWN
/// spending wallet — the internal funding kind's own signer (funding-
/// unification M2). Unlike the external kinds, there is no PSBT export/
/// import round-trip: this app holds the keys. `coins` (the funding-scan
/// result that selected these inputs) matches each such input to its
/// (chain, index) leaf by outpoint, and `crate::spending` re-derives the
/// raw key on demand — never persisted (key storage spec).
///
/// The BIP143 sighash and ECDSA signature come from `notes_core::wpkh` —
/// never hand-rolled here (FROZEN invariant: notes-core is the only
/// producer of on-chain-signature bytes). The result is a standard BIP-174
/// `partial_sigs` entry, so the SAME miniscript finalizer path
/// (`psbt_finalize::finalize_extract`) picks it up exactly like any signed
/// `wpkh` descriptor input — no forked finalize path — and composes with
/// [`sign_own_taproot_inputs`] for a mixed tx (rare: sweeping notebook
/// dust together with spending-wallet fee inputs). Returns how many
/// inputs it signed.
pub fn sign_own_wpkh_inputs(
    psbt: &mut Psbt,
    material: &KeyMaterial,
    network: Network,
    account: u32,
    coins: &[FundingUtxo],
) -> Result<usize, Error> {
    let notes_tx = to_notes_tx(psbt)?;
    let mut signed = 0;
    for i in 0..psbt.inputs.len() {
        let outpoint = psbt.unsigned_tx.input[i].previous_output;
        let Some(coin) = coins.iter().find(|c| {
            c.vout == outpoint.vout
                && c.txid.parse::<Txid>().map(|t| t == outpoint.txid).unwrap_or(false)
        }) else {
            continue; // not a spending-wallet input (e.g. a notebook taproot coin)
        };
        let key = crate::spending::derive_spending_key(
            material,
            network,
            account,
            coin.chain as u32,
            coin.index,
        )?;
        let witness = notes_core::wpkh::sign_p2wpkh_input(&notes_tx, i, &key.seckey)
            .map_err(Error::Notes)?;
        let sig = bitcoin::ecdsa::Signature::from_slice(&witness[0])
            .map_err(|e| Error::Funding(format!("wpkh signature: {e}")))?;
        let pubkey = bitcoin::PublicKey::from_slice(&witness[1])
            .map_err(|e| Error::Funding(format!("wpkh pubkey: {e}")))?;
        psbt.inputs[i].partial_sigs.insert(pubkey, sig);
        signed += 1;
    }
    Ok(signed)
}

/// Build the unsigned funding PSBT. Fails with `Error::Funding` on bad coins,
/// insufficient funds, or descriptor derivation problems.
pub fn build_funding_psbt(
    plan: &FundingPlan,
    note: &NoteParams,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    build_funding_psbt_amount(plan, note, DUST_LIMIT, lock_time)
}

/// [`build_funding_psbt`] with a configurable recipient amount (the "gift",
/// funding-unification M3) instead of the hardcoded dust minimum — additive,
/// mirrors the `recipient_amount` parameter [`build_watch_funded_note_psbt`]
/// already takes. `build_funding_psbt` delegates here with `DUST_LIMIT` so
/// every existing caller (external funding wallets, both keyed and watch)
/// stays byte-identical; the internal spending-wallet compose path is the
/// first caller that passes a real gift.
pub fn build_funding_psbt_amount(
    plan: &FundingPlan,
    note: &NoteParams,
    recipient_amount: u64,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    let (payloads, recipient_spk) = sealed_note_payloads(
        note.identity,
        note.text,
        note.private,
        note.recipient,
        note.note_id,
        note.max_op_return_bytes,
    )?;
    let self_spk = notes_core::address::p2tr_script_pubkey(&note.identity.output_x);
    let amount = if recipient_spk.is_some() { recipient_amount.max(DUST_LIMIT) } else { DUST_LIMIT };
    let recipients: Vec<(Vec<u8>, u64)> = recipient_spk.map(|spk| vec![(spk, amount)]).unwrap_or_default();
    assemble_funded_note_psbt(plan, &payloads, &recipients, self_spk, lock_time)
}

/// Multi-recipient generalization of [`build_funding_psbt_amount`]: a
/// KEYED identity's spending-wallet/external-funding note to 2+ recipients
/// (the internal spending-wallet compose path — funding-unification M3 —
/// is the first caller; external-wallet-only funding for a keyed identity
/// reuses it too). `note.recipient` is IGNORED here — `recipients` replaces
/// it (0 = self-note, 1 = ordinary directed note byte-identical to
/// [`build_funding_psbt_amount`], 2+ = genuine multi-recipient, each
/// getting the same `gift_amount`). Private multi-recipient bodies need a
/// fresh one-shot content key (notes-core's hybrid seal) — drawn from OS
/// TRNG via [`crate::compose::fresh_content_key`] and zeroized immediately
/// after use, same one-shot convention as `note_id`/aux-rand.
pub fn build_funding_psbt_multi(
    plan: &FundingPlan,
    note: &NoteParams,
    recipients: &[Recipient],
    gift_amount: u64,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    let gift = gift_amount.max(DUST_LIMIT);
    let (payloads, spks): (Vec<Vec<u8>>, Vec<Vec<u8>>) = if recipients.is_empty() {
        let (p, spk) = sealed_note_payloads(
            note.identity, note.text, note.private, None, note.note_id, note.max_op_return_bytes,
        )?;
        (p, spk.into_iter().collect())
    } else {
        let mut content_key = crate::compose::fresh_content_key()?;
        let result = notes_core::bundle::sealed_note_payloads_multi(
            note.identity,
            note.text,
            note.private,
            recipients,
            note.note_id,
            content_key,
            note.max_op_return_bytes,
        );
        content_key.zeroize();
        result?
    };
    let self_spk = notes_core::address::p2tr_script_pubkey(&note.identity.output_x);
    let out_recipients: Vec<(Vec<u8>, u64)> = spks.into_iter().map(|spk| (spk, gift)).collect();
    assemble_funded_note_psbt(plan, &payloads, &out_recipients, self_spk, lock_time)
}

/// A WATCH identity's externally funded PUBLIC note: the funding wallet's
/// coins pay for OP_RETURN chunks + an optional directed-recipient output
/// (the gift) + the dust-to-self that keeps the note discoverable, change
/// back to the funding wallet. NOTE the frozen-scan caveat: without the
/// key, a rescan attributes an externally funded PUBLIC note as RECEIVED
/// from the funding wallet (ownership is only provable for
/// directed-private) — the app's own record keeps it "own" locally.
pub fn build_watch_funded_note_psbt(
    self_output_x: &[u8; 32],
    plan: &FundingPlan,
    text: &str,
    recipient_spk: Option<Vec<u8>>,
    recipient_amount: u64,
    note_id: [u8; 4],
    max_op_return_bytes: usize,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    let recipients: Vec<(Vec<u8>, u64)> =
        recipient_spk.map(|spk| vec![(spk, recipient_amount)]).unwrap_or_default();
    build_watch_funded_note_psbt_multi(
        self_output_x, plan, text, &recipients, note_id, max_op_return_bytes, lock_time,
    )
}

/// Multi-recipient generalization of [`build_watch_funded_note_psbt`] — the
/// watch-identity analog of [`build_funding_psbt_multi`]: PUBLIC only (no
/// key to seal a private multi body), hand-framed via
/// [`public_multi_payloads`] for 2+ recipients exactly like
/// [`build_watch_note_psbt_multi`].
pub fn build_watch_funded_note_psbt_multi(
    self_output_x: &[u8; 32],
    plan: &FundingPlan,
    text: &str,
    recipients: &[(Vec<u8>, u64)],
    note_id: [u8; 4],
    max_op_return_bytes: usize,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    if text.is_empty() {
        return Err(Error::Funding("empty note".into()));
    }
    if recipients.len() > 255 {
        return Err(Error::Funding("recipients: 1..=255".into()));
    }
    for (_, amount) in recipients {
        if *amount < DUST_LIMIT {
            return Err(Error::Funding(format!("gift below dust ({DUST_LIMIT} sats minimum)")));
        }
    }
    let payloads = if recipients.len() >= 2 {
        public_multi_payloads(text, recipients.len(), note_id, max_op_return_bytes)?
    } else {
        let flags = if !recipients.is_empty() { notes_core::envelope::FLAG_DIRECTED } else { 0 };
        notes_core::envelope::encode_chunks(note_id, flags, text.as_bytes(), max_op_return_bytes)?
    };
    let self_spk = notes_core::address::p2tr_script_pubkey(self_output_x);
    assemble_funded_note_psbt(plan, &payloads, recipients, self_spk, lock_time)
}

/// Shared tail of both funded-note builders: payloads → outputs (OP_RETURNs,
/// recipient carrying `recipient_amount`, dust-to-self, funding change) →
/// PSBT with witness data + key origins on every funding input.
///
/// The dust-to-self output here is UNCONDITIONAL, unlike
/// [`crate::mixed::assemble_mixed_note_psbt`]'s input-anchored skip: `plan`
/// only ever carries `FundingPlan::coins` from a single external/spending
/// `FundingSource` (`build_funding_psbt_amount`'s own doc — this is the
/// spending-wallet-only or external-wallet-only path), never the identity's
/// own notebook UTXOs, so a note built here is NEVER already input-anchored
/// — the dust-to-self is the only thing that keeps it discoverable/owned.
/// (No `CoinSource` flows through this path to assert against; the
/// invariant is structural, enforced by `FundingPlan`'s shape rather than a
/// runtime flag.)
fn assemble_funded_note_psbt(
    plan: &FundingPlan,
    payloads: &[Vec<u8>],
    recipients: &[(Vec<u8>, u64)],
    self_spk: Vec<u8>,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    if plan.coins.is_empty() {
        return Err(Error::Funding("no funding coins selected".into()));
    }

    // --- inputs ---
    let mut inputs = Vec::with_capacity(plan.coins.len());
    let mut prevouts = Vec::with_capacity(plan.coins.len());
    let mut weight_inputs = Vec::with_capacity(plan.coins.len());
    let input_weight = match plan.source.kind {
        crate::funding::FundingKind::Taproot => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
        crate::funding::FundingKind::Wpkh => InputWeightPrediction::P2WPKH_MAX,
    };
    for coin in plan.coins {
        let txid = Txid::from_str(&coin.txid).map_err(|e| Error::Funding(format!("bad txid: {e}")))?;
        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout: coin.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        let spk = ScriptBuf::from_bytes(plan.source.derive(coin.chain, coin.index)?.spk);
        prevouts.push(TxOut { value: Amount::from_sat(coin.value), script_pubkey: spk });
        weight_inputs.push(input_weight);
    }

    // --- fixed outputs (everything but change) ---
    let mut outputs: Vec<TxOut> = payloads
        .iter()
        .map(|p| TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(op_return_script(p)) })
        .collect();
    let mut sent_to_recipient = 0u64;
    for (spk, amount) in recipients {
        outputs.push(TxOut {
            value: Amount::from_sat(*amount),
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        });
        sent_to_recipient += amount;
    }
    outputs.push(TxOut { value: Amount::from_sat(DUST_LIMIT), script_pubkey: ScriptBuf::from_bytes(self_spk) });
    let dust_to_self = DUST_LIMIT;

    // --- fee / change selection (prefer a change output; else fold < dust into fee) ---
    let in_value: u64 = plan.coins.iter().map(|c| c.value).sum();
    let fixed_out: u64 = sent_to_recipient + dust_to_self; // OP_RETURNs are 0-value
    let change_spk = match &plan.change_override {
        Some(spk) => ScriptBuf::from_bytes(spk.clone()),
        None => ScriptBuf::from_bytes(plan.source.derive(1, plan.change_index)?.spk),
    };

    let base_lens: Vec<usize> = outputs.iter().map(|o| o.script_pubkey.len()).collect();
    let mut selected: Option<(u64, u64, bool)> = None; // (fee, change, with_change)
    for with_change in [true, false] {
        let mut lens = base_lens.clone();
        if with_change {
            lens.push(change_spk.len());
        }
        let weight = predict_weight(weight_inputs.iter().copied(), lens.iter().copied());
        let vsize = weight.to_vbytes_ceil();
        let fee = (vsize as f64 * plan.fee_rate).ceil() as u64;
        if in_value < fixed_out + fee {
            continue;
        }
        let change = in_value - fixed_out - fee;
        if with_change {
            if change >= DUST_LIMIT {
                selected = Some((fee, change, true));
                break;
            }
        } else {
            // No change output: any sub-dust remainder folds into the fee.
            selected = Some((in_value - fixed_out, 0, false));
            break;
        }
    }
    let (fee, change, with_change) =
        selected.ok_or_else(|| Error::Funding("insufficient funds for note + fee".into()))?;
    if with_change {
        outputs.push(TxOut { value: Amount::from_sat(change), script_pubkey: change_spk });
    }

    // --- assemble tx + PSBT ---
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(lock_time),
        input: inputs,
        output: outputs,
    };
    let txid = tx.compute_txid().to_string();
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| Error::Funding(format!("psbt: {e}")))?;
    for (i, coin) in plan.coins.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(prevouts[i].clone());
        let def = plan.source.definite(coin.chain, coin.index)?;
        psbt.inputs[i]
            .update_with_descriptor_unchecked(&def)
            .map_err(|e| Error::Funding(format!("psbt key origins: {e}")))?;
    }

    Ok(BuiltPsbt { psbt, fee, change, sent_to_recipient, dust_to_self, txid })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::funding::FundingUtxo;
    use notes_core::bundle::{extract_notes, OnchainTx, SyncBundle};

    const BIP86_ACCT_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
    const NET: Network = Network::Mainnet;

    fn source() -> FundingSource {
        FundingSource::parse(&format!("tr({BIP86_ACCT_XPUB}/<0;1>/*)"), NET).unwrap()
    }

    fn one_coin(src: &FundingSource) -> Vec<FundingUtxo> {
        let a = src.derive(0, 0).unwrap();
        vec![FundingUtxo {
            txid: "a".repeat(64),
            vout: 0,
            value: 100_000,
            address: a.address,
            chain: 0,
            index: 0,
            confirmed: true,
        }]
    }

    #[test]
    fn builds_and_decodes_directed_private() {
        let src = source();
        let coins = one_coin(&src);
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let to_bob = Recipient::parse(NET, &bob.address(NET)).unwrap();

        let plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 2.0, change_override: None };
        let np = NoteParams {
            identity: &alice,
            text: "hi bob, paid from cold storage",
            private: true,
            recipient: Some(&to_bob),
            note_id: [1, 2, 3, 4],
            max_op_return_bytes: 80,
            network: NET,
        };
        let built = build_funding_psbt(&plan, &np, 0).unwrap();
        let tx = &built.psbt.unsigned_tx;

        // dust to self (identity, discoverability) + dust to bob + change present.
        let self_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);
        assert!(tx.output.iter().any(|o| o.script_pubkey.as_bytes() == self_spk && o.value.to_sat() == 330));
        assert!(tx.output.iter().any(|o| o.script_pubkey.as_bytes() == to_bob.spk && o.value.to_sat() == 330));
        let change_spk = src.derive(1, 0).unwrap().spk;
        assert!(tx.output.iter().any(|o| o.script_pubkey.as_bytes() == change_spk));

        // PSBT inputs carry witness_utxo + taproot origin.
        assert!(built.psbt.inputs[0].witness_utxo.is_some());
        assert!(built.psbt.inputs[0].tap_internal_key.is_some());

        // Value balances: in = fee + change + dust_self + dust_recipient.
        assert_eq!(100_000, built.fee + built.change + built.dust_to_self + built.sent_to_recipient);
        assert!(built.fee > 0);

        // END-TO-END: Bob decodes the externally-funded note via the M0
        // candidate-key search (author key = the dust-to-self output).
        let funder = src.derive(0, 0).unwrap().address;
        let payloads: Vec<String> = tx
            .output
            .iter()
            .filter_map(|o| notes_core::tx::op_return_payload(o.script_pubkey.as_bytes()).map(hex::encode))
            .collect();
        let onchain = OnchainTx {
            txid: built.txid.clone(),
            height: Some(1),
            blocktime: Some(1),
            spends_from_self: false,
            payloads,
            pays_self: true,
            sender: Some(funder),                       // funder, NOT the author
            author_candidates: vec![alice.address(NET)], // dust-to-self carries the author key
            recipient: None,
            input_prevout_spks: Vec::new(),
            output_addrs: Vec::new(),
        };
        let bundle = SyncBundle { network: "mainnet".into(), notes_onchain: vec![onchain], ..Default::default() };
        let notes = extract_notes(&bundle, &bob, NET);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].text.as_deref(), Some("hi bob, paid from cold storage"));
        assert_eq!(notes[0].sender.as_deref(), Some(alice.address(NET).as_str()));
    }

    #[test]
    fn self_note_has_no_recipient_dust() {
        let src = source();
        let coins = one_coin(&src);
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 1.0, change_override: None };
        let np = NoteParams {
            identity: &alice,
            text: "note to self",
            private: false,
            recipient: None,
            note_id: [5, 5, 5, 5],
            max_op_return_bytes: 80,
            network: NET,
        };
        let built = build_funding_psbt(&plan, &np, 0).unwrap();
        assert_eq!(built.sent_to_recipient, 0);
        assert_eq!(built.dust_to_self, 330);
        assert_eq!(100_000, built.fee + built.change + 330);
    }

    /// `build_funding_psbt` == `build_funding_psbt_amount(.., DUST_LIMIT, 0)`
    /// byte-for-byte (the delegation this milestone introduced must not
    /// change the existing external-funding path), and a configurable gift
    /// (funding-unification M3, the spending-wallet compose path) sizes the
    /// recipient output instead of the dust default — a self-note's ignores
    /// the amount entirely (no recipient output to size).
    #[test]
    fn funding_psbt_amount_delegates_and_supports_a_gift() {
        let src = source();
        let coins = one_coin(&src);
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let to_bob = Recipient::parse(NET, &bob.address(NET)).unwrap();
        let plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 1.0, change_override: None };
        let np = NoteParams {
            identity: &alice,
            text: "gift test",
            private: false,
            recipient: Some(&to_bob),
            note_id: [2, 2, 2, 2],
            max_op_return_bytes: 80,
            network: NET,
        };
        let default_built = build_funding_psbt(&plan, &np, 0).unwrap();
        let dust_built = build_funding_psbt_amount(&plan, &np, DUST_LIMIT, 0).unwrap();
        assert_eq!(default_built.sent_to_recipient, dust_built.sent_to_recipient);
        assert_eq!(default_built.fee, dust_built.fee);
        assert_eq!(default_built.sent_to_recipient, DUST_LIMIT);

        let gifted = build_funding_psbt_amount(&plan, &np, 5_000, 0).unwrap();
        assert_eq!(gifted.sent_to_recipient, 5_000);
        assert!(gifted.psbt.unsigned_tx.output.iter().any(|o| o.script_pubkey.as_bytes() == to_bob.spk && o.value.to_sat() == 5_000));

        // A gift below dust is clamped UP to dust, never dropped.
        let below_dust = build_funding_psbt_amount(&plan, &np, 10, 0).unwrap();
        assert_eq!(below_dust.sent_to_recipient, DUST_LIMIT);

        // Self-note: the amount is irrelevant (no recipient output exists).
        let self_np = NoteParams { recipient: None, ..np };
        let self_plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 1.0, change_override: None };
        let self_built = build_funding_psbt_amount(&self_plan, &self_np, 99_999, 0).unwrap();
        assert_eq!(self_built.sent_to_recipient, 0);
        assert_eq!(self_built.dust_to_self, DUST_LIMIT);
    }

    /// Watch spend (sweep/consolidate) + bump: build from the identity
    /// descriptor, sign in-process with the matching master key, finalize —
    /// the exact pipeline the external-signer e2e runs against a real node.
    #[test]
    fn watch_spend_and_bump_sign_roundtrip() {
        use crate::psbt_finalize::{finalize_extract, validate_signed};
        use bitcoin::bip32::{Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &[0x22u8; 32]).unwrap();
        let account = master
            .derive_priv(
                &secp,
                &[
                    bitcoin::bip32::ChildNumber::from_hardened_idx(86).unwrap(),
                    bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap(),
                    bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap(),
                ],
            )
            .unwrap();
        let xpub = Xpub::from_priv(&secp, &account);
        let fp = master.fingerprint(&secp);
        let src =
            FundingSource::parse(&format!("tr([{fp}/86'/0'/0']{xpub}/<0;1>/*)"), NET).unwrap();

        let coins = vec![
            WatchCoin { txid: "a".repeat(64), vout: 0, value: 60_000, chain: 0, index: 0 },
            WatchCoin { txid: "b".repeat(64), vout: 1, value: 40_000, chain: 0, index: 0 },
        ];
        let dest = src.derive(0, 0).unwrap().spk; // consolidate to self
        let built = build_watch_spend_psbt(&src, &coins, dest.clone(), 2.0, 0).unwrap();
        assert_eq!(built.psbt.unsigned_tx.output.len(), 1);
        assert_eq!(100_000, built.fee + built.sent_to_recipient);
        assert!(built.psbt.inputs.iter().all(|i| i.tap_internal_key.is_some()
            && i.witness_utxo.is_some()
            && !i.tap_key_origins.is_empty()));

        // Sign with the master (BIP-32 origins route it), finalize.
        let mut psbt = built.psbt.clone();
        let _ = psbt.sign(&master, &secp);
        validate_signed(&psbt, &built.txid).expect("master signs via key origins");
        let (raw, txid, _) = finalize_extract(psbt).expect("finalize");
        assert_eq!(txid, built.txid);
        assert!(!raw.is_empty());

        // Bump the same tx: outputs preserved, fee delta out of output 0.
        let prev_outputs = vec![(dest.clone(), built.sent_to_recipient)];
        let bumped = build_watch_bump_psbt(&src, &coins, &prev_outputs, 0, 5.0, 0).unwrap();
        assert!(bumped.fee > built.fee, "BIP-125: fee must rise");
        assert_eq!(
            bumped.psbt.unsigned_tx.output[0].value.to_sat(),
            built.sent_to_recipient - (bumped.fee - built.fee)
        );
        // Same inputs → same outpoints (a true replacement).
        assert_eq!(
            built.psbt.unsigned_tx.input[0].previous_output,
            bumped.psbt.unsigned_tx.input[0].previous_output
        );
        let mut psbt = bumped.psbt.clone();
        let _ = psbt.sign(&master, &secp);
        validate_signed(&psbt, &bumped.txid).expect("bump signs too");
        assert!(finalize_extract(psbt).is_ok());

        // A bump at (or below) the old rate is rejected.
        assert!(build_watch_bump_psbt(&src, &coins, &prev_outputs, 0, 2.0, 0).is_err());
        // Sweeping less than fee+dust is rejected.
        let tiny = vec![WatchCoin { txid: "c".repeat(64), vout: 0, value: 400, chain: 0, index: 0 }];
        assert!(build_watch_spend_psbt(&src, &tiny, dest, 2.0, 0).is_err());
    }

    /// Unit 6 (watch-only spends the chain-1 change chain): a watch spend
    /// PSBT containing a MIXED chain-0 notebook coin and a chain-1 change
    /// coin must carry per-input taproot key origins whose derivation path
    /// ends in `/{chain}/{index}` — `/0/{index}` for the notebook coin,
    /// `/1/{index}` for the change coin, never swapped. This is the
    /// money-critical guarantee an external signer relies on to derive the
    /// right key; a wrong path signs (or fails to sign) the WRONG key. Also
    /// proves the round-trip: the SAME master key signs BOTH inputs
    /// correctly via their key origins alone (exactly like a hardware
    /// signer would), and the finished tx finalizes.
    #[test]
    fn watch_spend_chain1_input_has_change_key_origin() {
        use crate::psbt_finalize::{finalize_extract, validate_signed};
        use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &[0x44u8; 32]).unwrap();
        let account = master
            .derive_priv(
                &secp,
                &[
                    ChildNumber::from_hardened_idx(86).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                    ChildNumber::from_hardened_idx(0).unwrap(),
                ],
            )
            .unwrap();
        let xpub = Xpub::from_priv(&secp, &account);
        let fp = master.fingerprint(&secp);
        let src = FundingSource::parse(&format!("tr([{fp}/86'/0'/0']{xpub}/<0;1>/*)"), NET).unwrap();

        // Notebook coin at receive index 2, change coin at change index 5 —
        // deliberately DIFFERENT indexes so a chain/index swap would also
        // change the derived pubkey (same-index coins alone couldn't rule
        // out a swap that just happened to still look consistent).
        let coins = vec![
            WatchCoin { txid: "1".repeat(64), vout: 0, value: 50_000, chain: 0, index: 2 },
            WatchCoin { txid: "2".repeat(64), vout: 1, value: 70_000, chain: 1, index: 5 },
        ];
        let dest = src.derive(0, 0).unwrap().spk;
        let built = build_watch_spend_psbt(&src, &coins, dest, 2.0, 0).unwrap();
        assert_eq!(built.psbt.inputs.len(), 2);

        let path_of = |i: usize| {
            let pin = &built.psbt.inputs[i];
            assert!(pin.witness_utxo.is_some(), "input {i} missing witness_utxo");
            let (_leaf_hashes, (_fp, path)) = pin
                .tap_key_origins
                .values()
                .next()
                .unwrap_or_else(|| panic!("input {i} has no taproot key origin"));
            path.clone()
        };
        let path0 = path_of(0).to_string();
        let path1 = path_of(1).to_string();
        assert!(path0.ends_with("/0/2"), "chain-0 input must end /0/2, got {path0}");
        assert!(path1.ends_with("/1/5"), "chain-1 input must end /1/5, got {path1}");
        assert_ne!(path0, path1);

        // Prevout scripts differ (different leaves) — never accidentally equal.
        assert_ne!(
            built.psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey,
            built.psbt.inputs[1].witness_utxo.as_ref().unwrap().script_pubkey
        );

        // The signer (the SAME master key, via BIP-32 key origins alone —
        // exactly the mechanism a hardware wallet uses) signs BOTH inputs
        // correctly and the tx finalizes — proving the key origins actually
        // route to the right leaf, not just that they're present.
        let mut psbt = built.psbt.clone();
        let _ = psbt.sign(&master, &secp);
        validate_signed(&psbt, &built.txid)
            .expect("master signs chain-0 AND chain-1 inputs via key origins");
        assert!(finalize_extract(psbt).is_ok());
    }

    /// Fee-funded sweep, both identity flavors: the notes balance rides in
    /// FULL to the destination, the external wallet pays the fee. Keyed:
    /// the app signs its own taproot inputs (sign_own_taproot_inputs) and
    /// the funding master signs the rest. Watch: both sides sign via key
    /// origins. Finalizes to a valid network tx either way.
    #[test]
    fn funded_sweep_full_value_mixed_signing() {
        use crate::psbt_finalize::{finalize_extract, validate_signed};
        use bitcoin::bip32::{Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;
        use notes_core::sign::schnorr_verify;

        let secp = Secp256k1::new();
        // Funding wallet (external), taproot descriptor with origin.
        let acct_path = [
            bitcoin::bip32::ChildNumber::from_hardened_idx(86).unwrap(),
            bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap(),
            bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap(),
        ];
        let fund_master = Xpriv::new_master(bitcoin::Network::Bitcoin, &[0x33u8; 32]).unwrap();
        let fund_xpub = Xpub::from_priv(&secp, &fund_master.derive_priv(&secp, &acct_path).unwrap());
        let fp = fund_master.fingerprint(&secp);
        let fund_src =
            FundingSource::parse(&format!("tr([{fp}/86'/0'/0']{fund_xpub}/<0;1>/*)"), NET).unwrap();
        let fund_addr = fund_src.derive(0, 0).unwrap();
        let fund_coins = vec![FundingUtxo {
            txid: "d".repeat(64),
            vout: 0,
            value: 5_000,
            address: fund_addr.address,
            chain: 0,
            index: 0,
            confirmed: true,
        }];
        let plan = FundingPlan {
            source: &fund_src,
            coins: &fund_coins,
            change_index: 0,
            fee_rate: 2.0,
            change_override: None,
        };
        let dest = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let dest_spk = notes_core::address::p2tr_script_pubkey(&dest.output_x);

        // ---- keyed identity: app signs its inputs, funding master the rest.
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let alice_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);
        let notes_coins = vec![
            WatchCoin { txid: "e".repeat(64), vout: 0, value: 60_000, chain: 0, index: 0 },
            WatchCoin { txid: "f".repeat(64), vout: 1, value: 40_000, chain: 0, index: 0 },
        ];
        let built =
            build_funded_sweep_psbt(alice_spk.clone(), None, &notes_coins, &plan, dest_spk.clone(), 0)
                .unwrap();
        assert_eq!(built.sent_to_recipient, 100_000, "full notes balance to dest");
        let tx = &built.psbt.unsigned_tx;
        assert!(tx.output.iter().any(|o| o.script_pubkey.as_bytes() == dest_spk && o.value.to_sat() == 100_000));
        assert_eq!(5_000, built.fee + built.change, "fee comes from the funding side only");

        let mut psbt = built.psbt.clone();
        let n = sign_own_taproot_inputs(&mut psbt, &alice.output_x, &alice.tweaked_seckey).unwrap();
        assert_eq!(n, 2, "both notes inputs signed by the app");
        // The app's signatures verify against the identity's output key.
        {
            use bitcoin::sighash::{Prevouts, SighashCache};
            let prevouts: Vec<_> =
                psbt.inputs.iter().map(|i| i.witness_utxo.clone().unwrap()).collect();
            let mut cache = SighashCache::new(&psbt.unsigned_tx);
            for i in 0..2 {
                let sh = cache
                    .taproot_key_spend_signature_hash(
                        i,
                        &Prevouts::All(&prevouts),
                        bitcoin::TapSighashType::Default,
                    )
                    .unwrap();
                let sig = psbt.inputs[i].tap_key_sig.unwrap();
                assert!(schnorr_verify(&alice.output_x, sh.as_ref(), sig.signature.as_ref()));
            }
        }
        let _ = psbt.sign(&fund_master, &secp); // funding wallet signs its input
        validate_signed(&psbt, &built.txid).expect("all inputs signed");
        let (raw, txid, _) = finalize_extract(psbt).expect("finalize mixed tx");
        assert_eq!(txid, built.txid);
        assert!(!raw.is_empty());

        // ---- watch identity: notes inputs carry origins; its master signs.
        let id_master = Xpriv::new_master(bitcoin::Network::Bitcoin, &[0x44u8; 32]).unwrap();
        let id_xpub = Xpub::from_priv(&secp, &id_master.derive_priv(&secp, &acct_path).unwrap());
        let id_fp = id_master.fingerprint(&secp);
        let id_src = FundingSource::parse(
            &format!("tr([{id_fp}/86'/0'/0']{id_xpub}/<0;1>/*)"),
            NET,
        )
        .unwrap();
        let id_spk = id_src.derive(0, 0).unwrap().spk;
        let built =
            build_funded_sweep_psbt(id_spk, Some(&id_src), &notes_coins, &plan, dest_spk, 0).unwrap();
        assert!(!built.psbt.inputs[0].tap_key_origins.is_empty(), "identity origins present");
        let mut psbt = built.psbt.clone();
        let _ = psbt.sign(&id_master, &secp);
        let _ = psbt.sign(&fund_master, &secp);
        validate_signed(&psbt, &built.txid).expect("two external signers");
        assert!(finalize_extract(psbt).is_ok());
    }

    /// Watch compose (public notes): the PSBT spends the identity's own
    /// coins (own-note rule), its OP_RETURN bytes decode as the note, a
    /// directed variant delivers the gift to the recipient, and the
    /// identity's external master signs it into a valid network tx.
    #[test]
    fn watch_note_psbt_public_own_and_directed() {
        use crate::psbt_finalize::{finalize_extract, validate_signed};
        use bitcoin::bip32::{Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;
        use notes_core::bundle::{extract_notes_watch, OnchainTx, SyncBundle};

        let secp = Secp256k1::new();
        let acct_path = [
            bitcoin::bip32::ChildNumber::from_hardened_idx(86).unwrap(),
            bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap(),
            bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap(),
        ];
        let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &[0x55u8; 32]).unwrap();
        let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &acct_path).unwrap());
        let fp = master.fingerprint(&secp);
        let src = FundingSource::parse(&format!("tr([{fp}/86'/0'/0']{xpub}/<0;1>/*)"), NET).unwrap();
        let self_addr = src.derive(0, 0).unwrap();
        let coins = vec![WatchCoin { txid: "9".repeat(64), vout: 0, value: 50_000, chain: 0, index: 0 }];

        // Self public note.
        let built = build_watch_note_psbt(
            &src, &coins, "public from a watch device", None, 0, [1, 2, 3, 4], 80, 2.0, 0)
        .unwrap();
        assert_eq!(built.sent_to_recipient, 0);
        assert_eq!(50_000, built.fee + built.change);
        let mut psbt = built.psbt.clone();
        let _ = psbt.sign(&master, &secp);
        validate_signed(&psbt, &built.txid).expect("identity master signs");
        let (_raw, txid, _) = finalize_extract(psbt).expect("finalize");
        assert_eq!(txid, built.txid);

        // The scan sees an OWN public note (tx spends from self).
        let payloads: Vec<String> = built
            .psbt
            .unsigned_tx
            .output
            .iter()
            .filter_map(|o| notes_core::tx::op_return_payload(o.script_pubkey.as_bytes()).map(hex::encode))
            .collect();
        let bundle = SyncBundle {
            network: "mainnet".into(),
            notes_onchain: vec![OnchainTx {
                txid: built.txid.clone(),
                height: Some(1),
                blocktime: Some(1),
                spends_from_self: true,
                payloads,
                pays_self: true,
                sender: None,
                author_candidates: vec![],
                recipient: None,
                input_prevout_spks: Vec::new(),
                output_addrs: Vec::new(),
            }],
            ..Default::default()
        };
        let notes = extract_notes_watch(&bundle, NET);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].text.as_deref(), Some("public from a watch device"));
        assert!(!notes[0].private && !notes[0].received);

        // Directed public with a gift: recipient output carries the sats,
        // change returns to self, and sub-dust gifts are rejected.
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let to_bob = Recipient::parse(NET, &bob.address(NET)).unwrap();
        let built = build_watch_note_psbt(
            &src, &coins, "hi bob", Some(to_bob.spk.clone()), 1_000, [5, 6, 7, 8], 80, 2.0, 0)
        .unwrap();
        assert_eq!(built.sent_to_recipient, 1_000);
        assert_eq!(50_000, built.fee + built.change + 1_000);
        let tx = &built.psbt.unsigned_tx;
        assert!(tx.output.iter().any(|o| o.script_pubkey.as_bytes() == to_bob.spk && o.value.to_sat() == 1_000));
        // Change is the LAST output, back to the notes address (ledger rule).
        let self_spk = src.derive(0, 0).unwrap().spk;
        assert_eq!(tx.output.last().unwrap().script_pubkey.as_bytes(), self_spk);
        let mut psbt = built.psbt.clone();
        let _ = psbt.sign(&master, &secp);
        assert!(finalize_extract(psbt).is_ok());
        assert!(build_watch_note_psbt(
            &src, &coins, "hi", Some(to_bob.spk.clone()), 100, [5, 6, 7, 9], 80, 2.0
        , 0)
        .is_err(), "sub-dust gift rejected");
        let _ = self_addr;
    }

    /// Watch + external funding compose: the funding wallet pays for the
    /// note, dust-to-self keeps it discoverable, the gift rides to the
    /// recipient, and a key-less rescan attributes it received-from-funder
    /// (the frozen scan rule for externally funded PUBLIC notes).
    #[test]
    fn watch_funded_note_psbt_public() {
        use crate::psbt_finalize::{finalize_extract, validate_signed};
        use bitcoin::bip32::{Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;
        use notes_core::bundle::{extract_notes_watch, OnchainTx, SyncBundle};

        let secp = Secp256k1::new();
        let acct_path = [
            bitcoin::bip32::ChildNumber::from_hardened_idx(86).unwrap(),
            bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap(),
            bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap(),
        ];
        let fund_master = Xpriv::new_master(bitcoin::Network::Bitcoin, &[0x66u8; 32]).unwrap();
        let fund_xpub = Xpub::from_priv(&secp, &fund_master.derive_priv(&secp, &acct_path).unwrap());
        let fp = fund_master.fingerprint(&secp);
        let fund_src =
            FundingSource::parse(&format!("tr([{fp}/86'/0'/0']{fund_xpub}/<0;1>/*)"), NET).unwrap();
        let fund_addr = fund_src.derive(0, 0).unwrap();
        let fund_coins = vec![FundingUtxo {
            txid: "c".repeat(64),
            vout: 0,
            value: 30_000,
            address: fund_addr.address.clone(),
            chain: 0,
            index: 0,
            confirmed: true,
        }];
        let plan = FundingPlan {
            source: &fund_src,
            coins: &fund_coins,
            change_index: 0,
            fee_rate: 2.0,
            change_override: None,
        };
        let me = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let to_bob = Recipient::parse(NET, &bob.address(NET)).unwrap();

        let built = build_watch_funded_note_psbt(
            &me.output_x,
            &plan,
            "funded public note",
            Some(to_bob.spk.clone()),
            700,
            [4, 4, 4, 4],
            80,
            0)
        .unwrap();
        assert_eq!(built.sent_to_recipient, 700, "gift carried");
        assert_eq!(built.dust_to_self, 330);
        assert_eq!(30_000, built.fee + built.change + 700 + 330);
        let tx = &built.psbt.unsigned_tx;
        let self_spk = notes_core::address::p2tr_script_pubkey(&me.output_x);
        assert!(tx.output.iter().any(|o| o.script_pubkey.as_bytes() == self_spk && o.value.to_sat() == 330));

        let mut psbt = built.psbt.clone();
        let _ = psbt.sign(&fund_master, &secp);
        validate_signed(&psbt, &built.txid).expect("funding master signs");
        assert!(finalize_extract(psbt).is_ok());

        // Frozen scan rule: key-less rescan sees it received-from-funder.
        let payloads: Vec<String> = tx
            .output
            .iter()
            .filter_map(|o| notes_core::tx::op_return_payload(o.script_pubkey.as_bytes()).map(hex::encode))
            .collect();
        let bundle = SyncBundle {
            network: "mainnet".into(),
            notes_onchain: vec![OnchainTx {
                txid: built.txid.clone(),
                height: Some(1),
                blocktime: Some(1),
                spends_from_self: false,
                payloads,
                pays_self: true,
                sender: Some(fund_addr.address.clone()),
                author_candidates: vec![],
                recipient: None,
                input_prevout_spks: Vec::new(),
                output_addrs: Vec::new(),
            }],
            ..Default::default()
        };
        let notes = extract_notes_watch(&bundle, NET);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].text.as_deref(), Some("funded public note"));
        assert!(notes[0].received, "external funding ⇒ received on a key-less rescan");
        assert_eq!(notes[0].sender.as_deref(), Some(fund_addr.address.as_str()));

        // Sub-dust gift rejected.
        assert!(build_watch_funded_note_psbt(
            &me.output_x, &plan, "x", Some(to_bob.spk), 100, [4, 4, 4, 5], 80
        , 0)
        .is_err());
    }

    #[test]
    fn insufficient_funds_rejected() {
        let src = source();
        let a = src.derive(0, 0).unwrap();
        let coins = vec![FundingUtxo {
            txid: "b".repeat(64),
            vout: 0,
            value: 400, // < dust_to_self + fee
            address: a.address,
            chain: 0,
            index: 0,
            confirmed: true,
        }];
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 5.0, change_override: None };
        let np = NoteParams {
            identity: &alice,
            text: "too poor",
            private: false,
            recipient: None,
            note_id: [1, 1, 1, 1],
            max_op_return_bytes: 80,
            network: NET,
        };
        assert!(build_funding_psbt(&plan, &np, 0).is_err());
    }

    /// Fully in-app funded note (funding-unification M2): the internal
    /// spending-wallet kind reuses `assemble_funded_note_psbt` byte-for-
    /// byte (via `crate::spending::funding_source`, a `wpkh(...)`
    /// descriptor over the derived account xpub — same code path the
    /// external watch-only wallets use) and signs immediately with
    /// `sign_own_wpkh_inputs` — no PSBT export/import round-trip. Proves:
    /// the funded output shape is unchanged, the P2WPKH witness verifies
    /// under rust-bitcoin's own BIP143 sighash, and a bundle carrying
    /// `input_prevout_spks` scans the note back as OWN even though the tx
    /// never spends from the notebook address itself.
    #[test]
    fn internal_spending_wallet_funds_and_signs_in_app() {
        use crate::identity::parse_key_material;
        use notes_core::bundle::{extract_notes_multi, OnchainTx, SyncBundle};

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon about";
        let material = parse_key_material(mnemonic, NET).unwrap();
        let source = crate::spending::funding_source(&material, NET, 0).unwrap();
        let coin_addr = source.derive(0, 0).unwrap();
        let coins = vec![FundingUtxo {
            txid: "a".repeat(64),
            vout: 0,
            value: 100_000,
            address: coin_addr.address.clone(),
            chain: 0,
            index: 0,
            confirmed: true,
        }];
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();

        let plan =
            FundingPlan { source: &source, coins: &coins, change_index: 0, fee_rate: 2.0, change_override: None };
        let np = NoteParams {
            identity: &alice,
            text: "funded fully in-app",
            private: false,
            recipient: None,
            note_id: [3, 3, 3, 3],
            max_op_return_bytes: 80,
            network: NET,
        };
        let built = build_funding_psbt(&plan, &np, 0).unwrap();

        // Output order unchanged: OP_RETURN, dust-to-self (330), change.
        let outs = &built.psbt.unsigned_tx.output;
        assert!(outs[0].script_pubkey.is_op_return());
        let self_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);
        assert_eq!(outs[1].script_pubkey.as_bytes(), self_spk);
        assert_eq!(outs[1].value.to_sat(), 330);
        let change_spk = source.derive(1, 0).unwrap().spk;
        assert_eq!(outs[2].script_pubkey.as_bytes(), change_spk);

        // Sign fully in-app — no PSBT export, no external wallet.
        let mut psbt = built.psbt.clone();
        let signed = sign_own_wpkh_inputs(&mut psbt, &material, NET, 0, &coins).unwrap();
        assert_eq!(signed, 1);

        let (raw, txid, _vsize) = crate::psbt_finalize::finalize_extract(psbt).unwrap();
        assert_eq!(txid, built.txid, "finalize must not change the txid");

        // rust-bitcoin accepts the P2WPKH witness (sig + pubkey) and its
        // own BIP143 sighash verifies against the derived spending pubkey.
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&hex::decode(&raw).unwrap()).unwrap();
        assert_eq!(tx.input[0].witness.len(), 2);
        let witness = tx.input[0].witness.to_vec();
        let key = crate::spending::derive_spending_key(&material, NET, 0, 0, 0).unwrap();
        assert_eq!(witness[1], key.pubkey.to_vec());

        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::from_bytes(coin_addr.spk.clone()),
        };
        let mut cache = bitcoin::sighash::SighashCache::new(&tx);
        let sighash = cache
            .p2wpkh_signature_hash(
                0,
                &prevout.script_pubkey,
                prevout.value,
                bitcoin::sighash::EcdsaSighashType::All,
            )
            .unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&witness[0][..witness[0].len() - 1]).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_slice(&witness[1]).unwrap();
        secp.verify_ecdsa(&bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array()), &sig, &pk)
            .expect("P2WPKH witness verifies under rust-bitcoin's own sighash");

        // Scan it back: the spending wallet's spk is in the self-spk SET,
        // so the note extracts as OWN even though the tx spends from a
        // bc1q address, not the notebook's own bc1p address.
        let payloads: Vec<String> = tx
            .output
            .iter()
            .filter_map(|o| notes_core::tx::op_return_payload(o.script_pubkey.as_bytes()).map(hex::encode))
            .collect();
        let onchain = OnchainTx {
            txid: txid.clone(),
            height: Some(1),
            blocktime: Some(1),
            spends_from_self: false, // doesn't spend the NOTEBOOK's own spk
            payloads,
            pays_self: true, // the dust-to-self output
            sender: None,
            author_candidates: vec![],
            recipient: None,
            input_prevout_spks: vec![hex::encode(&coin_addr.spk)],
            output_addrs: Vec::new(),
        };
        let bundle = SyncBundle { network: "mainnet".into(), notes_onchain: vec![onchain], ..Default::default() };
        let self_spks = vec![self_spk, coin_addr.spk.clone()];
        let notes = extract_notes_multi(&bundle, &alice, NET, &self_spks);
        assert_eq!(notes.len(), 1);
        assert!(!notes[0].received, "spending-wallet-funded note scans as OWN");
        assert_eq!(notes[0].text.as_deref(), Some("funded fully in-app"));

        // Without the spending spk in the set, the self-spend rule alone
        // (spends_from_self=false) correctly leaves it RECEIVED-shaped —
        // proves the self-spk SET is what's doing the work above, not
        // some other path.
        let notes_without = extract_notes_multi(&bundle, &alice, NET, &[notes_core::address::p2tr_script_pubkey(&alice.output_x)]);
        assert_eq!(notes_without.len(), 1);
        assert!(notes_without[0].received, "without the spk in the set it looks received");
    }

    // ---- multi-all-paths: build_funding_psbt_multi (keyed spending/
    // external funding, 0) + the watch keyless public-multi byte-parity ----

    /// [`public_multi_payloads`] (the watch-identity keyless hand-framer)
    /// must produce EXACTLY the bytes a KEYED identity's
    /// `sealed_note_payloads_multi` produces for a public (non-private)
    /// note with the same text/recipient-count/note_id/chunk — the public
    /// multi body never touches key material (`count(u8) || utf8 text`,
    /// see notes-core's `multi_body`), so the two must be byte-identical
    /// regardless of which (or whose) recipients are named.
    #[test]
    fn public_multi_payloads_byte_parity_with_keyed_sealer() {
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let carol = Identity::from_app_seed(&[11u8; 32]).unwrap();
        let recipients = vec![
            Recipient::parse(NET, &bob.address(NET)).unwrap(),
            Recipient::parse(NET, &carol.address(NET)).unwrap(),
        ];
        let note_id = [9u8, 8, 7, 6];
        let text = "public group note from a watch device";
        let content_key = [0u8; 32]; // unused for a public body — any value must give the same bytes

        let (keyed_payloads, keyed_spks) = notes_core::bundle::sealed_note_payloads_multi(
            &alice, text, false, &recipients, note_id, content_key, 80,
        )
        .unwrap();
        let keyless_payloads = public_multi_payloads(text, recipients.len(), note_id, 80).unwrap();

        assert_eq!(keyed_payloads, keyless_payloads, "hand-framed body must match the keyed sealer byte-for-byte");
        assert_eq!(keyed_spks.len(), 2);

        // Different content_key, different identity: still byte-identical
        // (proves the public body genuinely ignores both).
        let (keyed_payloads_2, _) = notes_core::bundle::sealed_note_payloads_multi(
            &bob, text, false, &recipients, note_id, [0xffu8; 32], 80,
        )
        .unwrap();
        assert_eq!(keyed_payloads, keyed_payloads_2);
    }

    /// A watch identity's SELF-funded public note to 3 recipients: output
    /// order is OP_RETURNs → 3 recipient outputs (uniform gift, in the
    /// caller-supplied order) → change; the tx still signs under the
    /// identity's own descriptor and a key-less scan decodes the
    /// `FLAG_MULTI` body (count byte matches the real recipient count).
    #[test]
    fn watch_note_psbt_multi_three_recipients() {
        use crate::psbt_finalize::{finalize_extract, validate_signed};
        use bitcoin::bip32::{Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let acct_path = [
            bitcoin::bip32::ChildNumber::from_hardened_idx(86).unwrap(),
            bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap(),
            bitcoin::bip32::ChildNumber::from_hardened_idx(0).unwrap(),
        ];
        let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &[0x77u8; 32]).unwrap();
        let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &acct_path).unwrap());
        let fp = master.fingerprint(&secp);
        let src = FundingSource::parse(&format!("tr([{fp}/86'/0'/0']{xpub}/<0;1>/*)"), NET).unwrap();
        let coins = vec![WatchCoin { txid: "9".repeat(64), vout: 0, value: 80_000, chain: 0, index: 0 }];

        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let carol = Identity::from_app_seed(&[11u8; 32]).unwrap();
        let dave = Identity::from_app_seed(&[13u8; 32]).unwrap();
        let (bob_spk, carol_spk, dave_spk) = (
            notes_core::address::p2tr_script_pubkey(&bob.output_x),
            notes_core::address::p2tr_script_pubkey(&carol.output_x),
            notes_core::address::p2tr_script_pubkey(&dave.output_x),
        );
        let recipients = vec![(bob_spk.clone(), 330u64), (carol_spk.clone(), 330u64), (dave_spk.clone(), 330u64)];

        let built = build_watch_note_psbt_multi(&src, &coins, "group note from watch", &recipients, [1, 2, 3, 4], 80, 2.0, 0)
            .unwrap();
        assert_eq!(built.sent_to_recipient, 990);
        assert_eq!(80_000, built.fee + built.change + 990);

        let tx = &built.psbt.unsigned_tx;
        let op_returns = tx.output.iter().filter(|o| o.script_pubkey.is_op_return()).count();
        assert_eq!(tx.output[op_returns].script_pubkey.as_bytes(), bob_spk.as_slice());
        assert_eq!(tx.output[op_returns + 1].script_pubkey.as_bytes(), carol_spk.as_slice());
        assert_eq!(tx.output[op_returns + 2].script_pubkey.as_bytes(), dave_spk.as_slice());

        let mut psbt = built.psbt.clone();
        let _ = psbt.sign(&master, &secp);
        validate_signed(&psbt, &built.txid).expect("identity master signs");
        let (_raw, txid, _) = finalize_extract(psbt).expect("finalize");
        assert_eq!(txid, built.txid);

        // Single/zero recipients must delegate byte-identically to the old
        // signature (`build_watch_note_psbt`).
        let one = build_watch_note_psbt(&src, &coins, "solo", Some(bob_spk.clone()), 500, [5, 5, 5, 5], 80, 2.0, 0).unwrap();
        let one_multi = build_watch_note_psbt_multi(&src, &coins, "solo", &[(bob_spk, 500)], [5, 5, 5, 5], 80, 2.0, 0).unwrap();
        assert_eq!(one.txid, one_multi.txid);
        assert_eq!(one.fee, one_multi.fee);

        // A sub-dust gift among the recipients is rejected before any
        // signing happens.
        assert!(build_watch_note_psbt_multi(
            &src, &coins, "x", &[(carol_spk, 100), (dave_spk, 500)], [6, 6, 6, 6], 80, 2.0
        , 0)
        .is_err());
    }

    /// A KEYED identity's spending-wallet-funded note to 3 recipients
    /// (`build_funding_psbt_multi`): uniform gift on all three outputs, in
    /// order, dust-to-self unconditional (this path never spends a
    /// notebook coin), and the exactly-one-recipient case delegates
    /// byte-identically to [`build_funding_psbt_amount`].
    #[test]
    fn funding_psbt_multi_three_recipients_uniform_gift() {
        let src = source();
        let coins = one_coin(&src);
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let carol = Identity::from_app_seed(&[11u8; 32]).unwrap();
        let dave = Identity::from_app_seed(&[13u8; 32]).unwrap();
        let recipients = vec![
            Recipient::parse(NET, &bob.address(NET)).unwrap(),
            Recipient::parse(NET, &carol.address(NET)).unwrap(),
            Recipient::parse(NET, &dave.address(NET)).unwrap(),
        ];
        let plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 2.0, change_override: None };
        let np = NoteParams {
            identity: &alice,
            text: "group note, spending-funded",
            private: false,
            recipient: None, // ignored by the multi entry point — `recipients` replaces it
            note_id: [2, 0, 1, 6],
            max_op_return_bytes: 80,
            network: NET,
        };
        let built = build_funding_psbt_multi(&plan, &np, &recipients, 500, 0).unwrap();
        assert_eq!(built.sent_to_recipient, 1_500, "3 x 500 uniform gift");
        assert_eq!(built.dust_to_self, DUST_LIMIT, "spending/external funding is never input-anchored");
        assert_eq!(100_000, built.fee + built.change + built.dust_to_self + built.sent_to_recipient);

        let tx = &built.psbt.unsigned_tx;
        let op_returns = tx.output.iter().filter(|o| o.script_pubkey.is_op_return()).count();
        for (i, r) in recipients.iter().enumerate() {
            assert_eq!(tx.output[op_returns + i].script_pubkey.as_bytes(), r.spk.as_slice());
            assert_eq!(tx.output[op_returns + i].value.to_sat(), 500);
        }

        // Exactly one recipient must be byte-identical to the pre-existing
        // single-recipient entry point.
        let single_np = NoteParams { recipient: Some(&recipients[0]), ..np };
        let via_amount = build_funding_psbt_amount(&plan, &single_np, 500, 0).unwrap();
        let via_multi = build_funding_psbt_multi(&plan, &np, &recipients[..1], 500, 0).unwrap();
        assert_eq!(via_amount.txid, via_multi.txid);
        assert_eq!(via_amount.fee, via_multi.fee);
        assert_eq!(via_amount.sent_to_recipient, via_multi.sent_to_recipient);

        // Zero recipients (self-note): dust-to-self only, no recipient outputs.
        let self_built = build_funding_psbt_multi(&plan, &np, &[], 999, 0).unwrap();
        assert_eq!(self_built.sent_to_recipient, 0);
        assert_eq!(self_built.dust_to_self, DUST_LIMIT);
    }

    /// A PRIVATE multi-recipient note through `build_funding_psbt_multi`:
    /// the content-key seal must produce a body every recipient's directed-
    /// private decode can open (sanity check that the fresh-TRNG
    /// content_key path — [`crate::compose::fresh_content_key`], zeroized
    /// after use — actually reaches notes-core's hybrid seal correctly).
    #[test]
    fn funding_psbt_multi_private_recipients_taproot_required() {
        let src = source();
        let coins = one_coin(&src);
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let carol = Identity::from_app_seed(&[11u8; 32]).unwrap();
        let recipients =
            vec![Recipient::parse(NET, &bob.address(NET)).unwrap(), Recipient::parse(NET, &carol.address(NET)).unwrap()];
        let plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 2.0, change_override: None };
        let np = NoteParams {
            identity: &alice,
            text: "private group note",
            private: true,
            recipient: None,
            note_id: [3, 3, 3, 3],
            max_op_return_bytes: 80,
            network: NET,
        };
        let built = build_funding_psbt_multi(&plan, &np, &recipients, DUST_LIMIT, 0).unwrap();
        assert_eq!(built.sent_to_recipient, DUST_LIMIT * 2);

        // A non-taproot recipient among the extras is rejected before any
        // signing — same `RecipientNotTaproot` notes-core raises for the
        // single-recipient private path.
        let non_taproot = Recipient::parse(NET, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        let bad_recipients =
            vec![Recipient::parse(NET, &bob.address(NET)).unwrap(), non_taproot];
        match build_funding_psbt_multi(&plan, &np, &bad_recipients, DUST_LIMIT, 0) {
            Err(e) => assert!(format!("{e}").to_lowercase().contains("taproot"), "got: {e}"),
            Ok(_) => panic!("expected a taproot-required error"),
        }
    }

    /// CHANGE-CHAIN sweep signing (taproot-change unit 6, see
    /// `../PLAN-chain-notes-app-taproot-change.md`): a coin sitting at the
    /// account's chain-1 (`m/86'/…/1/{index}`) leaf — the same leaf
    /// `sweep`'s change-idents loop derives via `realize_change` — signs
    /// with `sign_own_taproot_inputs` exactly like a chain-0 notebook coin
    /// does, and the resulting `tap_key_sig` verifies against the OWNER'S
    /// OWN tweaked output key (the P2TR output key for that chain-1
    /// address), not some other leaf — proving the sweep signs the change
    /// coin with the correct key, not a stray or chain-0 one.
    #[test]
    fn sign_own_taproot_inputs_signs_change_chain_coin() {
        use crate::identity::{parse_key_material, realize_change};
        use notes_core::sign::schnorr_verify;

        const MNEMONIC: &str =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let material = parse_key_material(MNEMONIC, NET).unwrap();
        let owner = realize_change(&material, NET, 0, 0).unwrap();
        let identity = owner.full().expect("keyed material realizes a full identity");
        let owner_spk = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&identity.output_x));

        // A different chain-1 index (a DIFFERENT owner) — used below to
        // prove the signature does NOT verify against the wrong key,
        // ruling out a signer that ignores which leaf it's given.
        let other = realize_change(&material, NET, 0, 1).unwrap();
        let other_identity = other.full().unwrap();
        assert_ne!(
            identity.output_x, other_identity.output_x,
            "chain-1 index 0 and 1 must derive to different leaves"
        );

        // One-input, one-output sweep-style PSBT: the chain-1 coin spent
        // to an arbitrary destination, minus fee — the exact shape
        // `build_sweep_tx_multi`/`build_wallet_sweep_mixed` construct
        // (here assembled at the PSBT level, mirroring `assemble_watch_psbt`
        // above, so `sign_own_taproot_inputs` runs against a real PSBT).
        let dest = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let dest_spk = ScriptBuf::from_bytes(notes_core::address::p2tr_script_pubkey(&dest.output_x));
        let coin_value = 60_000u64;
        let fee = 200u64;
        let txid = Txid::from_str(&"c".repeat(64)).unwrap();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(coin_value - fee), script_pubkey: dest_spk }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo =
            Some(TxOut { value: Amount::from_sat(coin_value), script_pubkey: owner_spk.clone() });

        let n = sign_own_taproot_inputs(&mut psbt, &identity.output_x, &identity.tweaked_seckey).unwrap();
        assert_eq!(n, 1, "the one change-chain input was signed");
        let sig = psbt.inputs[0].tap_key_sig.expect("tap_key_sig set");

        // Recompute the exact sighash `sign_own_taproot_inputs` signed and
        // verify the signature against the coin's OWN chain-1 output key —
        // the money proof: this is a byte-valid BIP-340 signature that a
        // full node would accept spending THIS chain-1 P2TR output.
        use bitcoin::sighash::{Prevouts, SighashCache};
        let prevouts: Vec<TxOut> = psbt.inputs.iter().map(|i| i.witness_utxo.clone().unwrap()).collect();
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), bitcoin::TapSighashType::Default)
            .unwrap();
        assert!(
            schnorr_verify(&identity.output_x, sighash.as_ref(), sig.signature.as_ref()),
            "signature must verify against the change coin's own chain-1 output key"
        );
        assert!(
            !schnorr_verify(&other_identity.output_x, sighash.as_ref(), sig.signature.as_ref()),
            "signature must NOT verify against a different chain-1 leaf's key"
        );
    }
}
