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

use crate::funding::{FundingSource, FundingUtxo};
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

/// A coin a watch identity spends — at the descriptor's receive leaf
/// `0/{index}` (rev 3: each notebook is one receive index; pre-rev-3
/// coins are all index 0, the original notes address).
#[derive(Debug, Clone)]
pub struct WatchCoin {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
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
        let leaf_spk = ScriptBuf::from_bytes(source.derive(0, coin.index)?.spk);
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
) -> Result<(Psbt, String), Error> {
    let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: inputs, output: outputs };
    let txid = tx.compute_txid().to_string();
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| Error::Funding(format!("psbt: {e}")))?;
    for (i, coin) in coins.iter().enumerate() {
        // Per-coin definite descriptor: key origins carry each input's own
        // receive index, so a signer recognizes every notebook's coins.
        let def = source.definite(0, coin.index)?;
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
    let (psbt, txid) = assemble_watch_psbt(source, coins, inputs, prevouts, outputs)?;
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
    let (psbt, txid) = assemble_watch_psbt(source, coins, inputs, prevouts, outputs)?;
    Ok(BuiltPsbt {
        psbt,
        fee: new_fee,
        change: 0,
        sent_to_recipient: out_value - delta,
        dust_to_self: 0,
        txid,
    })
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
) -> Result<BuiltPsbt, Error> {
    if coins.is_empty() {
        return Err(Error::Funding("no coins selected".into()));
    }
    if text.is_empty() {
        return Err(Error::Funding("empty note".into()));
    }
    let flags = if recipient_spk.is_some() { notes_core::envelope::FLAG_DIRECTED } else { 0 };
    let payloads =
        notes_core::envelope::encode_chunks(note_id, flags, text.as_bytes(), max_op_return_bytes)?;
    let (inputs, prevouts, weights) = taproot_keyspend_inputs(source, coins)?;
    let self_spk = ScriptBuf::from_bytes(source.derive(0, 0)?.spk);

    let mut outputs: Vec<TxOut> = payloads
        .iter()
        .map(|p| TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(op_return_script(p)) })
        .collect();
    let mut sent_to_recipient = 0u64;
    if let Some(spk) = &recipient_spk {
        if recipient_amount < DUST_LIMIT {
            return Err(Error::Funding(format!("gift below dust ({DUST_LIMIT} sats minimum)")));
        }
        outputs.push(TxOut {
            value: Amount::from_sat(recipient_amount),
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        });
        sent_to_recipient = recipient_amount;
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

    let (psbt, txid) = assemble_watch_psbt(source, coins, inputs, prevouts, outputs)?;
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
        prevouts.push(TxOut { value: Amount::from_sat(coin.value), script_pubkey: notes_spk.clone() });
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

    let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: inputs, output: outputs };
    let txid = tx.compute_txid().to_string();
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| Error::Funding(format!("psbt: {e}")))?;
    for (i, prevout) in prevouts.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(prevout.clone());
    }
    if let Some(src) = identity_source {
        let def = src.definite(0, 0)?;
        for i in 0..notes_coins.len() {
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

/// Build the unsigned funding PSBT. Fails with `Error::Funding` on bad coins,
/// insufficient funds, or descriptor derivation problems.
pub fn build_funding_psbt(plan: &FundingPlan, note: &NoteParams) -> Result<BuiltPsbt, Error> {
    let (payloads, recipient_spk) = sealed_note_payloads(
        note.identity,
        note.text,
        note.private,
        note.recipient,
        note.note_id,
        note.max_op_return_bytes,
    )?;
    let self_spk = notes_core::address::p2tr_script_pubkey(&note.identity.output_x);
    assemble_funded_note_psbt(plan, &payloads, recipient_spk, DUST_LIMIT, self_spk)
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
) -> Result<BuiltPsbt, Error> {
    if text.is_empty() {
        return Err(Error::Funding("empty note".into()));
    }
    if recipient_spk.is_some() && recipient_amount < DUST_LIMIT {
        return Err(Error::Funding(format!("gift below dust ({DUST_LIMIT} sats minimum)")));
    }
    let flags = if recipient_spk.is_some() { notes_core::envelope::FLAG_DIRECTED } else { 0 };
    let payloads =
        notes_core::envelope::encode_chunks(note_id, flags, text.as_bytes(), max_op_return_bytes)?;
    let self_spk = notes_core::address::p2tr_script_pubkey(self_output_x);
    assemble_funded_note_psbt(plan, &payloads, recipient_spk, recipient_amount, self_spk)
}

/// Shared tail of both funded-note builders: payloads → outputs (OP_RETURNs,
/// recipient carrying `recipient_amount`, dust-to-self, funding change) →
/// PSBT with witness data + key origins on every funding input.
fn assemble_funded_note_psbt(
    plan: &FundingPlan,
    payloads: &[Vec<u8>],
    recipient_spk: Option<Vec<u8>>,
    recipient_amount: u64,
    self_spk: Vec<u8>,
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
    if let Some(spk) = &recipient_spk {
        outputs.push(TxOut {
            value: Amount::from_sat(recipient_amount),
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        });
        sent_to_recipient = recipient_amount;
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
    let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: inputs, output: outputs };
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
        let built = build_funding_psbt(&plan, &np).unwrap();
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
        let built = build_funding_psbt(&plan, &np).unwrap();
        assert_eq!(built.sent_to_recipient, 0);
        assert_eq!(built.dust_to_self, 330);
        assert_eq!(100_000, built.fee + built.change + 330);
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
            WatchCoin { txid: "a".repeat(64), vout: 0, value: 60_000, index: 0 },
            WatchCoin { txid: "b".repeat(64), vout: 1, value: 40_000, index: 0 },
        ];
        let dest = src.derive(0, 0).unwrap().spk; // consolidate to self
        let built = build_watch_spend_psbt(&src, &coins, dest.clone(), 2.0).unwrap();
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
        let bumped = build_watch_bump_psbt(&src, &coins, &prev_outputs, 0, 5.0).unwrap();
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
        assert!(build_watch_bump_psbt(&src, &coins, &prev_outputs, 0, 2.0).is_err());
        // Sweeping less than fee+dust is rejected.
        let tiny = vec![WatchCoin { txid: "c".repeat(64), vout: 0, value: 400, index: 0 }];
        assert!(build_watch_spend_psbt(&src, &tiny, dest, 2.0).is_err());
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
            WatchCoin { txid: "e".repeat(64), vout: 0, value: 60_000, index: 0 },
            WatchCoin { txid: "f".repeat(64), vout: 1, value: 40_000, index: 0 },
        ];
        let built =
            build_funded_sweep_psbt(alice_spk.clone(), None, &notes_coins, &plan, dest_spk.clone())
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
            build_funded_sweep_psbt(id_spk, Some(&id_src), &notes_coins, &plan, dest_spk).unwrap();
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
        let coins = vec![WatchCoin { txid: "9".repeat(64), vout: 0, value: 50_000, index: 0 }];

        // Self public note.
        let built = build_watch_note_psbt(
            &src, &coins, "public from a watch device", None, 0, [1, 2, 3, 4], 80, 2.0,
        )
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
            &src, &coins, "hi bob", Some(to_bob.spk.clone()), 1_000, [5, 6, 7, 8], 80, 2.0,
        )
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
        )
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
        )
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
        )
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
        assert!(build_funding_psbt(&plan, &np).is_err());
    }
}
