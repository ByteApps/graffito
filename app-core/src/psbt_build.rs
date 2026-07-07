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

/// Build the unsigned funding PSBT. Fails with `Error::Funding` on bad coins,
/// insufficient funds, or descriptor derivation problems.
pub fn build_funding_psbt(plan: &FundingPlan, note: &NoteParams) -> Result<BuiltPsbt, Error> {
    if plan.coins.is_empty() {
        return Err(Error::Funding("no funding coins selected".into()));
    }
    let (payloads, recipient_spk) = sealed_note_payloads(
        note.identity,
        note.text,
        note.private,
        note.recipient,
        note.note_id,
        note.max_op_return_bytes,
    )?;

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
            value: Amount::from_sat(DUST_LIMIT),
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        });
        sent_to_recipient = DUST_LIMIT;
    }
    let self_spk = notes_core::address::p2tr_script_pubkey(&note.identity.output_x);
    outputs.push(TxOut { value: Amount::from_sat(DUST_LIMIT), script_pubkey: ScriptBuf::from_bytes(self_spk) });
    let dust_to_self = DUST_LIMIT;

    // --- fee / change selection (prefer a change output; else fold < dust into fee) ---
    let in_value: u64 = plan.coins.iter().map(|c| c.value).sum();
    let fixed_out: u64 = sent_to_recipient + dust_to_self; // OP_RETURNs are 0-value
    let change_spk = ScriptBuf::from_bytes(plan.source.derive(1, plan.change_index)?.spk);

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

        let plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 2.0 };
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
        let plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 1.0 };
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
        let plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 5.0 };
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
