//! The import side of external funding: parse a signed PSBT, present a
//! Sparrow-style breakdown for confirmation, validate it against the tx we
//! built, and finalize it into broadcastable raw hex.

use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Psbt};
use miniscript::psbt::PsbtExt;
use notes_core::address::p2tr_script_pubkey;
use notes_core::envelope;
use notes_core::tx::op_return_payload;
use notes_core::Network;

use crate::derive::btc_network;
use crate::Error;

/// Parse a PSBT from base64 (`.psbt` text / clipboard) or raw hex.
pub fn parse_psbt(input: &str) -> Result<Psbt, Error> {
    let s = input.trim();
    if let Ok(p) = s.parse::<Psbt>() {
        return Ok(p);
    }
    if let Ok(bytes) = hex::decode(s) {
        if let Ok(p) = Psbt::deserialize(&bytes) {
            return Ok(p);
        }
    }
    Err(Error::Funding("not a valid PSBT (base64 or hex)".into()))
}

/// What an output is, for the confirmation screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputRole {
    /// An OP_RETURN note. Public notes carry their text; private ones don't.
    Note { text: Option<String>, chunks: usize },
    /// Dust to our own identity address (keeps the note in our notebook).
    SelfDust,
    /// Dust delivered to a directed-note recipient.
    Recipient,
    /// Change back to the funding wallet.
    Change,
    /// Any other payment.
    Other,
}

#[derive(Debug, Clone)]
pub struct SummaryInput {
    pub address: Option<String>,
    pub value: u64,
    pub outpoint: String,
}

#[derive(Debug, Clone)]
pub struct SummaryOutput {
    pub role: OutputRole,
    pub address: Option<String>,
    pub value: u64,
}

/// A human-readable breakdown of a PSBT for the confirmation UI.
#[derive(Debug, Clone)]
pub struct PsbtSummary {
    pub inputs: Vec<SummaryInput>,
    pub outputs: Vec<SummaryOutput>,
    pub input_total: u64,
    pub output_total: u64,
    pub fee: u64,
    pub txid: String,
}

/// Context that lets the summary label outputs precisely (the app knows these
/// from the build): our identity output key (works for watch-only too), the
/// directed recipient, and the funding change address.
pub struct SummaryContext<'a> {
    pub identity_output_x: [u8; 32],
    pub network: Network,
    pub recipient_addr: Option<&'a str>,
    pub change_addr: Option<&'a str>,
}

fn addr_of_spk(spk: &bitcoin::ScriptBuf, network: Network) -> Option<String> {
    Address::from_script(spk, btc_network(network)).ok().map(|a| a.to_string())
}

/// Decode consecutive OP_RETURN chunks into note text (public) or a chunk
/// count (private / undecodable).
fn note_role(payloads: &[Vec<u8>]) -> OutputRole {
    let chunks: Vec<_> = payloads.iter().filter_map(|p| envelope::decode(p)).collect();
    if chunks.is_empty() {
        return OutputRole::Note { text: None, chunks: payloads.len() };
    }
    let private = chunks[0].flags & envelope::FLAG_PRIVATE != 0;
    let text = if private {
        None
    } else {
        envelope::reassemble(&chunks).ok().and_then(|b| String::from_utf8(b).ok())
    };
    OutputRole::Note { text, chunks: chunks.len() }
}

/// Build a `PsbtSummary`. Requires every input's `witness_utxo` (present in a
/// well-formed funding PSBT).
pub fn summarize(psbt: &Psbt, ctx: &SummaryContext) -> Result<PsbtSummary, Error> {
    let tx = &psbt.unsigned_tx;

    let mut inputs = Vec::with_capacity(tx.input.len());
    let mut input_total = 0u64;
    for (i, txin) in tx.input.iter().enumerate() {
        let wu = psbt.inputs.get(i).and_then(|pi| pi.witness_utxo.as_ref());
        let value = wu.map(|o| o.value.to_sat()).unwrap_or(0);
        input_total += value;
        inputs.push(SummaryInput {
            address: wu.and_then(|o| addr_of_spk(&o.script_pubkey, ctx.network)),
            value,
            outpoint: format!("{}:{}", txin.previous_output.txid, txin.previous_output.vout),
        });
    }

    let self_spk = p2tr_script_pubkey(&ctx.identity_output_x);
    // Group all OP_RETURN outputs into a single note payload set.
    let note_payloads: Vec<Vec<u8>> = tx
        .output
        .iter()
        .filter_map(|o| op_return_payload(o.script_pubkey.as_bytes()).map(<[u8]>::to_vec))
        .collect();
    let mut note_emitted = false;

    let mut outputs = Vec::new();
    let mut output_total = 0u64;
    for o in &tx.output {
        output_total += o.value.to_sat();
        if o.script_pubkey.is_op_return() {
            // Emit the (merged) note once, on the first OP_RETURN.
            if note_emitted {
                continue;
            }
            note_emitted = true;
            outputs.push(SummaryOutput { role: note_role(&note_payloads), address: None, value: 0 });
            continue;
        }
        let address = addr_of_spk(&o.script_pubkey, ctx.network);
        let role = if o.script_pubkey.as_bytes() == self_spk {
            OutputRole::SelfDust
        } else if ctx.recipient_addr.is_some() && address.as_deref() == ctx.recipient_addr {
            OutputRole::Recipient
        } else if ctx.change_addr.is_some() && address.as_deref() == ctx.change_addr {
            OutputRole::Change
        } else {
            OutputRole::Other
        };
        outputs.push(SummaryOutput { role, address, value: o.value.to_sat() });
    }

    let fee = input_total.saturating_sub(output_total);
    Ok(PsbtSummary { inputs, outputs, input_total, output_total, fee, txid: tx.compute_txid().to_string() })
}

/// Validate a returned PSBT against the tx we built: same unsigned txid
/// (outputs/inputs unchanged) and every input carries a signature. Guards
/// against a signer that altered the transaction.
pub fn validate_signed(psbt: &Psbt, expected_txid: &str) -> Result<(), Error> {
    if psbt.unsigned_tx.compute_txid().to_string() != expected_txid {
        return Err(Error::Funding("signed PSBT does not match the built transaction".into()));
    }
    for (i, inp) in psbt.inputs.iter().enumerate() {
        let signed = inp.tap_key_sig.is_some()
            || !inp.tap_script_sigs.is_empty()
            || !inp.partial_sigs.is_empty()
            || inp.final_script_witness.is_some();
        if !signed {
            return Err(Error::Funding(format!("input {i} is unsigned")));
        }
    }
    Ok(())
}

/// Finalize a fully-signed PSBT and extract broadcastable raw tx hex + txid +
/// vsize.
pub fn finalize_extract(mut psbt: Psbt) -> Result<(String, String, usize), Error> {
    let secp = Secp256k1::verification_only();
    psbt.finalize_mut(&secp)
        .map_err(|errs| Error::Funding(format!("finalize failed: {errs:?}")))?;
    let tx = psbt.extract_tx().map_err(|e| Error::Funding(format!("extract tx: {e}")))?;
    let raw = bitcoin::consensus::encode::serialize_hex(&tx);
    Ok((raw, tx.compute_txid().to_string(), tx.vsize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::funding::{FundingSource, FundingUtxo};
    use crate::psbt_build::{build_funding_psbt, FundingPlan, NoteParams};
    use notes_core::address::Recipient;
    use notes_core::bundle::Identity;

    const BIP86_ACCT_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
    const NET: Network = Network::Mainnet;

    fn built() -> (crate::psbt_build::BuiltPsbt, Identity, Recipient, FundingSource) {
        let src = FundingSource::parse(&format!("tr({BIP86_ACCT_XPUB}/<0;1>/*)"), NET).unwrap();
        let a = src.derive(0, 0).unwrap();
        let coins = vec![FundingUtxo {
            txid: "a".repeat(64),
            vout: 0,
            value: 100_000,
            address: a.address,
            chain: 0,
            index: 0,
            confirmed: true,
        }];
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let to_bob = Recipient::parse(NET, &bob.address(NET)).unwrap();
        // build owns `coins`; move it into a leaked-free local via closure scope.
        let plan = FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 2.0, change_override: None };
        let np = NoteParams {
            identity: &alice,
            text: "public hi",
            private: false,
            recipient: Some(&to_bob),
            note_id: [1, 2, 3, 4],
            max_op_return_bytes: 80,
            network: NET,
        };
        let b = build_funding_psbt(&plan, &np, 0).unwrap();
        (b, alice, to_bob, src)
    }

    #[test]
    fn summary_labels_outputs() {
        let (b, alice, to_bob, src) = built();
        let change_addr = src.derive(1, 0).unwrap().address;
        let ctx = SummaryContext {
            identity_output_x: alice.output_x,
            network: NET,
            recipient_addr: Some(&to_bob.address),
            change_addr: Some(&change_addr),
        };
        let s = summarize(&b.psbt, &ctx).unwrap();
        assert_eq!(s.input_total, 100_000);
        assert_eq!(s.fee, b.fee);
        // The (public) note text is surfaced.
        assert!(s.outputs.iter().any(|o| matches!(&o.role, OutputRole::Note { text: Some(t), .. } if t == "public hi")));
        assert!(s.outputs.iter().any(|o| o.role == OutputRole::SelfDust && o.value == 330));
        assert!(s.outputs.iter().any(|o| o.role == OutputRole::Recipient && o.value == 330));
        assert!(s.outputs.iter().any(|o| o.role == OutputRole::Change));
    }

    #[test]
    fn parse_roundtrips_base64_and_hex() {
        let (b, ..) = built();
        let base64 = b.to_base64();
        assert_eq!(parse_psbt(&base64).unwrap().unsigned_tx.compute_txid(), b.psbt.unsigned_tx.compute_txid());
        let hexs = hex::encode(b.to_bytes());
        assert_eq!(parse_psbt(&hexs).unwrap().unsigned_tx.compute_txid(), b.psbt.unsigned_tx.compute_txid());
        assert!(parse_psbt("garbage").is_err());
    }

    #[test]
    fn validate_rejects_unsigned_and_mismatch() {
        let (b, ..) = built();
        // Unsigned build → validate must reject (no signatures yet).
        assert!(validate_signed(&b.psbt, &b.txid).is_err());
        // Wrong expected txid → reject.
        assert!(validate_signed(&b.psbt, "deadbeef").is_err());
        // Finalizing an unsigned PSBT must fail, not panic.
        assert!(finalize_extract(b.psbt).is_err());
    }

    /// Full desktop pipeline, hermetic: build an unsigned funding PSBT from a
    /// watch-only descriptor, have the (in-process) external wallet sign it
    /// with the matching master key, validate, and finalize to a broadcastable
    /// tx that rust-bitcoin accepts. This is the finalize path the M6 regtest
    /// run exercises against a real node — proven here without one.
    #[test]
    fn build_sign_finalize_roundtrip_taproot() {
        use bitcoin::bip32::{Xpriv, Xpub};
        use bitcoin::secp256k1::Secp256k1;

        let secp = Secp256k1::new();
        let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &[0x11u8; 32]).unwrap();
        let xpub = Xpub::from_priv(&secp, &master);
        let src = FundingSource::parse(&format!("tr({xpub}/<0;1>/*)"), NET).unwrap();

        let coin = src.derive(0, 0).unwrap();
        let coins = vec![crate::funding::FundingUtxo {
            txid: "a".repeat(64),
            vout: 0,
            value: 100_000,
            address: coin.address,
            chain: 0,
            index: 0,
            confirmed: true,
        }];
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let plan = crate::psbt_build::FundingPlan { source: &src, coins: &coins, change_index: 0, fee_rate: 2.0, change_override: None };
        let np = crate::psbt_build::NoteParams {
            identity: &alice,
            text: "paid by an external wallet",
            private: false,
            recipient: None,
            note_id: [9, 9, 9, 9],
            max_op_return_bytes: 80,
            network: NET,
        };
        let built = crate::psbt_build::build_funding_psbt(&plan, &np, 0).unwrap();
        let expected_txid = built.txid.clone();

        // The external wallet signs (taproot key-path via bip32/tap origins).
        let mut psbt = built.psbt;
        let _ = psbt.sign(&master, &secp);
        validate_signed(&psbt, &expected_txid).expect("signed by the funding key");

        let (raw, txid, vsize) = finalize_extract(psbt).expect("finalize");
        assert_eq!(txid, expected_txid, "finalize must not change the txid");
        assert!(vsize > 0);

        // rust-bitcoin accepts the final tx and every input is witnessed.
        let tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&hex::decode(&raw).unwrap()).unwrap();
        assert_eq!(tx.compute_txid().to_string(), expected_txid);
        assert!(tx.input.iter().all(|i| !i.witness.is_empty()), "all inputs finalized");
    }
}
