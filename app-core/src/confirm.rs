//! The universal "Confirm & broadcast" screen's byte-truth summarizer.
//!
//! Philosophy (paranoid-bitcoiner): every fact shown to the user is decoded
//! from the ACTUAL signed raw transaction bytes about to hit the wire —
//! never from the app's own intent/state. `ConfirmCtx` supplies only
//! LOOKUPS (what a prevout or address means to us); it never supplies an
//! amount or a classification verdict. In particular the fee is always
//! computed from decoded input/output values, never accepted from the
//! caller — a compromised or buggy build-step can lie about what it
//! *meant* to build, but it cannot lie about what the signed bytes *are*.

use std::collections::HashMap;
use std::str::FromStr;

use bitcoin::consensus::encode::deserialize;
use bitcoin::{Address, Transaction};

use notes_core::envelope;
use notes_core::tx::op_return_payload;

use crate::mixed::commas;

/// What we know about an input's previous output. `source` is a human
/// wallet label, e.g. "Notebook · Alice", "Spending wallet", "ColdBox"
/// (external), or "" if unknown.
pub struct PrevoutInfo {
    pub value: u64,
    pub address: Option<String>,
    pub source: String,
}

pub struct ConfirmCtx {
    pub network: bitcoin::Network,
    /// key = "txid:vout" (lowercase hex txid, decimal vout)
    pub prevouts: HashMap<String, PrevoutInfo>,
    /// every script_pubkey we control (all notebooks + spending wallet), raw bytes
    pub self_spks: Vec<Vec<u8>>,
    /// subset of self_spks that belong to the BIP-84 spending wallet
    pub spending_spks: Vec<Vec<u8>>,
    /// address we expect change at, if a custom/external change address was chosen
    pub expected_change: Option<String>,
    /// directed-note recipient address + optional contact name
    pub recipient: Option<String>,
    pub recipient_name: Option<String>,
    /// decoded note text to display (public notes) — display-only, pass-through
    pub note_preview: Option<String>,
}

/// Mirrors the slint PsbtRow struct { title, subtitle, amount, kind }.
/// kinds used: "input" for inputs; outputs: "note" | "recipient" | "self" | "change" | "other".
pub struct SummaryRow {
    pub title: String,    // address or outpoint (elided by UI, give full string)
    pub subtitle: String, // e.g. source label, "OP_RETURN · PNTE note", "change back to Spending wallet"
    pub amount: String,   // thousands-separated sats, "" for the OP_RETURN row
    pub kind: String,
}

pub struct TxSummary {
    pub txid: String,
    pub inputs: Vec<SummaryRow>,
    pub outputs: Vec<SummaryRow>,
    pub total_in: Option<u64>, // None if any prevout value missing
    pub total_out: u64,
    pub fee: Option<u64>, // total_in - total_out; None if total_in is None
    pub vsize: u64,
    pub fee_line: String, // "1,234 sats · 2.0 sat/vB" or "fee unknown — missing input data"
    pub warn: Option<String>, // set when something needs user attention (see rules)
}

/// self_dust-ish threshold used to tell a "keep the note discoverable" dust
/// output apart from ordinary change back to the same notebook address. The
/// app's own self-dust output is [`notes_core::DUST_LIMIT`] (330); the
/// classic dust limit (546) is used here as the deciding line so an
/// unusually small BUT real change amount still reads as dust-ish.
const SELF_DUST_CEILING: u64 = 546;

/// Decode a signed raw tx and label every input/output from `ctx`'s
/// lookups. Every fact in the returned [`TxSummary`] — the txid, the
/// output values, the output script classification, the fee — comes from
/// `raw_hex` itself; `ctx` only supplies what an outpoint/address MEANS to
/// this wallet.
pub fn summarize_signed_tx(raw_hex: &str, ctx: &ConfirmCtx) -> Result<TxSummary, String> {
    let bytes = hex::decode(raw_hex.trim()).map_err(|e| format!("not valid hex: {e}"))?;
    let tx: Transaction = deserialize(&bytes).map_err(|e| format!("not a valid transaction: {e}"))?;

    let mut warns: Vec<String> = Vec::new();

    // Resolve the two "known destination" addresses to scriptPubKeys ONCE
    // (spk compare, never string compare, per the paranoid rule — a string
    // compare can be fooled by address-encoding quirks the spk can't be).
    let recipient_spk: Option<Vec<u8>> = ctx.recipient.as_deref().and_then(|a| resolve_spk(a, ctx.network));
    let expected_change_spk: Option<Vec<u8>> =
        ctx.expected_change.as_deref().and_then(|a| resolve_spk(a, ctx.network));

    // --- inputs -------------------------------------------------------
    let mut inputs = Vec::with_capacity(tx.input.len());
    let mut sum_in: u64 = 0;
    let mut any_prevout_missing = false;
    for txin in &tx.input {
        let outpoint = format!("{}:{}", txin.previous_output.txid, txin.previous_output.vout);
        match ctx.prevouts.get(&outpoint) {
            Some(info) => {
                sum_in += info.value;
                let title = info.address.clone().unwrap_or_else(|| outpoint.clone());
                let subtitle = if info.source.is_empty() { "source unknown".to_string() } else { info.source.clone() };
                inputs.push(SummaryRow { title, subtitle, amount: commas(info.value), kind: "input".into() });
            }
            None => {
                any_prevout_missing = true;
                inputs.push(SummaryRow {
                    title: outpoint,
                    subtitle: "outpoint · amount unknown".into(),
                    amount: "?".into(),
                    kind: "input".into(),
                });
            }
        }
    }
    let total_in = if any_prevout_missing { None } else { Some(sum_in) };

    // --- outputs --------------------------------------------------------
    let mut outputs = Vec::with_capacity(tx.output.len());
    let mut total_out: u64 = 0;
    for txout in &tx.output {
        let value = txout.value.to_sat();
        total_out += value;
        let spk = txout.script_pubkey.as_bytes();

        if txout.script_pubkey.is_op_return() {
            let is_pnte = op_return_payload(spk)
                .map(|p| p.len() >= envelope::MAGIC.len() && p[..envelope::MAGIC.len()] == envelope::MAGIC)
                .unwrap_or(false);
            outputs.push(SummaryRow {
                title: String::new(),
                subtitle: if is_pnte { "OP_RETURN · PNTE note".to_string() } else { "OP_RETURN · data".to_string() },
                amount: if value == 0 { String::new() } else { commas(value) },
                kind: "note".into(),
            });
            continue;
        }

        let Ok(addr) = Address::from_script(&txout.script_pubkey, ctx.network) else {
            warns.push("an output script couldn't be decoded to an address".to_string());
            outputs.push(SummaryRow {
                title: hex::encode(spk),
                subtitle: "unrenderable output script".to_string(),
                amount: commas(value),
                kind: "other".into(),
            });
            continue;
        };

        let (kind, subtitle) = if recipient_spk.as_deref() == Some(spk) {
            ("recipient", ctx.recipient_name.clone().unwrap_or_else(|| "directed recipient".to_string()))
        } else if ctx.self_spks.iter().any(|s| s.as_slice() == spk) {
            if ctx.spending_spks.iter().any(|s| s.as_slice() == spk) {
                ("change", "change · Spending wallet".to_string())
            } else if value <= SELF_DUST_CEILING {
                ("self", "your notebook (keeps the note yours)".to_string())
            } else {
                ("change", "change · your notebook".to_string())
            }
        } else if expected_change_spk.as_deref() == Some(spk) {
            ("change", "change · chosen change address".to_string())
        } else {
            warns.push("an output pays an address this app doesn't recognize".to_string());
            ("other", "not one of your addresses".to_string())
        };

        outputs.push(SummaryRow { title: addr.to_string(), subtitle, amount: commas(value), kind: kind.to_string() });
    }

    let vsize = tx.vsize() as u64;
    // in < out can't happen in a valid tx — it means the caller's prevout
    // data is wrong, which is exactly what this module exists to catch.
    if let Some(ti) = total_in {
        if total_out > ti {
            warns.push("outputs exceed the known input total — the input data is inconsistent".to_string());
        }
    }
    let fee = total_in.filter(|ti| *ti >= total_out).map(|ti| ti - total_out);
    let fee_line = match fee {
        Some(f) => {
            let rate = if vsize > 0 { f as f64 / vsize as f64 } else { 0.0 };
            format!("{} sats · {rate:.1} sat/vB", commas(f))
        }
        None if total_in.is_some() => "fee unknown — inconsistent input data".to_string(),
        None => {
            warns.push("one or more input amounts are unknown — the fee could not be verified".to_string());
            "fee unknown — missing input data".to_string()
        }
    };

    Ok(TxSummary {
        txid: tx.compute_txid().to_string(),
        inputs,
        outputs,
        total_in,
        total_out,
        fee,
        vsize,
        fee_line,
        warn: if warns.is_empty() { None } else { Some(warns.join("; ")) },
    })
}

/// Parse `address` for `network` and return its scriptPubKey bytes, or
/// `None` if it doesn't parse or isn't valid for this network. Never
/// panics on adversarial/foreign-network input.
fn resolve_spk(address: &str, network: bitcoin::Network) -> Option<Vec<u8>> {
    Address::from_str(address.trim())
        .ok()?
        .require_network(network)
        .ok()
        .map(|a| a.script_pubkey().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, Network as BtcNetwork, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Txid, Witness};
    use notes_core::bundle::Identity;
    use notes_core::tx::op_return_script;

    const NET: BtcNetwork = BtcNetwork::Bitcoin;
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                             abandon abandon abandon about";

    fn notebook_spk(seed: u8) -> ([u8; 32], Vec<u8>) {
        let id = Identity::from_app_seed(&[seed; 32]).unwrap();
        (id.output_x, notes_core::address::p2tr_script_pubkey(&id.output_x))
    }

    fn addr_of(spk: &[u8]) -> String {
        Address::from_script(&ScriptBuf::from_bytes(spk.to_vec()), NET).unwrap().to_string()
    }

    fn pnte_op_return(text: &str) -> Vec<u8> {
        let payload = envelope::encode_chunks([1, 2, 3, 4], 0, text.as_bytes(), 100_000).unwrap();
        op_return_script(&payload[0])
    }

    fn spending_spk() -> Vec<u8> {
        let material = crate::identity::parse_key_material(MNEMONIC, notes_core::Network::Mainnet).unwrap();
        crate::spending::derive_spending_key(&material, notes_core::Network::Mainnet, 0, 1, 0).unwrap().script_pubkey
    }

    fn txin(txid_byte: u8, vout: u32) -> TxIn {
        TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array([txid_byte; 32]), vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::from_slice(&[vec![0x11; 64]]), // dummy taproot-shaped sig — decode doesn't verify it
        }
    }

    fn txout(value: u64, spk: Vec<u8>) -> TxOut {
        TxOut { value: Amount::from_sat(value), script_pubkey: ScriptBuf::from_bytes(spk) }
    }

    fn raw_hex(tx: &Transaction) -> String {
        bitcoin::consensus::encode::serialize_hex(tx)
    }

    fn prevout_key(txid_byte: u8, vout: u32) -> String {
        format!("{}:{vout}", Txid::from_byte_array([txid_byte; 32]))
    }

    fn base_ctx(self_spks: Vec<Vec<u8>>, spending_spks: Vec<Vec<u8>>) -> ConfirmCtx {
        ConfirmCtx {
            network: NET,
            prevouts: HashMap::new(),
            self_spks,
            spending_spks,
            expected_change: None,
            recipient: None,
            recipient_name: None,
            note_preview: None,
        }
    }

    /// 1 taproot input (known prevout) · OP_RETURN PNTE · self-dust 330 ·
    /// change back to the same notebook → full classification, exact fee
    /// and fee_line asserted.
    #[test]
    fn typical_note_tx_full_classification() {
        let (_, spk_a) = notebook_spk(7);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin(1, 0)],
            output: vec![
                txout(0, pnte_op_return("hello world")),
                txout(330, spk_a.clone()),
                txout(99_000, spk_a.clone()),
            ],
        };
        let vsize = tx.vsize() as u64;
        let hex_str = raw_hex(&tx);

        let mut ctx = base_ctx(vec![spk_a.clone()], vec![]);
        ctx.prevouts.insert(
            prevout_key(1, 0),
            PrevoutInfo { value: 100_000, address: Some(addr_of(&spk_a)), source: "Notebook · Alice".into() },
        );

        let sum = summarize_signed_tx(&hex_str, &ctx).unwrap();
        assert_eq!(sum.txid, tx.compute_txid().to_string());
        assert_eq!(sum.vsize, vsize);

        assert_eq!(sum.inputs.len(), 1);
        assert_eq!(sum.inputs[0].title, addr_of(&spk_a));
        assert_eq!(sum.inputs[0].subtitle, "Notebook · Alice");
        assert_eq!(sum.inputs[0].amount, "100,000");
        assert_eq!(sum.inputs[0].kind, "input");

        assert_eq!(sum.outputs.len(), 3);
        assert_eq!(sum.outputs[0].kind, "note");
        assert_eq!(sum.outputs[0].title, "");
        assert_eq!(sum.outputs[0].subtitle, "OP_RETURN · PNTE note");
        assert_eq!(sum.outputs[0].amount, "");

        assert_eq!(sum.outputs[1].kind, "self");
        assert_eq!(sum.outputs[1].subtitle, "your notebook (keeps the note yours)");
        assert_eq!(sum.outputs[1].amount, "330");

        assert_eq!(sum.outputs[2].kind, "change");
        assert_eq!(sum.outputs[2].subtitle, "change · your notebook");
        assert_eq!(sum.outputs[2].amount, "99,000");

        assert_eq!(sum.total_in, Some(100_000));
        assert_eq!(sum.total_out, 99_330);
        let expected_fee = 100_000 - 99_330;
        assert_eq!(sum.fee, Some(expected_fee));
        let expected_rate = expected_fee as f64 / vsize as f64;
        assert_eq!(sum.fee_line, format!("{} sats · {expected_rate:.1} sat/vB", commas(expected_fee)));
        assert!(sum.warn.is_none());
    }

    /// Two input sources with different labels + change to the spending
    /// wallet → both input subtitles surface and the change output is
    /// classified "change · Spending wallet".
    #[test]
    fn mixed_inputs_and_spending_change() {
        let (_, spk_a) = notebook_spk(7);
        let spend_spk = spending_spk();
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin(1, 0), txin(2, 1)],
            output: vec![txout(0, pnte_op_return("mixed sources")), txout(90_000, spend_spk.clone())],
        };
        let hex_str = raw_hex(&tx);

        let mut ctx = base_ctx(vec![spk_a.clone(), spend_spk.clone()], vec![spend_spk.clone()]);
        ctx.prevouts.insert(
            prevout_key(1, 0),
            PrevoutInfo { value: 40_000, address: Some(addr_of(&spk_a)), source: "Notebook · Alice".into() },
        );
        ctx.prevouts.insert(
            prevout_key(2, 1),
            PrevoutInfo { value: 60_000, address: None, source: "ColdBox".into() },
        );

        let sum = summarize_signed_tx(&hex_str, &ctx).unwrap();
        assert_eq!(sum.inputs.len(), 2);
        assert_eq!(sum.inputs[0].subtitle, "Notebook · Alice");
        assert_eq!(sum.inputs[1].subtitle, "ColdBox");
        // Unknown address on the ColdBox prevout falls back to the outpoint string.
        assert_eq!(sum.inputs[1].title, prevout_key(2, 1));

        let change_row = sum.outputs.iter().find(|o| o.kind == "change").expect("change output");
        assert_eq!(change_row.subtitle, "change · Spending wallet");
        assert_eq!(change_row.amount, "90,000");

        assert_eq!(sum.total_in, Some(100_000));
        assert_eq!(sum.fee, Some(10_000));
        assert!(sum.warn.is_none());
    }

    /// Directed note with a recipient + a gift amount → the recipient row
    /// carries the contact name, not the generic label.
    #[test]
    fn directed_note_with_named_recipient() {
        let (_, spk_a) = notebook_spk(7);
        let (_, spk_bob) = notebook_spk(9);
        let bob_addr = addr_of(&spk_bob);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin(1, 0)],
            output: vec![
                txout(0, pnte_op_return("gift for bob")),
                txout(5_000, spk_bob.clone()),
                txout(94_500, spk_a.clone()),
            ],
        };
        let hex_str = raw_hex(&tx);

        let mut ctx = base_ctx(vec![spk_a.clone()], vec![]);
        ctx.recipient = Some(bob_addr.clone());
        ctx.recipient_name = Some("Bob".to_string());
        ctx.prevouts.insert(
            prevout_key(1, 0),
            PrevoutInfo { value: 100_000, address: Some(addr_of(&spk_a)), source: "Notebook · Alice".into() },
        );

        let sum = summarize_signed_tx(&hex_str, &ctx).unwrap();
        let recipient_row = sum.outputs.iter().find(|o| o.kind == "recipient").expect("recipient output");
        assert_eq!(recipient_row.title, bob_addr);
        assert_eq!(recipient_row.subtitle, "Bob");
        assert_eq!(recipient_row.amount, "5,000");
        assert!(sum.warn.is_none());
    }

    /// Missing one input's prevout data → fee unknown, warn set.
    #[test]
    fn missing_prevout_makes_fee_unknown() {
        let (_, spk_a) = notebook_spk(7);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin(1, 0), txin(2, 1)],
            output: vec![txout(0, pnte_op_return("partial data")), txout(50_000, spk_a.clone())],
        };
        let hex_str = raw_hex(&tx);

        let mut ctx = base_ctx(vec![spk_a.clone()], vec![]);
        ctx.prevouts.insert(
            prevout_key(1, 0),
            PrevoutInfo { value: 40_000, address: Some(addr_of(&spk_a)), source: "Notebook · Alice".into() },
        );
        // input (2,1) intentionally left out of ctx.prevouts.

        let sum = summarize_signed_tx(&hex_str, &ctx).unwrap();
        assert_eq!(sum.total_in, None);
        assert_eq!(sum.fee, None);
        assert_eq!(sum.fee_line, "fee unknown — missing input data");
        assert!(sum.warn.is_some());
        assert_eq!(sum.inputs[1].amount, "?");
        assert_eq!(sum.inputs[1].subtitle, "outpoint · amount unknown");
    }

    /// An output paying an address we don't recognize is flagged, not
    /// silently swallowed — the paranoid tripwire.
    #[test]
    fn foreign_output_flags_a_warning() {
        let (_, spk_a) = notebook_spk(7);
        let (_, spk_stranger) = notebook_spk(42);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin(1, 0)],
            output: vec![txout(0, pnte_op_return("uh oh")), txout(60_000, spk_stranger.clone())],
        };
        let hex_str = raw_hex(&tx);

        let mut ctx = base_ctx(vec![spk_a.clone()], vec![]);
        ctx.prevouts.insert(
            prevout_key(1, 0),
            PrevoutInfo { value: 100_000, address: Some(addr_of(&spk_a)), source: "Notebook · Alice".into() },
        );

        let sum = summarize_signed_tx(&hex_str, &ctx).unwrap();
        let foreign_row = sum.outputs.iter().find(|o| o.kind == "other").expect("foreign output");
        assert_eq!(foreign_row.title, addr_of(&spk_stranger));
        assert_eq!(foreign_row.subtitle, "not one of your addresses");
        assert!(sum.warn.is_some());
        assert!(sum.warn.as_ref().unwrap().contains("doesn't recognize"));
    }

    /// Adversarial input never panics — it just errors.
    #[test]
    fn garbage_and_truncated_input_errs_without_panicking() {
        let ctx = base_ctx(vec![], vec![]);
        assert!(summarize_signed_tx("", &ctx).is_err());
        assert!(summarize_signed_tx("not hex at all", &ctx).is_err());
        assert!(summarize_signed_tx("deadbeef", &ctx).is_err());
        // Odd-length hex.
        assert!(summarize_signed_tx("abc", &ctx).is_err());
        // A varint claiming a huge input count with no bytes behind it —
        // must error, not allocate/panic.
        assert!(summarize_signed_tx("0200000001ff", &ctx).is_err());
        // A truncated, otherwise-valid-looking real tx.
        let (_, spk_a) = notebook_spk(7);
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin(1, 0)],
            output: vec![txout(50_000, spk_a)],
        };
        let full = raw_hex(&tx);
        let truncated = &full[..full.len() / 2];
        assert!(summarize_signed_tx(truncated, &ctx).is_err());
    }
}
