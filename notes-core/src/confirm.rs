//! The device's universal "Confirm & sign" screen's byte-truth summarizer.
//!
//! Philosophy (paranoid-bitcoiner, mirrors the graffito desktop app's
//! `app-core/src/confirm.rs` — same rules, ported off `rust-bitcoin` onto
//! this crate's own [`crate::decode::decode_transaction`] since
//! `rust-bitcoin`/secp256k1-sys stays a dev-dependency only on this
//! device): every fact shown to the user is decoded from the ACTUAL
//! signed raw transaction bytes about to hit the wire — never from the
//! app's own intent/state. [`ConfirmCtx`] supplies only LOOKUPS (what a
//! prevout or address means to us); it never supplies an amount or a
//! classification verdict. In particular the fee is always computed from
//! decoded input/output values, never accepted from the caller — a
//! compromised or buggy build step can lie about what it *meant* to
//! build, but it cannot lie about what the signed bytes *are*.

use std::collections::BTreeMap;

use crate::address::address_from_spk;
use crate::envelope;
use crate::tx::op_return_payload;
use crate::{Error, Network};

/// Same convention as `bundle.rs`'s scanner: 0x6a (OP_RETURN) marks a
/// candidate output; whether it's actually a PNTE payload is decided by
/// the FIRST OP_RETURN output's header (`envelope::parse_header`) — later
/// OP_RETURN outputs of the SAME tx carry no header of their own
/// (PLAN-pnte-redesign.md: one note = one tx, header only on the first
/// output), so once the tx's first OP_RETURN validates, every later one is
/// labeled as part of the same note too.
fn op_return_payloads_in_order(outputs: &[crate::tx::TxOut]) -> Vec<&[u8]> {
    outputs.iter().filter_map(|o| op_return_payload(&o.script_pubkey)).collect()
}

/// One visible character per PAYLOAD BYTE, for the confirm screen's
/// OP_RETURN row — the answer to "is what I'm broadcasting actually
/// encrypted?" (Sal, 2026-09-10).
///
/// A public note's body is its UTF-8 text verbatim (see `envelope`), so it
/// decodes and you READ YOUR NOTE. A private note's body is ciphertext, so
/// there is no text to find: printable ASCII bytes show as themselves and
/// everything else as `·`, one glyph per byte.
///
/// Deliberately NOT mempool.space's rendering. Their `hex2ascii` pipe
/// decodes UTF-8 and then `.replace(/\uFFFD/g, '')` — it DELETES every
/// undecodable byte, so ~2/3 of a ciphertext vanishes and 189 bytes
/// collapse into a short run of arbitrary characters that reads like odd
/// text rather than like "not text at all". One-glyph-per-byte keeps the
/// length honest.
///
/// `·` is U+00B7 (Latin-1): femtovg has no font fallback in this app, so
/// the placeholder must be a character the bundled font actually carries.
pub fn payload_glyphs(payload: &[u8], decode_utf8: bool) -> String {
    if decode_utf8 {
        if let Ok(text) = core::str::from_utf8(payload) {
            return text.replace(['\n', '\r', '\t'], " ");
        }
    }
    payload
        .iter()
        .map(|b| match b {
            0x20..=0x7e => *b as char,
            _ => '·',
        })
        .collect()
}

/// The complete payload as lowercase hex — the row's tap-to-expand detail.
/// Block explorers show exactly these bytes (mempool.space puts them in the
/// ScriptPubKey/ASM row), so this is what lets a signer byte-compare the
/// app against an explorer.
pub fn payload_hex(payload: &[u8]) -> String {
    payload.iter().map(|b| format!("{b:02x}")).collect()
}

/// What we know about an input's previous output. `source` is a human
/// wallet label, e.g. "Notebook · Alice", "Spending wallet", "ColdBox"
/// (external), or "" if unknown.
pub struct PrevoutInfo {
    pub value: u64,
    pub address: Option<String>,
    pub source: String,
}

pub struct ConfirmCtx {
    pub network: Network,
    /// key = "txid:vout" (lowercase hex txid, decimal vout) — `BTreeMap`
    /// so lookups and any incidental iteration stay deterministically
    /// ordered, unlike a hasher-seeded `HashMap`.
    pub prevouts: BTreeMap<String, PrevoutInfo>,
    /// every script_pubkey we control (all notebooks + spending wallet), raw bytes
    pub self_spks: Vec<Vec<u8>>,
    /// subset of self_spks that belong to the BIP-84 spending wallet
    pub spending_spks: Vec<Vec<u8>>,
    /// address we expect change at, if a custom/external change address was chosen
    pub expected_change: Option<String>,
    /// directed-note recipient address + optional contact name
    pub recipient: Option<String>,
    pub recipient_name: Option<String>,
    /// Every recipient of a multi-recipient directed note (2..=255),
    /// including the primary `recipient` above — additive, empty for a
    /// classic single-recipient (or self) note, in which case only
    /// `recipient`/`recipient_name` are consulted (unchanged behavior).
    /// When non-empty, ANY output matching an address in this list
    /// classifies as `"recipient"` kind instead of falling through to
    /// `"other"` (which would otherwise show a scary "doesn't recognize
    /// this address" warning for a perfectly normal 2nd+ recipient) — the
    /// exact address that also equals `recipient` still gets
    /// `recipient_name`'s subtitle; every other match gets the generic
    /// "directed recipient" subtitle (this ctx has no per-address name
    /// map for the extras).
    pub recipients: Vec<String>,
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
    /// The row's FULL byte truth, revealed on tap — today only the
    /// OP_RETURN row sets it (the complete payload as lowercase hex, the
    /// same bytes a block explorer will show once this is on chain).
    /// Empty everywhere else, which is what the UI keys "is this row
    /// expandable" off.
    pub detail: String,
}

pub struct TxSummary {
    pub txid: String,
    pub inputs: Vec<SummaryRow>,
    pub outputs: Vec<SummaryRow>,
    pub total_in: Option<u64>, // None if any prevout value missing
    pub total_out: u64,
    pub fee: Option<u64>, // total_in - total_out; None if total_in is None
    pub vsize: u64,
    pub fee_line: String, // "1,234 sats · 2.0 sat/vB" or "fee unknown - missing input data"
    pub warn: Option<String>, // set when something needs user attention (see rules)
}

/// self_dust-ish threshold used to tell a "keep the note discoverable" dust
/// output apart from ordinary change back to the same notebook address. The
/// app's own self-dust output is [`crate::DUST_LIMIT`] (330); the classic
/// dust limit (546) is used here as the deciding line so an unusually
/// small BUT real change amount still reads as dust-ish.
const SELF_DUST_CEILING: u64 = 546;

/// Decode a signed raw tx and label every input/output from `ctx`'s
/// lookups. Every fact in the returned [`TxSummary`] — the txid, the
/// output values, the output script classification, the fee — comes from
/// `raw_hex` itself (via [`crate::decode::decode_transaction`]); `ctx`
/// only supplies what an outpoint/address MEANS to this wallet.
pub fn summarize_signed_tx(raw_hex: &str, ctx: &ConfirmCtx) -> Result<TxSummary, Error> {
    let bytes = hex::decode(raw_hex.trim()).map_err(|_| Error::Decode("not valid hex"))?;
    let tx = crate::decode::decode_transaction(&bytes)?;

    let mut warns: Vec<String> = Vec::new();

    // Resolve the two "known destination" addresses to scriptPubKeys ONCE
    // (spk compare, never string compare, per the paranoid rule — a string
    // compare can be fooled by address-encoding quirks the spk can't be).
    let recipient_spk: Option<Vec<u8>> = ctx.recipient.as_deref().and_then(|a| resolve_spk(a, ctx.network));
    // Multi-recipient (2..=255): every OTHER recipient beyond `recipient`
    // resolved the same way — empty when `ctx.recipients` is empty (a
    // classic single-recipient/self note), so this is a strict no-op
    // addition for every existing caller.
    let extra_recipient_spks: Vec<Vec<u8>> = ctx
        .recipients
        .iter()
        .filter(|a| ctx.recipient.as_deref() != Some(a.as_str()))
        .filter_map(|a| resolve_spk(a, ctx.network))
        .collect();
    let expected_change_spk: Option<Vec<u8>> =
        ctx.expected_change.as_deref().and_then(|a| resolve_spk(a, ctx.network));

    // --- inputs -------------------------------------------------------
    let mut inputs = Vec::with_capacity(tx.inputs.len());
    let mut sum_in: u64 = 0;
    let mut any_prevout_missing = false;
    for txin in &tx.inputs {
        // `Utxo::txid` is internal byte order; the outpoint key (and every
        // human-facing txid this app shows) is the conventional REVERSED
        // display hex — same convention `Transaction::txid_hex` uses.
        let mut txid_display = txin.txid;
        txid_display.reverse();
        let outpoint = format!("{}:{}", hex::encode(txid_display), txin.vout);
        match ctx.prevouts.get(&outpoint) {
            Some(info) => {
                sum_in += info.value;
                let title = info.address.clone().unwrap_or_else(|| outpoint.clone());
                let subtitle = if info.source.is_empty() { "source unknown".to_string() } else { info.source.clone() };
                inputs.push(SummaryRow { title, subtitle, amount: commas(info.value), kind: "input".into(), detail: String::new() });
            }
            None => {
                any_prevout_missing = true;
                inputs.push(SummaryRow {
                    title: outpoint,
                    subtitle: "outpoint · amount unknown".into(),
                    amount: "?".into(),
                    kind: "input".into(),
                    detail: String::new(),
                });
            }
        }
    }
    let total_in = if any_prevout_missing { None } else { Some(sum_in) };

    // --- outputs --------------------------------------------------------
    // Whether the tx's first OP_RETURN output carries a valid PNTE header —
    // decided ONCE, since later OP_RETURN outputs of the same tx carry no
    // header of their own (they're raw continuation bytes; see
    // `op_return_payloads_in_order`'s doc comment).
    let first_header = op_return_payloads_in_order(&tx.outputs).first().and_then(|p| envelope::parse_header(p));
    let is_pnte_tx = first_header.is_some();
    // FLAG_PRIVATE off the wire — a public note's body IS its UTF-8 text, a
    // private one's is ciphertext, and the row renders accordingly.
    let is_private_tx = first_header.is_some_and(|(flags, ..)| flags & envelope::FLAG_PRIVATE != 0);
    let mut outputs = Vec::with_capacity(tx.outputs.len());
    let mut total_out: u64 = 0;
    for txout in &tx.outputs {
        let value = txout.value;
        total_out += value;
        let spk = txout.script_pubkey.as_slice();

        if spk.first() == Some(&0x6a) {
            let is_pnte = is_pnte_tx;
            // The row shows the payload ITSELF, not a label for it: a public
            // note reads back as its own text, a private one cannot, and
            // that contrast IS the proof the note is sealed (Sal,
            // 2026-09-10). `decode_utf8` comes from the FLAGS ON THE WIRE,
            // never from app state — byte truth is this module's whole job.
            let payload = op_return_payload(&txout.script_pubkey).unwrap_or_default();
            let title = payload_glyphs(payload, !is_private_tx);
            let size = format!(
                "{} byte{}",
                payload.len(),
                if payload.len() == 1 { "" } else { "s" }
            );
            let subtitle = match (is_pnte, is_private_tx) {
                (true, true) => format!("OP_RETURN · PNTE note · encrypted · {size}"),
                (true, false) => format!("OP_RETURN · PNTE note · public · {size}"),
                (false, _) => format!("OP_RETURN · data · {size}"),
            };
            outputs.push(SummaryRow {
                title,
                subtitle,
                amount: if value == 0 { String::new() } else { commas(value) },
                kind: "note".into(),
                detail: payload_hex(payload),
            });
            continue;
        }

        let Some(addr) = address_from_spk(spk, ctx.network) else {
            warns.push("an output script couldn't be decoded to an address".to_string());
            outputs.push(SummaryRow {
                title: hex::encode(spk),
                subtitle: "unrenderable output script".to_string(),
                amount: commas(value),
                kind: "other".into(),
                detail: String::new(),
            });
            continue;
        };

        let (kind, subtitle) = if recipient_spk.as_deref() == Some(spk) {
            ("recipient", ctx.recipient_name.clone().unwrap_or_else(|| "directed recipient".to_string()))
        } else if extra_recipient_spks.iter().any(|s| s.as_slice() == spk) {
            ("recipient", "directed recipient".to_string())
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

        outputs.push(SummaryRow { title: addr, subtitle, amount: commas(value), kind: kind.to_string(), detail: String::new() });
    }

    let vsize = tx.vsize() as u64;
    // in < out can't happen in a valid tx — it means the caller's prevout
    // data is wrong, which is exactly what this module exists to catch.
    if let Some(ti) = total_in {
        if total_out > ti {
            warns.push("outputs exceed the known input total - the input data is inconsistent".to_string());
        }
    }
    let fee = total_in.filter(|ti| *ti >= total_out).map(|ti| ti - total_out);
    let fee_line = match fee {
        Some(f) => {
            let rate = if vsize > 0 { f as f64 / vsize as f64 } else { 0.0 };
            format!("{} sats · {rate:.1} sat/vB", commas(f))
        }
        None if total_in.is_some() => "fee unknown - inconsistent input data".to_string(),
        None => {
            warns.push("one or more input amounts are unknown - the fee could not be verified".to_string());
            "fee unknown - missing input data".to_string()
        }
    };

    Ok(TxSummary {
        txid: tx.txid_hex(),
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
fn resolve_spk(address: &str, network: Network) -> Option<Vec<u8>> {
    crate::address::address_to_script_pubkey(network, address).ok()
}

/// Thousands-separated sats, e.g. `1234567` -> `"1,234,567"`. notes-core
/// has no existing helper for this (unlike the graffito desktop app's
/// `mixed::commas`) — a fresh, minimal implementation.
fn commas(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out.chars().rev().collect()
}
