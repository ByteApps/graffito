//! Mixed-source funding for a single note tx (funding-unification UI
//! rework, 2026-07-16): coins nest per wallet on the Pay-from screen and are
//! individually selectable ACROSS notebook / spending-wallet / external
//! watch-only sources — a single note may spend all three kinds of coin in
//! one PSBT. This module is ADDITIVE glue over the existing single-source
//! machinery: [`crate::psbt_build::assemble_funded_note_psbt`]'s output
//! shape (OP_RETURNs, optional recipient, dust-to-self, then change) is
//! reused verbatim, with ONE additive rule on top —
//! [`assemble_mixed_note_psbt`] SKIPS the dust-to-self output when the
//! selection includes a `CoinSource::Notebook` OR `CoinSource::Change`
//! coin (input-anchored: both are the identity's own coin — chain 0 and
//! chain 1 of the same account, taproot-change unit 5 — so the note's
//! ownership/discoverability already hold via the input side, and the
//! extra output is redundant there); `assemble_funded_note_psbt` never
//! sees a notebook or change coin by construction (spending/external
//! funding never spends them), so its own dust-to-self stays unconditional.
//! Only input assembly otherwise generalizes to per-coin sources. Signing
//! still dispatches to the existing per-kind signers
//! ([`crate::psbt_build::sign_own_taproot_inputs`],
//! [`crate::psbt_build::sign_own_wpkh_inputs`]); external-wallet inputs are
//! left unsigned with key-origin metadata so the existing screens-13/14
//! PSBT export/import flow can complete them, exactly like the watch-spend
//! pattern this module composes with.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use bitcoin::transaction::{predict_weight, InputWeightPrediction, Version};
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use miniscript::psbt::PsbtInputExt;
use notes_core::DUST_LIMIT;

use crate::funding::FundingSource;
use crate::psbt_build::BuiltPsbt;
use crate::Error;

/// Which wallet a selected coin belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CoinSource {
    /// The identity's own notebook (taproot) coin.
    Notebook,
    /// The identity's own BIP-84 spending-wallet coin.
    Spending,
    /// An external (watch-only) funding wallet, identified by its saved id.
    Wallet(String),
    /// The identity's own taproot CHANGE-chain coin (`m/86'/…/1/{index}`,
    /// taproot-change unit 5 — see `../PLAN-chain-notes-app-taproot-change.md`).
    /// Same account as `Notebook`, just chain 1 instead of chain 0 — an
    /// OWN coin, not a distinct wallet (Sal's "one unified balance" rule).
    /// `MixedCoin.index` is its chain-1 index (needed by the caller to
    /// derive its signing owner via `identity::realize_change`); `chain`
    /// is always 1.
    Change,
}

/// One coin selected for a mixed-source note, tagged with its source and
/// (for Spending/Wallet coins) the descriptor leaf that derives its spk.
/// `chain`/`index` are unused for `Notebook` (a notebook is a single fixed
/// address, not a ranged descriptor leaf).
#[derive(Debug, Clone)]
pub struct MixedCoin {
    pub source: CoinSource,
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub chain: usize,
    pub index: u32,
}

/// The default change destination, resolved from which sources participate
/// in this compose — see [`resolve_change_default`]. An explicit user pick
/// on the Change screen always wins; the UI only consults this when nothing
/// has been picked yet this compose session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeDefault {
    Spending,
    Notebook,
    Wallet(String),
}

/// Sal's rule (funding-unification UI rework, agreed): the spending wallet,
/// when enabled AND participating in this compose (selected as a coin
/// source, or simply the active "Pay from" choice even before any coin is
/// toggled), wins change by default — it's the wallet meant to absorb
/// day-to-day change. Failing that, coins drawn from exactly one external
/// wallet (and nothing else) send change back to that wallet. Otherwise
/// (notebook coins present, or a mixed notebook+external selection with no
/// spending-wallet participation) change goes to the notebook address — the
/// safe fallback every identity always has. An explicit user pick is never
/// overridden by this function; callers only consult it while unset.
pub fn resolve_change_default(
    spending_enabled: bool,
    spending_participates: bool,
    external_wallet_only: Option<&str>,
) -> ChangeDefault {
    if spending_enabled && spending_participates {
        ChangeDefault::Spending
    } else if let Some(id) = external_wallet_only {
        ChangeDefault::Wallet(id.to_string())
    } else {
        ChangeDefault::Notebook
    }
}

/// Whether `coins` draw from more than one wallet — the Pay-from screen's
/// linkage-hint trigger (same tone as the consolidate confirm's
/// all-addresses-link warning: coins from different wallets spent in one tx
/// link their addresses on-chain).
pub fn spans_multiple_wallets(coins: &[MixedCoin]) -> bool {
    let sources: HashSet<&CoinSource> = coins.iter().map(|c| &c.source).collect();
    sources.len() > 1
}

/// The spending wallet's contribution to [`coins_summary_line`] — distinct
/// from "off" (no spending wallet at all, which isn't representable here;
/// the caller passes `None` for that case instead of this enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendingSummaryState {
    /// Enabled, but the first scan hasn't landed yet this session.
    NotScanned,
    /// Scanned: `n` spendable coins totalling `sats`.
    Scanned { n: usize, sats: u64 },
}

/// The Settings "Coins" card subtitle (and the Coins screen's notebook
/// segment caption, which reuses the same property) — CHANGE 1 of the
/// wallet-level-flows-learn-the-spending-wallet rework (2026-07-17): when
/// the spending wallet is enabled+capable, the notebook-side count
/// aggregates BOTH pools; disabled/incapable identities (`spending: None`)
/// get the ORIGINAL line, byte-for-byte, so nothing changes for them.
/// `nb_notebooks` is how many distinct notebooks contributed a coin — only
/// shown in the non-aggregate line (the aggregate line drops it for
/// brevity, matching Sal's examples: "3 notebook coins · 100,660 sats —
/// spending: 1 coin · 49,423 sats").
pub fn coins_summary_line(
    nb_n: usize,
    nb_sats: u64,
    nb_notebooks: usize,
    spending: Option<SpendingSummaryState>,
) -> String {
    let Some(spending) = spending else {
        return if nb_n == 0 {
            "No notebook coins yet — fund a notebook's address to add some.".to_string()
        } else {
            format!(
                "{nb_n} coin{} · {} sats across {nb_notebooks} notebook{}",
                if nb_n == 1 { "" } else { "s" },
                commas(nb_sats),
                if nb_notebooks == 1 { "" } else { "s" }
            )
        };
    };
    let nb_part = if nb_n == 0 {
        "No notebook coins".to_string()
    } else {
        format!("{nb_n} notebook coin{} · {} sats", if nb_n == 1 { "" } else { "s" }, commas(nb_sats))
    };
    let spending_part = match spending {
        SpendingSummaryState::NotScanned => "spending: not scanned yet".to_string(),
        SpendingSummaryState::Scanned { n: 0, .. } => "spending: no coins".to_string(),
        SpendingSummaryState::Scanned { n, sats } => {
            format!("spending: {n} coin{} · {} sats", if n == 1 { "" } else { "s" }, commas(sats))
        }
    };
    format!("{nb_part} — {spending_part}")
}

/// Group digits with thousands separators — local copy of the same helper
/// `src/lib.rs` has (kept tiny and dependency-free rather than plumbing a
/// shared crate for one function). `pub(crate)` so `confirm.rs` (the
/// universal confirm-screen summarizer) reuses it instead of writing a
/// third copy.
pub(crate) fn commas(n: u64) -> String {
    let s = n.to_string();
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in b.iter().enumerate() {
        if i > 0 && (b.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*c as char);
    }
    out
}

/// Fee-only estimate for the FUNDED output shape (OP_RETURNs + optional
/// recipient dust/gift + an optional dust-to-self output + change) —
/// [`crate::psbt_build::assemble_funded_note_psbt`] / [`assemble_mixed_note_psbt`]'s
/// exact output order, but WITHOUT their insufficiency gate: both builders
/// intentionally `Err` rather than report a fee once the selected coins
/// can't cover it (correct for the real build) — which is exactly the case
/// the Pay-from screen's summary card most needs a number for, to explain a
/// red state (Sal's iPhone bug cluster, 2026-07-18: the summary/"Required"
/// line was going blank right when it mattered most). `payloads` come from
/// the SAME `sealed_note_payloads` call those builders make internally —
/// this function only does the weight/fee arithmetic, via the same
/// `predict_weight` call they use, never a separately invented formula.
/// `dust_to_self`: pass `false` only when the caller's selection already
/// includes a `CoinSource::Notebook` coin (the same condition
/// [`assemble_mixed_note_psbt`] uses to skip the output for real) — every
/// other caller (spending-only, external-only) passes `true`, matching
/// `assemble_funded_note_psbt`'s unconditional dust-to-self.
pub fn estimate_funded_fee(
    input_weights: &[InputWeightPrediction],
    payloads: &[Vec<u8>],
    recipient_spk_len: Option<usize>,
    change_spk_len: usize,
    dust_to_self: bool,
    fee_rate: f64,
) -> u64 {
    let lens: Vec<usize> = recipient_spk_len.into_iter().collect();
    estimate_funded_fee_multi(input_weights, payloads, &lens, change_spk_len, dust_to_self, fee_rate)
}

/// Multi-recipient generalization of [`estimate_funded_fee`]: `recipient_spk_lens`
/// carries EVERY recipient output's spk length (uniform gift means only the
/// LENGTH matters for sizing, not the amount) instead of at most one — empty
/// = self-note, 2+ = a genuine multi-recipient note's real output-shape
/// list. The old signature delegates here with a 0/1-element vec, so it
/// stays byte-identical.
pub fn estimate_funded_fee_multi(
    input_weights: &[InputWeightPrediction],
    payloads: &[Vec<u8>],
    recipient_spk_lens: &[usize],
    change_spk_len: usize,
    dust_to_self: bool,
    fee_rate: f64,
) -> u64 {
    let mut lens: Vec<usize> =
        payloads.iter().map(|p| notes_core::tx::op_return_script(p).len()).collect();
    lens.extend(recipient_spk_lens.iter().copied());
    if dust_to_self {
        lens.push(34); // our own P2TR notebook address, when present
    }
    lens.push(change_spk_len);
    let vsize = predict_weight(input_weights.iter().copied(), lens.into_iter()).to_vbytes_ceil();
    (vsize as f64 * fee_rate).ceil().max(0.0) as u64
}

/// The other half of [`estimate_funded_fee`]'s output-shape list: the SAME
/// funded shape (OP_RETURNs + optional recipient + the same optional
/// dust-to-self) but WITHOUT a discretionary change output — the "no
/// change" branch of the with-change/no-change decision
/// [`assemble_mixed_note_psbt`] / [`crate::psbt_build::assemble_funded_note_psbt`]
/// make for real. Paired with `estimate_funded_fee` by [`predict_fold`] to
/// tell whether the CURRENT selection would fold a sub-dust leftover into
/// the fee. `dust_to_self`: same rule as [`estimate_funded_fee`]'s.
pub fn estimate_funded_fee_no_change(
    input_weights: &[InputWeightPrediction],
    payloads: &[Vec<u8>],
    recipient_spk_len: Option<usize>,
    dust_to_self: bool,
    fee_rate: f64,
) -> u64 {
    let lens: Vec<usize> = recipient_spk_len.into_iter().collect();
    estimate_funded_fee_no_change_multi(input_weights, payloads, &lens, dust_to_self, fee_rate)
}

/// Multi-recipient generalization of [`estimate_funded_fee_no_change`] —
/// see [`estimate_funded_fee_multi`]'s doc for the same convention.
pub fn estimate_funded_fee_no_change_multi(
    input_weights: &[InputWeightPrediction],
    payloads: &[Vec<u8>],
    recipient_spk_lens: &[usize],
    dust_to_self: bool,
    fee_rate: f64,
) -> u64 {
    let mut lens: Vec<usize> =
        payloads.iter().map(|p| notes_core::tx::op_return_script(p).len()).collect();
    lens.extend(recipient_spk_lens.iter().copied());
    if dust_to_self {
        lens.push(34); // present with or without change, unless anchored
    }
    let vsize = predict_weight(input_weights.iter().copied(), lens.into_iter()).to_vbytes_ceil();
    (vsize as f64 * fee_rate).ceil().max(0.0) as u64
}

/// Honest-fee-label prediction (2026-07-18): every note-tx builder in this
/// app picks between a WITH-CHANGE shape and a NO-CHANGE shape — when a
/// discretionary change output would be sub-dust, its value is folded into
/// the fee instead (`build_note_tx_with_change`/`_exact` in notes-core for
/// the notebook shape; [`assemble_mixed_note_psbt`] /
/// [`crate::psbt_build::assemble_funded_note_psbt`] for spending/external/
/// mixed). Without a UI split, the fee figure shown looks unexplainably
/// high for tiny coins. `predict_fold` is the shared decision, applied to a
/// FIXED selection (no coin-set growing, matching how the "current
/// selection" is already fully known once coins are chosen): given the
/// with-change and no-change fee figures for that exact selection, returns
/// `Some((nominal, folded))` when the shape actually needed is no-change —
/// `nominal` is the real fee at the given rate for that shape, `folded` is
/// the sub-dust leftover swept into it on top (so `nominal + folded` is the
/// byte-true fee the tx will pay). `None` when a change output is
/// affordable, or nothing folds.
///
/// `cap_at_dust`: the plain notebook builder's no-change branch ALSO
/// refuses a leftover ABOVE dust (`if !change && change_value > DUST_LIMIT
/// { continue }` in `build_note_tx_with_change`/`_exact`) — for a fixed
/// selection that means the real build would simply fail rather than fold
/// an oversized leftover, so callers predicting the notebook shape must
/// pass `true` (see [`predict_notebook_fold`]). The funded/mixed builders'
/// no-change fallback has no such ceiling — it always folds whatever's
/// left once a change output is ruled out — so [`predict_funded_fold`]
/// passes `false`.
pub fn predict_fold(
    in_value: u64,
    fixed_out: u64,
    fee_with_change: u64,
    fee_no_change: u64,
    cap_at_dust: bool,
) -> Option<(u64, u64)> {
    if in_value >= fixed_out.saturating_add(fee_with_change) {
        let change_wc = in_value - fixed_out - fee_with_change;
        if change_wc >= DUST_LIMIT {
            return None; // a change output is affordable — no fold
        }
    }
    if in_value < fixed_out.saturating_add(fee_no_change) {
        return None; // can't even afford the no-change shape
    }
    let leftover = in_value - fixed_out - fee_no_change;
    if leftover == 0 {
        return None; // nothing folds
    }
    if cap_at_dust && leftover > DUST_LIMIT {
        return None; // the real (fixed-selection) build would refuse this shape
    }
    Some((fee_no_change, leftover))
}

/// [`predict_fold`] for the notebook (pure self-funded taproot) shape.
/// `vsize_with_change` is the WITH-CHANGE vsize already sized for
/// `change_len` — e.g. the app's own `note_est`, which mirrors notes-core's
/// `estimate_vsize(…, true)` byte for byte. The no-change vsize is derived
/// from it by subtracting the change output's own serialized byte cost
/// (8-byte value + a 1-byte length varint + the script itself — every
/// change script in this app is well under the 253-byte varint threshold,
/// same assumption `note_est`'s own custom-change correction already
/// makes): weight is exactly linear in whether the change output is
/// present, and subtracting an integer before or after `ceil(weight/4)`
/// gives the same vsize, so this is an EXACT match for calling
/// `estimate_vsize(…, false)` directly — not an approximation. Verified
/// against a real notebook build by `predict_notebook_fold_matches_real_build`.
pub fn predict_notebook_fold(
    in_value: u64,
    sent: u64,
    vsize_with_change: usize,
    change_len: usize,
    fee_rate: f64,
) -> Option<(u64, u64)> {
    let vsize_no_change = notebook_vsize_no_change(vsize_with_change, change_len);
    let fee_wc = (vsize_with_change as f64 * fee_rate).ceil().max(0.0) as u64;
    let fee_nc = (vsize_no_change as f64 * fee_rate).ceil().max(0.0) as u64;
    predict_fold(in_value, sent, fee_wc, fee_nc, true)
}

/// The exact vsize a notebook note tx would have WITHOUT its discretionary
/// change output, derived algebraically from the WITH-CHANGE vsize (e.g.
/// `note_est`'s result) — see [`predict_notebook_fold`]'s doc for why
/// subtracting the change output's own serialized byte cost this way is
/// EXACT, not an approximation. Exposed separately from
/// `predict_notebook_fold` so callers that already know a fold happened
/// (its `Some`) can also show the real no-change vsize (the compose cost
/// line's "~<N> vB").
pub fn notebook_vsize_no_change(vsize_with_change: usize, change_len: usize) -> usize {
    vsize_with_change.saturating_sub(9 + change_len) // 8 (value) + 1 (length varint) + script bytes
}

/// [`predict_fold`] for the funded shape (spending-only / external-only /
/// mixed compose) — the `estimate_funded_fee` / `estimate_funded_fee_no_change`
/// pair IS the with-change/no-change comparison, so this just runs both and
/// hands them to `predict_fold` with `cap_at_dust = false` (see its doc).
/// `dust_to_self`: forwarded to both estimators — `false` when the
/// selection includes a `CoinSource::Notebook` coin, `true` otherwise (see
/// [`estimate_funded_fee`]'s doc).
pub fn predict_funded_fold(
    input_weights: &[InputWeightPrediction],
    payloads: &[Vec<u8>],
    recipient_spk_len: Option<usize>,
    change_spk_len: usize,
    dust_to_self: bool,
    in_value: u64,
    fixed_out: u64,
    fee_rate: f64,
) -> Option<(u64, u64)> {
    let lens: Vec<usize> = recipient_spk_len.into_iter().collect();
    predict_funded_fold_multi(input_weights, payloads, &lens, change_spk_len, dust_to_self, in_value, fixed_out, fee_rate)
}

/// Multi-recipient generalization of [`predict_funded_fold`] — see
/// [`estimate_funded_fee_multi`]'s doc for the same convention.
#[allow(clippy::too_many_arguments)]
pub fn predict_funded_fold_multi(
    input_weights: &[InputWeightPrediction],
    payloads: &[Vec<u8>],
    recipient_spk_lens: &[usize],
    change_spk_len: usize,
    dust_to_self: bool,
    in_value: u64,
    fixed_out: u64,
    fee_rate: f64,
) -> Option<(u64, u64)> {
    let fee_wc = estimate_funded_fee_multi(
        input_weights, payloads, recipient_spk_lens, change_spk_len, dust_to_self, fee_rate,
    );
    let fee_nc =
        estimate_funded_fee_no_change_multi(input_weights, payloads, recipient_spk_lens, dust_to_self, fee_rate);
    predict_fold(in_value, fixed_out, fee_wc, fee_nc, false)
}

/// Coerce this mixed selection's Spending-source coins into the
/// `FundingUtxo` shape [`crate::psbt_build::sign_own_wpkh_inputs`] expects.
pub fn spending_funding_utxos(coins: &[MixedCoin]) -> Vec<crate::funding::FundingUtxo> {
    coins
        .iter()
        .filter(|c| c.source == CoinSource::Spending)
        .map(|c| crate::funding::FundingUtxo {
            txid: c.txid.clone(),
            vout: c.vout,
            value: c.value,
            address: String::new(),
            chain: c.chain,
            index: c.index,
            confirmed: true,
        })
        .collect()
}

/// Assemble the unsigned mixed-source note PSBT: inputs from potentially
/// notebook + change-chain + spending + several external wallets, in ONE
/// transaction. Output shape mirrors
/// [`crate::psbt_build::assemble_funded_note_psbt`] byte-for-byte (OP_RETURNs,
/// optional recipient, dust-to-self, then change) — EXCEPT the dust-to-self
/// output is SKIPPED when `coins` includes any `CoinSource::Notebook` OR
/// `CoinSource::Change` coin (input-anchored: the note is already provably
/// ours via the input side — both are this identity's own coin — so the
/// discoverability/ownership dust would be redundant — Sal's rule,
/// funding-unification, 2026-07-18; extended to change-chain coins by
/// taproot-change unit 5). Otherwise this is an additive generalization of
/// that function's INPUT side only.
///
/// `notebook_spk` is the identity's own P2TR scriptPubkey (Notebook coins'
/// prevout and, when present, the dust-to-self output — one notebook, one
/// fixed address).
/// `wallets` resolves an external wallet id to its live `FundingSource`;
/// `spending_source` is the identity's own BIP-84 wallet. `change_spk_override`
/// mirrors `FundingPlan::change_override` (an explicit pick always wins);
/// otherwise `change_default` picks a fresh address from the matching
/// descriptor (Spending/Wallet, at `change_index`) or `notebook_spk` itself
/// (Notebook — a single fixed address, same as the plain compose path's own
/// change).
#[allow(clippy::too_many_arguments)]
pub fn assemble_mixed_note_psbt(
    coins: &[MixedCoin],
    notebook_spk: Vec<u8>,
    spending_source: Option<&FundingSource>,
    wallets: &HashMap<String, FundingSource>,
    payloads: &[Vec<u8>],
    recipient_spk: Option<Vec<u8>>,
    recipient_amount: u64,
    change_default: &ChangeDefault,
    change_spk_override: Option<Vec<u8>>,
    change_index: u32,
    fee_rate: f64,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    let recipients: Vec<(Vec<u8>, u64)> =
        recipient_spk.map(|spk| vec![(spk, recipient_amount)]).unwrap_or_default();
    assemble_mixed_note_psbt_multi(
        coins,
        notebook_spk,
        spending_source,
        wallets,
        payloads,
        &recipients,
        change_default,
        change_spk_override,
        change_index,
        fee_rate,
        lock_time,
    )
}

/// Multi-recipient generalization of [`assemble_mixed_note_psbt`]: `recipients`
/// carries EVERY recipient output's (scriptPubKey, amount) pair, in the exact
/// order the caller must have already resolved from
/// `notes_core::bundle::sealed_note_payloads_multi`'s returned spk order (a
/// FROZEN protocol rule — wrap order = output order). Empty = a self-note,
/// one entry = an ordinary directed note (byte-identical to
/// [`assemble_mixed_note_psbt`], which delegates here), 2+ = a genuine
/// multi-recipient note — every recipient output lands where the single
/// recipient output used to (after the OP_RETURNs, before dust-to-self/
/// change), and the input-anchored dust-to-self skip is unaffected by
/// recipient count (it only ever looks at the INPUT side).
#[allow(clippy::too_many_arguments)]
pub fn assemble_mixed_note_psbt_multi(
    coins: &[MixedCoin],
    notebook_spk: Vec<u8>,
    spending_source: Option<&FundingSource>,
    wallets: &HashMap<String, FundingSource>,
    payloads: &[Vec<u8>],
    recipients: &[(Vec<u8>, u64)],
    change_default: &ChangeDefault,
    change_spk_override: Option<Vec<u8>>,
    change_index: u32,
    fee_rate: f64,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    assemble_mixed_note_psbt_multi_ext(
        coins,
        notebook_spk,
        spending_source,
        wallets,
        &HashMap::new(),
        payloads,
        recipients,
        change_default,
        change_spk_override,
        change_index,
        fee_rate,
        lock_time,
    )
}

/// [`assemble_mixed_note_psbt_multi`] extended with taproot CHANGE-chain
/// coins (`CoinSource::Change`, taproot-change unit 5 — see
/// `../PLAN-chain-notes-app-taproot-change.md`): `change_spks` maps a
/// chain-1 index to that leaf's own P2TR scriptPubKey (the caller derives
/// these via `identity::realize_change` — this builder has no key
/// material, only spks). `assemble_mixed_note_psbt_multi`/
/// `assemble_mixed_note_psbt` delegate here with an empty map, so every
/// existing caller (no `Change` coins possible without one) stays
/// byte-identical — the additive-delegation discipline this module's
/// other generalizations (e.g. `_multi` itself) already follow.
#[allow(clippy::too_many_arguments)]
pub fn assemble_mixed_note_psbt_multi_ext(
    coins: &[MixedCoin],
    notebook_spk: Vec<u8>,
    spending_source: Option<&FundingSource>,
    wallets: &HashMap<String, FundingSource>,
    change_spks: &HashMap<u32, Vec<u8>>,
    payloads: &[Vec<u8>],
    recipients: &[(Vec<u8>, u64)],
    change_default: &ChangeDefault,
    change_spk_override: Option<Vec<u8>>,
    change_index: u32,
    fee_rate: f64,
    lock_time: u32,
) -> Result<BuiltPsbt, Error> {
    if coins.is_empty() {
        return Err(Error::Funding("no coins selected".into()));
    }

    let mut inputs = Vec::with_capacity(coins.len());
    let mut prevouts = Vec::with_capacity(coins.len());
    let mut weights = Vec::with_capacity(coins.len());
    for coin in coins {
        let txid = Txid::from_str(&coin.txid).map_err(|e| Error::Funding(format!("bad txid: {e}")))?;
        inputs.push(TxIn {
            previous_output: OutPoint { txid, vout: coin.vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        let (spk, weight) = match &coin.source {
            CoinSource::Notebook => {
                (notebook_spk.clone(), InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH)
            }
            CoinSource::Spending => {
                let src = spending_source
                    .ok_or_else(|| Error::Funding("spending wallet not available".into()))?;
                (src.derive(coin.chain, coin.index)?.spk, InputWeightPrediction::P2WPKH_MAX)
            }
            CoinSource::Wallet(id) => {
                let src = wallets.get(id).ok_or_else(|| Error::Funding(format!("unknown wallet {id}")))?;
                let w = match src.kind {
                    crate::funding::FundingKind::Taproot => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
                    crate::funding::FundingKind::Wpkh => InputWeightPrediction::P2WPKH_MAX,
                };
                (src.derive(coin.chain, coin.index)?.spk, w)
            }
            CoinSource::Change => {
                let spk = change_spks
                    .get(&coin.index)
                    .cloned()
                    .ok_or_else(|| Error::Funding(format!("missing change spk for chain-1 index {}", coin.index)))?;
                (spk, InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH)
            }
        };
        prevouts.push(TxOut { value: Amount::from_sat(coin.value), script_pubkey: ScriptBuf::from_bytes(spk) });
        weights.push(weight);
    }

    let mut outputs: Vec<TxOut> = payloads
        .iter()
        .map(|p| TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(notes_core::tx::op_return_script(p)),
        })
        .collect();
    let mut sent_to_recipient = 0u64;
    for (spk, amount) in recipients {
        outputs.push(TxOut {
            value: Amount::from_sat(*amount),
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        });
        sent_to_recipient += amount;
    }
    // Input-anchored skip (Sal's rule, funding-unification, 2026-07-18;
    // extended to `Change` by taproot-change unit 5): a notebook coin in
    // this selection is always this identity's OWN notebook UTXO (see
    // `notebook_prevouts`'s doc comment in src/lib.rs — coin control never
    // crosses notebooks), so the tx already spends from self; a chain-1
    // CHANGE coin is the SAME identity's own coin too (same account, just
    // chain 1 instead of chain 0 — Sal's "one unified balance" rule), so it
    // anchors the note as self exactly like a notebook input. Either way
    // the dust-to-self output would be a redundant discoverability signal
    // and is skipped entirely.
    let has_self_input =
        coins.iter().any(|c| matches!(c.source, CoinSource::Notebook | CoinSource::Change));
    let dust_to_self = if has_self_input {
        0
    } else {
        outputs.push(TxOut { value: Amount::from_sat(DUST_LIMIT), script_pubkey: ScriptBuf::from_bytes(notebook_spk.clone()) });
        DUST_LIMIT
    };

    let change_spk: Vec<u8> = if let Some(spk) = change_spk_override {
        spk
    } else {
        match change_default {
            ChangeDefault::Notebook => notebook_spk,
            ChangeDefault::Spending => {
                let src = spending_source
                    .ok_or_else(|| Error::Funding("spending wallet not available".into()))?;
                src.derive(1, change_index)?.spk
            }
            ChangeDefault::Wallet(id) => {
                let src = wallets.get(id).ok_or_else(|| Error::Funding(format!("unknown wallet {id}")))?;
                src.derive(1, change_index)?.spk
            }
        }
    };
    let change_spk = ScriptBuf::from_bytes(change_spk);

    let in_value: u64 = coins.iter().map(|c| c.value).sum();
    let fixed_out: u64 = sent_to_recipient + dust_to_self;
    let base_lens: Vec<usize> = outputs.iter().map(|o| o.script_pubkey.len()).collect();
    let mut selected: Option<(u64, u64, bool)> = None;
    for with_change in [true, false] {
        let mut lens = base_lens.clone();
        if with_change {
            lens.push(change_spk.len());
        }
        let vsize = predict_weight(weights.iter().copied(), lens.iter().copied()).to_vbytes_ceil();
        let fee = (vsize as f64 * fee_rate).ceil() as u64;
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
            selected = Some((in_value - fixed_out, 0, false));
            break;
        }
    }
    let (fee, change, with_change) =
        selected.ok_or_else(|| Error::Funding("insufficient funds for note + fee".into()))?;
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
    for (i, coin) in coins.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(prevouts[i].clone());
        // Key origins for hardware-wallet recognition are only meaningful
        // (and only attempted) for external-wallet inputs; our own
        // notebook/spending inputs are signed directly (spk/outpoint match,
        // no PSBT round-trip), so origins are skipped for them.
        if let CoinSource::Wallet(id) = &coin.source {
            if let Some(src) = wallets.get(id) {
                let def = src.definite(coin.chain, coin.index)?;
                psbt.inputs[i]
                    .update_with_descriptor_unchecked(&def)
                    .map_err(|e| Error::Funding(format!("psbt key origins: {e}")))?;
            }
        }
    }

    Ok(BuiltPsbt { psbt, fee, change, sent_to_recipient, dust_to_self, txid })
}

/// One notebook's contribution to a mixed wallet sweep — same shape
/// `on_sweep`'s all-taproot path already gathers via `SweepSource`, but
/// per-coin here because `MixedInput` is flat (no source grouping).
pub struct NotebookSweepSource<'a> {
    pub output_x: [u8; 32],
    pub tweaked_seckey: &'a [u8; 32],
    pub utxos: &'a [notes_core::tx::Utxo],
}

/// Wallet-level sweep across every active notebook's taproot coins AND the
/// spending wallet's P2WPKH coins, in ONE mixed tx — the sweep analog of
/// [`assemble_mixed_note_psbt`]'s input-side generalization, but for
/// sweeping (single destination output, no change, no note payload):
/// flattens `notebook_sources` (each entry's `utxos` signed with that
/// notebook's own tweaked key) plus, if present, the spending wallet's
/// coins (each re-derived and signed via `crate::spending::derive_spending_key`)
/// into a single `Vec<MixedInput>` and hands it to
/// `notes_core::tx::build_sweep_tx_mixed`. `spending` is `None` when the
/// spending wallet isn't participating in this sweep (not enabled, or no
/// spending coins selected) — notebook-only sweeps still route through
/// here so callers don't need two code paths.
pub fn build_wallet_sweep_mixed(
    notebook_sources: &[NotebookSweepSource],
    spending: Option<(&crate::identity::KeyMaterial, notes_core::Network, u32, &[crate::funding::FundingUtxo])>,
    dest_spk: Vec<u8>,
    fee_rate: f64,
    lock_time: u32,
) -> Result<notes_core::tx::NoteTx, Error> {
    let mut inputs: Vec<notes_core::tx::MixedInput> = Vec::new();

    for src in notebook_sources {
        let prevout_spk = notes_core::address::p2tr_script_pubkey(&src.output_x);
        for u in src.utxos {
            inputs.push(notes_core::tx::MixedInput {
                utxo: u.clone(),
                prevout_spk: prevout_spk.clone(),
                kind: notes_core::tx::InputKind::Taproot,
                seckey: *src.tweaked_seckey,
            });
        }
    }

    if let Some((material, network, account, coins)) = spending {
        for coin in coins {
            let key = crate::spending::derive_spending_key(
                material,
                network,
                account,
                coin.chain as u32,
                coin.index,
            )?;
            // FundingUtxo.txid is display-order hex (like MixedCoin.txid
            // above); notes_core::tx::Utxo wants internal byte order — same
            // decode+reverse `Store::available_utxos` already does.
            let mut txid = [0u8; 32];
            hex::decode_to_slice(&coin.txid, &mut txid)
                .map_err(|e| Error::Funding(format!("bad txid: {e}")))?;
            txid.reverse();
            inputs.push(notes_core::tx::MixedInput {
                utxo: notes_core::tx::Utxo { txid, vout: coin.vout, value: coin.value },
                prevout_spk: key.script_pubkey,
                kind: notes_core::tx::InputKind::P2wpkh,
                seckey: *key.seckey,
            });
        }
    }

    if inputs.is_empty() {
        return Err(Error::Funding("no coins to sweep".into()));
    }

    notes_core::tx::build_sweep_tx_mixed(
        &inputs,
        dest_spk,
        fee_rate,
        lock_time,
        notes_core::keys::generate_aux_rand,
    )
    .map_err(Error::Notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{parse_key_material, realize, realize_change};
    use crate::psbt_build::{sign_own_taproot_inputs, sign_own_wpkh_inputs};
    use crate::psbt_finalize::{finalize_extract, validate_signed};
    use notes_core::bundle::Identity;
    use notes_core::Network;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                             abandon abandon abandon about";

    /// Mixed notebook + spending-wallet coins in ONE PSBT: both input kinds
    /// sign via their existing per-kind signer and the result verifies
    /// under rust-bitcoin (BIP-341 taproot + BIP-143 wpkh sighashes both
    /// checked by `validate_signed`/`finalize_extract`, the same pipeline
    /// the funded-sweep and watch-spend tests use). ALSO the input-anchored
    /// dust-to-self pin (2026-07-18): a notebook coin participates here, so
    /// the built tx must carry NO dust-to-self output at all — the note is
    /// already input-anchored — while everything else about the mixed shape
    /// (recipient, spending-wallet change, both signers, finalize) stays
    /// exactly as before.
    #[test]
    fn mixed_notebook_and_spending_psbt_signs_both_kinds() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let spending_src = crate::spending::funding_source(&material, net, 0).unwrap();

        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let notebook_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let recipient_spk = notes_core::address::p2tr_script_pubkey(&bob.output_x);

        let coins = vec![
            MixedCoin { source: CoinSource::Notebook, txid: "a".repeat(64), vout: 0, value: 60_000, chain: 0, index: 0 },
            MixedCoin { source: CoinSource::Spending, txid: "b".repeat(64), vout: 1, value: 40_000, chain: 0, index: 0 },
        ];
        assert!(spans_multiple_wallets(&coins), "notebook + spending = two distinct sources");

        let payloads =
            notes_core::envelope::encode_outputs(notes_core::envelope::FLAG_DIRECTED, None, b"mixed source note", 80)
                .unwrap();
        let wallets = HashMap::new();
        let built = assemble_mixed_note_psbt(
            &coins,
            notebook_spk.clone(),
            Some(&spending_src),
            &wallets,
            &payloads,
            Some(recipient_spk.clone()),
            330,
            &ChangeDefault::Spending,
            None,
            0,
            2.0,
            0)
        .unwrap();

        let tx = &built.psbt.unsigned_tx;
        assert_eq!(built.dust_to_self, 0, "a notebook coin is spending — the tx is already input-anchored");
        assert!(
            !tx.output.iter().any(|o| o.script_pubkey.as_bytes() == notebook_spk),
            "no dust-to-self output at all when a notebook coin funds the tx"
        );
        assert!(tx.output.iter().any(|o| o.script_pubkey.as_bytes() == recipient_spk && o.value.to_sat() == 330));
        let change_spk = spending_src.derive(1, 0).unwrap().spk;
        assert!(tx.output.iter().any(|o| o.script_pubkey.as_bytes() == change_spk));
        assert_eq!(100_000, built.fee + built.change + built.dust_to_self + built.sent_to_recipient);

        let mut psbt = built.psbt.clone();
        let n1 = sign_own_taproot_inputs(&mut psbt, &alice.output_x, &alice.tweaked_seckey).unwrap();
        assert_eq!(n1, 1, "the notebook input signs");
        let spending_coins = spending_funding_utxos(&coins);
        let n2 = sign_own_wpkh_inputs(&mut psbt, &material, net, 0, &spending_coins).unwrap();
        assert_eq!(n2, 1, "the spending-wallet input signs");

        validate_signed(&psbt, &built.txid).expect("both input kinds signed");
        let (raw, txid, _) = finalize_extract(psbt).expect("finalize mixed tx");
        assert_eq!(txid, built.txid);
        assert!(!raw.is_empty());
    }

    /// `estimate_funded_fee` must equal the REAL builder's fee for the same
    /// selection — its output-shape list is a duplicate of
    /// `assemble_mixed_note_psbt`'s, and this pin is what keeps the two from
    /// drifting (a drifted estimate makes the Pay-from sufficiency verdict
    /// lie, the exact bug class the 2026-07-18 rework fixed). ANCHORED shape
    /// (2026-07-18 dust-skip rework): notebook + spending coins together —
    /// the real builder omits dust-to-self, so the estimate must be called
    /// with `dust_to_self = false` to match.
    #[test]
    fn estimate_funded_fee_matches_real_mixed_build_anchored() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let spending_src = crate::spending::funding_source(&material, net, 0).unwrap();
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let notebook_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let recipient_spk = notes_core::address::p2tr_script_pubkey(&bob.output_x);
        let coins = vec![
            MixedCoin { source: CoinSource::Notebook, txid: "a".repeat(64), vout: 0, value: 60_000, chain: 0, index: 0 },
            MixedCoin { source: CoinSource::Spending, txid: "b".repeat(64), vout: 1, value: 40_000, chain: 0, index: 0 },
        ];
        let payloads = notes_core::envelope::encode_outputs(
            notes_core::envelope::FLAG_DIRECTED,
            None,
            b"mixed source note",
            80,
        )
        .unwrap();
        let built = assemble_mixed_note_psbt(
            &coins,
            notebook_spk.clone(),
            Some(&spending_src),
            &HashMap::new(),
            &payloads,
            Some(recipient_spk.clone()),
            330,
            &ChangeDefault::Spending,
            None,
            0,
            2.0,
            0)
        .unwrap();
        assert_eq!(built.dust_to_self, 0, "notebook input present — anchored, no dust-to-self");
        let change_spk_len = spending_src.derive(1, 0).unwrap().spk.len();
        let est = estimate_funded_fee(
            &[InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH, InputWeightPrediction::P2WPKH_MAX],
            &payloads,
            Some(recipient_spk.len()),
            change_spk_len,
            false, // anchored: no dust-to-self, matching the real build
            2.0,
        );
        assert_eq!(est, built.fee, "estimate drifted from the real builder's fee");
    }

    /// The UNANCHORED sibling of the above (2026-07-18 dust-skip rework): no
    /// notebook coin in the selection (spending + an external wallet coin)
    /// — the real builder keeps its unconditional dust-to-self, so the
    /// estimate must be called with `dust_to_self = true` to match. Exercises
    /// the WITH-CHANGE branch (plenty of value for a change output), the
    /// complement of `predict_funded_fold_matches_real_build`'s no-change
    /// case below.
    #[test]
    fn estimate_funded_fee_matches_real_mixed_build_unanchored() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let spending_src = crate::spending::funding_source(&material, net, 0).unwrap();
        let notebook_spk = notes_core::address::p2tr_script_pubkey(&Identity::from_app_seed(&[7u8; 32]).unwrap().output_x);
        // Official BIP-86 test vector xpub (mainnet account m/86'/0'/0') —
        // same one `funding::tests::taproot_multipath_derives_bip86_vectors`
        // uses; a bare xpub parses as taproot BIP-86 (`FundingSource::parse`).
        let external = crate::funding::FundingSource::parse(
            "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
            net,
        )
        .unwrap();
        let mut wallets = HashMap::new();
        wallets.insert("ext1".to_string(), external);
        let coins = vec![
            MixedCoin { source: CoinSource::Spending, txid: "b".repeat(64), vout: 1, value: 40_000, chain: 0, index: 0 },
            MixedCoin { source: CoinSource::Wallet("ext1".to_string()), txid: "c".repeat(64), vout: 0, value: 40_000, chain: 0, index: 0 },
        ];
        let payloads = notes_core::envelope::encode_outputs(0, None, b"unanchored mixed note", 80).unwrap();
        let built = assemble_mixed_note_psbt(
            &coins,
            notebook_spk,
            Some(&spending_src),
            &wallets,
            &payloads,
            None,
            0,
            &ChangeDefault::Spending,
            None,
            0,
            2.0,
            0)
        .unwrap();
        assert!(built.dust_to_self > 0, "no notebook input — unanchored, dust-to-self stays");
        assert!(built.change > 0, "plenty of value — this must exercise the WITH-CHANGE branch");
        let change_spk_len = spending_src.derive(1, 0).unwrap().spk.len();
        let est = estimate_funded_fee(
            &[InputWeightPrediction::P2WPKH_MAX, InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH],
            &payloads,
            None,
            change_spk_len,
            true, // unanchored: dust-to-self present, matching the real build
            2.0,
        );
        assert_eq!(est, built.fee, "estimate drifted from the real builder's fee");
    }

    /// The honest-fee-label pin (2026-07-18) for the notebook shape: a
    /// selection that folds must predict the SAME (nominal, folded) split
    /// notes-core's own `compose_note_exact` actually pays. Uses Sal's
    /// concrete example (330-sat coin, 1 sat/vB, a note whose single
    /// OP_RETURN chunk sizes to a 99-vB no-change tx — was 103 vB before
    /// PLAN-pnte-redesign.md shrank the envelope header by 4 bytes, no
    /// more binary `note_id`) so the numbers in the UI copy are provably
    /// real, not illustrative.
    #[test]
    fn predict_notebook_fold_matches_real_build() {
        let identity = Identity::from_app_seed(&[3u8; 32]).unwrap();
        let utxo = notes_core::tx::Utxo { txid: [0x11; 32], vout: 0, value: 330 };
        let text = "x".repeat(12);
        let rate = 1.0;
        let chunk = 100_000usize;
        let built = notes_core::bundle::compose_note_exact(
            &identity,
            std::slice::from_ref(&utxo),
            &text,
            false,
            None,
            chunk,
            rate,
            0,
            || Ok([7u8; 32]))
        .unwrap();
        assert_eq!(built.change, 0, "the 330-sat coin must force the no-change fold shape");
        assert_eq!(built.fee, 330, "the whole coin goes to the fee — no room for anything else");

        // Independent oracle: real payload lengths for the same body/flags,
        // vsize computed directly (change=true/false) rather than through
        // the predictor's Δ-shortcut, so this also proves the shortcut
        // matches calling `estimate_vsize(.., false)` outright.
        let payloads = notes_core::envelope::encode_outputs(0, None, text.as_bytes(), chunk).unwrap();
        let payload_lens: Vec<usize> = payloads.iter().map(Vec::len).collect();
        let vsize_wc = notes_core::tx::estimate_vsize(1, &payload_lens, None, true);
        let vsize_nc_direct = notes_core::tx::estimate_vsize(1, &payload_lens, None, false);
        let fee_nc_direct = (vsize_nc_direct as f64 * rate).ceil() as u64;

        let (nominal, folded) =
            predict_notebook_fold(330, 0, vsize_wc, 34, rate).expect("fold predicted");
        assert_eq!(nominal, fee_nc_direct, "Δ-shortcut must match direct no-change vsize math");
        assert_eq!(nominal, 99, "matches Sal's concrete example exactly (PLAN-pnte-redesign.md: was 103 before the 4-byte-shorter envelope header)");
        assert_eq!(folded, 231);
        assert_eq!(nominal + folded, built.fee, "predicted split must equal the real built tx's fee");
    }

    /// The honest-fee-label pin for the funded shape (spending/external/
    /// mixed compose): a spending-wallet-only selection too small to leave
    /// a P2WPKH change output must fold, and `predict_funded_fold`'s split
    /// must equal `assemble_mixed_note_psbt`'s real fee — the same drift
    /// guard `estimate_funded_fee_matches_real_mixed_build_unanchored` gives
    /// the with-change case, for the no-change one. UNANCHORED (2026-07-18
    /// dust-skip rework): no notebook coin here, so the real build keeps its
    /// unconditional dust-to-self — `predict_funded_fold` is called with
    /// `dust_to_self = true` to match.
    #[test]
    fn predict_funded_fold_matches_real_build_unanchored() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let spending_src = crate::spending::funding_source(&material, net, 0).unwrap();
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let notebook_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);

        let value = 700u64; // deliberately small — leaves no room for spending-wallet change
        let rate = 2.0;
        let coins = vec![MixedCoin {
            source: CoinSource::Spending,
            txid: "c".repeat(64),
            vout: 0,
            value,
            chain: 0,
            index: 0,
        }];
        let payloads = notes_core::envelope::encode_outputs(0, None, b"fold pin test", 80).unwrap();
        let built = assemble_mixed_note_psbt(
            &coins,
            notebook_spk,
            Some(&spending_src),
            &HashMap::new(),
            &payloads,
            None,
            0,
            &ChangeDefault::Spending,
            None,
            0,
            rate,
            0)
        .unwrap();
        assert_eq!(built.change, 0, "the 700-sat coin must force the no-change fold shape");
        assert!(built.dust_to_self > 0, "no notebook input — unanchored, dust-to-self stays");

        let weights = [InputWeightPrediction::P2WPKH_MAX];
        let (nominal, folded) = predict_funded_fold(&weights, &payloads, None, 22, true, value, DUST_LIMIT, rate)
            .expect("fold predicted");
        assert_eq!(nominal + folded, built.fee, "predicted split must equal the real builder's fee");
        assert_eq!(
            built.fee + built.dust_to_self,
            value,
            "no discretionary change: the whole coin covers dust-to-self + fee"
        );
    }

    /// The ANCHORED sibling of the above (2026-07-18 dust-skip rework): a
    /// notebook coin participates alongside a spending coin, both too small
    /// to leave a change output — the real build omits dust-to-self
    /// entirely, so `predict_funded_fold` is called with `dust_to_self =
    /// false` to match, and the WHOLE selection (not selection-minus-dust)
    /// folds into the fee.
    #[test]
    fn predict_funded_fold_matches_real_build_anchored() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let spending_src = crate::spending::funding_source(&material, net, 0).unwrap();
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let notebook_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);

        let notebook_value = 300u64;
        let spending_value = 300u64;
        let rate = 2.0;
        let coins = vec![
            MixedCoin { source: CoinSource::Notebook, txid: "d".repeat(64), vout: 0, value: notebook_value, chain: 0, index: 0 },
            MixedCoin { source: CoinSource::Spending, txid: "e".repeat(64), vout: 0, value: spending_value, chain: 0, index: 0 },
        ];
        let payloads = notes_core::envelope::encode_outputs(0, None, b"anchored fold pin test", 80).unwrap();
        let built = assemble_mixed_note_psbt(
            &coins,
            notebook_spk.clone(),
            Some(&spending_src),
            &HashMap::new(),
            &payloads,
            None,
            0,
            &ChangeDefault::Spending,
            None,
            0,
            rate,
            0)
        .unwrap();
        assert_eq!(built.dust_to_self, 0, "notebook input present — anchored, no dust-to-self");
        assert!(
            !built.psbt.unsigned_tx.output.iter().any(|o| o.script_pubkey.as_bytes() == notebook_spk),
            "no dust-to-self output when a notebook coin funds the tx"
        );
        assert_eq!(built.change, 0, "small coins must force the no-change fold shape");

        let weights = [InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH, InputWeightPrediction::P2WPKH_MAX];
        let in_value = notebook_value + spending_value;
        let (nominal, folded) = predict_funded_fold(&weights, &payloads, None, 22, false, in_value, 0, rate)
            .expect("fold predicted");
        assert_eq!(nominal + folded, built.fee, "predicted split must equal the real builder's fee");
        assert_eq!(built.fee, in_value, "anchored + no fixed output: the whole selection covers the fee");
    }

    /// The four change-default scenarios Sal's rule distinguishes.
    #[test]
    fn change_default_resolution_covers_all_scenarios() {
        // (a) spending enabled AND participating -> Spending.
        assert_eq!(resolve_change_default(true, true, None), ChangeDefault::Spending);
        // (b) spending disabled (never wins, even if flagged participating) -> Notebook.
        assert_eq!(resolve_change_default(false, true, None), ChangeDefault::Notebook);
        // (c) only-external coins, spending not participating -> that wallet.
        assert_eq!(
            resolve_change_default(true, false, Some("ab12cd34")),
            ChangeDefault::Wallet("ab12cd34".into())
        );
        // (d) notebook-only (nothing else participating) -> Notebook.
        assert_eq!(resolve_change_default(true, false, None), ChangeDefault::Notebook);
    }

    /// CHANGE 1 (funding-unification wallet-level flows, 2026-07-17): the
    /// Settings Coins card aggregates both pools once spending is enabled,
    /// but is BYTE-IDENTICAL to the pre-feature line when it isn't.
    #[test]
    fn coins_summary_line_covers_every_state() {
        // Spending off/incapable: original line, unchanged.
        assert_eq!(
            coins_summary_line(0, 0, 0, None),
            "No notebook coins yet — fund a notebook's address to add some."
        );
        assert_eq!(coins_summary_line(3, 100_660, 2, None), "3 coins · 100,660 sats across 2 notebooks");
        assert_eq!(coins_summary_line(1, 500, 1, None), "1 coin · 500 sats across 1 notebook");

        // Spending on: aggregate, per Sal's examples.
        assert_eq!(
            coins_summary_line(3, 100_660, 2, Some(SpendingSummaryState::Scanned { n: 1, sats: 49_423 })),
            "3 notebook coins · 100,660 sats — spending: 1 coin · 49,423 sats"
        );
        assert_eq!(
            coins_summary_line(0, 0, 0, Some(SpendingSummaryState::Scanned { n: 1, sats: 49_423 })),
            "No notebook coins — spending: 1 coin · 49,423 sats"
        );
        assert_eq!(
            coins_summary_line(0, 0, 0, Some(SpendingSummaryState::NotScanned)),
            "No notebook coins — spending: not scanned yet"
        );
        assert_eq!(
            coins_summary_line(2, 5_000, 1, Some(SpendingSummaryState::Scanned { n: 0, sats: 0 })),
            "2 notebook coins · 5,000 sats — spending: no coins"
        );
    }

    #[test]
    fn spans_multiple_wallets_is_false_for_a_single_source() {
        let coins = vec![
            MixedCoin { source: CoinSource::Notebook, txid: "a".repeat(64), vout: 0, value: 1000, chain: 0, index: 0 },
            MixedCoin { source: CoinSource::Notebook, txid: "b".repeat(64), vout: 0, value: 2000, chain: 0, index: 0 },
        ];
        assert!(!spans_multiple_wallets(&coins));
        let mixed = vec![
            MixedCoin { source: CoinSource::Notebook, txid: "a".repeat(64), vout: 0, value: 1000, chain: 0, index: 0 },
            MixedCoin { source: CoinSource::Wallet("w1".into()), txid: "c".repeat(64), vout: 0, value: 1000, chain: 0, index: 0 },
        ];
        assert!(spans_multiple_wallets(&mixed));
    }

    /// One notebook (one taproot coin) + one spending-wallet coin, swept
    /// into a single external output — the mixed-source wallet-sweep
    /// analog of `mixed_notebook_and_spending_psbt_signs_both_kinds` above,
    /// but through `build_wallet_sweep_mixed`/`build_sweep_tx_mixed`
    /// (raw signed tx, not a PSBT). Verification recipe mirrors notes-core's
    /// own `sweep_mixed_taproot_and_wpkh_cross_check` test one layer down
    /// (`prime-graffito/notes-core/tests/mixed_tx.rs`): re-derive both
    /// sighashes independently via rust-bitcoin and check each witness
    /// verifies under its own BIP against the actual signing key.
    #[test]
    fn wallet_sweep_mixed_one_notebook_and_spending_verifies_both_kinds() {
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::ecdsa::Signature as SecpEcdsaSignature;
        use bitcoin::secp256k1::{
            schnorr::Signature as SecpSchnorrSignature, Message, PublicKey as SecpPublicKey, Secp256k1,
            XOnlyPublicKey,
        };
        use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
        use bitcoin::{Amount, ScriptBuf, TxOut as BtcTxOut};

        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();

        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let taproot_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);
        let taproot_utxo = notes_core::tx::Utxo { txid: [31u8; 32], vout: 0, value: 60_000 };
        let notebook_sources = [NotebookSweepSource {
            output_x: alice.output_x,
            tweaked_seckey: &alice.tweaked_seckey,
            utxos: std::slice::from_ref(&taproot_utxo),
        }];

        let spending_key0 = crate::spending::derive_spending_key(&material, net, 0, 0, 0).unwrap();
        let coins = vec![crate::funding::FundingUtxo {
            txid: "b".repeat(64),
            vout: 1,
            value: 40_000,
            address: spending_key0.address.clone(),
            chain: 0,
            index: 0,
            confirmed: true,
        }];

        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let dest_spk = notes_core::address::p2tr_script_pubkey(&bob.output_x);

        let sweep = build_wallet_sweep_mixed(
            &notebook_sources,
            Some((&material, net, 0, &coins)),
            dest_spk.clone(),
            2.0,
            0)
        .unwrap();

        // Single destination output, everything minus fee — no change, no
        // recipient, no OP_RETURN.
        assert_eq!(sweep.tx.outputs.len(), 1);
        assert_eq!(sweep.tx.outputs[0].script_pubkey, dest_spk);
        assert_eq!(sweep.sent, 0);
        assert_eq!(sweep.change, 0);

        // Value conservation.
        let in_value = 60_000 + 40_000u64;
        assert_eq!(in_value, sweep.fee + sweep.tx.outputs[0].value);

        // txid/vsize agreement with rust-bitcoin.
        let raw = hex::decode(&sweep.raw_hex).unwrap();
        let btx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&raw).unwrap();
        assert_eq!(btx.compute_txid().to_string(), sweep.txid_hex);
        assert_eq!(btx.vsize(), sweep.vsize);

        // Both witness kinds verify under their own BIP.
        let wpkh_input_spk = spending_key0.script_pubkey.clone();
        let prevouts: Vec<BtcTxOut> = vec![
            BtcTxOut { value: Amount::from_sat(60_000), script_pubkey: ScriptBuf::from_bytes(taproot_spk.clone()) },
            BtcTxOut { value: Amount::from_sat(40_000), script_pubkey: ScriptBuf::from_bytes(wpkh_input_spk.clone()) },
        ];
        let secp = Secp256k1::verification_only();
        let mut cache = SighashCache::new(&btx);

        // Input 0: notebook taproot key-path (BIP340/341).
        let output_key = XOnlyPublicKey::from_slice(&alice.output_x).unwrap();
        let tap_sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        secp.verify_schnorr(
            &SecpSchnorrSignature::from_slice(&sweep.tx.witnesses[0][0]).unwrap(),
            &Message::from_digest(tap_sighash.to_byte_array()),
            &output_key,
        )
        .expect("notebook sweep input must verify under BIP340/341");

        // Input 1: spending-wallet P2WPKH (BIP143).
        let wpkh_script_spk = ScriptBuf::from_bytes(wpkh_input_spk);
        let wpkh_sighash = cache
            .p2wpkh_signature_hash(1, &wpkh_script_spk, Amount::from_sat(40_000), EcdsaSighashType::All)
            .unwrap();
        let witness1 = &sweep.tx.witnesses[1];
        let sig_bytes = &witness1[0];
        assert_eq!(*sig_bytes.last().unwrap(), 0x01, "SIGHASH_ALL byte");
        let der = &sig_bytes[..sig_bytes.len() - 1];
        let pubkey_bytes = &witness1[1];
        let secp_sig = SecpEcdsaSignature::from_der(der).unwrap();
        let secp_pubkey = SecpPublicKey::from_slice(pubkey_bytes).unwrap();
        secp.verify_ecdsa(&Message::from_digest(wpkh_sighash.to_byte_array()), &secp_sig, &secp_pubkey)
            .expect("spending-wallet sweep input must verify under BIP143");
    }

    /// Two notebooks + the spending wallet flattened into ONE mixed sweep
    /// tx — proves `build_wallet_sweep_mixed` correctly flattens several
    /// `NotebookSweepSource` entries and that each notebook's coin is
    /// signed with ITS OWN key (not a shared/wrong one): each witness
    /// verifies against its own notebook's `output_x` and explicitly does
    /// NOT verify against the other notebook's.
    #[test]
    fn wallet_sweep_mixed_multiple_notebooks_each_sign_their_own_coin() {
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{schnorr::Signature as SecpSchnorrSignature, Message, Secp256k1, XOnlyPublicKey};
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        use bitcoin::{Amount, ScriptBuf, TxOut as BtcTxOut};

        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();

        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let carol = Identity::from_app_seed(&[11u8; 32]).unwrap();
        let alice_utxo = notes_core::tx::Utxo { txid: [31u8; 32], vout: 0, value: 30_000 };
        let carol_utxo = notes_core::tx::Utxo { txid: [32u8; 32], vout: 2, value: 20_000 };
        let notebook_sources = [
            NotebookSweepSource {
                output_x: alice.output_x,
                tweaked_seckey: &alice.tweaked_seckey,
                utxos: std::slice::from_ref(&alice_utxo),
            },
            NotebookSweepSource {
                output_x: carol.output_x,
                tweaked_seckey: &carol.tweaked_seckey,
                utxos: std::slice::from_ref(&carol_utxo),
            },
        ];

        let spending_key0 = crate::spending::derive_spending_key(&material, net, 0, 0, 0).unwrap();
        let coins = vec![crate::funding::FundingUtxo {
            txid: "c".repeat(64),
            vout: 1,
            value: 50_000,
            address: spending_key0.address.clone(),
            chain: 0,
            index: 0,
            confirmed: true,
        }];

        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let dest_spk = notes_core::address::p2tr_script_pubkey(&bob.output_x);

        let sweep = build_wallet_sweep_mixed(
            &notebook_sources,
            Some((&material, net, 0, &coins)),
            dest_spk.clone(),
            2.0,
            0)
        .unwrap();

        assert_eq!(sweep.tx.outputs.len(), 1);
        assert_eq!(sweep.tx.outputs[0].script_pubkey, dest_spk);
        let in_value = 30_000 + 20_000 + 50_000u64;
        assert_eq!(in_value, sweep.fee + sweep.tx.outputs[0].value);

        let raw = hex::decode(&sweep.raw_hex).unwrap();
        let btx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&raw).unwrap();
        assert_eq!(btx.compute_txid().to_string(), sweep.txid_hex);

        let alice_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);
        let carol_spk = notes_core::address::p2tr_script_pubkey(&carol.output_x);
        let prevouts: Vec<BtcTxOut> = vec![
            BtcTxOut { value: Amount::from_sat(30_000), script_pubkey: ScriptBuf::from_bytes(alice_spk) },
            BtcTxOut { value: Amount::from_sat(20_000), script_pubkey: ScriptBuf::from_bytes(carol_spk) },
            BtcTxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(spending_key0.script_pubkey.clone()),
            },
        ];
        let secp = Secp256k1::verification_only();
        let mut cache = SighashCache::new(&btx);

        for (id, i) in [(&alice, 0usize), (&carol, 1usize)] {
            let output_key = XOnlyPublicKey::from_slice(&id.output_x).unwrap();
            let sighash = cache
                .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
                .unwrap();
            secp.verify_schnorr(
                &SecpSchnorrSignature::from_slice(&sweep.tx.witnesses[i][0]).unwrap(),
                &Message::from_digest(sighash.to_byte_array()),
                &output_key,
            )
            .unwrap_or_else(|_| panic!("notebook at input {i} must verify with its own key"));
        }

        // Cross-check: alice's signature must NOT verify against carol's
        // key — proves each notebook signs with its OWN key, not a shared
        // or swapped one.
        let carol_key = XOnlyPublicKey::from_slice(&carol.output_x).unwrap();
        let alice_sighash = cache
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        assert!(secp
            .verify_schnorr(
                &SecpSchnorrSignature::from_slice(&sweep.tx.witnesses[0][0]).unwrap(),
                &Message::from_digest(alice_sighash.to_byte_array()),
                &carol_key,
            )
            .is_err());
    }

    /// `spending: None` — the all-taproot degenerate case still routes
    /// through the mixed path cleanly (notebook-only wallet sweeps don't
    /// need a separate code path from mixed ones).
    #[test]
    fn wallet_sweep_mixed_notebook_only_with_no_spending_participant() {
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let utxo = notes_core::tx::Utxo { txid: [41u8; 32], vout: 0, value: 50_000 };
        let notebook_sources = [NotebookSweepSource {
            output_x: alice.output_x,
            tweaked_seckey: &alice.tweaked_seckey,
            utxos: std::slice::from_ref(&utxo),
        }];
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let dest_spk = notes_core::address::p2tr_script_pubkey(&bob.output_x);

        let sweep = build_wallet_sweep_mixed(&notebook_sources, None, dest_spk.clone(), 2.0, 0).unwrap();
        assert_eq!(sweep.tx.outputs.len(), 1);
        assert_eq!(sweep.tx.outputs[0].script_pubkey, dest_spk);
        assert_eq!(sweep.fee + sweep.tx.outputs[0].value, 50_000);
    }

    /// Empty combined inputs (no notebook coins, no spending participant)
    /// returns a clean "nothing to sweep" error rather than panicking or
    /// falling through to notes-core's generic `InsufficientFunds`.
    #[test]
    fn wallet_sweep_mixed_empty_inputs_errors_cleanly() {
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let dest_spk = notes_core::address::p2tr_script_pubkey(&bob.output_x);
        let err = build_wallet_sweep_mixed(&[], None, dest_spk, 2.0, 0).unwrap_err();
        match err {
            Error::Funding(msg) => assert!(msg.contains("no coins to sweep"), "unexpected message: {msg}"),
            other => panic!("expected Error::Funding, got {other:?}"),
        }
    }

    // ---- multi-all-paths: assemble_mixed_note_psbt_multi ----

    /// [`assemble_mixed_note_psbt`] with exactly one recipient must stay
    /// byte-identical (same txid, same fee/change/dust accounting) to
    /// [`assemble_mixed_note_psbt_multi`] called with the equivalent
    /// one-element recipients slice — proves the old signature really is a
    /// thin delegating wrapper, not a second implementation that could
    /// drift.
    #[test]
    fn single_recipient_multi_is_byte_identical_to_old_signature() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let spending_src = crate::spending::funding_source(&material, net, 0).unwrap();
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let notebook_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let recipient_spk = notes_core::address::p2tr_script_pubkey(&bob.output_x);
        let coins = vec![MixedCoin {
            source: CoinSource::Spending, txid: "b".repeat(64), vout: 1, value: 100_000, chain: 0, index: 0,
        }];
        let payloads = notes_core::envelope::encode_outputs(
            notes_core::envelope::FLAG_DIRECTED, None, b"single via multi", 80,
        )
        .unwrap();
        let old = assemble_mixed_note_psbt(
            &coins, notebook_spk.clone(), Some(&spending_src), &HashMap::new(), &payloads,
            Some(recipient_spk.clone()), 330, &ChangeDefault::Spending, None, 0, 2.0, 0)
        .unwrap();
        let new = assemble_mixed_note_psbt_multi(
            &coins, notebook_spk, Some(&spending_src), &HashMap::new(), &payloads,
            &[(recipient_spk, 330)], &ChangeDefault::Spending, None, 0, 2.0, 0)
        .unwrap();
        assert_eq!(old.txid, new.txid);
        assert_eq!(old.fee, new.fee);
        assert_eq!(old.change, new.change);
        assert_eq!(old.sent_to_recipient, new.sent_to_recipient);
        assert_eq!(old.dust_to_self, new.dust_to_self);
        assert_eq!(old.psbt.unsigned_tx.output.len(), new.psbt.unsigned_tx.output.len());
    }

    /// A THREE-recipient note funded by a notebook + spending coin: three
    /// recipient outputs land in EXACTLY the caller-supplied order, each
    /// carrying the uniform gift; the notebook input still anchors the tx,
    /// so dust-to-self stays skipped (2026-07-18 rule, unaffected by
    /// recipient count) — and every input still signs under both per-kind
    /// signers.
    #[test]
    fn multi_recipient_anchored_by_notebook_input_has_no_dust_to_self() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let spending_src = crate::spending::funding_source(&material, net, 0).unwrap();
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let notebook_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let carol = Identity::from_app_seed(&[11u8; 32]).unwrap();
        let dave = Identity::from_app_seed(&[13u8; 32]).unwrap();
        let (bob_spk, carol_spk, dave_spk) = (
            notes_core::address::p2tr_script_pubkey(&bob.output_x),
            notes_core::address::p2tr_script_pubkey(&carol.output_x),
            notes_core::address::p2tr_script_pubkey(&dave.output_x),
        );
        let coins = vec![
            MixedCoin { source: CoinSource::Notebook, txid: "a".repeat(64), vout: 0, value: 60_000, chain: 0, index: 0 },
            MixedCoin { source: CoinSource::Spending, txid: "b".repeat(64), vout: 1, value: 40_000, chain: 0, index: 0 },
        ];
        let payloads = notes_core::envelope::encode_outputs(
            notes_core::envelope::FLAG_DIRECTED | notes_core::envelope::FLAG_MULTI,
            Some(3),
            b"group note",
            80,
        )
        .unwrap();
        let recipients = vec![(bob_spk.clone(), 330u64), (carol_spk.clone(), 330u64), (dave_spk.clone(), 330u64)];
        let built = assemble_mixed_note_psbt_multi(
            &coins, notebook_spk.clone(), Some(&spending_src), &HashMap::new(), &payloads,
            &recipients, &ChangeDefault::Spending, None, 0, 2.0, 0)
        .unwrap();

        assert_eq!(built.dust_to_self, 0, "notebook input anchors — no dust-to-self regardless of recipient count");
        assert_eq!(built.sent_to_recipient, 990, "3 x 330 uniform gift");
        assert!(!built.psbt.unsigned_tx.output.iter().any(|o| o.script_pubkey.as_bytes() == notebook_spk));

        // Recipient outputs land in EXACTLY the caller-supplied order,
        // right after the OP_RETURNs (before change) — the FROZEN
        // wrap-order-equals-output-order rule.
        let op_returns = payloads.len();
        let outs = &built.psbt.unsigned_tx.output;
        assert_eq!(outs[op_returns].script_pubkey.as_bytes(), bob_spk.as_slice());
        assert_eq!(outs[op_returns].value.to_sat(), 330);
        assert_eq!(outs[op_returns + 1].script_pubkey.as_bytes(), carol_spk.as_slice());
        assert_eq!(outs[op_returns + 1].value.to_sat(), 330);
        assert_eq!(outs[op_returns + 2].script_pubkey.as_bytes(), dave_spk.as_slice());
        assert_eq!(outs[op_returns + 2].value.to_sat(), 330);

        // Both input kinds still sign and the tx finalizes.
        let mut psbt = built.psbt.clone();
        let n1 = sign_own_taproot_inputs(&mut psbt, &alice.output_x, &alice.tweaked_seckey).unwrap();
        assert_eq!(n1, 1);
        let spending_coins = spending_funding_utxos(&coins);
        let n2 = sign_own_wpkh_inputs(&mut psbt, &material, net, 0, &spending_coins).unwrap();
        assert_eq!(n2, 1);
        validate_signed(&psbt, &built.txid).expect("both input kinds signed");
        let (raw, txid, _) = finalize_extract(psbt).expect("finalize multi-recipient mixed tx");
        assert_eq!(txid, built.txid);
        assert!(!raw.is_empty());
    }

    /// The SAME three-recipient note, but funded ENTIRELY by the spending
    /// wallet (no notebook coin) — the dust-to-self rule flips back on
    /// (input side isn't anchored), landing AFTER the three recipient
    /// outputs and BEFORE change.
    #[test]
    fn multi_recipient_without_notebook_input_keeps_dust_to_self() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let spending_src = crate::spending::funding_source(&material, net, 0).unwrap();
        let alice = Identity::from_app_seed(&[7u8; 32]).unwrap();
        let notebook_spk = notes_core::address::p2tr_script_pubkey(&alice.output_x);
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let carol = Identity::from_app_seed(&[11u8; 32]).unwrap();
        let (bob_spk, carol_spk) = (
            notes_core::address::p2tr_script_pubkey(&bob.output_x),
            notes_core::address::p2tr_script_pubkey(&carol.output_x),
        );
        let coins = vec![MixedCoin {
            source: CoinSource::Spending, txid: "b".repeat(64), vout: 1, value: 100_000, chain: 0, index: 0,
        }];
        let payloads = notes_core::envelope::encode_outputs(
            notes_core::envelope::FLAG_DIRECTED | notes_core::envelope::FLAG_MULTI,
            Some(2),
            b"two recipients, spending only",
            80,
        )
        .unwrap();
        let recipients = vec![(bob_spk.clone(), 330u64), (carol_spk.clone(), 330u64)];
        let built = assemble_mixed_note_psbt_multi(
            &coins, notebook_spk.clone(), Some(&spending_src), &HashMap::new(), &payloads,
            &recipients, &ChangeDefault::Spending, None, 0, 2.0, 0)
        .unwrap();

        assert_eq!(built.dust_to_self, DUST_LIMIT, "no notebook input — dust-to-self stays unconditional");
        assert_eq!(built.sent_to_recipient, 660);
        let op_returns = payloads.len();
        let outs = &built.psbt.unsigned_tx.output;
        assert_eq!(outs[op_returns].script_pubkey.as_bytes(), bob_spk.as_slice());
        assert_eq!(outs[op_returns + 1].script_pubkey.as_bytes(), carol_spk.as_slice());
        assert_eq!(outs[op_returns + 2].script_pubkey.as_bytes(), notebook_spk.as_slice());
        assert_eq!(outs[op_returns + 2].value.to_sat(), DUST_LIMIT);
    }

    // ---- taproot-change unit 5: CoinSource::Change compose paths ----
    // See `../PLAN-chain-notes-app-taproot-change.md`. `realize_change`
    // derives the chain-1 (`m/86'/…/1/{index}`) owner exactly as
    // `build_sweep_confirm`'s change-idents loop already does for the
    // SWEEP path (unit 4, MONEY-VERIFIED on regtest) — these three tests
    // are that same derivation + `sign_own_taproot_inputs` proof, but for
    // the COMPOSE builder (`assemble_mixed_note_psbt_multi_ext`).

    /// (a) A change-ONLY selection: no notebook coin at all, just one
    /// chain-1 coin. Must build with NO dust-to-self (a change coin
    /// anchors as self on its own), correct P2TR input weight (proven by
    /// cross-checking the real fee against `estimate_funded_fee_multi`
    /// called with the same weight independently), and change-to-self —
    /// then sign + finalize under rust-bitcoin.
    #[test]
    fn mixed_note_change_only_no_dust_to_self() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let change_owner = realize_change(&material, net, 0, 0).unwrap();
        let change_identity = change_owner.full().unwrap();
        let change_spk = notes_core::address::p2tr_script_pubkey(&change_identity.output_x);

        // `notebook_spk` is still a required builder param (it's also the
        // ChangeDefault::Notebook change destination below) even though no
        // Notebook-sourced coin participates.
        let notebook_spk =
            notes_core::address::p2tr_script_pubkey(&Identity::from_app_seed(&[7u8; 32]).unwrap().output_x);
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let recipient_spk = notes_core::address::p2tr_script_pubkey(&bob.output_x);

        let coins = vec![MixedCoin {
            source: CoinSource::Change, txid: "a".repeat(64), vout: 0, value: 60_000, chain: 1, index: 0,
        }];
        let mut change_spks = HashMap::new();
        change_spks.insert(0u32, change_spk.clone());

        let payloads = notes_core::envelope::encode_outputs(
            notes_core::envelope::FLAG_DIRECTED, None, b"change only note", 80,
        )
        .unwrap();
        let built = assemble_mixed_note_psbt_multi_ext(
            &coins, notebook_spk, None, &HashMap::new(), &change_spks, &payloads,
            &[(recipient_spk.clone(), 330)], &ChangeDefault::Notebook, None, 0, 2.0, 0)
        .unwrap();

        assert_eq!(built.dust_to_self, 0, "a change coin anchors the tx as self — no dust-to-self");
        assert!(built.change > 0, "plenty of value — a change output is affordable");
        // The assembled prevout spk for the change input equals the
        // passed-in change spk — proves the map lookup wired the right
        // scriptPubKey in, not the notebook's or a blank one.
        assert_eq!(
            built.psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey.as_bytes(),
            change_spk.as_slice()
        );
        assert!(built
            .psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.as_bytes() == recipient_spk.as_slice() && o.value.to_sat() == 330));

        // Correct P2TR input weight: an independent fee estimate using the
        // SAME weight (`P2TR_KEY_DEFAULT_SIGHASH`) the builder used for a
        // Change coin must equal the real build's fee — the same drift
        // guard the notebook/spending cases already have.
        let est = estimate_funded_fee(
            &[InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH],
            &payloads,
            Some(recipient_spk.len()),
            34, // notebook-default change spk length
            false,
            2.0,
        );
        assert_eq!(est, built.fee, "estimate drifted from the real builder's fee for a Change coin");

        let mut psbt = built.psbt.clone();
        let n = sign_own_taproot_inputs(&mut psbt, &change_identity.output_x, &change_identity.tweaked_seckey)
            .unwrap();
        assert_eq!(n, 1, "the change-chain input signs");
        validate_signed(&psbt, &built.txid).expect("the change input signed");
        let (raw, txid, _) = finalize_extract(psbt).expect("finalize change-only tx");
        assert_eq!(txid, built.txid);
        assert!(!raw.is_empty());
    }

    /// (b) A notebook (chain-0) + change (chain-1) selection of the SAME
    /// account: two DIFFERENT owners (different leaves), each must sign
    /// ONLY its own input — proven the same way
    /// `wallet_sweep_mixed_multiple_notebooks_each_sign_their_own_coin`
    /// proves it for the sweep builder. No dust-to-self (both inputs are
    /// this identity's own coin).
    #[test]
    fn mixed_note_notebook_plus_change() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let notebook_owner = realize(&material, net, 0, 0).unwrap();
        let notebook_identity = notebook_owner.full().unwrap();
        let notebook_spk = notes_core::address::p2tr_script_pubkey(&notebook_identity.output_x);

        let change_owner = realize_change(&material, net, 0, 0).unwrap();
        let change_identity = change_owner.full().unwrap();
        let change_spk = notes_core::address::p2tr_script_pubkey(&change_identity.output_x);
        assert_ne!(notebook_spk, change_spk, "chain-0 and chain-1 leaves at the same index must differ");

        let coins = vec![
            MixedCoin { source: CoinSource::Notebook, txid: "a".repeat(64), vout: 0, value: 50_000, chain: 0, index: 0 },
            MixedCoin { source: CoinSource::Change, txid: "b".repeat(64), vout: 1, value: 40_000, chain: 1, index: 0 },
        ];
        let mut change_spks = HashMap::new();
        change_spks.insert(0u32, change_spk.clone());

        let payloads =
            notes_core::envelope::encode_outputs(0, None, b"notebook plus change, self note", 80).unwrap();
        let built = assemble_mixed_note_psbt_multi_ext(
            &coins, notebook_spk.clone(), None, &HashMap::new(), &change_spks, &payloads,
            &[], &ChangeDefault::Notebook, None, 0, 2.0, 0)
        .unwrap();

        assert_eq!(built.dust_to_self, 0, "both inputs are this identity's own coin — anchored, no dust-to-self");
        assert_eq!(built.psbt.inputs.len(), 2);
        assert_eq!(
            built.psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey.as_bytes(),
            notebook_spk.as_slice()
        );
        assert_eq!(
            built.psbt.inputs[1].witness_utxo.as_ref().unwrap().script_pubkey.as_bytes(),
            change_spk.as_slice()
        );

        let mut psbt = built.psbt.clone();
        let n1 = sign_own_taproot_inputs(&mut psbt, &notebook_identity.output_x, &notebook_identity.tweaked_seckey)
            .unwrap();
        assert_eq!(n1, 1, "the notebook input signs");
        let n2 = sign_own_taproot_inputs(&mut psbt, &change_identity.output_x, &change_identity.tweaked_seckey)
            .unwrap();
        assert_eq!(n2, 1, "the change input signs");

        // Cross-check: the notebook owner's key must NOT verify the change
        // input's signature (each owner signs strictly its own input, not
        // a shared/wrong key) — mirrors the sweep builder's own cross-check.
        use bitcoin::hashes::Hash;
        use bitcoin::secp256k1::{schnorr::Signature as SecpSchnorrSignature, Message, Secp256k1, XOnlyPublicKey};
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        let prevouts: Vec<TxOut> =
            psbt.inputs.iter().map(|i| i.witness_utxo.clone().unwrap()).collect();
        let mut cache = SighashCache::new(&psbt.unsigned_tx);
        let change_sighash =
            cache.taproot_key_spend_signature_hash(1, &Prevouts::All(&prevouts), TapSighashType::Default).unwrap();
        let notebook_key = XOnlyPublicKey::from_slice(&notebook_identity.output_x).unwrap();
        let secp = Secp256k1::verification_only();
        assert!(
            secp.verify_schnorr(
                &SecpSchnorrSignature::from_slice(psbt.inputs[1].tap_key_sig.unwrap().signature.as_ref()).unwrap(),
                &Message::from_digest(change_sighash.to_byte_array()),
                &notebook_key,
            )
            .is_err(),
            "the change input's signature must NOT verify against the notebook owner's key"
        );

        validate_signed(&psbt, &built.txid).expect("both taproot inputs signed");
        let (raw, txid, _) = finalize_extract(psbt).expect("finalize notebook+change tx");
        assert_eq!(txid, built.txid);
        assert!(!raw.is_empty());
    }

    /// (c) A change (chain-1) + spending-wallet (BIP-84) selection: two
    /// taproot/P2WPKH input kinds sign via their existing per-kind signers
    /// (mirrors `mixed_notebook_and_spending_psbt_signs_both_kinds`), but
    /// with NO notebook coin present — proving the own-note dust-to-self
    /// skip fires from the Change coin ALONE, not only a Notebook one
    /// (contrast `predict_funded_fold_matches_real_build_unanchored` above,
    /// spending-only, where dust-to-self stays).
    #[test]
    fn mixed_note_change_plus_spending() {
        let net = Network::Mainnet;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let spending_src = crate::spending::funding_source(&material, net, 0).unwrap();
        let change_owner = realize_change(&material, net, 0, 0).unwrap();
        let change_identity = change_owner.full().unwrap();
        let change_spk = notes_core::address::p2tr_script_pubkey(&change_identity.output_x);
        let notebook_spk =
            notes_core::address::p2tr_script_pubkey(&Identity::from_app_seed(&[7u8; 32]).unwrap().output_x);
        let bob = Identity::from_app_seed(&[9u8; 32]).unwrap();
        let recipient_spk = notes_core::address::p2tr_script_pubkey(&bob.output_x);

        let coins = vec![
            MixedCoin { source: CoinSource::Change, txid: "c".repeat(64), vout: 0, value: 40_000, chain: 1, index: 0 },
            MixedCoin { source: CoinSource::Spending, txid: "d".repeat(64), vout: 1, value: 40_000, chain: 0, index: 0 },
        ];
        let mut change_spks = HashMap::new();
        change_spks.insert(0u32, change_spk.clone());

        let payloads = notes_core::envelope::encode_outputs(
            notes_core::envelope::FLAG_DIRECTED, None, b"change plus spending", 80,
        )
        .unwrap();
        let built = assemble_mixed_note_psbt_multi_ext(
            &coins, notebook_spk, Some(&spending_src), &HashMap::new(), &change_spks, &payloads,
            &[(recipient_spk.clone(), 330)], &ChangeDefault::Spending, None, 0, 2.0, 0)
        .unwrap();

        assert_eq!(
            built.dust_to_self, 0,
            "a change input anchors the tx as self, even without a notebook coin — no dust-to-self"
        );
        assert_eq!(
            built.psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey.as_bytes(),
            change_spk.as_slice()
        );
        let spending_spk = spending_src.derive(0, 0).unwrap().spk;
        assert_eq!(
            built.psbt.inputs[1].witness_utxo.as_ref().unwrap().script_pubkey.as_bytes(),
            spending_spk.as_slice()
        );

        let mut psbt = built.psbt.clone();
        let n1 = sign_own_taproot_inputs(&mut psbt, &change_identity.output_x, &change_identity.tweaked_seckey)
            .unwrap();
        assert_eq!(n1, 1, "the change input signs");
        let spending_coins = spending_funding_utxos(&coins);
        let n2 = sign_own_wpkh_inputs(&mut psbt, &material, net, 0, &spending_coins).unwrap();
        assert_eq!(n2, 1, "the spending-wallet input signs");

        validate_signed(&psbt, &built.txid).expect("both input kinds signed");
        let (raw, txid, _) = finalize_extract(psbt).expect("finalize change+spending tx");
        assert_eq!(txid, built.txid);
        assert!(!raw.is_empty());
    }
}
