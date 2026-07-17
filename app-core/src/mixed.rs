//! Mixed-source funding for a single note tx (funding-unification UI
//! rework, 2026-07-16): coins nest per wallet on the Pay-from screen and are
//! individually selectable ACROSS notebook / spending-wallet / external
//! watch-only sources — a single note may spend all three kinds of coin in
//! one PSBT. This module is ADDITIVE glue over the existing single-source
//! machinery: [`crate::psbt_build::assemble_funded_note_psbt`]'s output
//! shape (OP_RETURNs, optional recipient, dust-to-self ALWAYS, then change)
//! is reused verbatim — only input assembly generalizes to per-coin
//! sources. Signing still dispatches to the existing per-kind signers
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
/// notebook + spending + several external wallets, in ONE transaction.
/// Output shape mirrors
/// [`crate::psbt_build::assemble_funded_note_psbt`] byte-for-byte (OP_RETURNs,
/// optional recipient, dust-to-self ALWAYS, then change) — this is additive
/// generalization of that function's INPUT side only.
///
/// `notebook_spk` is the identity's own P2TR scriptPubkey (Notebook coins'
/// prevout and the dust-to-self output — one notebook, one fixed address).
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
    if let Some(spk) = &recipient_spk {
        outputs.push(TxOut {
            value: Amount::from_sat(recipient_amount),
            script_pubkey: ScriptBuf::from_bytes(spk.clone()),
        });
        sent_to_recipient = recipient_amount;
    }
    outputs.push(TxOut { value: Amount::from_sat(DUST_LIMIT), script_pubkey: ScriptBuf::from_bytes(notebook_spk.clone()) });
    let dust_to_self = DUST_LIMIT;

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

    let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: inputs, output: outputs };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::parse_key_material;
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
    /// the funded-sweep and watch-spend tests use).
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
            notes_core::envelope::encode_chunks([1, 2, 3, 4], notes_core::envelope::FLAG_DIRECTED, b"mixed source note", 80)
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
        )
        .unwrap();

        let tx = &built.psbt.unsigned_tx;
        assert!(tx.output.iter().any(|o| o.script_pubkey.as_bytes() == notebook_spk && o.value.to_sat() == 330));
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
}
