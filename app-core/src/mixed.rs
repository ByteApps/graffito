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

    notes_core::tx::build_sweep_tx_mixed(&inputs, dest_spk, fee_rate, notes_core::keys::generate_aux_rand)
        .map_err(Error::Notes)
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

    /// One notebook (one taproot coin) + one spending-wallet coin, swept
    /// into a single external output — the mixed-source wallet-sweep
    /// analog of `mixed_notebook_and_spending_psbt_signs_both_kinds` above,
    /// but through `build_wallet_sweep_mixed`/`build_sweep_tx_mixed`
    /// (raw signed tx, not a PSBT). Verification recipe mirrors notes-core's
    /// own `sweep_mixed_taproot_and_wpkh_cross_check` test one layer down
    /// (`prime-chain-notes/notes-core/tests/mixed_tx.rs`): re-derive both
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
        )
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
        )
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

        let sweep = build_wallet_sweep_mixed(&notebook_sources, None, dest_spk.clone(), 2.0).unwrap();
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
        let err = build_wallet_sweep_mixed(&[], None, dest_spk, 2.0).unwrap_err();
        match err {
            Error::Funding(msg) => assert!(msg.contains("no coins to sweep"), "unexpected message: {msg}"),
            other => panic!("expected Error::Funding, got {other:?}"),
        }
    }
}
