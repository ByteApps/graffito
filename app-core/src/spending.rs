//! Spending wallet: BIP-84 branch of the SAME seed tree as the notebook's
//! BIP-86 branch (PLAN-chain-notes-funding-unification.md, "Derivation (the
//! core spec)"). `m/84'/{coin}'/{account}'/{chain}/{index}` — chain 0 =
//! receive, 1 = change, P2WPKH (bc1q…), unlike the notebook's P2TR. Only HD
//! identities can derive it: a BIP-39 mnemonic or a master-depth (0) xprv
//! (the same set [`crate::identity::KeyMaterial::is_hierarchical`] already
//! gates the BIP-86 account picker on) — the sibling branch hangs off the
//! SAME master the notebook leaf does, so an account-depth xprv (depth 3),
//! WIF, hex, or watch-only import — none of which ever held the master —
//! has no way to reach it.
//!
//! [`funding_source`] wraps the derived account xpub as a `wpkh(...)`
//! descriptor (with its key origin) and hands it to the EXISTING
//! `FundingSource` machinery (funding.rs) — so the spending wallet's coin
//! scan (`ChainClient::scan_funding`) and its funded-note PSBT assembly
//! (`psbt_build::assemble_funded_note_psbt` / `build_funding_psbt`) are the
//! exact same code paths the external watch-only funding wallets already
//! use; nothing is forked. Only the SIGNER differs: this module also
//! derives the raw leaf key so [`crate::psbt_build::sign_own_wpkh_inputs`]
//! can sign in-app — the internal kind never leaves the app for a PSBT
//! round-trip.

use bitcoin::bip32::{Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use notes_core::address::{p2wpkh_address, p2wpkh_script_pubkey};
use notes_core::keys::hash160;
use notes_core::Network;
use zeroize::Zeroizing;

use crate::derive::{btc_network, coin_type, hardened, normal};
use crate::funding::FundingSource;
use crate::identity::KeyMaterial;
use crate::Error;

const NEEDS_HD: &str = "spending wallet needs a BIP-39 seed or master-xprv identity";

/// Whether `material` can derive a spending wallet — identical to
/// [`KeyMaterial::is_hierarchical`] (the m/84' branch hangs off the same
/// master m/86' does), spelled out here so call sites read like a
/// capability check on THIS feature rather than borrowing the account-
/// picker's name.
pub fn can_derive_spending(material: &KeyMaterial) -> bool {
    material.is_hierarchical()
}

fn master_xpriv(material: &KeyMaterial, network: Network) -> Result<Xpriv, Error> {
    match material {
        KeyMaterial::Mnemonic(m) => {
            let seed = Zeroizing::new(m.to_seed(""));
            Xpriv::new_master(btc_network(network), seed.as_ref())
                .map_err(|e| Error::Xprv(e.to_string()))
        }
        KeyMaterial::Xprv(x) if x.depth == 0 => Ok(*x),
        _ => Err(Error::Funding(NEEDS_HD.into())),
    }
}

/// The spending wallet's account-level xpub (`m/84'/{coin}'/{account}'`)
/// plus the master fingerprint — the two pieces a
/// `wpkh([fp/84'/coin'/account']xpub/<0;1>/*)` descriptor needs.
pub fn account_xpub(
    material: &KeyMaterial,
    network: Network,
    account: u32,
) -> Result<(Xpub, Fingerprint), Error> {
    let secp = Secp256k1::new();
    let master = master_xpriv(material, network)?;
    let fp = master.fingerprint(&secp);
    let path = [hardened(84), hardened(coin_type(network)), hardened(account)];
    let acct = master.derive_priv(&secp, &path).map_err(|e| Error::Xprv(e.to_string()))?;
    Ok((Xpub::from_priv(&secp, &acct), fp))
}

/// The `wpkh([fp/84'/coin'/account']xpub/<0;1>/*)` descriptor STRING for
/// the identity's spending wallet — e.g. for
/// [`crate::chain::CoreRpcTransport::watch_descriptors`] (U4), which needs
/// the raw string, not just a parsed [`FundingSource`]. [`funding_source`]
/// delegates here so the two can never drift apart.
pub fn funding_descriptor(material: &KeyMaterial, network: Network, account: u32) -> Result<String, Error> {
    let (xpub, fp) = account_xpub(material, network, account)?;
    Ok(format!("wpkh([{fp}/84'/{}'/{account}']{xpub}/<0;1>/*)", coin_type(network)))
}

/// The identity's spending wallet as a `FundingSource` — a `wpkh(...)`
/// descriptor over the derived account xpub, so every existing
/// FundingSource-based code path (coin scan, funded-note PSBT assembly)
/// reuses byte-for-byte instead of being forked for the internal kind.
pub fn funding_source(
    material: &KeyMaterial,
    network: Network,
    account: u32,
) -> Result<FundingSource, Error> {
    let desc = funding_descriptor(material, network, account)?;
    FundingSource::parse(&desc, network)
}

/// One derived spending leaf: the raw secp keypair — held only in memory,
/// recomputed on demand like every other derived key in this app, NEVER
/// persisted (key storage spec) — its compressed pubkey, scriptPubKey, and
/// bech32 (witness v0) address.
pub struct SpendingKey {
    pub seckey: Zeroizing<[u8; 32]>,
    pub pubkey: [u8; 33],
    pub script_pubkey: Vec<u8>,
    pub address: String,
}

/// `m/84'/{coin}'/{account}'/{chain}/{index}` — `chain` 0 = receive, 1 =
/// change. The leaf-level counterpart to [`funding_source`]: same tree,
/// raw key instead of a watch-only descriptor — what the in-app signer
/// needs.
pub fn derive_spending_key(
    material: &KeyMaterial,
    network: Network,
    account: u32,
    chain: u32,
    index: u32,
) -> Result<SpendingKey, Error> {
    let secp = Secp256k1::new();
    let master = master_xpriv(material, network)?;
    let path = [
        hardened(84),
        hardened(coin_type(network)),
        hardened(account),
        normal(chain),
        normal(index),
    ];
    let leaf = master.derive_priv(&secp, &path).map_err(|e| Error::Xprv(e.to_string()))?;
    let seckey = Zeroizing::new(leaf.private_key.secret_bytes());
    let sk = SecretKey::from_slice(seckey.as_ref()).map_err(|_| Error::InvalidKey)?;
    let pubkey = PublicKey::from_secret_key(&secp, &sk).serialize();
    let pubkey_hash = hash160(&pubkey);
    Ok(SpendingKey {
        seckey,
        pubkey,
        script_pubkey: p2wpkh_script_pubkey(&pubkey_hash),
        address: p2wpkh_address(network, &pubkey_hash),
    })
}

/// Derive both spending chains' scriptPubKeys for indexes `0..upto` —
/// chain 0 (receive) then chain 1 (change), in that order. Pure secp math,
/// NO network calls. This is the classification-window widening lever
/// (`PLAN-chain-notes-app-spending-self-notes.md`, Unit A / RC1): the
/// caller unions the result into the self-spk SET handed to
/// `Store::apply_bundle`/`apply_bundle_watch`, so a note funded from a
/// spending address within the window classifies OWN even when the
/// recorded-`used` snapshot (`SpendingSection::self_spks`) is empty or
/// stale (fresh install, disk-loaded non-active store, a scan that hasn't
/// stamped the active store yet).
///
/// Returns an empty `Vec` (never `Err`) for material that can't derive a
/// spending wallet at all — mirrors [`can_derive_spending`], so a watch-only
/// or single-key identity gets an empty window rather than an error. Once
/// past that gate, `upto` is caller-controlled public derivation — a
/// failure past `can_derive_spending` would indicate a genuine bug, not an
/// expected "no spending wallet" case, so it propagates as `Err`.
pub fn window_spks(
    material: &KeyMaterial,
    network: Network,
    account: u32,
    upto: u32,
) -> Result<Vec<Vec<u8>>, Error> {
    if !can_derive_spending(material) {
        return Ok(Vec::new());
    }
    let src = funding_source(material, network, account)?;
    let mut out = Vec::with_capacity(upto as usize * 2);
    for chain in [0usize, 1usize] {
        for index in 0..upto {
            out.push(src.derive(chain, index)?.spk);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::parse_key_material;

    // Official BIP-84 test vector (mainnet) — the same "abandon…about"
    // mnemonic the BIP-32/BIP-84 spec vectors use for m/84'/0'/0'.
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                             abandon abandon abandon about";

    fn material() -> KeyMaterial {
        parse_key_material(MNEMONIC, Network::Mainnet).unwrap()
    }

    #[test]
    fn bip84_standard_vector() {
        let m = material();
        assert!(can_derive_spending(&m));
        // m/84'/0'/0'/0/0 — the published BIP-84 test vector receive address.
        let k = derive_spending_key(&m, Network::Mainnet, 0, 0, 0).unwrap();
        assert_eq!(k.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        // m/84'/0'/0'/1/0 — the published change address.
        let c = derive_spending_key(&m, Network::Mainnet, 0, 1, 0).unwrap();
        assert_eq!(c.address, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
    }

    #[test]
    fn funding_source_descriptor_matches_leaf_derivation() {
        // The wpkh(...) descriptor wrapping (miniscript) and the raw leaf
        // derivation (bitcoin::bip32) above must agree byte-for-byte — same
        // tree, two independent code paths, cross-checking each other.
        let m = material();
        let src = funding_source(&m, Network::Mainnet, 0).unwrap();
        assert_eq!(src.derive(0, 0).unwrap().address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(src.derive(1, 0).unwrap().address, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
        let k = derive_spending_key(&m, Network::Mainnet, 0, 0, 3).unwrap();
        assert_eq!(src.derive(0, 3).unwrap().address, k.address);
        assert_eq!(src.derive(0, 3).unwrap().spk, k.script_pubkey);
    }

    #[test]
    fn non_hierarchical_material_is_rejected() {
        // WIF/hex/account-depth xprv have no sibling m/84' branch off a
        // master they never held — the setting is hidden for them (PLAN
        // decision 7).
        let hex_key = "01".repeat(32);
        let m = parse_key_material(&hex_key, Network::Mainnet).unwrap();
        assert!(!can_derive_spending(&m));
        assert!(funding_source(&m, Network::Mainnet, 0).is_err());
        assert!(derive_spending_key(&m, Network::Mainnet, 0, 0, 0).is_err());
    }

    #[test]
    fn different_accounts_derive_different_wallets() {
        let m = material();
        let a0 = derive_spending_key(&m, Network::Mainnet, 0, 0, 0).unwrap();
        let a1 = derive_spending_key(&m, Network::Mainnet, 1, 0, 0).unwrap();
        assert_ne!(a0.address, a1.address);
    }

    #[test]
    fn window_spks_covers_both_chains_and_matches_leaf_derivation() {
        let m = material();
        let spks = window_spks(&m, Network::Mainnet, 0, 4).unwrap();
        assert_eq!(spks.len(), 8, "4 receive + 4 change");
        for i in 0..4u32 {
            let recv = derive_spending_key(&m, Network::Mainnet, 0, 0, i).unwrap();
            assert!(spks.contains(&recv.script_pubkey), "receive index {i} must be in the window");
            let chg = derive_spending_key(&m, Network::Mainnet, 0, 1, i).unwrap();
            assert!(spks.contains(&chg.script_pubkey), "change index {i} must be in the window");
        }
    }

    #[test]
    fn window_spks_is_empty_for_non_hierarchical_material_never_err() {
        let hex_key = "01".repeat(32);
        let m = parse_key_material(&hex_key, Network::Mainnet).unwrap();
        let spks = window_spks(&m, Network::Mainnet, 0, 100).unwrap();
        assert!(spks.is_empty());
    }
}
