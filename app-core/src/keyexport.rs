//! Key-export rendering for the Settings "Reveal keys" surface — every
//! format `parse_key_material` accepts, rendered from the identity's
//! stored material so the user can back it up or move it to another
//! wallet. Adaptive to provenance: a seed/xprv yields the whole set; a
//! single WIF/hex key yields only hex + WIF; watch-only yields only the
//! public descriptor.
//!
//! Rendered with rust-bitcoin, whose standard encodings are byte-identical
//! to `notes_core::export` (the Prime device's path) by construction —
//! pinned by notes-core's `export_vectors` cross-check — so a Prime reveal
//! and this reveal of the same key agree exactly.

use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use notes_core::Network;
use zeroize::Zeroizing;

use crate::derive::{btc_network, coin_type};
use crate::identity::{parse_key_material, realize, KeyMaterial};
use crate::Error;

/// Every importable rendering of an identity. `None` = not derivable from
/// this identity's material (e.g. no mnemonic for an xprv import, no
/// private keys for watch-only).
#[derive(Debug, Default, Clone)]
pub struct ExportFormats {
    /// The BIP-39 words (seed-derived identities only). Sensitive.
    pub mnemonic: Option<Zeroizing<String>>,
    /// Account xprv `m/86'/coin'/account'` — PRIVATE, whole account.
    pub account_xprv: Option<Zeroizing<String>>,
    /// Account xpub — public, watch-only import.
    pub account_xpub: Option<String>,
    /// Key-origin `tr(...)` descriptor — public, watch-only import.
    pub descriptor: Option<String>,
    /// This notebook's leaf key as raw 32-byte hex. Sensitive.
    pub leaf_hex: Option<Zeroizing<String>>,
    /// This notebook's leaf key as a compressed WIF. Sensitive.
    pub leaf_wif: Option<Zeroizing<String>>,
    /// Master key fingerprint (BIP-32 xfp, not a secret) — identifies the
    /// seed/wallet. None for single-key or account-level-xprv imports where
    /// the master fingerprint isn't known.
    pub fingerprint: Option<String>,
}

fn hardened(i: u32) -> ChildNumber {
    ChildNumber::from_hardened_idx(i).expect("index < 2^31")
}

/// Render `material_str` (the identity's stored key string) into every
/// importable format available for the notebook at (`account`, `index`).
pub fn export_formats(
    material_str: &str,
    network: Network,
    account: u32,
    index: u32,
) -> Result<ExportFormats, Error> {
    let material = parse_key_material(material_str, network)?;
    let secp = Secp256k1::new();
    let btc = btc_network(network);
    let coin = coin_type(network);
    let mut f = ExportFormats::default();

    // Leaf single-key formats — any identity that holds a private key.
    let id = realize(&material, network, account, index)?;
    if let Some(leaf) = id.leaf_secret() {
        f.leaf_hex = Some(Zeroizing::new(hex::encode(leaf)));
        let sk = SecretKey::from_slice(leaf).map_err(|_| Error::InvalidKey)?;
        f.leaf_wif = Some(Zeroizing::new(PrivateKey::new(sk, btc).to_wif()));
    }

    // Account-level formats — a master or account xprv is needed.
    // (node, Some(master_fp)) — the fp is known only from a master/seed.
    let account_node: Option<(Xpriv, Option<String>)> = match &material {
        KeyMaterial::Mnemonic(m) => {
            let seed = Zeroizing::new(m.to_seed(""));
            let master = Xpriv::new_master(btc, seed.as_ref())
                .map_err(|e| Error::Xprv(e.to_string()))?;
            let fp = hex::encode(master.fingerprint(&secp).to_bytes());
            let node = master
                .derive_priv(&secp, &[hardened(86), hardened(coin), hardened(account)])
                .map_err(|e| Error::Xprv(e.to_string()))?;
            Some((node, Some(fp)))
        }
        KeyMaterial::Xprv(x) if x.depth == 0 => {
            let fp = hex::encode(x.fingerprint(&secp).to_bytes());
            let node = x
                .derive_priv(&secp, &[hardened(86), hardened(coin), hardened(account)])
                .map_err(|e| Error::Xprv(e.to_string()))?;
            Some((node, Some(fp)))
        }
        // Account-level xprv already: the master fingerprint is unknown, so
        // the descriptor drops the key origin.
        KeyMaterial::Xprv(x) => Some((*x, None)),
        _ => None,
    };
    if let Some((node, fp)) = account_node {
        f.fingerprint = fp.clone();
        f.account_xprv = Some(Zeroizing::new(node.to_string()));
        let xpub = Xpub::from_priv(&secp, &node);
        f.account_xpub = Some(xpub.to_string());
        f.descriptor = Some(match fp {
            Some(fp) => format!("tr([{fp}/86'/{coin}'/{account}']{xpub}/<0;1>/*)"),
            None => format!("tr({xpub}/<0;1>/*)"),
        });
    }

    // The mnemonic itself (seed-derived identities).
    if let KeyMaterial::Mnemonic(m) = &material {
        f.mnemonic = Some(Zeroizing::new(m.to_string()));
    }

    // Watch-only: the descriptor is public and is exactly what re-imports.
    if let KeyMaterial::Xpub(_) = &material {
        f.descriptor = Some(material_str.trim().to_string());
    }

    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::DerivationPath;
    use std::str::FromStr;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn mnemonic_yields_full_set_matching_rust_bitcoin() {
        let f = export_formats(MNEMONIC, Network::Mainnet, 0, 5).unwrap();
        let secp = Secp256k1::new();
        let m = bip39::Mnemonic::parse(MNEMONIC).unwrap();
        let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &m.to_seed("")).unwrap();
        let acct = master
            .derive_priv(&secp, &DerivationPath::from_str("m/86'/0'/0'").unwrap())
            .unwrap();
        let xpub = Xpub::from_priv(&secp, &acct);
        assert_eq!(f.mnemonic.as_deref().map(|s| s.as_str()), Some(MNEMONIC));
        assert_eq!(f.account_xprv.as_deref().map(|s| s.as_str()), Some(acct.to_string().as_str()));
        assert_eq!(f.account_xpub.as_deref(), Some(xpub.to_string().as_str()));
        let fp = hex::encode(master.fingerprint(&secp).to_bytes());
        assert_eq!(
            f.descriptor.as_deref(),
            Some(format!("tr([{fp}/86'/0'/0']{xpub}/<0;1>/*)").as_str())
        );
        let leaf = master
            .derive_priv(&secp, &DerivationPath::from_str("m/86'/0'/0'/0/5").unwrap())
            .unwrap();
        assert_eq!(
            f.leaf_hex.as_deref().map(|s| s.as_str()),
            Some(hex::encode(leaf.private_key.secret_bytes()).as_str())
        );
        assert_eq!(
            f.leaf_wif.as_deref().map(|s| s.as_str()),
            Some(PrivateKey::new(leaf.private_key, bitcoin::Network::Bitcoin).to_wif().as_str())
        );
    }

    #[test]
    fn wif_import_yields_only_single_key() {
        // Standard vector: privkey = 0x00…01, compressed mainnet WIF.
        let wif = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
        let f = export_formats(wif, Network::Mainnet, 0, 0).unwrap();
        assert!(f.mnemonic.is_none());
        assert!(f.account_xprv.is_none());
        assert!(f.account_xpub.is_none());
        assert!(f.descriptor.is_none());
        assert_eq!(f.leaf_wif.as_deref().map(|s| s.as_str()), Some(wif));
        assert_eq!(
            f.leaf_hex.as_deref().map(|s| s.as_str()),
            Some("0000000000000000000000000000000000000000000000000000000000000001")
        );
    }

    #[test]
    fn watch_only_yields_descriptor_no_private() {
        let xpub = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
        let f = export_formats(xpub, Network::Mainnet, 0, 0).unwrap();
        assert!(f.mnemonic.is_none());
        assert!(f.account_xprv.is_none());
        assert!(f.leaf_hex.is_none());
        assert!(f.leaf_wif.is_none());
        assert_eq!(f.descriptor.as_deref(), Some(xpub));
    }
}
