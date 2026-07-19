//! Key derivation: BIP-86 paths for hierarchical imports and the FROZEN
//! note-encryption rule shared by all four import formats.
//!
//! FROZEN FOREVER once shipped (every private note depends on them):
//! - enc key = HKDF-SHA256(ikm = leaf internal-key secret,
//!   salt = "chain-notes-app/enc/v1", info = "note-enc/v1")
//! - hierarchical path = m/86'/{coin}'/{account}'/0/{index}, coin 0
//!   mainnet / 1 otherwise; notebook `index` on the receive chain
//!   (rev 3 — index 0 IS the pre-notebooks identity, byte-identical)
//! - raw keys (WIF/hex) ARE the leaf secret directly (no hierarchy)

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use notes_core::bundle::Identity;
use notes_core::Network;
use zeroize::Zeroizing;

use crate::Error;

pub const ENC_SALT: &[u8] = b"chain-notes-app/enc/v1";
pub const ENC_INFO: &[u8] = b"note-enc/v1";

/// BIP-44 coin type for the BIP-86 path: 0' on mainnet, 1' on every test
/// network (the BIP-44 convention).
pub fn coin_type(network: Network) -> u32 {
    match network {
        Network::Mainnet => 0,
        _ => 1,
    }
}

/// rust-bitcoin network for encoding checks (WIF bytes, xprv prefixes).
/// Testnet4/signet share testnet encodings; regtest differs only in
/// bech32 HRP, which notes-core owns.
pub fn btc_network(network: Network) -> bitcoin::Network {
    match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet4 => bitcoin::Network::Testnet,
        Network::Signet => bitcoin::Network::Signet,
        Network::Regtest => bitcoin::Network::Regtest,
    }
}

// pub(crate): the spending-wallet module (funding-unification M2) reuses
// these for its own BIP-84 path off the SAME master.
pub(crate) fn hardened(i: u32) -> ChildNumber {
    ChildNumber::from_hardened_idx(i).expect("index < 2^31")
}

pub(crate) fn normal(i: u32) -> ChildNumber {
    ChildNumber::from_normal_idx(i).expect("index < 2^31")
}

/// m/86'/{coin}'/{account}'/0/{index} from a master (depth-0) xprv.
pub fn leaf_from_master(
    master: &Xpriv,
    network: Network,
    account: u32,
    index: u32,
) -> Result<[u8; 32], Error> {
    let secp = Secp256k1::new();
    let path = [
        hardened(86),
        hardened(coin_type(network)),
        hardened(account),
        normal(0),
        normal(index),
    ];
    let leaf = master
        .derive_priv(&secp, &path)
        .map_err(|e| Error::Xprv(e.to_string()))?;
    Ok(leaf.private_key.secret_bytes())
}

/// 0/{index} below an account-level (depth-3, e.g. 86'/coin'/n') xprv.
pub fn leaf_from_account(account: &Xpriv, index: u32) -> Result<[u8; 32], Error> {
    let secp = Secp256k1::new();
    let leaf = account
        .derive_priv(&secp, &[normal(0), normal(index)])
        .map_err(|e| Error::Xprv(e.to_string()))?;
    Ok(leaf.private_key.secret_bytes())
}

/// The FROZEN note-encryption key rule — identical for all import formats.
/// The rule LIVES in notes-core now (relocated for the recovery-seeds
/// feature so device bip86 notebooks share this exact code path); this
/// delegation is pinned byte-identical by `enc_key_frozen_vector` and the
/// notes-core-side vector — both implementations were also cross-checked
/// against an independent HKDF at relocation time.
pub fn enc_key_from_leaf(leaf_secret: &[u8; 32]) -> [u8; 32] {
    notes_core::keys::enc_key_from_leaf(leaf_secret)
}

/// Leaf internal-key secret → full notes-core Identity (internal/output
/// x-only keys, BIP-341 tweaked signing key, enc key). Delegates to
/// notes-core's `Identity::from_leaf_secret` — the same constructor the
/// Prime app's bip86 notebooks use, byte-identical by construction.
pub fn identity_from_leaf(leaf_secret: &[u8; 32]) -> Result<Identity, Error> {
    Identity::from_leaf_secret(leaf_secret).map_err(Error::Notes)
}

/// BIP-39 seed bytes (mnemonic + empty passphrase) → leaf secret.
pub fn leaf_from_mnemonic(
    mnemonic: &bip39::Mnemonic,
    network: Network,
    account: u32,
    index: u32,
) -> Result<[u8; 32], Error> {
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let master = Xpriv::new_master(btc_network(network), seed.as_ref())
        .map_err(|e| Error::Xprv(e.to_string()))?;
    leaf_from_master(&master, network, account, index)
}
