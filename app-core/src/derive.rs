//! Key derivation: BIP-86 paths for hierarchical imports and the FROZEN
//! note-encryption rule shared by all four import formats.
//!
//! FROZEN FOREVER once shipped (every private note depends on them):
//! - enc key = HKDF-SHA256(ikm = leaf internal-key secret,
//!   salt = "chain-notes-app/enc/v1", info = "note-enc/v1")
//! - hierarchical path = m/86'/{coin}'/0'/0/0, coin 0 mainnet / 1 otherwise
//! - raw keys (WIF/hex) ARE the leaf secret directly (no hierarchy)

use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;
use hkdf::Hkdf;
use notes_core::bundle::Identity;
use notes_core::keys::xonly_pubkey;
use notes_core::taproot::{taproot_tweak_pubkey, taproot_tweak_seckey};
use notes_core::Network;
use sha2::Sha256;
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

fn hardened(i: u32) -> ChildNumber {
    ChildNumber::from_hardened_idx(i).expect("index < 2^31")
}

fn normal(i: u32) -> ChildNumber {
    ChildNumber::from_normal_idx(i).expect("index < 2^31")
}

/// m/86'/{coin}'/{account}'/0/0 from a master (depth-0) xprv.
pub fn leaf_from_master(master: &Xpriv, network: Network, account: u32) -> Result<[u8; 32], Error> {
    let secp = Secp256k1::new();
    let path = [
        hardened(86),
        hardened(coin_type(network)),
        hardened(account),
        normal(0),
        normal(0),
    ];
    let leaf = master
        .derive_priv(&secp, &path)
        .map_err(|e| Error::Xprv(e.to_string()))?;
    Ok(leaf.private_key.secret_bytes())
}

/// Watch-only: 0/0 below an account-level (depth-3, 86'/coin'/n') xpub →
/// tweaked output x-only key (the notes-address key). Public derivation
/// only — no leaf secret exists on this device, so no enc key either.
pub fn watch_output_from_account_xpub(account: &Xpub) -> Result<[u8; 32], Error> {
    let secp = Secp256k1::verification_only();
    let leaf = account
        .derive_pub(&secp, &[normal(0), normal(0)])
        .map_err(|e| Error::Xpub(e.to_string()))?;
    let internal_x = leaf.public_key.x_only_public_key().0.serialize();
    let (output_x, _) = taproot_tweak_pubkey(&internal_x, None)?;
    Ok(output_x)
}

/// 0/0 below an account-level (depth-3, e.g. 86'/coin'/n') xprv.
pub fn leaf_from_account(account: &Xpriv) -> Result<[u8; 32], Error> {
    let secp = Secp256k1::new();
    let leaf = account
        .derive_priv(&secp, &[normal(0), normal(0)])
        .map_err(|e| Error::Xprv(e.to_string()))?;
    Ok(leaf.private_key.secret_bytes())
}

/// The FROZEN note-encryption key rule — identical for all import formats.
pub fn enc_key_from_leaf(leaf_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(ENC_SALT), leaf_secret);
    let mut out = [0u8; 32];
    hk.expand(ENC_INFO, &mut out).expect("32 bytes is a valid HKDF length");
    out
}

/// Leaf internal-key secret → full notes-core Identity (internal/output
/// x-only keys, BIP-341 tweaked signing key, enc key).
pub fn identity_from_leaf(leaf_secret: &[u8; 32]) -> Result<Identity, Error> {
    let (internal_x, _) = xonly_pubkey(leaf_secret)?;
    let (output_x, _) = taproot_tweak_pubkey(&internal_x, None)?;
    let tweaked_seckey = taproot_tweak_seckey(leaf_secret, None)?;
    Ok(Identity {
        internal_x,
        output_x,
        tweaked_seckey,
        enc_key: enc_key_from_leaf(leaf_secret),
    })
}

/// BIP-39 seed bytes (mnemonic + empty passphrase) → leaf secret.
pub fn leaf_from_mnemonic(
    mnemonic: &bip39::Mnemonic,
    network: Network,
    account: u32,
) -> Result<[u8; 32], Error> {
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let master = Xpriv::new_master(btc_network(network), seed.as_ref())
        .map_err(|e| Error::Xprv(e.to_string()))?;
    leaf_from_master(&master, network, account)
}
