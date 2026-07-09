//! Identity create/import: one parser behind every transport (typed,
//! QR, file). Accepts BIP-39 mnemonic (12/24), xprv (depth 0 or 3), WIF
//! (compressed), or 32-byte hex — network-aware, validated before
//! anything is stored.

use bitcoin::bip32::Xpriv;
use bitcoin::key::PrivateKey;
use notes_core::bundle::Identity;
use notes_core::Network;
use std::str::FromStr;
use zeroize::Zeroizing;

use crate::derive::{
    btc_network, identity_from_leaf, leaf_from_account, leaf_from_master, leaf_from_mnemonic,
};
use crate::Error;

/// Parsed, validated key material. The original user string should be
/// kept (Zeroizing) by the caller for the SecretStore — reveal shows
/// exactly what the user once had.
#[derive(Debug, Clone)]
pub enum KeyMaterial {
    Mnemonic(bip39::Mnemonic),
    Xprv(Xpriv),
    Wif(PrivateKey),
    Hex([u8; 32]),
}

impl KeyMaterial {
    pub fn kind(&self) -> &'static str {
        match self {
            KeyMaterial::Mnemonic(_) => "mnemonic",
            KeyMaterial::Xprv(_) => "xprv",
            KeyMaterial::Wif(_) => "wif",
            KeyMaterial::Hex(_) => "hex",
        }
    }
}

/// A realized identity: leaf secret + notes-core Identity + address.
pub struct AppIdentity {
    pub kind: &'static str,
    /// BIP-86 account index (meaningful for mnemonic / master-xprv;
    /// 0 and ignored for account-xprv / WIF / hex).
    pub account: u32,
    pub leaf_secret: Zeroizing<[u8; 32]>,
    pub identity: Identity,
    pub address: String,
}

/// One parser for all transports. Dispatch: whitespace ⇒ mnemonic;
/// xprv/tprv prefix ⇒ BIP-32; 64 hex chars ⇒ raw key; else try WIF.
pub fn parse_key_material(input: &str, network: Network) -> Result<KeyMaterial, Error> {
    let s = input.trim();
    if s.is_empty() {
        return Err(Error::UnrecognizedFormat);
    }

    if s.split_whitespace().nth(1).is_some() {
        return parse_mnemonic(s).map(KeyMaterial::Mnemonic);
    }

    let lower = s.to_ascii_lowercase();
    if lower.starts_with("xprv") || lower.starts_with("tprv") {
        let want_main = matches!(network, Network::Mainnet);
        if lower.starts_with("xprv") != want_main {
            return Err(Error::XprvNetwork);
        }
        let x = Xpriv::from_str(s).map_err(|e| Error::Xprv(e.to_string()))?;
        match x.depth {
            0 | 3 => Ok(KeyMaterial::Xprv(x)),
            d => Err(Error::XprvDepth(d)),
        }
    } else if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut key = [0u8; 32];
        hex::decode_to_slice(&lower, &mut key).map_err(|_| Error::HexLength(0))?;
        validate_scalar(&key)?;
        Ok(KeyMaterial::Hex(key))
    } else if let Ok(wif) = PrivateKey::from_wif(s) {
        if wif.network != btc_network(network).into() {
            return Err(Error::WifNetwork);
        }
        if !wif.compressed {
            return Err(Error::WifUncompressed);
        }
        Ok(KeyMaterial::Wif(wif))
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) {
        Err(Error::HexLength(s.len() / 2))
    } else {
        Err(Error::UnrecognizedFormat)
    }
}

fn parse_mnemonic(s: &str) -> Result<bip39::Mnemonic, Error> {
    let n = s.split_whitespace().count();
    if !matches!(n, 12 | 24) {
        return Err(Error::MnemonicWordCount(n));
    }
    let normalized = s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalized)
        .map_err(|e| Error::Mnemonic(e.to_string()))
}

fn validate_scalar(key: &[u8; 32]) -> Result<(), Error> {
    bitcoin::secp256k1::SecretKey::from_slice(key)
        .map(|_| ())
        .map_err(|_| Error::InvalidKey)
}

/// Create a brand-new mnemonic from OS randomness (the no-Prime door).
pub fn generate_mnemonic(word_count: usize) -> Result<bip39::Mnemonic, Error> {
    let entropy_len = match word_count {
        12 => 16,
        24 => 32,
        n => return Err(Error::MnemonicWordCount(n)),
    };
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut entropy[..entropy_len]).map_err(|_| Error::Entropy)?;
    bip39::Mnemonic::from_entropy_in(bip39::Language::English, &entropy[..entropy_len])
        .map_err(|e| Error::Mnemonic(e.to_string()))
}

/// Like [`generate_mnemonic`], but folds optional user-provided `salt` (dice
/// rolls, extra words…) into the entropy: `entropy = SHA256(csprng ‖ salt)`.
/// Hashing the FULL device-CSPRNG output with the salt means the salt can only
/// ADD randomness — it can never reduce the entropy below what the OS CSPRNG
/// already provides (belt-and-suspenders against a compromised RNG). Empty salt
/// falls back to the plain CSPRNG path.
pub fn generate_mnemonic_with_salt(word_count: usize, salt: &str) -> Result<bip39::Mnemonic, Error> {
    let entropy_len = match word_count {
        12 => 16,
        24 => 32,
        n => return Err(Error::MnemonicWordCount(n)),
    };
    if salt.trim().is_empty() {
        return generate_mnemonic(word_count);
    }
    use sha2::{Digest, Sha256};
    let mut csprng = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut csprng[..]).map_err(|_| Error::Entropy)?;
    let mut hasher = Sha256::new();
    hasher.update(&csprng[..]);
    hasher.update(salt.as_bytes());
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&hasher.finalize());
    bip39::Mnemonic::from_entropy_in(bip39::Language::English, &entropy[..entropy_len])
        .map_err(|e| Error::Mnemonic(e.to_string()))
}

/// Material → leaf secret → Identity + address on `network`.
/// `account` = BIP-86 account index for mnemonic / master-xprv imports
/// (each account is a fully separate identity: its own address AND its
/// own note-encryption key, since the frozen rule derives from the
/// leaf). Ignored for account-xprv / WIF / hex.
pub fn realize(
    material: &KeyMaterial,
    network: Network,
    account: u32,
) -> Result<AppIdentity, Error> {
    let leaf: Zeroizing<[u8; 32]> = Zeroizing::new(match material {
        KeyMaterial::Mnemonic(m) => leaf_from_mnemonic(m, network, account)?,
        KeyMaterial::Xprv(x) => match x.depth {
            0 => leaf_from_master(x, network, account)?,
            3 => leaf_from_account(x)?,
            d => return Err(Error::XprvDepth(d)),
        },
        KeyMaterial::Wif(w) => w.inner.secret_bytes(),
        KeyMaterial::Hex(k) => *k,
    });
    let identity = identity_from_leaf(&leaf)?;
    let address = identity.address(network);
    Ok(AppIdentity { kind: material.kind(), account, leaf_secret: leaf, identity, address })
}
