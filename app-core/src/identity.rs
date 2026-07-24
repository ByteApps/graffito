//! Identity create/import: one parser behind every transport (typed,
//! QR, file). Accepts BIP-39 mnemonic (12/18/24), xprv (depth 0 or 3), WIF
//! (compressed), 32-byte hex, or WATCH-ONLY material — a bare account
//! xpub (depth 3), a key-origin xpub (`[fp/86'/…]xpub…`, the hardware-
//! wallet export form), or a full `tr(...)` descriptor. Network-aware,
//! validated before anything is stored.

use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::key::PrivateKey;
use notes_core::bundle::Identity;
use notes_core::Network;
use std::str::FromStr;
use zeroize::Zeroizing;

use crate::derive::{
    btc_network, identity_from_leaf, leaf_from_account, leaf_from_account_chain, leaf_from_master,
    leaf_from_master_chain, leaf_from_mnemonic, leaf_from_mnemonic_chain,
};
use crate::funding::{FundingKind, FundingSource};
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
    /// Watch-only: an account-level (depth-3, 86'/coin'/n') xpub — bare,
    /// key-origin form, or tr() descriptor, held as a FundingSource so
    /// external-signer PSBTs carry the key origins hardware wallets need.
    /// Public notes and balance on-device; spends sign externally.
    Xpub(FundingSource),
}

impl KeyMaterial {
    pub fn kind(&self) -> &'static str {
        match self {
            KeyMaterial::Mnemonic(_) => "mnemonic",
            KeyMaterial::Xprv(_) => "xprv",
            KeyMaterial::Wif(_) => "wif",
            KeyMaterial::Hex(_) => "hex",
            KeyMaterial::Xpub(_) => "xpub",
        }
    }

    pub fn is_watch(&self) -> bool {
        matches!(self, KeyMaterial::Xpub(_))
    }

    /// Hierarchical material can derive many BIP-86 ACCOUNTS — the
    /// account-picker / Settings account-switch capability gate.
    pub fn is_hierarchical(&self) -> bool {
        match self {
            KeyMaterial::Mnemonic(_) => true,
            KeyMaterial::Xprv(x) => x.depth == 0,
            _ => false,
        }
    }

    /// Material that can derive many NOTEBOOKS (receive indexes 0/i of
    /// one account): everything except raw single keys. Watch-only
    /// qualifies when its descriptor has a wildcard (a fixed-address
    /// descriptor derives exactly one leaf).
    pub fn is_multi_notebook(&self) -> bool {
        match self {
            KeyMaterial::Mnemonic(_) | KeyMaterial::Xprv(_) => true,
            KeyMaterial::Xpub(src) => src.is_ranged(),
            KeyMaterial::Wif(_) | KeyMaterial::Hex(_) => false,
        }
    }
}

/// A stable 8-hex key for the notebook-index filename: the BIP-32 master
/// fingerprint for hierarchical material (identical across every account,
/// so all of one identity's notebooks share one index), else the account-0
/// identity's output-x prefix (those formats have exactly one notebook).
pub fn index_fp8(material: &KeyMaterial, network: Network) -> Result<String, Error> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let master = match material {
        KeyMaterial::Mnemonic(m) => {
            let seed = Zeroizing::new(m.to_seed(""));
            Some(
                Xpriv::new_master(btc_network(network), seed.as_ref())
                    .map_err(|e| Error::Xprv(e.to_string()))?,
            )
        }
        KeyMaterial::Xprv(x) if x.depth == 0 => Some(*x),
        _ => None,
    };
    match master {
        Some(x) => Ok(hex::encode(x.fingerprint(&secp).as_bytes())),
        None => Ok(hex::encode(&realize(material, network, 0, 0)?.output_x()[..4])),
    }
}

/// What the realized identity can do. Watch-only carries NO secrets — no
/// fabricated zero keys anywhere; every signing/decryption call site must
/// go through [`AppIdentity::full`] and decide what watch-only means.
/// Watch keeps its FundingSource so spend PSBTs (sweep/consolidate/bump,
/// signed by an external wallet) carry key origins.
pub enum IdentityKeys {
    Full { leaf_secret: Zeroizing<[u8; 32]>, identity: Identity },
    Watch { output_x: [u8; 32], source: FundingSource },
}

/// A realized identity: keys (full or watch-only) + address.
pub struct AppIdentity {
    pub kind: &'static str,
    /// BIP-86 account index (meaningful for mnemonic / master-xprv;
    /// 0 and ignored for account-xprv / WIF / hex / xpub).
    pub account: u32,
    /// Notebook index — the receive-chain address index `0/{index}`
    /// within the account (rev 3). 0 and ignored for WIF / hex.
    pub index: u32,
    pub keys: IdentityKeys,
    pub address: String,
}

impl AppIdentity {
    pub fn output_x(&self) -> [u8; 32] {
        match &self.keys {
            IdentityKeys::Full { identity, .. } => identity.output_x,
            IdentityKeys::Watch { output_x, .. } => *output_x,
        }
    }

    /// The descriptor behind a watch-only identity (None for full keys) —
    /// the source spend PSBTs derive inputs and key origins from.
    pub fn watch_source(&self) -> Option<&FundingSource> {
        match &self.keys {
            IdentityKeys::Watch { source, .. } => Some(source),
            IdentityKeys::Full { .. } => None,
        }
    }

    pub fn is_watch(&self) -> bool {
        matches!(self.keys, IdentityKeys::Watch { .. })
    }

    /// The leaf internal-key secret — None for watch-only.
    pub fn leaf_secret(&self) -> Option<&[u8; 32]> {
        match &self.keys {
            IdentityKeys::Full { leaf_secret, .. } => Some(leaf_secret),
            IdentityKeys::Watch { .. } => None,
        }
    }

    /// The full notes-core Identity — None for watch-only.
    pub fn full(&self) -> Option<&Identity> {
        match &self.keys {
            IdentityKeys::Full { identity, .. } => Some(identity),
            IdentityKeys::Watch { .. } => None,
        }
    }

    /// Signing/decryption paths, all UI-gated off for watch-only; reaching
    /// one with a watch identity is a bug, so panic rather than mis-sign.
    pub fn expect_full(&self) -> &Identity {
        self.full().expect("key-requiring path reached with a watch-only identity")
    }
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
    } else if lower.starts_with("xpub")
        || lower.starts_with("tpub")
        || lower.starts_with("tr(")
        || lower.starts_with('[')
    {
        parse_watch(s, network).map(KeyMaterial::Xpub)
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

/// Watch-only material → FundingSource. Accepts a bare account xpub, the
/// hardware-wallet key-origin form (`[fp/86'/…]xpub…`, with or without a
/// trailing `/<0;1>/*`), or a full `tr(...)` descriptor. The embedded
/// xpub must be account-level (depth 3): the hardened 86' path makes a
/// master xpub underivable. Key origins, when present, ride into every
/// spend PSBT so external signers recognize their inputs.
fn parse_watch(s: &str, network: Network) -> Result<FundingSource, Error> {
    // Network by embedded key prefix: xpub = mainnet, tpub = the rest.
    let has_xpub = s.contains("xpub");
    let has_tpub = s.contains("tpub");
    if has_xpub == has_tpub {
        return Err(Error::Xpub("need exactly one xpub/tpub".into()));
    }
    if has_xpub != matches!(network, Network::Mainnet) {
        return Err(Error::XpubNetwork);
    }
    let token_start = s.find(if has_xpub { "xpub" } else { "tpub" }).expect("checked above");
    let token: String =
        s[token_start..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
    let x = Xpub::from_str(&token).map_err(|e| Error::Xpub(e.to_string()))?;
    if x.depth != 3 {
        return Err(Error::XpubDepth(x.depth));
    }

    let desc = if s.starts_with('[') {
        // Key-origin xpub: wrap into a taproot descriptor, adding the
        // receive/change wildcard unless the user already included one.
        if s.contains('*') {
            format!("tr({s})")
        } else {
            format!("tr({s}/<0;1>/*)")
        }
    } else {
        s.to_string() // tr(...) descriptor, or bare xpub (FundingSource wraps)
    };
    let src = FundingSource::parse(&desc, network)?;
    if src.kind != FundingKind::Taproot {
        return Err(Error::Xpub("identity must be a taproot (tr) descriptor".into()));
    }
    Ok(src)
}

fn parse_mnemonic(s: &str) -> Result<bip39::Mnemonic, Error> {
    // 12/18/24 — the lengths BIP-85 emits (and hardware wallets import); 15/21
    // stay rejected deliberately so a dropped word fails loudly here.
    let n = s.split_whitespace().count();
    if !matches!(n, 12 | 18 | 24) {
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
        18 => 24,
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
        18 => 24,
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
/// `account` = BIP-86 account index for mnemonic / master-xprv imports;
/// `index` = the notebook's receive-chain address index within that
/// account (rev 3: each index is a notebook — its own address AND its
/// own note-encryption key, since the frozen rule derives from the
/// leaf). Both ignored for WIF / hex; `account` ignored for
/// account-xprv / xpub (the material IS the account).
pub fn realize(
    material: &KeyMaterial,
    network: Network,
    account: u32,
    index: u32,
) -> Result<AppIdentity, Error> {
    let leaf: Zeroizing<[u8; 32]> = Zeroizing::new(match material {
        KeyMaterial::Mnemonic(m) => leaf_from_mnemonic(m, network, account, index)?,
        KeyMaterial::Xprv(x) => match x.depth {
            0 => leaf_from_master(x, network, account, index)?,
            3 => leaf_from_account(x, index)?,
            d => return Err(Error::XprvDepth(d)),
        },
        KeyMaterial::Wif(w) => w.inner.secret_bytes(),
        KeyMaterial::Hex(k) => *k,
        KeyMaterial::Xpub(src) => {
            // The notebook address is the descriptor's receive leaf at
            // `index` (a fixed descriptor only has index 0).
            if index > 0 && !src.is_ranged() {
                return Err(Error::Xpub("descriptor has no wildcard — only index 0 exists".into()));
            }
            let d = src.derive(0, index)?;
            if d.spk.len() != 34 || d.spk[0] != 0x51 {
                return Err(Error::Xpub("descriptor does not derive a taproot output".into()));
            }
            let mut output_x = [0u8; 32];
            output_x.copy_from_slice(&d.spk[2..34]);
            return Ok(AppIdentity {
                kind: material.kind(),
                account: 0,
                index,
                keys: IdentityKeys::Watch { output_x, source: src.clone() },
                address: d.address,
            });
        }
    });
    let identity = identity_from_leaf(&leaf)?;
    let address = identity.address(network);
    Ok(AppIdentity {
        kind: material.kind(),
        account,
        index,
        keys: IdentityKeys::Full { leaf_secret: leaf, identity },
        address,
    })
}

/// Change-chain (`m/86'/{coin}'/{account}'/1/{index}`) counterpart to
/// [`realize`] — same account, `chain=1` instead of the notebook's frozen
/// `chain=0`. Foundation for the taproot change-chain feature
/// (`../PLAN-chain-notes-app-taproot-change.md`): derivation + address
/// only here, scanning/spending land in a later change. Reuses
/// [`identity_from_leaf`] (⇒ `notes_core::bundle::Identity::from_leaf_secret`)
/// for the BIP-341 tweak + P2TR address — the exact same code path
/// [`realize`]'s chain-0 leaves go through, never reimplemented.
///
/// WIF/hex/watch-only material has no chain concept (WIF/hex are a single
/// raw key with no hierarchy to walk; watch-only descriptors are out of
/// scope for this foundation unit) — all three error here rather than
/// fabricate a leaf.
pub fn realize_change(
    material: &KeyMaterial,
    network: Network,
    account: u32,
    index: u32,
) -> Result<AppIdentity, Error> {
    const NEEDS_HD: &str = "change chain needs a BIP-39 seed or master/account xprv identity";
    let leaf: Zeroizing<[u8; 32]> = Zeroizing::new(match material {
        KeyMaterial::Mnemonic(m) => leaf_from_mnemonic_chain(m, network, account, 1, index)?,
        KeyMaterial::Xprv(x) => match x.depth {
            0 => leaf_from_master_chain(x, network, account, 1, index)?,
            3 => leaf_from_account_chain(x, 1, index)?,
            d => return Err(Error::XprvDepth(d)),
        },
        KeyMaterial::Wif(_) | KeyMaterial::Hex(_) | KeyMaterial::Xpub(_) => {
            return Err(Error::Funding(NEEDS_HD.into()))
        }
    });
    let identity = identity_from_leaf(&leaf)?;
    let address = identity.address(network);
    Ok(AppIdentity {
        kind: material.kind(),
        account,
        index,
        keys: IdentityKeys::Full { leaf_secret: leaf, identity },
        address,
    })
}

/// Every ACTIVE (non-archived) notebook's own p2tr scriptPubKey for
/// `account`, in notebook-index order — the DISPLAY-OWNER anchor set fed
/// to notes-core's `extract_notes_multi_deduped`/
/// `extract_notes_watch_multi_deduped` (rev 6e36a23). Archived notebooks
/// are deliberately EXCLUDED: an anchor pointing at an archived notebook
/// must never suppress a note in an active notebook that also
/// contributed an input to the same tx, and a tx touching ONLY archived
/// notebooks never reaches an active store's bundle anyway. Mirrors
/// `confirm_self_spks`'s enumeration (`ix.active(account)` + `realize`)
/// in `src/lib.rs`, but collects notebook spks ONLY — never the spending
/// wallet's addresses, which must NOT be in this set (a spending-wallet
/// input earlier in a tx must never steal the anchor; see notes-core's
/// doc comment on `extract_notes_multi_deduped`). A `realize` failure for
/// one notebook (should not happen for material that already produced
/// this `NotebookIndex`) is skipped rather than propagated —
/// best-effort, matching `confirm_self_spks`.
pub fn active_notebook_spks(
    material: &KeyMaterial,
    network: Network,
    account: u32,
    ix: &crate::notebooks::NotebookIndex,
) -> Vec<Vec<u8>> {
    ix.active(account)
        .filter_map(|m| realize(material, network, account, m.index).ok())
        .map(|ident| notes_core::address::p2tr_script_pubkey(&ident.output_x()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notebooks::NotebookIndex;

    const MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// DISPLAY-OWNER anchor-set sourcing (notes-core rev 6e36a23, EDGE
    /// RULE from review): an archived notebook must be EXCLUDED from
    /// `notebook_spks` — its spk must never be able to anchor/suppress a
    /// note in a sibling active notebook — and the surviving set stays in
    /// notebook-index order.
    #[test]
    fn active_notebook_spks_excludes_archived_and_keeps_index_order() {
        let net = Network::Regtest;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let mut ix = NotebookIndex::new();
        ix.ensure(0, 0);
        ix.ensure(0, 1);
        ix.ensure(0, 2);
        ix.set_archived(0, 1, true); // notebook 1 archived — must drop out

        let spks = active_notebook_spks(&material, net, 0, &ix);

        let spk0 = notes_core::address::p2tr_script_pubkey(
            &realize(&material, net, 0, 0).unwrap().output_x(),
        );
        let spk1 = notes_core::address::p2tr_script_pubkey(
            &realize(&material, net, 0, 1).unwrap().output_x(),
        );
        let spk2 = notes_core::address::p2tr_script_pubkey(
            &realize(&material, net, 0, 2).unwrap().output_x(),
        );

        assert_eq!(spks, vec![spk0, spk2], "archived notebook 1 excluded; 0 then 2, index order");
        assert!(!spks.contains(&spk1), "the archived notebook's spk must never appear");
    }

    /// A different account's notebooks never leak into this one's set —
    /// no cross-account anchor stealing.
    #[test]
    fn active_notebook_spks_is_scoped_to_the_requested_account() {
        let net = Network::Regtest;
        let material = parse_key_material(MNEMONIC, net).unwrap();
        let mut ix = NotebookIndex::new();
        ix.ensure(0, 0);
        ix.ensure(1, 0);

        let spks = active_notebook_spks(&material, net, 0, &ix);
        let acct1_spk = notes_core::address::p2tr_script_pubkey(
            &realize(&material, net, 1, 0).unwrap().output_x(),
        );
        assert_eq!(spks.len(), 1, "only account 0's notebook");
        assert!(!spks.contains(&acct1_spk), "account 1's notebook must not appear");
    }
}
