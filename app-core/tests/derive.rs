//! Derivation gates: BIP-86 spec vector, independent rust-bitcoin
//! cross-check of the taproot tweak, frozen enc-key vector, xprv depth
//! equivalence.

use app_core::derive::{enc_key_from_leaf, identity_from_leaf, leaf_from_account};
use app_core::identity::{parse_key_material, realize, KeyMaterial};
use app_core::notes_core::Network;
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::key::Secp256k1;
use bitcoin::XOnlyPublicKey;

const BIP86_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// BIP-86 test vector: first receive address (m/86'/0'/0'/0/0) of the
/// standard test mnemonic.
const BIP86_ADDR_0: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

#[test]
fn bip86_spec_vector_mainnet() {
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    let ident = realize(&material, Network::Mainnet, 0).unwrap();
    assert_eq!(ident.kind, "mnemonic");
    assert_eq!(ident.address, BIP86_ADDR_0);
}

/// Same leaf, address built by rust-bitcoin's own taproot machinery —
/// independent of both notes-core's tweak math and the vector string.
#[test]
fn address_cross_checks_with_rust_bitcoin() {
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    let ident = realize(&material, Network::Mainnet, 0).unwrap();

    let secp = Secp256k1::new();
    let internal = XOnlyPublicKey::from_slice(&ident.identity.internal_x).unwrap();
    let addr = bitcoin::Address::p2tr(&secp, internal, None, bitcoin::Network::Bitcoin);
    assert_eq!(ident.address, addr.to_string());
}

/// FROZEN enc-key rule vector — if this ever changes, shipped private
/// notes become unreadable. Never update this expectation.
#[test]
fn enc_key_frozen_vector() {
    let key = enc_key_from_leaf(&[0x11u8; 32]);
    assert_eq!(
        hex::encode(key),
        "205d621601e88ed1f4503cdf776a6dfa3cd812a5311d96b417e674785a482a40",
    );
}

/// Importing the depth-3 account xprv must land on the same address as
/// importing the master.
#[test]
fn account_xprv_equals_master_derivation() {
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    let from_master = realize(&material, Network::Mainnet, 0).unwrap();

    let KeyMaterial::Mnemonic(m) = &material else { panic!("parsed as mnemonic") };
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &m.to_seed("")).unwrap();
    let account = master
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(86).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
            ],
        )
        .unwrap();
    assert_eq!(account.depth, 3);

    let parsed = parse_key_material(&account.to_string(), Network::Mainnet).unwrap();
    let from_account = realize(&parsed, Network::Mainnet, 0).unwrap();
    assert_eq!(from_account.address, from_master.address);

    let leaf = leaf_from_account(&account).unwrap();
    assert_eq!(*from_master.leaf_secret, leaf);
}

/// Different BIP-86 accounts are fully separate identities: different
/// address AND different note-encryption key.
#[test]
fn accounts_are_separate_identities() {
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    let a0 = realize(&material, Network::Mainnet, 0).unwrap();
    let a1 = realize(&material, Network::Mainnet, 1).unwrap();
    assert_ne!(a0.address, a1.address);
    assert_ne!(a0.identity.enc_key, a1.identity.enc_key);
    assert_eq!(a1.account, 1);
}

/// The full Identity wiring: enc key in the realized identity follows the
/// frozen rule, and internal != output (tweak applied).
#[test]
fn identity_wiring() {
    let leaf = [0x77u8; 32];
    let ident = identity_from_leaf(&leaf).unwrap();
    assert_eq!(ident.enc_key, enc_key_from_leaf(&leaf));
    assert_ne!(ident.internal_x, ident.output_x);
}
