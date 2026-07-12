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
    let ident = realize(&material, Network::Mainnet, 0, 0).unwrap();
    assert_eq!(ident.kind, "mnemonic");
    assert_eq!(ident.address, BIP86_ADDR_0);
}

/// Same leaf, address built by rust-bitcoin's own taproot machinery —
/// independent of both notes-core's tweak math and the vector string.
#[test]
fn address_cross_checks_with_rust_bitcoin() {
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    let ident = realize(&material, Network::Mainnet, 0, 0).unwrap();

    let secp = Secp256k1::new();
    let internal = XOnlyPublicKey::from_slice(&ident.expect_full().internal_x).unwrap();
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
    let from_master = realize(&material, Network::Mainnet, 0, 0).unwrap();

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
    let from_account = realize(&parsed, Network::Mainnet, 0, 0).unwrap();
    assert_eq!(from_account.address, from_master.address);

    let leaf = leaf_from_account(&account, 0).unwrap();
    assert_eq!(from_master.leaf_secret().unwrap(), &leaf);
}

/// Different BIP-86 accounts are fully separate identities: different
/// address AND different note-encryption key.
#[test]
fn accounts_are_separate_identities() {
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    let a0 = realize(&material, Network::Mainnet, 0, 0).unwrap();
    let a1 = realize(&material, Network::Mainnet, 1, 0).unwrap();
    assert_ne!(a0.address, a1.address);
    assert_ne!(a0.expect_full().enc_key, a1.expect_full().enc_key);
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

/// Watch-only xpub import: same address/output key as the full import of
/// the same account, no secrets anywhere, unusable depths and wrong
/// networks rejected.
#[test]
fn watch_xpub_import_matches_full_identity() {
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    let full = realize(&material, Network::Mainnet, 0, 0).unwrap();

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
    let xpub = bitcoin::bip32::Xpub::from_priv(&secp, &account);

    let parsed = parse_key_material(&xpub.to_string(), Network::Mainnet).unwrap();
    assert!(parsed.is_watch());
    let watch = realize(&parsed, Network::Mainnet, 0, 0).unwrap();
    assert_eq!(watch.kind, "xpub");
    assert!(watch.is_watch());
    assert_eq!(watch.address, BIP86_ADDR_0, "xpub lands on the BIP-86 spec address");
    assert_eq!(watch.output_x(), full.output_x());
    assert!(watch.full().is_none());
    assert!(watch.leaf_secret().is_none());

    // The hardware-wallet export forms land on the same identity: key-origin
    // xpub (hardware-wallet style) and a full tr() descriptor.
    let fp = master.fingerprint(&secp);
    for form in [
        format!("[{fp}/86'/0'/0']{xpub}"),
        format!("[{fp}/86h/0h/0h]{xpub}/<0;1>/*"),
        format!("tr([{fp}/86'/0'/0']{xpub}/<0;1>/*)"),
        format!("tr({xpub}/<0;1>/*)"),
    ] {
        let m = parse_key_material(&form, Network::Mainnet).unwrap_or_else(|e| panic!("{form}: {e}"));
        assert!(m.is_watch());
        let w = realize(&m, Network::Mainnet, 0, 0).unwrap();
        assert_eq!(w.address, BIP86_ADDR_0, "form {form} must land on the BIP-86 address");
        assert_eq!(w.output_x(), full.output_x());
        assert!(w.watch_source().is_some());
    }

    // Master (depth-0) xpub: the hardened account path makes it useless.
    let master_pub = bitcoin::bip32::Xpub::from_priv(&secp, &master);
    assert!(matches!(
        parse_key_material(&master_pub.to_string(), Network::Mainnet),
        Err(app_core::Error::XpubDepth(0))
    ));

    // Network mismatch both ways.
    assert!(matches!(
        parse_key_material(&xpub.to_string(), Network::Testnet4),
        Err(app_core::Error::XpubNetwork)
    ));
}

/// Recovery-seeds interop (PLAN-chain-notes-seed-rotation.md): a Prime
/// device seed's 24 words, imported through OUR normal mnemonic path,
/// must land on the byte-identical leaf, enc key, and address that the
/// device derives via notes-core's seeds pipeline. This is the whole
/// point of the feature — pinned here so neither side can drift.
#[test]
fn prime_recovery_seed_words_import_identically() {
    use app_core::derive::leaf_from_mnemonic;
    use app_core::notes_core::bundle::Identity as CoreIdentity;
    use app_core::notes_core::seeds;

    let mut app_seed = [0u8; 32];
    for (i, b) in app_seed.iter_mut().enumerate() {
        *b = i as u8;
    }

    for (seed_index, account, index) in [(0u32, 0u32, 0u32), (0, 1, 2), (1, 0, 0), (7, 3, 5)] {
        // Device side: app seed → words → BIP-86 leaf (notes-core).
        let words = seeds::seed_mnemonic(&app_seed, seed_index).unwrap();
        let device_leaf =
            seeds::derive_leaf(&app_seed, seed_index, Network::Mainnet, account, index).unwrap();
        let device_id = CoreIdentity::from_leaf_secret(&device_leaf).unwrap();

        // App side: the SAME words through the normal import pipeline.
        let mnemonic = bip39::Mnemonic::parse(&*words).unwrap();
        let app_leaf = leaf_from_mnemonic(&mnemonic, Network::Mainnet, account, index).unwrap();
        let app_id = identity_from_leaf(&app_leaf).unwrap();

        assert_eq!(app_leaf, device_leaf, "leaf s{seed_index} a{account} i{index}");
        assert_eq!(app_id.enc_key, device_id.enc_key, "enc key");
        assert_eq!(app_id.output_x, device_id.output_x, "output key");
        assert_eq!(app_id.tweaked_seckey, device_id.tweaked_seckey, "signing key");
    }

    // And the notes-core frozen pipeline vector holds through our path too.
    let words = seeds::seed_mnemonic(&app_seed, 0).unwrap();
    let mnemonic = bip39::Mnemonic::parse(&*words).unwrap();
    let leaf = leaf_from_mnemonic(&mnemonic, Network::Mainnet, 0, 0).unwrap();
    let ident = identity_from_leaf(&leaf).unwrap();
    let ident = app_core::identity::realize(
        &app_core::identity::parse_key_material(&words, Network::Mainnet).unwrap(),
        Network::Mainnet,
        0,
        0,
    )
    .map(|i| (i.address.clone(), i.expect_full().enc_key))
    .map(|(addr, enc)| {
        assert_eq!(addr, "bc1pjezt70dslyv2pfglhncglc3granc7wmgkz5j4u5eyyx92su5ghsqaqxt88");
        assert_eq!(enc, ident.enc_key);
    });
    ident.unwrap();
}
