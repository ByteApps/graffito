//! Derivation gates: BIP-86 spec vector, independent rust-bitcoin
//! cross-check of the taproot tweak, frozen enc-key vector, xprv depth
//! equivalence.

use app_core::derive::{
    enc_key_from_leaf, identity_from_leaf, leaf_from_account, leaf_from_account_chain,
    leaf_from_master, leaf_from_master_chain, leaf_from_mnemonic, leaf_from_mnemonic_chain,
};
use app_core::identity::{parse_key_material, realize, realize_change, KeyMaterial};
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
/// notes become unreadable. Never update this expectation — with ONE
/// recorded exception: the 2026-08-18 graffito crypto epoch deliberately
/// rebound the salt (`chain-notes-app/enc/v1` -> `graffito/enc/v1`,
/// old-salt notes unreadable forever by explicit decision), and this
/// literal is the POST-epoch value (updated 2026-08-21 — the epoch merge
/// missed this integration-test copy because only `--lib` suites were run;
/// verified against an independent HKDF-SHA256 computation, not against
/// the code under test).
#[test]
fn enc_key_frozen_vector() {
    let key = enc_key_from_leaf(&[0x11u8; 32]);
    assert_eq!(
        hex::encode(key),
        "5c721ed6e799803079b6ddec26360f51d7b60fcd80a06b41d8e88bfa4b6ae604",
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
        // Post-epoch literal (2026-08-21): the 2026-08-18 crypto epoch
        // rebound the seeds pipeline's salts, so the seed-0 words — and
        // therefore this address — changed once, deliberately.
        assert_eq!(addr, "bc1p0plxgrp03zh56hnydnuagyjyn6rue3e525cccm75rpfzake985lss7kc7a");
        assert_eq!(enc, ident.enc_key);
    });
    ident.unwrap();
}

// ---------------------------------------------------------------------
// Change chain (m/86'/{coin}'/{account}'/1/{index}) — foundation for
// PLAN-chain-notes-app-taproot-change.md. This unit ONLY adds derivation
// + address; the tests below are the correctness proof: chain-0 stays
// byte-identical, and chain-1 matches an independent rust-bitcoin
// derivation of the same BIP-86 change path.
// ---------------------------------------------------------------------

/// The new chain-param leaf functions, called with `chain=0`, must be
/// byte-identical to the EXISTING (frozen) `leaf_from_*` functions for the
/// same inputs — proves the additive change touched nothing on the
/// receive chain.
#[test]
fn chain_zero_is_byte_identical_to_existing_leaf_fns() {
    let mnemonic = bip39::Mnemonic::parse(BIP86_MNEMONIC).unwrap();
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &mnemonic.to_seed("")).unwrap();

    for account in [0u32, 1, 7] {
        for index in [0u32, 1, 42] {
            assert_eq!(
                leaf_from_master_chain(&master, Network::Mainnet, account, 0, index).unwrap(),
                leaf_from_master(&master, Network::Mainnet, account, index).unwrap(),
                "leaf_from_master_chain(chain=0) vs leaf_from_master a{account} i{index}",
            );
            assert_eq!(
                leaf_from_mnemonic_chain(&mnemonic, Network::Mainnet, account, 0, index).unwrap(),
                leaf_from_mnemonic(&mnemonic, Network::Mainnet, account, index).unwrap(),
                "leaf_from_mnemonic_chain(chain=0) vs leaf_from_mnemonic a{account} i{index}",
            );
        }
    }

    let account_xprv = master
        .derive_priv(
            &secp,
            &[
                ChildNumber::from_hardened_idx(86).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
                ChildNumber::from_hardened_idx(0).unwrap(),
            ],
        )
        .unwrap();
    for index in [0u32, 1, 42] {
        assert_eq!(
            leaf_from_account_chain(&account_xprv, 0, index).unwrap(),
            leaf_from_account(&account_xprv, index).unwrap(),
            "leaf_from_account_chain(chain=0) vs leaf_from_account i{index}",
        );
    }

    // And the full realize() path (which calls the unchanged leaf_from_*
    // functions) still lands on the frozen BIP-86 spec address.
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    let ident = realize(&material, Network::Mainnet, 0, 0).unwrap();
    assert_eq!(ident.address, BIP86_ADDR_0);
}

/// Chain-1 (change) addresses for the standard test mnemonic, cross-checked
/// against an INDEPENDENT derivation through rust-bitcoin's own bip32 +
/// taproot machinery (path built by hand here, not via app-core's
/// `hardened`/`normal` helpers; address built via `bitcoin::Address::p2tr`,
/// not via notes-core's `Identity::from_leaf_secret`). This is the proof
/// that our change-chain leaves are what a standard BIP-86 taproot wallet
/// would derive as the change chain — the funds a
/// later feature sweeps from here are really the seed's change coins.
#[test]
fn change_chain_matches_independent_rust_bitcoin_derivation() {
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    let secp = Secp256k1::new();
    let mnemonic = bip39::Mnemonic::parse(BIP86_MNEMONIC).unwrap();
    let master = Xpriv::new_master(bitcoin::Network::Bitcoin, &mnemonic.to_seed("")).unwrap();

    for index in [0u32, 1] {
        // app-core's change-chain path.
        let ours = realize_change(&material, Network::Mainnet, 0, index).unwrap();

        // Independent rust-bitcoin derivation of m/86'/0'/0'/1/{index}.
        let path = [
            ChildNumber::from_hardened_idx(86).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_hardened_idx(0).unwrap(),
            ChildNumber::from_normal_idx(1).unwrap(),
            ChildNumber::from_normal_idx(index).unwrap(),
        ];
        let leaf = master.derive_priv(&secp, &path).unwrap();
        let (internal, _parity) = leaf.private_key.public_key(&secp).x_only_public_key();
        let addr = bitcoin::Address::p2tr(&secp, internal, None, bitcoin::Network::Bitcoin);

        assert_eq!(ours.address, addr.to_string(), "change address index {index}");
        // Gold standard: the literal BIP-86 spec change-0 vector (bip-0086.md,
        // "abandon…about", m/86'/0'/0'/1/0). Human-verifiable, not just
        // rust-bitcoin-agrees — money-critical.
        if index == 0 {
            assert_eq!(
                ours.address,
                "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
                "chain-1 index 0 MUST equal the BIP-86 spec change-address vector"
            );
        }
        // And the raw leaf secret itself matches too (not just the address
        // — an address collision on a bug would be extraordinarily
        // unlucky, but comparing the underlying secret is the real proof).
        assert_eq!(ours.expect_full().internal_x.as_slice(), internal.serialize().as_slice());
    }
}

/// Sanity: the change chain (1) and receive chain (0) diverge — same
/// account, same index, different address. If they ever matched it would
/// mean the chain child number silently collapsed.
#[test]
fn change_chain_differs_from_receive_chain() {
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    for index in [0u32, 1, 5] {
        let receive = realize(&material, Network::Mainnet, 0, index).unwrap();
        let change = realize_change(&material, Network::Mainnet, 0, index).unwrap();
        assert_ne!(receive.address, change.address, "index {index}");
    }
}

/// Account-xprv (depth 3) change-chain derivation must land on the same
/// leaf as deriving through the master — same equivalence the existing
/// `account_xprv_equals_master_derivation` test proves for chain 0.
#[test]
fn change_chain_account_xprv_equals_master_derivation() {
    let material = parse_key_material(BIP86_MNEMONIC, Network::Mainnet).unwrap();
    let from_master = realize_change(&material, Network::Mainnet, 0, 3).unwrap();

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

    let parsed = parse_key_material(&account.to_string(), Network::Mainnet).unwrap();
    let from_account = realize_change(&parsed, Network::Mainnet, 0, 3).unwrap();
    assert_eq!(from_account.address, from_master.address);

    let leaf = leaf_from_account_chain(&account, 1, 3).unwrap();
    assert_eq!(from_master.leaf_secret().unwrap(), &leaf);
}

/// WIF and raw hex have no chain concept (single raw key, no hierarchy) —
/// the change chain must error rather than fabricate a leaf.
#[test]
fn change_chain_rejects_non_hierarchical_material() {
    let hex_key = "01".repeat(32);
    let m = parse_key_material(&hex_key, Network::Mainnet).unwrap();
    assert!(realize_change(&m, Network::Mainnet, 0, 0).is_err());
}
