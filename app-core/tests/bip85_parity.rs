//! Flagship-path parity: REAL prime-bip85 outputs (via bip85-core, the
//! exact crate the Prime app runs) fed through our importer — mnemonic,
//! WIF, XPRV, HEX, and the SeedQR digit stream. No hand-copied vectors.

use app_core::identity::{parse_key_material, realize, KeyMaterial};
use app_core::notes_core::Network;
use app_core::seedqr::decode_standard;
use bip85_core::bip32::Xprv;
use bip85_core::bip85::{derive, Application};

fn root() -> Xprv {
    Xprv::from_seed(&[0x42u8; 64]).unwrap()
}

#[test]
fn bip39_child_and_its_seedqr() {
    let child = derive(&root(), Application::Bip39 { words: 12 }, 0, bip85_core::Network::Mainnet)
        .unwrap();

    let material = parse_key_material(&child.display, Network::Mainnet).unwrap();
    let ident = realize(&material, Network::Mainnet, 0).unwrap();
    assert!(ident.address.starts_with("bc1p"));

    // prime-bip85's SeedQR digit stream decodes to the same mnemonic.
    let digits = bip85_core::seedqr::seedqr_digits(&child.entropy).unwrap();
    let from_qr = decode_standard(&digits).unwrap();
    assert_eq!(from_qr.to_string(), child.display);

    let ident_qr = realize(
        &parse_key_material(&from_qr.to_string(), Network::Mainnet).unwrap(),
        Network::Mainnet,
            0,
    )
    .unwrap();
    assert_eq!(ident_qr.address, ident.address);
}

#[test]
fn wif_child_matches_hex_of_same_entropy() {
    let child = derive(&root(), Application::Wif, 0, bip85_core::Network::Mainnet).unwrap();

    let via_wif = realize(
        &parse_key_material(&child.display, Network::Mainnet).unwrap(),
        Network::Mainnet,
            0,
    )
    .unwrap();
    assert_eq!(via_wif.kind, "wif");

    let via_hex = realize(
        &parse_key_material(&hex::encode(&child.entropy), Network::Mainnet).unwrap(),
        Network::Mainnet,
            0,
    )
    .unwrap();
    assert_eq!(via_wif.address, via_hex.address);
}

#[test]
fn xprv_child_imports_as_master() {
    let child = derive(&root(), Application::Xprv, 0, bip85_core::Network::Mainnet).unwrap();
    let material = parse_key_material(&child.display, Network::Mainnet).unwrap();
    assert!(matches!(&material, KeyMaterial::Xprv(x) if x.depth == 0));
    let ident = realize(&material, Network::Mainnet, 0).unwrap();
    assert!(ident.address.starts_with("bc1p"));
}

#[test]
fn hex_child_imports_raw() {
    let child =
        derive(&root(), Application::Hex { num_bytes: 32 }, 0, bip85_core::Network::Mainnet)
            .unwrap();
    let material = parse_key_material(&child.display, Network::Mainnet).unwrap();
    assert!(matches!(material, KeyMaterial::Hex(_)));
    let ident = realize(&material, Network::Mainnet, 0).unwrap();
    assert!(ident.address.starts_with("bc1p"));
}
