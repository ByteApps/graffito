//! Import-format matrix: WIF/hex equivalence, network awareness,
//! rejection cases, mnemonic create.

use app_core::identity::{generate_mnemonic, parse_key_material, realize, KeyMaterial};
use app_core::notes_core::Network;
use app_core::Error;
use bitcoin::key::PrivateKey;
use bitcoin::secp256k1::SecretKey;

#[test]
fn wif_and_hex_same_key_same_address() {
    let key = [7u8; 32];
    let wif = PrivateKey::new(SecretKey::from_slice(&key).unwrap(), bitcoin::Network::Testnet);

    let via_wif = realize(
        &parse_key_material(&wif.to_wif(), Network::Testnet4).unwrap(),
        Network::Testnet4,
            0,
    )
    .unwrap();
    let via_hex = realize(
        &parse_key_material(&hex::encode(key), Network::Testnet4).unwrap(),
        Network::Testnet4,
            0,
    )
    .unwrap();

    assert_eq!(via_wif.kind, "wif");
    assert_eq!(via_hex.kind, "hex");
    assert_eq!(via_wif.address, via_hex.address);
    assert!(via_wif.address.starts_with("tb1p"));

    // Same raw key on regtest: same x-only program, regtest HRP.
    let via_hex_rt = realize(
        &parse_key_material(&hex::encode(key), Network::Regtest).unwrap(),
        Network::Regtest,
            0,
    )
    .unwrap();
    assert!(via_hex_rt.address.starts_with("bcrt1p"));
}

#[test]
fn network_mismatches_rejected() {
    let key = [7u8; 32];
    let main_wif =
        PrivateKey::new(SecretKey::from_slice(&key).unwrap(), bitcoin::Network::Bitcoin).to_wif();
    assert!(matches!(
        parse_key_material(&main_wif, Network::Testnet4),
        Err(Error::WifNetwork)
    ));

    // tprv offered while on mainnet.
    let seed = [9u8; 64];
    let tprv = bitcoin::bip32::Xpriv::new_master(bitcoin::Network::Testnet, &seed).unwrap();
    assert!(matches!(
        parse_key_material(&tprv.to_string(), Network::Mainnet),
        Err(Error::XprvNetwork)
    ));
    // ... and accepted on testnet4.
    assert!(matches!(
        parse_key_material(&tprv.to_string(), Network::Testnet4),
        Ok(KeyMaterial::Xprv(_))
    ));
}

#[test]
fn malformed_inputs_rejected() {
    // 15-word mnemonics are valid BIP-39 but not accepted here.
    let fifteen = ["abandon"; 15].join(" ");
    assert!(matches!(
        parse_key_material(&fifteen, Network::Mainnet),
        Err(Error::MnemonicWordCount(15))
    ));

    // Bad checksum.
    let twelve = ["abandon"; 12].join(" ");
    assert!(matches!(
        parse_key_material(&twelve, Network::Mainnet),
        Err(Error::Mnemonic(_))
    ));

    // Hex: wrong length, and out-of-range scalar.
    assert!(matches!(
        parse_key_material(&"ab".repeat(16), Network::Mainnet),
        Err(Error::HexLength(16))
    ));
    assert!(matches!(
        parse_key_material(&"ff".repeat(32), Network::Mainnet),
        Err(Error::InvalidKey)
    ));

    assert!(matches!(
        parse_key_material("not a key at all!!", Network::Mainnet),
        Err(Error::MnemonicWordCount(5))
    ));
    assert!(matches!(
        parse_key_material("garbage1string", Network::Mainnet),
        Err(Error::UnrecognizedFormat)
    ));
}

#[test]
fn generated_mnemonics_are_valid_and_distinct() {
    for words in [12usize, 24] {
        let m = generate_mnemonic(words).unwrap();
        assert_eq!(m.word_count(), words);
        // Round-trips through the importer.
        let parsed = parse_key_material(&m.to_string(), Network::Mainnet).unwrap();
        realize(&parsed, Network::Mainnet, 0).unwrap();
    }
    let a = generate_mnemonic(12).unwrap();
    let b = generate_mnemonic(12).unwrap();
    assert_ne!(a.to_string(), b.to_string(), "entropy source is not varying");

    assert!(matches!(generate_mnemonic(18), Err(Error::MnemonicWordCount(18))));
}
