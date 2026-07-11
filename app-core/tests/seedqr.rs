//! SeedQR round-trips, standard and compact, 12/18/24 words.

use app_core::seedqr::{decode, decode_compact, decode_standard, encode_compact, encode_standard};
use app_core::Error;
use bip39::{Language, Mnemonic};

fn fixed(words: usize) -> Mnemonic {
    let entropy = vec![0xA5u8; words * 4 / 3]; // 12→16, 18→24, 24→32 bytes
    Mnemonic::from_entropy_in(Language::English, &entropy).unwrap()
}

#[test]
fn standard_roundtrip() {
    for words in [12usize, 18, 24] {
        let m = fixed(words);
        let digits = encode_standard(&m);
        assert_eq!(digits.len(), words * 4);
        assert_eq!(decode_standard(&digits).unwrap(), m);
        assert_eq!(decode(digits.as_bytes()).unwrap(), m);
    }
}

#[test]
fn compact_roundtrip() {
    for words in [12usize, 18, 24] {
        let m = fixed(words);
        let entropy = encode_compact(&m);
        assert_eq!(entropy.len(), words * 4 / 3);
        assert_eq!(decode_compact(&entropy).unwrap(), m);
        assert_eq!(decode(&entropy).unwrap(), m);
    }
}

#[test]
fn rejects_bad_payloads() {
    assert!(matches!(decode_standard("123"), Err(Error::SeedQr(_))));
    // 48 digits but an out-of-range index (2048).
    let bad = format!("2048{}", "0000".repeat(11));
    assert!(matches!(decode_standard(&bad), Err(Error::SeedQr(_))));
    // Valid indices, broken checksum: last word forced to index 3 ("about"
    // is unlikely to satisfy the checksum for constant entropy).
    let m = fixed(12);
    let mut digits = encode_standard(&m);
    digits.replace_range(44..48, "0003");
    assert!(matches!(decode_standard(&digits), Err(Error::SeedQr(_))));

    assert!(matches!(decode_compact(&[0u8; 15]), Err(Error::SeedQr(_))));
}
