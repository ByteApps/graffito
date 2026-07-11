//! SeedQR (SeedSigner spec), both directions.
//!
//! Standard: each word's BIP-39 index as 4 zero-padded decimal digits,
//! concatenated (digit-mode QR) — 48 digits for 12 words, 72 for 18,
//! 96 for 24.
//! Compact: the raw entropy bytes (byte-mode QR) — 16, 24 or 32 bytes.
//! Checksum validation falls out of BIP-39 parsing in both cases.

use bip39::{Language, Mnemonic};

use crate::Error;

pub fn decode_standard(digits: &str) -> Result<Mnemonic, Error> {
    let s = digits.trim();
    if !matches!(s.len(), 48 | 72 | 96) || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::SeedQr("standard form is 48, 72 or 96 decimal digits"));
    }
    let list = Language::English.word_list();
    let mut words: Vec<&str> = Vec::with_capacity(s.len() / 4);
    for group in s.as_bytes().chunks(4) {
        let idx: usize = std::str::from_utf8(group)
            .expect("ascii digits")
            .parse()
            .expect("4 ascii digits");
        if idx >= 2048 {
            return Err(Error::SeedQr("word index out of range"));
        }
        words.push(list[idx]);
    }
    Mnemonic::parse_in_normalized(Language::English, &words.join(" "))
        .map_err(|_| Error::SeedQr("checksum failed"))
}

pub fn decode_compact(bytes: &[u8]) -> Result<Mnemonic, Error> {
    if !matches!(bytes.len(), 16 | 24 | 32) {
        return Err(Error::SeedQr("compact form is 16, 24 or 32 entropy bytes"));
    }
    Mnemonic::from_entropy_in(Language::English, bytes)
        .map_err(|_| Error::SeedQr("invalid entropy"))
}

/// Auto-detect: ASCII digit payloads of the right length are standard
/// SeedQR, 16/24/32-byte payloads are compact.
pub fn decode(payload: &[u8]) -> Result<Mnemonic, Error> {
    if matches!(payload.len(), 48 | 72 | 96) && payload.iter().all(|b| b.is_ascii_digit()) {
        decode_standard(std::str::from_utf8(payload).expect("ascii digits"))
    } else {
        decode_compact(payload)
    }
}

pub fn encode_standard(mnemonic: &Mnemonic) -> String {
    let list = Language::English.word_list();
    mnemonic
        .words()
        .map(|w| {
            let idx = list.iter().position(|c| *c == w).expect("word from this wordlist");
            format!("{idx:04}")
        })
        .collect()
}

pub fn encode_compact(mnemonic: &Mnemonic) -> Vec<u8> {
    mnemonic.to_entropy()
}
