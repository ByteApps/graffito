//! app-core — UI-free core for chain-notes-app.
//!
//! Wraps notes-core (the frozen PNTE protocol, pinned by rev) with what a
//! native online app adds: identity create/import (BIP-39 / xprv / WIF /
//! hex → one taproot notes address), the frozen leaf-secret HKDF
//! note-encryption rule, an esplora chain client that assembles in-memory
//! SyncBundles, the local store, and compose orchestration.
//!
//! Milestones and design: ../../PLAN-chain-notes-app.md (prime workspace).

pub mod chain;
pub mod compose;
pub mod derive;
pub mod funding;
pub mod identity;
pub mod psbt_build;
pub mod psbt_finalize;
pub mod ur;

/// Re-export so the binary uses the exact same `bitcoin` (and `Psbt` type) as
/// app-core — no version-skew risk across the crate boundary.
pub use bitcoin;
pub mod seedqr;
pub mod store;

pub use notes_core;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Frozen-protocol layer error (notes-core).
    Notes(notes_core::Error),
    /// Mnemonic had a word count we don't accept (only 12 and 24).
    MnemonicWordCount(usize),
    /// Mnemonic failed BIP-39 parsing (unknown word, bad checksum, ...).
    Mnemonic(String),
    /// xprv/tprv prefix does not match the active network.
    XprvNetwork,
    /// xprv at a depth we don't interpret (only 0 = master, 3 = account).
    XprvDepth(u8),
    Xprv(String),
    /// WIF network byte does not match the active network.
    WifNetwork,
    /// Uncompressed WIF — taproot identities require compressed keys.
    WifUncompressed,
    Wif(String),
    /// Hex key material must be exactly 32 bytes (64 hex chars).
    HexLength(usize),
    /// Key bytes are not a valid secp256k1 secret.
    InvalidKey,
    /// Input matched none of: mnemonic, xprv, WIF, 32-byte hex.
    UnrecognizedFormat,
    SeedQr(&'static str),
    Entropy,
    /// HTTP transport failure (network, status, body).
    Http(String),
    /// Response body did not parse as expected.
    Json(String),
    /// Store I/O, (de)serialization, or identity-mismatch failure.
    Store(String),
    /// External funding descriptor: parse, derivation, or unsupported type.
    Funding(String),
    /// Animated UR (crypto-psbt) framing/parse/reassembly failure.
    Ur(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Notes(e) => write!(f, "{e}"),
            Error::MnemonicWordCount(n) => {
                write!(f, "mnemonic must be 12 or 24 words (got {n})")
            }
            Error::Mnemonic(m) => write!(f, "mnemonic: {m}"),
            Error::XprvNetwork => write!(f, "xprv is for a different network"),
            Error::XprvDepth(d) => {
                write!(f, "xprv depth {d} unsupported (need master or 86' account)")
            }
            Error::Xprv(m) => write!(f, "xprv: {m}"),
            Error::WifNetwork => write!(f, "WIF is for a different network"),
            Error::WifUncompressed => write!(f, "uncompressed WIF unsupported"),
            Error::Wif(m) => write!(f, "WIF: {m}"),
            Error::HexLength(n) => write!(f, "hex key must be 32 bytes (got {n})"),
            Error::InvalidKey => write!(f, "not a valid secp256k1 secret key"),
            Error::UnrecognizedFormat => {
                write!(f, "not a mnemonic, xprv, WIF, or 32-byte hex key")
            }
            Error::SeedQr(m) => write!(f, "SeedQR: {m}"),
            Error::Entropy => write!(f, "entropy source failure"),
            Error::Http(m) => write!(f, "http: {m}"),
            Error::Json(m) => write!(f, "response: {m}"),
            Error::Store(m) => write!(f, "store: {m}"),
            Error::Funding(m) => write!(f, "funding: {m}"),
            Error::Ur(m) => write!(f, "ur: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<notes_core::Error> for Error {
    fn from(e: notes_core::Error) -> Self {
        Error::Notes(e)
    }
}
