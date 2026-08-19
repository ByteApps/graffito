//! app-core — UI-free core for graffito.
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
pub mod confirm;
pub mod contacts;
pub mod derive;
pub mod funding;
pub mod identity;
pub mod keyexport;
pub mod mixed;
pub mod netq;
pub mod notebooks;
pub mod psbt_build;
pub mod psbt_finalize;
pub mod scan_gate;
pub mod spending;
pub mod ur;
pub mod ur_account;

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
    /// xpub/tpub prefix does not match the active network.
    XpubNetwork,
    /// Watch-only xpub at a depth we can't use (only 3 = 86' account —
    /// the hardened account path makes a master xpub underivable).
    XpubDepth(u8),
    Xpub(String),
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
    /// Dice-roll entropy input was rejected (bad character, or too few rolls
    /// for the requested word count). Carries a user-facing reason.
    Dice(String),
    /// HTTP transport failure (network, status, body).
    Http(String),
    /// The request never reached a server at all — connection refused/reset,
    /// DNS failure, timeout, dropped mid-transfer (see
    /// `HttpTransport::get_text`/`post_text`'s `.send()`/body-read steps in
    /// chain.rs). Kept distinct from [`Error::Http`] (a response DID come
    /// back, just with an error status) so callers can retry only the
    /// transport case — a rejected tx must never be silently retried.
    Transport(String),
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
                write!(f, "mnemonic must be 12, 18 or 24 words (got {n})")
            }
            Error::Mnemonic(m) => write!(f, "mnemonic: {m}"),
            Error::XprvNetwork => write!(f, "xprv is for a different network"),
            Error::XprvDepth(d) => {
                write!(f, "xprv depth {d} unsupported (need master or 86' account)")
            }
            Error::Xprv(m) => write!(f, "xprv: {m}"),
            Error::XpubNetwork => write!(f, "xpub is for a different network"),
            Error::XpubDepth(d) => {
                write!(f, "xpub depth {d} unsupported (need an 86' account-level xpub)")
            }
            Error::Xpub(m) => write!(f, "xpub: {m}"),
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
            Error::Dice(m) => write!(f, "dice rolls: {m}"),
            Error::Http(m) => write!(f, "http: {m}"),
            Error::Transport(m) => write!(f, "transport: {m}"),
            Error::Json(m) => write!(f, "response: {m}"),
            Error::Store(m) => write!(f, "store: {m}"),
            Error::Funding(m) => write!(f, "funding: {m}"),
            Error::Ur(m) => write!(f, "ur: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// True iff this is an HTTP error carrying a 429 (Too Many Requests)
    /// status — i.e. every 429 retry in `chain::HttpTransport` was
    /// exhausted and the caller is seeing the rate-limit itself, not a
    /// synthesized message. Relies on `Error::Http`'s message always
    /// starting with the numeric status code followed by `:` (the format
    /// `chain::trim_error_body` builds and the only place `Error::Http` is
    /// constructed from a real HTTP response) — kept reliable by that
    /// invariant rather than carrying the status code as a separate field,
    /// so existing `Error::Http(String)` matchers/tests are untouched.
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Error::Http(m) if m.starts_with("429:") || m == "429")
    }
}

impl From<notes_core::Error> for Error {
    fn from(e: notes_core::Error) -> Self {
        Error::Notes(e)
    }
}
