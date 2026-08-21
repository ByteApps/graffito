//! ML-KEM key import: pulls the ML-KEM-768 component out of an RFC 9980
//! OpenPGP key (public-key algorithm 35, "ML-KEM-768+X25519") so graffito
//! can use it for note encryption, plus a graffito-native armored ML-KEM
//! key format for material that never goes through OpenPGP at all.
//!
//! Sources this is expected to import from: the "OpenPGP Keys" Passport
//! Prime app (`prime-openpgp-keys`, `pgp-core` crate — rpgp 0.20 with the
//! `draft-pqc` feature, exactly the composite this module targets),
//! Sequoia, and any other RFC 9980-conformant implementation.
//!
//! # rpgp 0.20 API facts (read from `~/.cargo/registry/.../pgp-0.20.0/src`)
//!
//! - Public-key algorithm 35 ("ML-KEM-768+X25519") deserializes to
//!   `PublicParams::MlKem768X25519(MlKem768X25519PublicParams)`
//!   (`types/params/public/ml_kem768_x25519.rs`), which carries a plain
//!   X25519 public key (32 bytes) AND a boxed ML-KEM-768 `EncapsulationKey`
//!   (`ml_kem_key.as_bytes()`, 1184 bytes) — the `ek` this module extracts.
//! - The matching secret packet deserializes to
//!   `PlainSecretParams::MlKem768X25519(pgp::crypto::ml_kem768_x25519::SecretKey)`.
//!   That `SecretKey` (`crypto/ml_kem768_x25519.rs`) stores an X25519
//!   scalar plus **only** the ML-KEM `(d, z)` seed pair — 32 + 32 = 64
//!   bytes, `SecretKey::as_bytes() -> (&[u8;32], &[u8;32], &[u8;32])` —
//!   never an expanded decapsulation key. `SecretKey::generate` and
//!   `SecretKey::try_from_bytes` both go through
//!   `MlKem768::generate_deterministic(&d, &z)`. **rpgp 0.20 therefore
//!   always hands back `MlKemSecretMaterial::Seed`, never `Expanded`** —
//!   the `Expanded` variant exists so the type stays honest about the
//!   wider RFC 9980 wire format (and about the graffito-native private
//!   armor, which is also seed-only by spec), not because this crate
//!   ever produces it.
//! - GnuPG/LibrePGP's rival Kyber encoding uses public-key algorithm ID 8.
//!   That ID is unassigned in classic OpenPGP and gated out of rpgp's
//!   `#[cfg(feature = "draft-pqc")]` arm, so it parses as
//!   `PublicKeyAlgorithm::Unknown(8)` / `PublicParams::Unknown{ data }` —
//!   the packet parses fine (rpgp reads exactly the declared packet
//!   length into an opaque blob), it just isn't algorithm 35. That is
//!   what lets this module tell "no PQC component" apart from "PQC
//!   component present, but it's the incompatible LibrePGP encoding".
//! - `pgp::crypto::ml_kem768_x25519` and `pgp::crypto::ml_kem1024_x448`
//!   are `pub` modules (gated on `draft-pqc`, which this crate always
//!   enables) exposing `SecretKey::try_from_bytes(classical_bytes, seed)`
//!   and a `From<&SecretKey> for {MlKem768X25519,MlKem1024X448}PublicParams`
//!   impl. Because the ML-KEM half of that expansion is fully independent
//!   of the classical half, calling `try_from_bytes` with a throwaway
//!   all-zero classical key and a REAL ML-KEM seed correctly re-derives
//!   the same ML-KEM keypair a pure keygen would — which is how
//!   `derive_ek_from_seed` expands a graffito-native private-only import
//!   into its encapsulation key using only the `pgp` crate (already a
//!   regular dependency), with no separate `ml-kem` dependency.
//! - There is no OpenPGP (or rpgp) composite for ML-KEM-512 — RFC 9980
//!   only defines algorithm 35 (768+X25519) and 36 (1024+X448) — so that
//!   expansion trick has nothing to reuse for level 512.
//!   `derive_ek_from_seed` reports that gap via `ImportError::WrongAlg`
//!   rather than silently returning wrong bytes; see that function's docs.
//!
//! # Scope note
//!
//! This module does not verify self-signatures / binding signatures
//! (`verify_bindings`) — it only extracts key material for use as note
//! encryption input, which is a UI-level concern distinct from certificate
//! trust validation and was not asked for by this unit's spec.

use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use pgp::composed::{PublicOrSecret, SignedPublicKey, SignedSecretKey};
use pgp::ser::Serialize as _;
use pgp::types::{KeyDetails as _, PlainSecretParams, PublicParams, SecretParams};

/// GnuPG/LibrePGP's rival Kyber encoding — permanently incompatible with
/// RFC 9980's algorithm 35 (see module docs). Unassigned in classic
/// OpenPGP, so rpgp parses it as `PublicKeyAlgorithm::Unknown(8)`.
const LIBREPGP_KYBER_ALGORITHM_ID: u8 = 8;
/// RFC 9980 algorithm 35: ML-KEM-768 + X25519 composite — the one PQC
/// algorithm legal on v4 OpenPGP keys, and the one this module targets.
const RFC9980_MLKEM768_X25519_ALGORITHM_ID: u8 = 35;

const NATIVE_PRIV_BEGIN: &str = "-----BEGIN GRAFFITO ML-KEM PRIVATE KEY-----";
const NATIVE_PRIV_END: &str = "-----END GRAFFITO ML-KEM PRIVATE KEY-----";
const NATIVE_PUB_BEGIN: &str = "-----BEGIN GRAFFITO ML-KEM PUBLIC KEY-----";
const NATIVE_PUB_END: &str = "-----END GRAFFITO ML-KEM PUBLIC KEY-----";
/// The one format version the native armor has ever had.
const NATIVE_FORMAT_VERSION: u8 = 0x01;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// ML-KEM parameter level. OpenPGP import is always [`MlKemLevel::MlKem768`]
/// (the only level RFC 9980 defines a composite for on a v4 key); native
/// import carries whichever level the armor declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemLevel {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemLevel {
    /// Byte length of the encapsulation key (`ek`) at this level.
    pub fn ek_len(self) -> usize {
        match self {
            MlKemLevel::MlKem512 => 800,
            MlKemLevel::MlKem768 => 1184,
            MlKemLevel::MlKem1024 => 1568,
        }
    }

    fn from_native_id(id: u8) -> Option<Self> {
        match id {
            0x01 => Some(MlKemLevel::MlKem512),
            0x02 => Some(MlKemLevel::MlKem768),
            0x03 => Some(MlKemLevel::MlKem1024),
            _ => None,
        }
    }
}

/// The ML-KEM secret, in whichever form the source provided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlKemSecretMaterial {
    /// RFC 9980's storage form: the 64-byte `(d, z)` seed pair the ML-KEM
    /// keygen algorithm deterministically re-expands into a full
    /// decapsulation key. This is what rpgp 0.20 always exposes for an
    /// OpenPGP algorithm-35 key, and what graffito-native private armor
    /// stores too — see the module docs.
    Seed([u8; 64]),
    /// A pre-expanded decapsulation key. rpgp 0.20 never produces this
    /// (see module docs); kept so the type stays honest about the wider
    /// wire format rather than assuming every future source is seed-only.
    Expanded(Vec<u8>),
}

/// Where an [`ImportedMlKem`] came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSource {
    /// Extracted from an OpenPGP certificate/key. `fingerprint` is the
    /// PRIMARY key's fingerprint (lowercase hex) — the identity a user
    /// recognizes — not the ML-KEM subkey's own fingerprint.
    OpenPgp {
        fingerprint: String,
        primary_uid: Option<String>,
    },
    /// Parsed from graffito's own native ML-KEM armor.
    GraffitoNative,
}

/// A successfully imported ML-KEM key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedMlKem {
    /// The encapsulation (public) key, `alg.ek_len()` bytes.
    pub ek: Vec<u8>,
    /// The decapsulation (secret) key material, if this was a secret-key
    /// import. `None` for a public-only certificate or native public key.
    pub secret: Option<MlKemSecretMaterial>,
    pub source: ImportSource,
    pub alg: MlKemLevel,
}

/// Why [`parse_mlkem_key`] failed. Every variant has a clear, user-facing
/// [`Display`](std::fmt::Display) message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// The input has no recognized armor header at all — not OpenPGP,
    /// not graffito-native.
    NotPgp,
    /// The input looked like OpenPGP or graffito-native armor but could
    /// not be parsed (malformed packets, bad base64, wrong length, …).
    ParseFailed(String),
    /// A valid OpenPGP key was parsed, but it has no algorithm-35
    /// (RFC 9980 ML-KEM-768+X25519) component — only classical algorithms
    /// (RSA, EdDSA, ECDH, …).
    NoPqcKey,
    /// The key's post-quantum component uses GnuPG/LibrePGP's Kyber
    /// encoding (public-key algorithm ID 8) rather than RFC 9980's
    /// algorithm 35. These are permanently incompatible, non-interoperable
    /// encodings that happen to be described by the same two rival specs —
    /// not a version skew that a newer GnuPG will fix.
    LibrePgpKyber,
    /// The matching secret key packet is passphrase-protected. This unit
    /// does not implement passphrase unlock.
    Protected,
    /// The declared algorithm doesn't match what's actually there (e.g. an
    /// unrecognized native-armor level id, or algorithm-35 declared over
    /// malformed key material).
    WrongAlg(String),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::NotPgp => write!(
                f,
                "This doesn't look like an OpenPGP key or a Graffito ML-KEM key \
                 (no recognized armor header)."
            ),
            ImportError::ParseFailed(msg) => write!(f, "Could not parse this key: {msg}"),
            ImportError::NoPqcKey => write!(
                f,
                "This OpenPGP key has no post-quantum (ML-KEM) component — it only \
                 contains classical algorithms (e.g. RSA, EdDSA, ECDH). Generate or \
                 obtain a key with an RFC 9980 ML-KEM-768+X25519 component \
                 (algorithm 35) to use it here."
            ),
            ImportError::LibrePgpKyber => write!(
                f,
                "This key's post-quantum component uses GnuPG/LibrePGP's Kyber \
                 encoding (algorithm ID 8), not the RFC 9980 OpenPGP standard \
                 (algorithm ID 35). These are permanently incompatible encodings — \
                 LibrePGP and RFC 9980 assign the same numeric algorithm slot to two \
                 different, non-interoperable formats, so no GnuPG version will ever \
                 read as RFC 9980. Generate a post-quantum key in an RFC \
                 9980-conformant tool instead (e.g. Sequoia, an rpgp-based tool such \
                 as the OpenPGP Keys Passport Prime app)."
            ),
            ImportError::Protected => write!(
                f,
                "This key's secret material is passphrase-protected. Export it \
                 without a passphrase and try again."
            ),
            ImportError::WrongAlg(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ImportError {}

/// Parse an armored key and extract its ML-KEM component. Auto-detects,
/// in order: graffito-native private armor, graffito-native public armor,
/// an armored OpenPGP secret key, an armored OpenPGP public key/cert.
pub fn parse_mlkem_key(input: &str) -> Result<ImportedMlKem, ImportError> {
    let trimmed = input.trim();

    if let Some(result) = try_parse_native(trimmed) {
        return result;
    }

    if !trimmed.contains("-----BEGIN PGP") {
        return Err(ImportError::NotPgp);
    }

    // rpgp has a history of panics on crafted packets (CVE-2026-21895) and
    // this is untrusted input, so parsing runs behind catch_unwind — same
    // discipline as prime-openpgp-keys/pgp-core.
    let data = trimmed.as_bytes().to_vec();
    catch_unwind(AssertUnwindSafe(move || parse_openpgp(&data))).unwrap_or_else(|_| {
        Err(ImportError::ParseFailed(
            "malformed key data (parser crashed)".into(),
        ))
    })
}

// ---------------------------------------------------------------------------
// Graffito-native armor
// ---------------------------------------------------------------------------

fn try_parse_native(trimmed: &str) -> Option<Result<ImportedMlKem, ImportError>> {
    if trimmed.starts_with(NATIVE_PRIV_BEGIN) {
        Some(parse_native(trimmed, NATIVE_PRIV_BEGIN, NATIVE_PRIV_END, true))
    } else if trimmed.starts_with(NATIVE_PUB_BEGIN) {
        Some(parse_native(trimmed, NATIVE_PUB_BEGIN, NATIVE_PUB_END, false))
    } else {
        None
    }
}

fn parse_native(
    trimmed: &str,
    begin: &str,
    end: &str,
    is_secret: bool,
) -> Result<ImportedMlKem, ImportError> {
    let end_idx = trimmed
        .find(end)
        .ok_or_else(|| ImportError::ParseFailed(format!("missing matching \"{end}\" footer")))?;
    let body = &trimmed[begin.len()..end_idx];
    parse_native_body(body, is_secret)
}

fn parse_native_body(body: &str, is_secret: bool) -> Result<ImportedMlKem, ImportError> {
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = BASE64
        .decode(cleaned.as_bytes())
        .map_err(|e| ImportError::ParseFailed(format!("invalid base64: {e}")))?;

    if raw.len() < 2 {
        return Err(ImportError::ParseFailed(format!(
            "payload too short: {} bytes (need at least a version and algorithm id)",
            raw.len()
        )));
    }

    let version = raw[0];
    if version != NATIVE_FORMAT_VERSION {
        return Err(ImportError::ParseFailed(format!(
            "unsupported native format version {version:#04x} (expected {NATIVE_FORMAT_VERSION:#04x})"
        )));
    }

    let alg_id = raw[1];
    let level = MlKemLevel::from_native_id(alg_id)
        .ok_or_else(|| ImportError::WrongAlg(format!("unrecognized ML-KEM level id {alg_id:#04x}")))?;
    let payload = &raw[2..];

    if is_secret {
        let seed: [u8; 64] = payload.try_into().map_err(|_| {
            ImportError::ParseFailed(format!(
                "expected a 64-byte ML-KEM seed, got {} bytes",
                payload.len()
            ))
        })?;
        let ek = derive_ek_from_seed(level, &seed)?;
        Ok(ImportedMlKem {
            ek,
            secret: Some(MlKemSecretMaterial::Seed(seed)),
            source: ImportSource::GraffitoNative,
            alg: level,
        })
    } else {
        let expected = level.ek_len();
        if payload.len() != expected {
            return Err(ImportError::ParseFailed(format!(
                "expected a {expected}-byte encapsulation key for {level:?}, got {} bytes",
                payload.len()
            )));
        }
        Ok(ImportedMlKem {
            ek: payload.to_vec(),
            secret: None,
            source: ImportSource::GraffitoNative,
            alg: level,
        })
    }
}

/// Expand a bare 64-byte `(d, z)` ML-KEM seed into its encapsulation key,
/// using only rpgp's own composite modules (see module docs for why this
/// is correct and why level 512 can't be supported this way).
///
/// The raw `EncapsulationKey::as_bytes()` accessor lives behind a trait
/// defined in the standalone `ml-kem` crate, which this unit deliberately
/// keeps out of app-core's regular dependencies (see Cargo.toml) — so
/// instead of naming that crate, this serializes the WHOLE composite
/// public-params struct through rpgp's own `Serialize` trait (classical
/// key || ek, exactly the OpenPGP wire layout) and strips the classical
/// prefix, using only APIs `pgp` itself exposes.
fn derive_ek_from_seed(level: MlKemLevel, seed: &[u8; 64]) -> Result<Vec<u8>, ImportError> {
    match level {
        MlKemLevel::MlKem768 => {
            let sk = pgp::crypto::ml_kem768_x25519::SecretKey::try_from_bytes([0u8; 32], *seed)
                .map_err(|e| ImportError::ParseFailed(format!("invalid ML-KEM-768 seed: {e}")))?;
            let params: pgp::types::MlKem768X25519PublicParams = (&sk).into();
            let wire = params
                .to_bytes()
                .map_err(|e| ImportError::ParseFailed(format!("failed to encode ek: {e}")))?;
            Ok(wire[32..].to_vec()) // strip the 32-byte X25519 public key prefix
        }
        MlKemLevel::MlKem1024 => {
            let sk = pgp::crypto::ml_kem1024_x448::SecretKey::try_from_bytes([0u8; 56], *seed)
                .map_err(|e| ImportError::ParseFailed(format!("invalid ML-KEM-1024 seed: {e}")))?;
            let params: pgp::types::MlKem1024X448PublicParams = (&sk).into();
            let wire = params
                .to_bytes()
                .map_err(|e| ImportError::ParseFailed(format!("failed to encode ek: {e}")))?;
            Ok(wire[56..].to_vec()) // strip the 56-byte X448 public key prefix
        }
        MlKemLevel::MlKem512 => Err(ImportError::WrongAlg(
            "ML-KEM-512 has no RFC 9980 OpenPGP composite algorithm, so this build has \
             no way to expand a bare ML-KEM-512 seed into its encapsulation key: rpgp \
             only implements the ML-KEM-768+X25519 and ML-KEM-1024+X448 composites, and \
             a standalone ML-KEM-512 keygen would need the `ml-kem` crate as a regular \
             dependency, which this unit deliberately does not add. Import the public \
             form instead, or use ML-KEM-768."
                .into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// OpenPGP
// ---------------------------------------------------------------------------

fn parse_openpgp(data: &[u8]) -> Result<ImportedMlKem, ImportError> {
    let (mut iter, _headers) = PublicOrSecret::from_armor_many(Cursor::new(data))
        .map_err(|e| ImportError::ParseFailed(e.to_string()))?;
    let first = iter
        .next()
        .ok_or_else(|| ImportError::ParseFailed("no OpenPGP key found in input".into()))?
        .map_err(|e| ImportError::ParseFailed(e.to_string()))?;

    match first {
        PublicOrSecret::Public(pk) => import_from_public(&pk),
        PublicOrSecret::Secret(sk) => import_from_secret(&sk),
    }
}

fn extract_ek(params: &PublicParams) -> Result<Vec<u8>, ImportError> {
    match params {
        // See derive_ek_from_seed's doc comment for why this goes through
        // Serialize + a slice rather than `p.ml_kem_key.as_bytes()`.
        PublicParams::MlKem768X25519(p) => {
            let wire = p
                .to_bytes()
                .map_err(|e| ImportError::ParseFailed(format!("failed to encode ek: {e}")))?;
            Ok(wire[32..].to_vec())
        }
        _ => Err(ImportError::WrongAlg(
            "algorithm 35 declared but the key material is not ML-KEM-768+X25519 shaped"
                .into(),
        )),
    }
}

fn extract_secret(params: &SecretParams) -> Result<MlKemSecretMaterial, ImportError> {
    match params {
        SecretParams::Encrypted(_) => Err(ImportError::Protected),
        SecretParams::Plain(PlainSecretParams::MlKem768X25519(key)) => {
            let (_x25519, d, z) = key.as_bytes();
            let mut seed = [0u8; 64];
            seed[..32].copy_from_slice(d);
            seed[32..].copy_from_slice(z);
            Ok(MlKemSecretMaterial::Seed(seed))
        }
        SecretParams::Plain(_) => Err(ImportError::WrongAlg(
            "algorithm 35 declared but the secret key material is not \
             ML-KEM-768+X25519 shaped"
                .into(),
        )),
    }
}

fn primary_uid_of(details: &pgp::composed::SignedKeyDetails) -> Option<String> {
    details
        .users
        .first()
        .and_then(|u| u.id.as_str())
        .map(str::to_string)
}

fn import_from_public(pk: &SignedPublicKey) -> Result<ImportedMlKem, ImportError> {
    let mut saw_librepgp_kyber = false;

    for sub in &pk.public_subkeys {
        let alg: u8 = sub.algorithm().into();
        if alg == RFC9980_MLKEM768_X25519_ALGORITHM_ID {
            let ek = extract_ek(sub.public_params())?;
            return Ok(ImportedMlKem {
                ek,
                secret: None,
                source: ImportSource::OpenPgp {
                    fingerprint: pk.fingerprint().to_string(),
                    primary_uid: primary_uid_of(&pk.details),
                },
                alg: MlKemLevel::MlKem768,
            });
        }
        if alg == LIBREPGP_KYBER_ALGORITHM_ID {
            saw_librepgp_kyber = true;
        }
    }

    let alg: u8 = pk.algorithm().into();
    if alg == RFC9980_MLKEM768_X25519_ALGORITHM_ID {
        let ek = extract_ek(pk.public_params())?;
        return Ok(ImportedMlKem {
            ek,
            secret: None,
            source: ImportSource::OpenPgp {
                fingerprint: pk.fingerprint().to_string(),
                primary_uid: primary_uid_of(&pk.details),
            },
            alg: MlKemLevel::MlKem768,
        });
    }
    if alg == LIBREPGP_KYBER_ALGORITHM_ID {
        saw_librepgp_kyber = true;
    }

    if saw_librepgp_kyber {
        Err(ImportError::LibrePgpKyber)
    } else {
        Err(ImportError::NoPqcKey)
    }
}

fn import_from_secret(sk: &SignedSecretKey) -> Result<ImportedMlKem, ImportError> {
    let mut saw_librepgp_kyber = false;

    for sub in &sk.secret_subkeys {
        let alg: u8 = sub.algorithm().into();
        if alg == RFC9980_MLKEM768_X25519_ALGORITHM_ID {
            let ek = extract_ek(sub.public_params())?;
            let secret = extract_secret(sub.secret_params())?;
            return Ok(ImportedMlKem {
                ek,
                secret: Some(secret),
                source: ImportSource::OpenPgp {
                    fingerprint: sk.fingerprint().to_string(),
                    primary_uid: primary_uid_of(&sk.details),
                },
                alg: MlKemLevel::MlKem768,
            });
        }
        if alg == LIBREPGP_KYBER_ALGORITHM_ID {
            saw_librepgp_kyber = true;
        }
    }

    let alg: u8 = sk.algorithm().into();
    if alg == RFC9980_MLKEM768_X25519_ALGORITHM_ID {
        let ek = extract_ek(sk.public_params())?;
        let secret = extract_secret(sk.secret_params())?;
        return Ok(ImportedMlKem {
            ek,
            secret: Some(secret),
            source: ImportSource::OpenPgp {
                fingerprint: sk.fingerprint().to_string(),
                primary_uid: primary_uid_of(&sk.details),
            },
            alg: MlKemLevel::MlKem768,
        });
    }
    if alg == LIBREPGP_KYBER_ALGORITHM_ID {
        saw_librepgp_kyber = true;
    }

    if saw_librepgp_kyber {
        Err(ImportError::LibrePgpKyber)
    } else {
        Err(ImportError::NoPqcKey)
    }
}

// ---------------------------------------------------------------------------
// Test-only helpers (fixture construction)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod native_armor_test_support {
    //! Builds graffito-native armor text for tests. Not part of the public
    //! API — production code only ever needs to PARSE this format.

    use super::*;

    pub fn wrap64(s: &str) -> String {
        s.as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn armor_native_private(level: MlKemLevel, seed: &[u8; 64]) -> String {
        let mut raw = vec![NATIVE_FORMAT_VERSION, native_id(level)];
        raw.extend_from_slice(seed);
        format!(
            "{NATIVE_PRIV_BEGIN}\n{}\n{NATIVE_PRIV_END}\n",
            wrap64(&BASE64.encode(raw))
        )
    }

    pub fn armor_native_public(level: MlKemLevel, ek: &[u8]) -> String {
        let mut raw = vec![NATIVE_FORMAT_VERSION, native_id(level)];
        raw.extend_from_slice(ek);
        format!(
            "{NATIVE_PUB_BEGIN}\n{}\n{NATIVE_PUB_END}\n",
            wrap64(&BASE64.encode(raw))
        )
    }

    fn native_id(level: MlKemLevel) -> u8 {
        match level {
            MlKemLevel::MlKem512 => 0x01,
            MlKemLevel::MlKem768 => 0x02,
            MlKemLevel::MlKem1024 => 0x03,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::native_armor_test_support::*;
    use super::*;

    // -----------------------------------------------------------------
    // Native armor: round-trip
    // -----------------------------------------------------------------

    #[test]
    fn native_public_round_trips_all_levels() {
        for (level, len) in [
            (MlKemLevel::MlKem512, 800),
            (MlKemLevel::MlKem768, 1184),
            (MlKemLevel::MlKem1024, 1568),
        ] {
            let ek: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let armored = armor_native_public(level, &ek);
            let imported = parse_mlkem_key(&armored).unwrap();
            assert_eq!(imported.alg, level);
            assert_eq!(imported.ek, ek);
            assert_eq!(imported.secret, None);
            assert_eq!(imported.source, ImportSource::GraffitoNative);
        }
    }

    #[test]
    fn native_private_round_trips_768_and_1024() {
        for level in [MlKemLevel::MlKem768, MlKemLevel::MlKem1024] {
            let mut seed = [0u8; 64];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = (i * 7 + 3) as u8;
            }
            let armored = armor_native_private(level, &seed);
            let imported = parse_mlkem_key(&armored).unwrap();
            assert_eq!(imported.alg, level);
            assert_eq!(imported.ek.len(), level.ek_len());
            assert_eq!(
                imported.secret,
                Some(MlKemSecretMaterial::Seed(seed))
            );

            // The derived ek must match a fresh, independent derivation.
            let ek_again = derive_ek_from_seed(level, &seed).unwrap();
            assert_eq!(imported.ek, ek_again);
        }
    }

    #[test]
    fn native_private_512_reports_the_real_gap_instead_of_faking_it() {
        let seed = [0x42u8; 64];
        let armored = armor_native_private(MlKemLevel::MlKem512, &seed);
        let err = parse_mlkem_key(&armored).unwrap_err();
        assert!(matches!(err, ImportError::WrongAlg(_)));
    }

    #[test]
    fn native_rejects_wrong_end_label() {
        let ek = vec![0u8; 1184];
        let mut armored = armor_native_public(MlKemLevel::MlKem768, &ek);
        armored = armored.replace(NATIVE_PUB_END, NATIVE_PRIV_END);
        let err = parse_mlkem_key(&armored).unwrap_err();
        assert!(matches!(err, ImportError::ParseFailed(_)));
    }

    #[test]
    fn native_rejects_bad_version_byte() {
        let mut raw = vec![0x02u8, 0x02]; // wrong version (0x02, not 0x01)
        raw.extend_from_slice(&[0u8; 1184]);
        let armored = format!(
            "{NATIVE_PUB_BEGIN}\n{}\n{NATIVE_PUB_END}\n",
            wrap64(&BASE64.encode(raw))
        );
        let err = parse_mlkem_key(&armored).unwrap_err();
        assert!(matches!(err, ImportError::ParseFailed(_)));
    }

    #[test]
    fn native_rejects_wrong_payload_length() {
        let ek_too_short = vec![0u8; 1183]; // one byte short of 768's 1184
        let armored = armor_native_public(MlKemLevel::MlKem768, &ek_too_short);
        let err = parse_mlkem_key(&armored).unwrap_err();
        assert!(matches!(err, ImportError::ParseFailed(_)));

        let mut raw = vec![NATIVE_FORMAT_VERSION, 0x02];
        raw.extend_from_slice(&[0u8; 63]); // one byte short of the 64-byte seed
        let armored = format!(
            "{NATIVE_PRIV_BEGIN}\n{}\n{NATIVE_PRIV_END}\n",
            wrap64(&BASE64.encode(raw))
        );
        let err = parse_mlkem_key(&armored).unwrap_err();
        assert!(matches!(err, ImportError::ParseFailed(_)));
    }

    #[test]
    fn native_rejects_unrecognized_level_id() {
        let mut raw = vec![NATIVE_FORMAT_VERSION, 0x09]; // no such level
        raw.extend_from_slice(&[0u8; 64]);
        let armored = format!(
            "{NATIVE_PRIV_BEGIN}\n{}\n{NATIVE_PRIV_END}\n",
            wrap64(&BASE64.encode(raw))
        );
        let err = parse_mlkem_key(&armored).unwrap_err();
        assert!(matches!(err, ImportError::WrongAlg(_)));
    }

    #[test]
    fn totally_unrecognized_input_is_not_pgp() {
        assert_eq!(parse_mlkem_key("hello world").unwrap_err(), ImportError::NotPgp);
        assert_eq!(parse_mlkem_key("").unwrap_err(), ImportError::NotPgp);
    }

    // -----------------------------------------------------------------
    // OpenPGP: fixture generation (mirrors pgp-core's generate_pqc_hybrid)
    // -----------------------------------------------------------------

    fn generate_pqc_hybrid(
        name: &str,
        email: &str,
        passphrase: Option<&str>,
    ) -> SignedSecretKey {
        use pgp::composed::{KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
        use pgp::composed::EncryptionCaps;

        let mut subkey = SubkeyParamsBuilder::default();
        subkey
            .key_type(KeyType::MlKem768X25519)
            .can_encrypt(EncryptionCaps::All);
        if let Some(pw) = passphrase {
            subkey.passphrase(Some(pw.to_string()));
        }
        let subkey = subkey.build().unwrap();

        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(format!("{name} <{email}>"))
            .subkeys(vec![subkey]);
        if let Some(pw) = passphrase {
            params.passphrase(Some(pw.to_string()));
        }
        let params = params.build().unwrap();

        let key = params.generate(rand::thread_rng()).unwrap();
        key.verify_bindings().unwrap();
        key
    }

    fn generate_classical_only(name: &str, email: &str) -> SignedSecretKey {
        use pgp::composed::{KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder};
        use pgp::composed::EncryptionCaps;

        let mut subkey = SubkeyParamsBuilder::default();
        subkey
            .key_type(KeyType::X25519)
            .can_encrypt(EncryptionCaps::All);
        let subkey = subkey.build().unwrap();

        let mut params = SecretKeyParamsBuilder::default();
        params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(format!("{name} <{email}>"))
            .subkeys(vec![subkey]);
        let params = params.build().unwrap();

        let key = params.generate(rand::thread_rng()).unwrap();
        key.verify_bindings().unwrap();
        key
    }

    fn armor_secret(key: &SignedSecretKey) -> String {
        use pgp::composed::ArmorOptions;
        key.to_armored_string(ArmorOptions::default()).unwrap()
    }

    fn armor_public(key: &pgp::composed::SignedPublicKey) -> String {
        use pgp::composed::ArmorOptions;
        key.to_armored_string(ArmorOptions::default()).unwrap()
    }

    // -----------------------------------------------------------------
    // Core evidence: extracted ek/secret really encapsulate/decapsulate
    // together, cross-checked against the standalone `ml-kem` crate.
    // -----------------------------------------------------------------

    #[test]
    fn openpgp_secret_key_extraction_round_trips_through_ml_kem() {
        use ml_kem::kem::{Decapsulate, Encapsulate};
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

        let key = generate_pqc_hybrid("Alice", "alice@example.com", None);
        let expected_fingerprint = key.fingerprint().to_string();
        let armored = armor_secret(&key);

        let imported = parse_mlkem_key(&armored).unwrap();
        assert_eq!(imported.alg, MlKemLevel::MlKem768);
        assert_eq!(imported.ek.len(), 1184);
        let ImportSource::OpenPgp {
            fingerprint,
            primary_uid,
        } = imported.source.clone()
        else {
            panic!("expected an OpenPgp source");
        };
        assert_eq!(fingerprint, expected_fingerprint);
        assert_eq!(primary_uid.as_deref(), Some("Alice <alice@example.com>"));

        let Some(MlKemSecretMaterial::Seed(seed)) = imported.secret else {
            panic!("expected Seed secret material (see module docs: rpgp never expands)");
        };

        // Re-expand the secret side independently via the standalone
        // ml-kem crate (dev-dep only) to prove the extracted ek/seed are a
        // genuine matching keypair, not just correctly-shaped bytes.
        let d: [u8; 32] = seed[..32].try_into().unwrap();
        let z: [u8; 32] = seed[32..].try_into().unwrap();
        let (dk, ek_from_seed) = MlKem768::generate_deterministic(&d.into(), &z.into());
        assert_eq!(ek_from_seed.as_bytes().as_slice(), imported.ek.as_slice());

        let ek_arr: [u8; 1184] = imported.ek.as_slice().try_into().unwrap();
        let ek_typed =
            ml_kem::kem::EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(&ek_arr.into());
        let (ciphertext, shared_secret_enc) =
            ek_typed.encapsulate(&mut rand::thread_rng()).unwrap();
        let shared_secret_dec = dk.decapsulate(&ciphertext).unwrap();
        assert_eq!(shared_secret_enc, shared_secret_dec);
    }

    #[test]
    fn openpgp_public_only_cert_has_no_secret() {
        let key = generate_pqc_hybrid("Bob", "bob@example.com", None);
        let public = key.to_public_key();
        let armored = armor_public(&public);

        let imported = parse_mlkem_key(&armored).unwrap();
        assert_eq!(imported.alg, MlKemLevel::MlKem768);
        assert_eq!(imported.ek.len(), 1184);
        assert_eq!(imported.secret, None);
        assert!(matches!(imported.source, ImportSource::OpenPgp { .. }));
    }

    #[test]
    fn openpgp_classical_only_key_is_no_pqc_key() {
        let key = generate_classical_only("Carol", "carol@example.com");
        let armored = armor_secret(&key);
        let err = parse_mlkem_key(&armored).unwrap_err();
        assert_eq!(err, ImportError::NoPqcKey);
    }

    #[test]
    fn openpgp_passphrase_protected_secret_is_protected() {
        let key = generate_pqc_hybrid("Dave", "dave@example.com", Some("hunter2"));
        let armored = armor_secret(&key);
        let err = parse_mlkem_key(&armored).unwrap_err();
        assert_eq!(err, ImportError::Protected);
    }

    // -----------------------------------------------------------------
    // LibrePGP algorithm-8 detection
    // -----------------------------------------------------------------
    //
    // A full, self-signed TPK with an algorithm-8 subkey can't be built
    // through rpgp's `SubkeyParamsBuilder` (algorithm 8 has no KeyType
    // variant — rpgp doesn't implement LibrePGP's Kyber at all) or hand-
    // crafted without re-implementing OpenPGP signature packets from
    // scratch. What CAN be done, and is done here: hand-build a real
    // single-packet "certificate" (a lone Public-Key packet, version 4,
    // algorithm id 8, opaque key material) via rpgp's own packet types
    // (`PubKeyInner::new` + `PacketTrait::to_writer_with_header`), armor
    // it with rpgp's own `armor::write`, and feed that through the SAME
    // `parse_mlkem_key` entry point real input goes through.
    // `SignedPublicKeyParser` tolerates zero User IDs / signatures / subkeys
    // (see `composed/signed_key/key_parser.rs`), so this is a valid
    // (if minimal) OpenPGP TPK, not a synthetic shortcut — the detection
    // is exercised through real rpgp parsing, algorithm 8 included.

    struct RawBytes(Vec<u8>);
    impl pgp::ser::Serialize for RawBytes {
        fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> pgp::errors::Result<()> {
            writer.write_all(&self.0)?;
            Ok(())
        }
        fn write_len(&self) -> usize {
            self.0.len()
        }
    }

    fn librepgp_kyber_public_key_armor() -> String {
        use pgp::armor::{self, BlockType};
        use pgp::crypto::public_key::PublicKeyAlgorithm;
        use pgp::packet::{PacketTrait, PublicKey as PgpPublicKey};
        use pgp::types::{KeyVersion, Timestamp};

        let params = PublicParams::Unknown {
            data: pgp::bytes::Bytes::from(vec![0xAAu8; 64]),
        };
        let key = PgpPublicKey::from_inner(
            pgp::packet::PubKeyInner::new(
                KeyVersion::V4,
                PublicKeyAlgorithm::Unknown(LIBREPGP_KYBER_ALGORITHM_ID),
                Timestamp::from_secs(1_700_000_000),
                None,
                params,
            )
            .unwrap(),
        )
        .unwrap();

        let mut framed = Vec::new();
        key.to_writer_with_header(&mut framed).unwrap();

        let mut out = Vec::new();
        armor::write(&RawBytes(framed), BlockType::PublicKey, &mut out, None, true).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn librepgp_kyber_algorithm_id_is_detected_via_real_rpgp_parsing() {
        let armored = librepgp_kyber_public_key_armor();
        let err = parse_mlkem_key(&armored).unwrap_err();
        assert_eq!(err, ImportError::LibrePgpKyber);
    }

    /// Fallback per the task spec: also pin the raw detection directly on
    /// the algorithm id, independent of the packet-construction path above.
    #[test]
    fn librepgp_kyber_algorithm_id_mapping_is_pinned() {
        assert_eq!(LIBREPGP_KYBER_ALGORITHM_ID, 8);
        assert_eq!(RFC9980_MLKEM768_X25519_ALGORITHM_ID, 35);
        assert_ne!(LIBREPGP_KYBER_ALGORITHM_ID, RFC9980_MLKEM768_X25519_ALGORITHM_ID);
    }

    // -----------------------------------------------------------------
    // Malformed-input handling
    // -----------------------------------------------------------------

    #[test]
    fn garbage_pgp_armor_is_parse_failed_not_a_panic() {
        let armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nnotbase64!!!\n-----END PGP PUBLIC KEY BLOCK-----\n";
        let err = parse_mlkem_key(armored).unwrap_err();
        assert!(matches!(err, ImportError::ParseFailed(_)));
    }
}
