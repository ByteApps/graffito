//! Per-notebook seed-derived ML-KEM receive keys (post-quantum note
//! support, `../../PLAN-graffito-pq-hybrid.md`) — one keypair per
//! (notebook leaf secret, ML-KEM level), deterministic from the
//! notebook's own leaf secret so recovery from the seed words reproduces
//! exactly the same key every time (same principle as the notes/ECDH key,
//! `derive::identity_from_leaf` — no key material this module derives is
//! ever generated fresh and thrown away).
//!
//! # Derivation — NEW domain, FROZEN once shipped
//!
//! ```text
//! seed64 = HKDF-SHA256(salt = "graffito/mlkem/v1", ikm = leaf_secret)
//!            .expand(info = "seed/v1" || alg_id(1), 64)
//! MlKemKeypair::from_seed(alg, &seed64)
//! ```
//!
//! `leaf_secret` is the SAME per-notebook secret the notebook's notes-
//! encryption/ECDH key derives from (`AppIdentity::leaf_secret()` —
//! `None` for a watch-only identity, which therefore has no derived
//! ML-KEM receive key either: importing an external key via
//! [`set_contact_pq_key`]/`pgp_import` is the only pq door open to a
//! watch-only wallet — for RECEIVING it would need a key it can decrypt
//! with, which watch-only structurally can't have, so this only matters
//! for a watch identity's own outgoing compose). `alg_id` is
//! `notes_core::pq::MlKemAlg::id()` — folding it into the HKDF `info`
//! makes the three levels independent draws from the same `leaf_secret`,
//! never the same seed truncated/reused three ways, so compromising one
//! level's decapsulation key reveals nothing about the other two.
//!
//! # Why per-notebook, not per-identity
//!
//! Every notebook already has its own notes/ECDH key (rev 3, "each index
//! is a notebook — its own address AND its own note-encryption key"); a
//! pq receive key is additive machinery on top of the SAME notebook, not
//! a new identity concept, so it derives from the SAME `leaf_secret` a
//! caller already has in hand for that notebook (`AppIdentity::
//! leaf_secret()`/`identity::realize`'s leaf) — no new derivation path
//! into the seed tree.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use notes_core::pq::{MlKemAlg, MlKemKeypair, MlKemSecret};

use crate::passphrase::MlKemLevel;

const MLKEM_SALT: &[u8] = b"graffito/mlkem/v1";
const MLKEM_INFO_PREFIX: &[u8] = b"seed/v1";

/// [`MlKemLevel`] (this crate's UI-facing enum, also used by
/// `passphrase::SecurityChoice`) <-> [`MlKemAlg`] (notes-core's crypto-
/// facing enum, also used by `compose::ComposeRequest::pq_mlkem`) — the
/// two exist for different audiences (UI copy/labels vs. the actual
/// `SealLayers` the compose path builds) but always name the same three
/// parameter sets, so converting between them is total in both
/// directions.
pub fn pq_alg(level: MlKemLevel) -> MlKemAlg {
    match level {
        MlKemLevel::MlKem512 => MlKemAlg::MlKem512,
        MlKemLevel::MlKem768 => MlKemAlg::MlKem768,
        MlKemLevel::MlKem1024 => MlKemAlg::MlKem1024,
    }
}

/// The inverse of [`pq_alg`].
pub fn from_pq_alg(alg: MlKemAlg) -> MlKemLevel {
    match alg {
        MlKemAlg::MlKem512 => MlKemLevel::MlKem512,
        MlKemAlg::MlKem768 => MlKemLevel::MlKem768,
        MlKemAlg::MlKem1024 => MlKemLevel::MlKem1024,
    }
}

/// The module doc's HKDF step alone (seed derivation, no ML-KEM keygen) —
/// broken out so [`derive_keypair`] and any future caller that only needs
/// the seed (never the expensive keygen) share one implementation.
/// Zeroizing: the 64-byte seed is exactly as sensitive as the
/// decapsulation key it deterministically reconstructs.
fn derive_seed64(leaf_secret: &[u8; 32], alg: MlKemAlg) -> Zeroizing<[u8; 64]> {
    let hk = Hkdf::<Sha256>::new(Some(MLKEM_SALT), leaf_secret);
    let mut info = Vec::with_capacity(MLKEM_INFO_PREFIX.len() + 1);
    info.extend_from_slice(MLKEM_INFO_PREFIX);
    info.push(alg.id());
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(&info, &mut *okm).expect("64 bytes is a valid HKDF length");
    okm
}

/// Deterministically derive this notebook's ML-KEM receive keypair at
/// `alg` from its `leaf_secret` — see the module doc for the exact
/// derivation. Infallible (HKDF expand to a fixed 64-byte length never
/// fails, and `MlKemKeypair::from_seed` is deterministic keygen, no
/// entropy draw).
pub fn derive_keypair(leaf_secret: &[u8; 32], alg: MlKemAlg) -> MlKemKeypair {
    let seed = derive_seed64(leaf_secret, alg);
    MlKemKeypair::from_seed(alg, &seed)
}

/// [`derive_keypair`] at all three levels, as decapsulation secrets —
/// the set a scan tries against every RECEIVED, KEM-flagged locked note
/// (`store::Store::apply_bundle`'s `mlkem_secrets` parameter,
/// `store::Store::unlock_note`'s `secrets` parameter). Order is
/// `[512, 768, 1024]`; callers that also hold imported secrets append
/// those themselves — this function only ever returns the notebook's OWN
/// derived keys.
pub fn derive_secrets(leaf_secret: &[u8; 32]) -> Vec<MlKemSecret> {
    [MlKemAlg::MlKem512, MlKemAlg::MlKem768, MlKemAlg::MlKem1024]
        .into_iter()
        .map(|alg| derive_keypair(leaf_secret, alg).secret())
        .collect()
}

/// Graffito-native PRIVATE armor for a derived (or any other) keypair —
/// thin passthrough to `notes_core::pq::export_private` so callers never
/// need to reach into notes-core directly for this.
pub fn export_private_armor(kp: &MlKemKeypair) -> String {
    notes_core::pq::export_private(kp.alg(), kp.seed())
}

/// Graffito-native PUBLIC armor — what a contact receives when sharing
/// this notebook's pq receive key (round-trips through
/// [`crate::pgp_import::parse_mlkem_key`]/[`set_contact_pq_key`] on the
/// other end).
pub fn export_public_armor(kp: &MlKemKeypair) -> String {
    notes_core::pq::export_public(kp.alg(), kp.ek())
}

/// Human-checkable fingerprint (short hex, grouped in fours) — passthrough
/// to `MlKemKeypair::fingerprint`, exposed here so callers that only
/// import app-core's `pqkeys` module (not notes-core directly) can still
/// show a confirmation string after a keypair derivation or import.
pub fn fingerprint(kp: &MlKemKeypair) -> String {
    kp.fingerprint()
}

/// Bridge a successful [`crate::pgp_import::parse_mlkem_key`] SECRET-key
/// import into this crate's own native PRIVATE armor — the ONE form the
/// app layer persists an imported ML-KEM secret in (its `pq-imported`
/// keychain account), regardless of whether the original was an OpenPGP
/// key or graffito-native armor. Also hands back the reconstructed
/// [`MlKemKeypair`] so the caller can show a fingerprint/level immediately
/// without re-parsing the armor it just wrote.
///
/// Errors:
/// - `imported.secret` is `None` (a public-only key/cert): "public key
///   only — it can't receive notes; import it on a contact instead" — the
///   exact UI-facing guidance for this case (use [`set_contact_pq_key`]
///   instead).
/// - `imported.secret` is [`crate::pgp_import::MlKemSecretMaterial::Expanded`]:
///   this crate's native private armor only has a slot for the 64-byte
///   seed form (see `pgp_import`'s module doc for why every real source —
///   rpgp 0.20 and graffito-native alike — is Seed-only in practice; this
///   branch exists only so the match stays exhaustive against the wider
///   wire format `MlKemSecretMaterial` documents).
pub fn import_to_native_private(
    imported: &crate::pgp_import::ImportedMlKem,
) -> Result<(MlKemKeypair, String), String> {
    use crate::pgp_import::MlKemSecretMaterial;

    let seed = match &imported.secret {
        Some(MlKemSecretMaterial::Seed(s)) => *s,
        Some(MlKemSecretMaterial::Expanded(_)) => {
            return Err(
                "this key's secret material is in an expanded form this app can't store — \
                 re-export it from its original source in seed form"
                    .into(),
            );
        }
        None => {
            return Err(
                "public key only — it can't receive notes; import it on a contact instead".into(),
            );
        }
    };
    let alg = MlKemAlg::from_id(match imported.alg {
        crate::pgp_import::MlKemLevel::MlKem512 => 0x01,
        crate::pgp_import::MlKemLevel::MlKem768 => 0x02,
        crate::pgp_import::MlKemLevel::MlKem1024 => 0x03,
    })
    .expect("pgp_import::MlKemLevel always maps to a valid MlKemAlg id");
    let kp = MlKemKeypair::from_seed(alg, &seed);
    let armor = export_private_armor(&kp);
    Ok((kp, armor))
}

/// Where a notebook's (or a contact's) ML-KEM key comes from — persisted
/// by the app layer (Phase C) in its config, never here (app-core stores
/// no config of its own). The imported SECRET material itself is never
/// held by this type or by app-core at all: only its public fingerprint
/// and declared level, matching app-core's pure/host-testable design —
/// the app layer keychains any imported secret and passes it back in as
/// a plain [`MlKemSecret`] parameter wherever it's needed (`store::
/// Store::apply_bundle`/`unlock_note`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PqKeySource {
    /// This notebook's own seed-derived key at the given level —
    /// [`derive_keypair`]/[`derive_secrets`] reconstruct it on demand from
    /// the notebook's `leaf_secret`; nothing about it needs to be stored
    /// beyond which level was chosen.
    Derived(MlKemLevel),
    /// An externally supplied key (an OpenPGP cert's ML-KEM subkey, or
    /// another graffito notebook's exported public key) — identified by
    /// its fingerprint so the UI can show/confirm which key is active
    /// without holding any secret material.
    Imported { fingerprint: String, alg: MlKemLevel },
}

/// Accepts either graffito-native PUBLIC armor or an OpenPGP cert/key
/// (routed through [`crate::pgp_import::parse_mlkem_key`] and re-armored
/// to native public form for storage — a `Contact` only ever holds the
/// native form, never OpenPGP framing) and sets `contact.mlkem_ek`,
/// returning the key's fingerprint for the UI to show as confirmation.
///
/// A SECRET-carrying input (an OpenPGP secret key, or graffito-native
/// PRIVATE armor) is accepted too — only its PUBLIC half is ever stored
/// on the contact (a contact's pq key exists to seal notes TO them, never
/// to decrypt anything ourselves), so no secret material leaks into
/// `Contact::mlkem_ek` even if the caller pastes a full private export by
/// mistake.
pub fn set_contact_pq_key(
    contact: &mut crate::store::Contact,
    input: &str,
) -> Result<String, crate::Error> {
    use notes_core::pq::{export_public, fingerprint as pq_fingerprint, import_public};

    // Native public armor first (the common case: a contact shared their
    // exported key directly) — falls through to the OpenPGP/native-private
    // importer for everything else.
    let (alg, ek) = match import_public(input) {
        Ok(v) => v,
        Err(_) => {
            let imported = crate::pgp_import::parse_mlkem_key(input)
                .map_err(|e| crate::Error::Store(e.to_string()))?;
            let alg = MlKemAlg::from_id(match imported.alg {
                crate::pgp_import::MlKemLevel::MlKem512 => 0x01,
                crate::pgp_import::MlKemLevel::MlKem768 => 0x02,
                crate::pgp_import::MlKemLevel::MlKem1024 => 0x03,
            })
            .expect("pgp_import::MlKemLevel always maps to a valid MlKemAlg id");
            (alg, imported.ek)
        }
    };

    let fp = pq_fingerprint(alg, &ek);
    contact.mlkem_ek = Some(export_public(alg, &ek));
    Ok(fp)
}

/// The compose screen's Quantum-encryption-row caption for a contact's
/// stored pq key: `(level, "<level name> · <fingerprint>")` on success. A
/// `Contact::mlkem_ek` is ALWAYS graffito-native public armor by
/// construction (`set_contact_pq_key` above never stores OpenPGP framing
/// on a contact), so this goes straight through `notes_core::pq::
/// import_public` rather than the fuller `pgp_import::parse_mlkem_key`
/// auto-detection that import-time parsing needs — pure formatting, no
/// crypto, safe to call on every recipient change without re-deriving
/// anything. Callers are expected to cache the result and only recompute
/// it when the resolved recipient address changes (parsing an armored
/// blob on every UI repaint would be wasted work, not incorrectness).
pub fn contact_pq_display(armor: &str) -> Result<(MlKemLevel, String), String> {
    use notes_core::pq::{fingerprint as pq_fingerprint, import_public};
    let (alg, ek) = import_public(armor).map_err(|e| e.to_string())?;
    let level = from_pq_alg(alg);
    Ok((level, format!("{} · {}", level.name(), pq_fingerprint(alg, &ek))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Contact;

    fn leaf(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    // ---- alg/level conversion ------------------------------------------

    #[test]
    fn pq_alg_and_from_pq_alg_are_inverses() {
        for level in [MlKemLevel::MlKem512, MlKemLevel::MlKem768, MlKemLevel::MlKem1024] {
            assert_eq!(from_pq_alg(pq_alg(level)), level);
        }
    }

    #[test]
    fn mlkem_level_serde_round_trips_as_plain_variant_names() {
        for (level, name) in [
            (MlKemLevel::MlKem512, "\"MlKem512\""),
            (MlKemLevel::MlKem768, "\"MlKem768\""),
            (MlKemLevel::MlKem1024, "\"MlKem1024\""),
        ] {
            let json = serde_json::to_string(&level).unwrap();
            assert_eq!(json, name);
            let back: MlKemLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(back, level);
        }
    }

    // ---- derivation: determinism + independence ------------------------

    #[test]
    fn derive_keypair_is_deterministic() {
        let l = leaf(0x11);
        let a = derive_keypair(&l, MlKemAlg::MlKem768);
        let b = derive_keypair(&l, MlKemAlg::MlKem768);
        assert_eq!(a.ek(), b.ek());
        assert_eq!(a.seed(), b.seed());
    }

    #[test]
    fn different_leaf_secrets_derive_different_keys() {
        let a = derive_keypair(&leaf(0x11), MlKemAlg::MlKem768);
        let b = derive_keypair(&leaf(0x22), MlKemAlg::MlKem768);
        assert_ne!(a.ek(), b.ek());
        assert_ne!(a.seed(), b.seed());
    }

    #[test]
    fn different_levels_of_the_same_leaf_are_independent_draws() {
        // Same leaf_secret, three levels: not only must the eks differ
        // (they're different lengths anyway), the SEEDS must differ too —
        // proving the alg id genuinely folds into the HKDF info rather
        // than the three levels sharing one expansion.
        let l = leaf(0x33);
        let k512 = derive_keypair(&l, MlKemAlg::MlKem512);
        let k768 = derive_keypair(&l, MlKemAlg::MlKem768);
        let k1024 = derive_keypair(&l, MlKemAlg::MlKem1024);
        assert_ne!(k512.seed(), k768.seed());
        assert_ne!(k768.seed(), k1024.seed());
        assert_ne!(k512.seed(), k1024.seed());
    }

    #[test]
    fn derive_secrets_returns_all_three_levels_matching_derive_keypair() {
        let l = leaf(0x44);
        let secrets = derive_secrets(&l);
        assert_eq!(secrets.len(), 3);
        for (alg, secret) in
            [MlKemAlg::MlKem512, MlKemAlg::MlKem768, MlKemAlg::MlKem1024].into_iter().zip(&secrets)
        {
            let kp = derive_keypair(&l, alg);
            let MlKemSecret::Seed(seed) = secret else {
                panic!("derive_secrets must hand back Seed-form secrets");
            };
            assert_eq!(*seed, *kp.seed());
        }
    }

    // ---- FROZEN-once-shipped derivation vectors -------------------------
    //
    // Pinned ek-prefix vectors for a fixed leaf_secret, one per level — if
    // this ever fails, the derivation changed (HKDF salt/info, or which
    // bytes MlKemKeypair::from_seed reads as (d, z)) and every already-
    // shared pq receive key on a real device would silently stop matching
    // what a contact has stored. Do not "fix" this test by updating the
    // hex; treat a failure here as SHIP-BLOCKING.

    const FIXED_LEAF: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];

    #[test]
    fn pinned_derivation_vectors_per_level() {
        for (alg, expected_ek_prefix_hex, expected_len) in [
            (MlKemAlg::MlKem512, "0b629735573ce73b363d2acc1ad998c4", 800usize),
            (MlKemAlg::MlKem768, "7cbbcf17294071d7674ffb5618848fa5", 1184usize),
            (MlKemAlg::MlKem1024, "7f7a36d7b029f0088dc9e970d5304f5f", 1568usize),
        ] {
            let kp = derive_keypair(&FIXED_LEAF, alg);
            assert_eq!(kp.ek().len(), expected_len);
            let prefix_hex = hex::encode(&kp.ek()[..16]);
            assert_eq!(
                prefix_hex, expected_ek_prefix_hex,
                "derivation for {alg:?} changed — this is a FROZEN-once-shipped vector"
            );
        }
    }

    // ---- armor / fingerprint passthroughs -------------------------------

    #[test]
    fn export_private_and_public_armor_round_trip_via_notes_core() {
        let kp = derive_keypair(&leaf(0x55), MlKemAlg::MlKem768);
        let priv_armor = export_private_armor(&kp);
        let pub_armor = export_public_armor(&kp);

        let (alg, seed) = notes_core::pq::import_private(&priv_armor).unwrap();
        assert_eq!(alg, MlKemAlg::MlKem768);
        assert_eq!(&seed, kp.seed());

        let (alg2, ek) = notes_core::pq::import_public(&pub_armor).unwrap();
        assert_eq!(alg2, MlKemAlg::MlKem768);
        assert_eq!(ek, kp.ek());
    }

    #[test]
    fn fingerprint_matches_notes_core_directly() {
        let kp = derive_keypair(&leaf(0x66), MlKemAlg::MlKem1024);
        assert_eq!(fingerprint(&kp), kp.fingerprint());
        assert_eq!(fingerprint(&kp), notes_core::pq::fingerprint(MlKemAlg::MlKem1024, kp.ek()));
    }

    // ---- import_to_native_private ----------------------------------------

    #[test]
    fn import_to_native_private_accepts_seed_form() {
        use crate::pgp_import::{ImportSource, ImportedMlKem, MlKemLevel as PgpLevel, MlKemSecretMaterial};

        let seed = [0x42u8; 64];
        let expected = MlKemKeypair::from_seed(MlKemAlg::MlKem768, &seed);
        let imported = ImportedMlKem {
            ek: expected.ek().to_vec(),
            secret: Some(MlKemSecretMaterial::Seed(seed)),
            source: ImportSource::GraffitoNative,
            alg: PgpLevel::MlKem768,
        };

        let (kp, armor) = import_to_native_private(&imported).unwrap();
        assert_eq!(kp.alg(), MlKemAlg::MlKem768);
        assert_eq!(kp.seed(), &seed);
        assert_eq!(kp.ek(), expected.ek());

        let (alg, round_seed) = notes_core::pq::import_private(&armor).unwrap();
        assert_eq!(alg, MlKemAlg::MlKem768);
        assert_eq!(round_seed, seed);
    }

    #[test]
    fn import_to_native_private_rejects_public_only() {
        use crate::pgp_import::{ImportSource, ImportedMlKem, MlKemLevel as PgpLevel};

        let imported = ImportedMlKem {
            ek: vec![0u8; MlKemAlg::MlKem768.ek_len()],
            secret: None,
            source: ImportSource::GraffitoNative,
            alg: PgpLevel::MlKem768,
        };
        let err = match import_to_native_private(&imported) {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        };
        assert!(err.contains("public key only"), "unexpected error: {err}");
    }

    #[test]
    fn import_to_native_private_rejects_expanded_form() {
        use crate::pgp_import::{ImportSource, ImportedMlKem, MlKemLevel as PgpLevel, MlKemSecretMaterial};

        let imported = ImportedMlKem {
            ek: vec![0u8; MlKemAlg::MlKem768.ek_len()],
            secret: Some(MlKemSecretMaterial::Expanded(vec![0u8; 2400])),
            source: ImportSource::GraffitoNative,
            alg: PgpLevel::MlKem768,
        };
        let err = match import_to_native_private(&imported) {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        };
        assert!(err.contains("expanded"), "unexpected error: {err}");
    }

    // ---- set_contact_pq_key ---------------------------------------------

    fn blank_contact() -> Contact {
        Contact {
            address: "bcrt1paddr".into(),
            name: String::new(),
            network: "regtest".into(),
            updated_at: 0,
            synced: false,
            mlkem_ek: None,
        }
    }

    #[test]
    fn set_contact_pq_key_accepts_native_public_armor() {
        let kp = derive_keypair(&leaf(0x77), MlKemAlg::MlKem768);
        let armor = export_public_armor(&kp);
        let mut c = blank_contact();

        let fp = set_contact_pq_key(&mut c, &armor).unwrap();
        assert_eq!(fp, kp.fingerprint());
        assert!(c.mlkem_ek.is_some());

        // Stored form re-parses to the exact same (alg, ek).
        let (alg, ek) = notes_core::pq::import_public(c.mlkem_ek.as_deref().unwrap()).unwrap();
        assert_eq!(alg, MlKemAlg::MlKem768);
        assert_eq!(ek, kp.ek());
    }

    #[test]
    fn set_contact_pq_key_accepts_native_private_armor_but_stores_only_public() {
        // A user pastes a PRIVATE export by mistake (or on purpose, to
        // register "my own" key as a contact for self-testing) — only the
        // public half must ever land on the contact.
        let kp = derive_keypair(&leaf(0x88), MlKemAlg::MlKem512);
        let priv_armor = export_private_armor(&kp);
        let mut c = blank_contact();

        let fp = set_contact_pq_key(&mut c, &priv_armor).unwrap();
        assert_eq!(fp, kp.fingerprint());
        let stored = c.mlkem_ek.clone().unwrap();
        assert!(stored.contains("PUBLIC KEY"));
        assert!(!stored.contains("PRIVATE KEY"));
        let (alg, ek) = notes_core::pq::import_public(&stored).unwrap();
        assert_eq!(alg, MlKemAlg::MlKem512);
        assert_eq!(ek, kp.ek());
    }

    #[test]
    fn set_contact_pq_key_rejects_garbage() {
        let mut c = blank_contact();
        let err = set_contact_pq_key(&mut c, "not a key at all");
        assert!(err.is_err());
        assert!(c.mlkem_ek.is_none());
    }

    #[test]
    fn set_contact_pq_key_overwrites_a_previous_key() {
        let kp1 = derive_keypair(&leaf(0x99), MlKemAlg::MlKem512);
        let kp2 = derive_keypair(&leaf(0xaa), MlKemAlg::MlKem1024);
        let mut c = blank_contact();
        set_contact_pq_key(&mut c, &export_public_armor(&kp1)).unwrap();
        let fp2 = set_contact_pq_key(&mut c, &export_public_armor(&kp2)).unwrap();
        assert_eq!(fp2, kp2.fingerprint());
        let (alg, ek) = notes_core::pq::import_public(c.mlkem_ek.as_deref().unwrap()).unwrap();
        assert_eq!(alg, MlKemAlg::MlKem1024);
        assert_eq!(ek, kp2.ek());
    }

    // ---- contact_pq_display ---------------------------------------------

    #[test]
    fn contact_pq_display_reports_level_and_fingerprint() {
        let kp = derive_keypair(&leaf(0x55), MlKemAlg::MlKem1024);
        let armor = export_public_armor(&kp);
        let (level, line) = contact_pq_display(&armor).unwrap();
        assert_eq!(level, MlKemLevel::MlKem1024);
        assert!(line.starts_with("ML-KEM-1024 · "));
        assert!(line.contains(&kp.fingerprint()));
    }

    #[test]
    fn contact_pq_display_matches_the_actual_stored_form() {
        // Exactly the round trip the compose screen exercises: set a
        // contact's key via set_contact_pq_key, then feed the STORED
        // armor (not the original export) into contact_pq_display.
        let kp = derive_keypair(&leaf(0x66), MlKemAlg::MlKem512);
        let mut c = blank_contact();
        set_contact_pq_key(&mut c, &export_public_armor(&kp)).unwrap();
        let (level, line) = contact_pq_display(c.mlkem_ek.as_deref().unwrap()).unwrap();
        assert_eq!(level, MlKemLevel::MlKem512);
        assert!(line.contains(&kp.fingerprint()));
    }

    #[test]
    fn contact_pq_display_rejects_garbage() {
        assert!(contact_pq_display("not a key").is_err());
    }
}
