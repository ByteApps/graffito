//! BIP-39 bit-length contract for the "create a new seed" door
//! (`generate_mnemonic` / `generate_mnemonic_with_salt`), plus the salt
//! security property: mixing in a salt must never make the CSPRNG
//! optional.
//!
//! `app-core/tests/import.rs` already covers round-tripping and basic
//! distinctness for the unsalted generator; this file is scoped to what
//! the entropy-hardening pass (see `tests/entropy.rs`) added on top —
//! exact bit lengths, the full salted API surface, and the property that
//! makes the salt safe: it can only ADD randomness, never substitute for
//! the OS CSPRNG.

#[path = "common/entropy_battery.rs"]
mod battery;

use app_core::identity::{generate_mnemonic, generate_mnemonic_with_salt, parse_key_material};
use app_core::notes_core::Network;
use app_core::Error;

const LENGTHS: [(usize, usize); 3] = [(12, 16), (18, 24), (24, 32)];

// ------------------------- bit-length contract -------------------------

/// `generate_mnemonic(N)` must yield exactly the BIP-39 entropy length for
/// N words (128/192/256 bits), and the resulting mnemonic must itself
/// report that same word count.
#[test]
fn generate_mnemonic_bit_lengths() {
    for (words, bytes) in LENGTHS {
        let m = generate_mnemonic(words).unwrap();
        assert_eq!(m.to_entropy().len(), bytes, "{words}-word mnemonic must carry {bytes} bytes of entropy");
        assert_eq!(m.word_count(), words);
    }
}

/// Every generated mnemonic must re-parse through the app's own importer
/// (BIP-39 checksum valid) — not just through `bip39` in isolation.
#[test]
fn generate_mnemonic_reparses_through_importer() {
    for (words, _) in LENGTHS {
        for _ in 0..20 {
            let m = generate_mnemonic(words).unwrap();
            let parsed = parse_key_material(&m.to_string(), Network::Mainnet)
                .unwrap_or_else(|e| panic!("generated {words}-word mnemonic failed to re-parse: {e}"));
            assert!(matches!(parsed, app_core::identity::KeyMaterial::Mnemonic(_)));
        }
    }
}

/// Word counts outside {12, 18, 24} are rejected with `MnemonicWordCount`
/// carrying the count that was asked for — this is the caller-facing
/// contract, so a caller can render "N is not a valid length" directly
/// off the error.
#[test]
fn generate_mnemonic_rejects_bad_word_counts() {
    for n in [15usize, 21, 0, 11, 25] {
        assert!(
            matches!(generate_mnemonic(n), Err(Error::MnemonicWordCount(got)) if got == n),
            "word count {n} must be rejected as MnemonicWordCount({n})"
        );
        assert!(
            matches!(generate_mnemonic_with_salt(n, "some salt"), Err(Error::MnemonicWordCount(got)) if got == n),
            "salted word count {n} must also be rejected as MnemonicWordCount({n})"
        );
    }
}

// ------------------------- salted generator -------------------------

/// The salted generator must carry the same bit-length contract as the
/// unsalted one.
#[test]
fn salted_bit_lengths() {
    for (words, bytes) in LENGTHS {
        let m = generate_mnemonic_with_salt(words, "correct horse battery staple").unwrap();
        assert_eq!(m.to_entropy().len(), bytes);
        assert_eq!(m.word_count(), words);
    }
}

/// Every salted mnemonic must also re-parse (checksum valid).
#[test]
fn salted_reparses_through_importer() {
    for (words, _) in LENGTHS {
        let m = generate_mnemonic_with_salt(words, "dice: 3 6 1 4 2 5").unwrap();
        parse_key_material(&m.to_string(), Network::Mainnet)
            .unwrap_or_else(|e| panic!("salted {words}-word mnemonic failed to re-parse: {e}"));
    }
}

/// An empty or whitespace-only salt must delegate to the unsalted path:
/// same bit-length contract, and — since the unsalted path still draws
/// fresh OS entropy on every call — still non-deterministic across calls
/// (an implementation that special-cased "no salt" into some fixed
/// derivation would fail this).
#[test]
fn empty_or_blank_salt_delegates_to_unsalted_path() {
    for salt in ["", "   ", "\t\n "] {
        let a = generate_mnemonic_with_salt(24, salt).unwrap();
        let b = generate_mnemonic_with_salt(24, salt).unwrap();
        assert_eq!(a.to_entropy().len(), 32);
        assert_ne!(
            a.to_string(),
            b.to_string(),
            "two calls with salt={salt:?} produced the same mnemonic — \
             the unsalted path must still draw fresh entropy each call"
        );
    }
}

/// **The security property that matters**: two calls with the SAME salt
/// must still differ. If they didn't, the salt would BE the entropy —
/// something a screen-shoulder-surfer or a value chosen from a small
/// dice-roll space could reproduce. Hashing `csprng ‖ salt` (see
/// `generate_mnemonic_with_salt`'s doc comment) means the CSPRNG draw
/// dominates regardless of how weak or repeated the salt is; this test
/// is the one that would fail if that mixing were ever reordered into
/// `salt ‖ csprng`-with-a-truncation bug or similar.
#[test]
fn same_salt_still_yields_different_mnemonics() {
    const SALT: &str = "fixed salt";
    let mut seen = std::collections::HashSet::new();
    for _ in 0..200 {
        let m = generate_mnemonic_with_salt(24, SALT).unwrap();
        assert!(
            seen.insert(m.to_string()),
            "generate_mnemonic_with_salt repeated an output under a FIXED salt — \
             the CSPRNG is not being genuinely mixed in"
        );
    }
}

/// Two different salts give two different mnemonics.
///
/// **This test cannot prove the salt is used at all** — the CSPRNG draw
/// differs between the two calls, so it would pass unchanged against an
/// implementation that ignored the salt entirely. It is a smoke test, and
/// the comment says so rather than letting a future reader mistake it for
/// coverage. Actually proving the salt reaches the hash needs an
/// injectable RNG, which `generate_mnemonic_with_salt` deliberately does
/// not expose; the property that genuinely matters is the one above
/// (a fixed salt must not make outputs repeat), and that one does
/// discriminate.
#[test]
fn different_salt_gives_different_mnemonic() {
    let a = generate_mnemonic_with_salt(24, "salt one").unwrap();
    let b = generate_mnemonic_with_salt(24, "salt two").unwrap();
    assert_ne!(a.to_string(), b.to_string());
}

/// Full statistical battery over the salted generator's output, fixed
/// salt included — the salt mixing step itself must not introduce bias,
/// truncation, or a reduced state space (`tests/entropy.rs` carries the
/// same battery for the unsalted `generate_mnemonic`; this is its salted
/// counterpart, prompted by the same disclosed class of bug).
#[test]
fn salted_generator_passes_battery() {
    fn salted_source(out: &mut [u8]) {
        let m = generate_mnemonic_with_salt(24, "fixed salt").expect("must succeed");
        out.copy_from_slice(&m.to_entropy());
    }
    let r = battery::battery_from(32, salted_source);
    println!("{}", r.summary());
    r.assert_ok("generate_mnemonic_with_salt(24, \"fixed salt\")");
}
