//! Passphrase strength estimation, one-tap generation, and security-label
//! copy for the optional post-quantum layers on directed private notes
//! (an Argon2id passphrase layer and an ML-KEM hybrid layer, composable —
//! see `../../PLAN-graffito-pq-hybrid.md` at the workspace level for the
//! encryption design; this module is the pure, UI-free logic the compose
//! screen's live strength meter, generator button, and security label all
//! read from). No key material, no crypto primitives — just numbers and
//! copy. Host-testable: `cargo test -p app-core`.
//!
//! # Why 128 bits (`REQUIRED_BITS`)
//!
//! A directed note's ciphertext sits on the blockchain forever, public,
//! and an attacker can try guesses entirely offline with no rate limit, no
//! lockout counter, nothing to trip. That is a different threat model from
//! a login form, where a handful of throttled online guesses is already
//! generous — so the zxcvbn 0-4 `Score` buckets (tuned for exactly that
//! throttled-login case) are the wrong yardstick here. 128 bits is the
//! number security consensus already treats as putting brute force out of
//! reach for an offline, unlimited-attempt attacker; Argon2id's own
//! memory-hardness slows each guess further, but that only ever multiplies
//! a guess budget that's finite to begin with — it can't manufacture
//! entropy the passphrase never had.
//!
//! And per the ColdCard RNG disclosure this workspace's own
//! `RANDOMNESS-AUDIT-2026-08-01.md` was prompted by: an entropy claim that
//! is only ever ASSUMED, never actually measured against what the user
//! typed, is exactly how a "strong passphrase" quietly turns out not to
//! be one. `estimate_bits`/`check` exist so the UI enforces the number
//! instead of hoping for it.
//!
//! # A load-bearing fact about zxcvbn 3.x: no typed input can clear 128 bits
//!
//! zxcvbn tracks its internal guess count as a plain `u64` throughout
//! (`saturating_mul`/`saturating_add` everywhere in its scoring code), and
//! `guesses_log10` is `(guesses as f64).log10()` — computed FROM that
//! already-saturated integer. Once a password's true guess space passes
//! roughly `2^64` (a random ~11-character string over a large charset
//! already gets there), every further character of real entropy is
//! invisible to the estimator: `guesses` pins at `u64::MAX` and
//! `estimate_bits` pins at `log2(u64::MAX) ≈ 64`. **This means
//! `check(...).ok` can never be `true` for ANY typed passphrase, however
//! random — 64 bits is zxcvbn 3.x's hard ceiling, and `REQUIRED_BITS` is
//! 128.** Confirmed empirically, not assumed (see
//! `estimate_bits_long_random_string_saturates_near_the_u64_ceiling` below).
//!
//! This is a deliberate, not a defective, outcome for this module: it's
//! consistent with the "never assume, always measure" principle above, and
//! it's exactly why [`generate`] exists — a passphrase's entropy is either
//! a closed-form fact (generated) or an ESTIMATE bounded by what zxcvbn can
//! even represent (typed), and the UI should never present the second as
//! having reached a bar only the first can actually clear. The live
//! strength meter's job for typed input is to warn honestly (including
//! "even our best-case estimate has a ceiling below what we require"), not
//! to certify — that's what makes the one-tap generator load-bearing
//! rather than a convenience.

use bip39::Language;

use crate::Error;

/// Minimum estimated classical entropy, in bits, before a typed passphrase
/// is considered strong enough for the passphrase layer to carry
/// quantum-resistance on its own (see the module doc for why 128, and
/// [`security_label`]/[`is_quantum_resistant`] for how this gates the
/// label the compose screen shows).
pub const REQUIRED_BITS: f64 = 128.0;

/// A generated passphrase's EXACT entropy: 12 words drawn independently
/// and uniformly from the 2048-word BIP-39 English list, 11 bits/word
/// (`log2(2048) = 11`), `12 * 11 = 132`. This is a closed-form fact about
/// the draw, not an estimate — unlike [`estimate_bits`], which has to
/// guess at what a human typed.
pub const GENERATED_BITS: f64 = 132.0;

/// Number of words in a generated passphrase. Deliberately NOT 12 or 24 —
/// those word counts read as "this is a BIP-39 seed phrase", and a
/// generated passphrase must never be mistaken for one (see [`generate`]).
const WORD_COUNT: usize = 12;

/// Converts zxcvbn's `guesses_log10` (the decimal log of its estimated
/// guess count) to bits (the binary log of the same number):
/// `log2(x) = log10(x) / log10(2) = log10(x) * log2(10)`. Multiplying by
/// `LOG2_10` rather than dividing by `LOG10_2` avoids a second rounding
/// step — both constants are exact `f64` representations of the same
/// irrational ratio, so this is the precise conversion, not an
/// approximation of one.
///
/// Empty string returns exactly `0.0` — zxcvbn itself reports
/// `guesses_log10 = NEG_INFINITY` for `""`("zero guesses needed"), which
/// would multiply through to `NEG_INFINITY` here too; that's correct in
/// spirit (an empty passphrase has zero entropy) but `-inf` is an awkward
/// value for a UI meter to render, so it's special-cased to `0.0`.
pub fn estimate_bits(passphrase: &str) -> f64 {
    if passphrase.is_empty() {
        return 0.0;
    }
    let entropy = zxcvbn::zxcvbn(passphrase, &[]);
    entropy.guesses_log10() * std::f64::consts::LOG2_10
}

/// A strength readout for a typed (not generated) passphrase.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Strength {
    /// Estimated classical entropy, in bits (see [`estimate_bits`]).
    pub bits: f64,
    /// Grover's-algorithm bound: a quantum attacker running an
    /// unstructured search over `2^bits` classical candidates needs only
    /// `2^(bits/2)` quantum evaluations, i.e. the quadratic speedup halves
    /// the bit count that actually resists a quantum adversary.
    /// Informational only — [`ok`](Strength::ok) and [`REQUIRED_BITS`]
    /// are gated on the CLASSICAL bits, because the passphrase layer's
    /// job is resisting today's offline classical brute force; carrying
    /// the note's *quantum* resistance is the ML-KEM layer's job (see
    /// [`is_quantum_resistant`]), not a bigger passphrase number.
    pub quantum_bits: f64,
    /// `true` iff `bits >= REQUIRED_BITS`.
    pub ok: bool,
}

/// Strength readout for a passphrase the user typed. See [`estimate_bits`]
/// for the estimation method and the module doc for why 128 bits is the
/// bar.
pub fn check(passphrase: &str) -> Strength {
    let bits = estimate_bits(passphrase);
    Strength {
        bits,
        quantum_bits: bits / 2.0,
        ok: bits >= REQUIRED_BITS,
    }
}

/// Strength readout for a passphrase produced by [`generate`]. Reports the
/// exact [`GENERATED_BITS`] figure rather than running it back through
/// [`estimate_bits`] — zxcvbn is tuned to catch dictionary-word patterns a
/// HUMAN might type (and would badly underestimate a random 12-word
/// phrase, since every word matches its own dictionary check), but a
/// generated phrase's entropy is a closed-form fact about the draw, known
/// exactly and independent of what zxcvbn's pattern matcher makes of it.
pub fn check_generated() -> Strength {
    Strength {
        bits: GENERATED_BITS,
        quantum_bits: GENERATED_BITS / 2.0,
        ok: GENERATED_BITS >= REQUIRED_BITS,
    }
}

/// Draws one uniformly random index in `0..bound` (`bound <= 65536`) from
/// a caller-supplied fallible byte source, using rejection sampling to
/// avoid modulo bias. Each candidate draw consumes 2 bytes (a little-
/// endian `u16`); a draw landing at or above the largest multiple of
/// `bound` that fits in 16 bits is discarded and redrawn instead of
/// reduced — that discard is what keeps `% bound` unbiased for ANY
/// `bound`, not just a power of two (a plain `random_u16 % bound` would
/// favour the low indices whenever `65536` isn't an exact multiple of
/// `bound`).
///
/// Our only caller passes `bound = 2048` (`2^11`, the BIP-39 English
/// wordlist size), for which `65536` divides evenly
/// (`65536 == 32 * 2048`): every possible `u16` is already in range, so
/// the discard branch is provably unreachable for THIS bound today. The
/// general algorithm is kept anyway — the guarantee this function exists
/// to provide (`result < bound`, always, with no bias) shouldn't depend on
/// that coincidence continuing to hold if the bound ever changes.
fn sample_index<F: FnMut(&mut [u8; 2]) -> Result<(), Error>>(
    bound: u16,
    mut fill: F,
) -> Result<usize, Error> {
    assert!(bound > 0, "sample_index: bound must be nonzero");
    let range = u32::from(u16::MAX) + 1; // 65536, exactly representable
    let limit = range / u32::from(bound) * u32::from(bound);
    loop {
        let mut buf = [0u8; 2];
        fill(&mut buf)?;
        let v = u32::from(u16::from_le_bytes(buf));
        if v < limit {
            return Ok((v % u32::from(bound)) as usize);
        }
    }
}

/// Generates a strong passphrase: [`WORD_COUNT`] words drawn independently
/// and uniformly (via [`sample_index`], OS-CSPRNG-backed through
/// `getrandom`) from the 2048-word BIP-39 English list, joined by single
/// spaces. Returns the phrase alongside its exact entropy
/// ([`GENERATED_BITS`]).
///
/// This is deliberately NOT a valid BIP-39 mnemonic — BIP-39 mnemonics
/// carry a checksum folded into their last word, which means the words
/// are NOT independent draws (the final word's ENTIRE range isn't free),
/// and using a real checksummed mnemonic here would maximize exactly the
/// confusion this function exists to avoid. **A phrase from this function
/// must never be typed into a wallet's seed-phrase import, and a wallet
/// seed phrase must never be used as a note passphrase** — they are
/// different secrets serving different purposes, and this function's
/// output will usually fail BIP-39 checksum validation by construction
/// (only 1-in-16 draws would happen to pass it, same as any 12 random
/// words would).
pub fn generate() -> Result<(String, f64), Error> {
    let words = Language::English.word_list();
    let bound = u16::try_from(words.len()).expect("BIP-39 English list is exactly 2048 words");

    let mut picked = Vec::with_capacity(WORD_COUNT);
    for _ in 0..WORD_COUNT {
        let idx = sample_index(bound, |buf| {
            getrandom::getrandom(buf).map_err(|_| Error::Entropy)
        })?;
        picked.push(words[idx]);
    }
    Ok((picked.join(" "), GENERATED_BITS))
}

/// The three ML-KEM (FIPS 203) parameter sets offered for the note's PQ
/// hybrid-encryption layer, ordered by parameter size (not necessarily by
/// UI display order). `Serialize`/`Deserialize` (added for `pqkeys::
/// PqKeySource`, which persists which level a per-notebook derived key —
/// or an imported one's declared level — uses) round-trip as the plain
/// variant name (`"MlKem512"`/`"MlKem768"`/`"MlKem1024"`) via serde's
/// default enum representation — pinned by a test in `pqkeys.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MlKemLevel {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemLevel {
    /// The level pre-selected in the picker UI — NIST's and most
    /// deployments' standard recommendation for general use, balancing
    /// ciphertext/key size against security margin.
    pub const DEFAULT: MlKemLevel = MlKemLevel::MlKem768;

    /// Short display name, e.g. for composing "ML-KEM-768 hybrid" in
    /// [`security_label`]. Distinct from [`describe`](Self::describe),
    /// which returns the longer explanatory sentence.
    pub fn name(self) -> &'static str {
        match self {
            MlKemLevel::MlKem512 => "ML-KEM-512",
            MlKemLevel::MlKem768 => "ML-KEM-768",
            MlKemLevel::MlKem1024 => "ML-KEM-1024",
        }
    }

    /// One-sentence explanation for the level-picker UI. Wording/AES
    /// comparisons are the exact strings reviewed and approved for that
    /// picker — treat them as pinned copy, not paraphrasable.
    pub fn describe(self) -> &'static str {
        match self {
            MlKemLevel::MlKem512 => {
                "Lowest parameter size; offers security roughly comparable to AES-128."
            }
            MlKemLevel::MlKem768 => {
                "Standard recommendation for most general applications; provides security comparable to AES-192."
            }
            MlKemLevel::MlKem1024 => {
                "Highest parameter size; offers security comparable to AES-256 for maximum long-term protection."
            }
        }
    }
}

/// The compose screen's selected protection for one note — enough to
/// derive both [`security_label`] and [`is_quantum_resistant`] without
/// reaching into the actual encryption code.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SecurityChoice {
    /// `false` for a public note (plaintext OP_RETURN content, readable by
    /// anyone). `true` for an encrypted note (self or directed).
    pub private: bool,
    /// `true` for a directed note (ECDH-sealed to a recipient); `false`
    /// for a self-note (symmetric key from the sender's own seed). Only
    /// meaningful when `private` is `true`.
    pub directed: bool,
    /// Estimated/exact entropy of the chosen passphrase-layer passphrase,
    /// if the passphrase layer is enabled — from [`check`]/[`check_generated`].
    /// `None` when the passphrase layer isn't in use. Offered on directed
    /// notes and — since PLAN-graffito-self-pw.md (2026-08-22) — self-notes
    /// too, though it never changes [`is_quantum_resistant`]'s answer for a
    /// self-note (already `true` regardless — see that fn's doc).
    pub passphrase_bits: Option<f64>,
    /// `true` iff the CURRENT passphrase text came out of [`generate`] this
    /// session, untouched since. A generated phrase's entropy is a
    /// closed-form fact ([`GENERATED_BITS`]); anything typed or pasted, or a
    /// generated phrase the user has since edited, has only an ESTIMATE
    /// ([`estimate_bits`]) that zxcvbn 3.x cannot even represent past ~64
    /// bits (see the module doc) — so an unverified passphrase must never
    /// count toward quantum-resistance no matter how high its estimate
    /// reads. The compose screen flips this back to `false` the instant the
    /// generated text changes.
    pub passphrase_verified: bool,
    /// The ML-KEM level, if the hybrid layer is enabled. `None` when it
    /// isn't in use. Offered on directed notes and — since
    /// PLAN-graffito-self-pw.md — self-notes too (there, ONLY when sealed
    /// to a non-seed-derived imported key — a compose-side obligation this
    /// struct can't see); same quantum-resistance caveat as
    /// `passphrase_bits` above.
    pub mlkem: Option<MlKemLevel>,
}

/// Whether the SELECTED protection resists a quantum adversary — the same
/// logic [`security_label`] describes in prose, exposed separately so the
/// UI can key a badge/icon off it without parsing the label string.
///
/// - Public note: never quantum-resistant (there's no encryption at all).
/// - Private self-note: always quantum-resistant — a symmetric key
///   derived from the seed puts no public-key material on-chain for a
///   quantum algorithm (e.g. Shor's) to attack in the first place.
/// - Private directed note: quantum-resistant iff the ML-KEM hybrid layer
///   is enabled, OR the passphrase layer is enabled with a VERIFIED
///   (app-[`generate`]d, unedited) passphrase whose exact entropy is at or
///   above [`REQUIRED_BITS`] (a sufficiently strong passphrase-derived key
///   has no public-key structure for a quantum algorithm to exploit either
///   — the base ECDH layer stays quantum-VULNERABLE regardless, but an
///   attacker who breaks it still hits the passphrase- or ML-KEM-derived
///   layer underneath). A typed/pasted passphrase never counts here, no
///   matter how high its `estimate_bits` reads — see
///   [`SecurityChoice::passphrase_verified`]'s doc for why an unverified
///   estimate can't be trusted as a quantum-resistance claim.
pub fn is_quantum_resistant(c: &SecurityChoice) -> bool {
    if !c.private {
        return false;
    }
    if !c.directed {
        return true;
    }
    if c.mlkem.is_some() {
        return true;
    }
    c.passphrase_verified && matches!(c.passphrase_bits, Some(bits) if bits >= REQUIRED_BITS)
}

/// One line of compose-screen copy summarizing the protection
/// [`SecurityChoice`] describes. See the module doc and
/// [`is_quantum_resistant`] for the underlying reasoning; this function
/// only turns that reasoning into a sentence.
pub fn security_label(c: &SecurityChoice) -> String {
    if !c.private {
        return "Public note: anyone can read it on the blockchain, forever.".to_string();
    }

    if !c.directed {
        return "Private note: sealed with a key derived from your seed. Already \
                 quantum-resistant — no public-key material ever touches the chain."
            .to_string();
    }

    // A passphrase counts toward quantum-resistance only when it's BOTH
    // verified (came from `generate()`, unedited since) AND at/above the
    // bit bar — see `SecurityChoice::passphrase_verified`'s doc for why an
    // unverified estimate, however high it reads, can never be trusted for
    // this claim (zxcvbn 3.x can't even represent 128 bits for typed
    // input — module doc). `passphrase_present` covers every other case
    // where the layer is on but doesn't (yet, or ever) count: unverified
    // typed/pasted input at any estimate, or a verified-but-somehow-short
    // reading that shouldn't occur in practice but is handled the same way
    // defensively.
    let passphrase_counts =
        c.passphrase_verified && matches!(c.passphrase_bits, Some(bits) if bits >= REQUIRED_BITS);
    let passphrase_present = c.passphrase_bits.is_some();

    match (c.mlkem, passphrase_counts, passphrase_present) {
        (None, false, false) => {
            "Directed note: end-to-end encrypted (~128-bit ECDH), but NOT quantum-resistant."
                .to_string()
        }
        (None, true, _) => {
            let bits = c.passphrase_bits.expect("passphrase_counts implies Some");
            format!("Quantum-resistant: protected by a strong passphrase (~{bits:.0} bits).")
        }
        (None, false, true) => {
            "Passphrase added — strength unverifiable, not counted as quantum-resistant."
                .to_string()
        }
        (Some(level), false, false) => format!(
            "Quantum-resistant: protected by {} hybrid encryption.",
            level.name()
        ),
        (Some(level), true, _) => {
            let bits = c.passphrase_bits.expect("passphrase_counts implies Some");
            format!(
                "Quantum-resistant: {} hybrid encryption plus a strong passphrase (~{bits:.0} bits).",
                level.name()
            )
        }
        (Some(level), false, true) => format!(
            "Quantum-resistant via {} hybrid encryption — passphrase layer added but unverified.",
            level.name()
        ),
    }
}

/// `(is_quantum_resistant(c), security_label(c))` together — the compose
/// screen's Security section always wants both for the same
/// [`SecurityChoice`] (the header status chip and the section's bottom
/// caption), so this is the ONE call site lib.rs makes rather than
/// duplicating the branching those two functions already do.
pub fn describe(c: &SecurityChoice) -> (bool, String) {
    (is_quantum_resistant(c), security_label(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ---- estimate_bits -----------------------------------------------

    #[test]
    fn estimate_bits_empty_is_zero() {
        assert_eq!(estimate_bits(""), 0.0);
        assert!(!check("").ok);
    }

    #[test]
    fn estimate_bits_common_password_is_weak() {
        let bits = estimate_bits("password123");
        assert!(
            bits < REQUIRED_BITS,
            "a top-of-the-dictionary password must not read as strong (got {bits} bits)"
        );
        assert!(!check("password123").ok);
    }

    #[test]
    fn estimate_bits_long_random_string_saturates_near_the_u64_ceiling() {
        // Mixed case + digits + symbols, no dictionary structure — zxcvbn
        // falls back to a brute-force estimate over the character classes
        // actually used. See `estimate_bits`'s doc for why this CANNOT
        // clear 128 bits no matter how long/random the input is: zxcvbn
        // 3.x tracks its guess count as a `u64` throughout
        // (`scoring.rs`'s pervasive `saturating_mul`/`saturating_add`), so
        // once the true guess space passes roughly `2^64` — which a
        // random 28+ char string with this much charset variety already
        // does — every additional bit of real entropy is invisible to the
        // estimator. This is exactly why REQUIRED_BITS can only
        // realistically be cleared by `generate()`'s closed-form figure,
        // never by a typed passphrase run through zxcvbn.
        let candidate = "j8#Kx2!zT9pQ$vB4nW7yH3gR6cL1mF5s";
        assert!(candidate.chars().count() >= 28);
        let strength = check(candidate);
        assert!(
            strength.bits < REQUIRED_BITS,
            "expected the u64 ceiling to keep this under {REQUIRED_BITS} bits, got {}",
            strength.bits
        );
        assert!(
            strength.bits > 50.0,
            "expected a strong random string to approach the ~64-bit ceiling, got {}",
            strength.bits
        );
        assert!(!strength.ok, "no typed passphrase can clear REQUIRED_BITS through zxcvbn — see the doc comment above");
        // Grover bound is exactly half the classical estimate.
        assert!((strength.quantum_bits - strength.bits / 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn estimate_bits_is_monotonic_in_length_for_unstructured_input() {
        let short = "xQ7!mK2p";
        let long = "xQ7!mK2pL9$vT4bN6zR1cW8yH3gJ5";
        assert!(long.len() > short.len());
        assert!(
            estimate_bits(long) > estimate_bits(short),
            "a longer unstructured passphrase must never score lower than a shorter prefix of it"
        );
    }

    // ---- generate() -----------------------------------------------------

    #[test]
    fn generate_reports_exact_132_bits() {
        let (_phrase, bits) = generate().expect("host CSPRNG must be available");
        assert_eq!(bits, 132.0);
        assert_eq!(bits, GENERATED_BITS);
        let strength = check_generated();
        assert_eq!(strength.bits, 132.0);
        assert!(strength.ok);
    }

    #[test]
    fn generate_has_12_words_all_in_the_bip39_list() {
        let (phrase, _bits) = generate().expect("host CSPRNG must be available");
        let words: Vec<&str> = phrase.split(' ').collect();
        assert_eq!(words.len(), 12);
        for w in &words {
            assert!(
                Language::English.find_word(w).is_some(),
                "word {w:?} is not in the BIP-39 English list"
            );
        }
    }

    #[test]
    fn generate_words_are_joined_by_single_spaces() {
        let (phrase, _bits) = generate().expect("host CSPRNG must be available");
        assert!(!phrase.contains("  "), "no double spaces");
        assert!(!phrase.starts_with(' '));
        assert!(!phrase.ends_with(' '));
        assert_eq!(phrase.split(' ').count(), 12);
    }

    #[test]
    fn generate_two_calls_differ() {
        let (a, _) = generate().expect("host CSPRNG must be available");
        let (b, _) = generate().expect("host CSPRNG must be available");
        assert_ne!(a, b, "two independent draws landing on the same 12 words is astronomically unlikely");
    }

    #[test]
    fn generate_statistical_spread_across_many_draws() {
        // 500 words drawn (via repeated generate() calls) should land on a
        // wide range of distinct words if the draw is actually uniform —
        // this is a coarse sanity check, not a rigorous uniformity test
        // (that's `sample_index_never_reaches_bound_and_covers_range`
        // below), but it exercises the real getrandom-backed path end to
        // end rather than an injected source.
        let mut seen: HashSet<String> = HashSet::new();
        for _ in 0..42 {
            let (phrase, _bits) = generate().expect("host CSPRNG must be available");
            seen.extend(phrase.split(' ').map(|w| w.to_string()));
        }
        // 42 draws * 12 words = 504 words total.
        assert!(
            seen.len() > 400,
            "expected >400 distinct words across ~500 draws, got {}",
            seen.len()
        );
    }

    // ---- sample_index (rejection sampling) -------------------------------

    #[test]
    fn sample_index_never_reaches_bound_and_covers_range() {
        // Real OS randomness, many draws: every result must be < 2048
        // (by construction — see sample_index's doc), and across enough
        // draws the results should spread across a wide swath of the
        // range rather than clustering (which would indicate a bias bug).
        let bound: u16 = 2048;
        let mut seen: HashSet<usize> = HashSet::new();
        for _ in 0..2000 {
            let idx = sample_index(bound, |buf| {
                getrandom::getrandom(buf).map_err(|_| Error::Entropy)
            })
            .expect("host CSPRNG must be available");
            assert!(idx < bound as usize, "sample_index returned {idx} >= bound {bound}");
            seen.insert(idx);
        }
        assert!(
            seen.len() > 1000,
            "expected wide coverage of 0..2048 across 2000 draws, got {} distinct values",
            seen.len()
        );
    }

    #[test]
    fn sample_index_rejects_out_of_range_draws_and_retries() {
        // A bound where the discard branch IS reachable (2048 never
        // triggers it — see sample_index's doc): bound = 3, range 65536,
        // limit = 65536 / 3 * 3 = 65535, so the single value 65535 must be
        // discarded and redrawn. Feed a fill sequence that returns the
        // discarded value first, then a valid one, and confirm the
        // sampler consumes BOTH draws and returns the valid one.
        let mut calls = 0u32;
        let sequence: [[u8; 2]; 2] = [[0xFF, 0xFF], [0x02, 0x00]]; // 65535 (reject), then 2
        let idx = sample_index(3, |buf| {
            *buf = sequence[calls as usize];
            calls += 1;
            Ok(())
        })
        .expect("infallible fill");
        assert_eq!(calls, 2, "the out-of-range draw must be discarded and a second draw taken");
        assert_eq!(idx, 2 % 3);
    }

    #[test]
    fn sample_index_propagates_fill_errors() {
        let result = sample_index(2048, |_buf: &mut [u8; 2]| Err(Error::Entropy));
        assert_eq!(result, Err(Error::Entropy));
    }

    // ---- MlKemLevel -------------------------------------------------------

    #[test]
    fn mlkem_describe_exact_strings() {
        assert_eq!(
            MlKemLevel::MlKem512.describe(),
            "Lowest parameter size; offers security roughly comparable to AES-128."
        );
        assert_eq!(
            MlKemLevel::MlKem768.describe(),
            "Standard recommendation for most general applications; provides security comparable to AES-192."
        );
        assert_eq!(
            MlKemLevel::MlKem1024.describe(),
            "Highest parameter size; offers security comparable to AES-256 for maximum long-term protection."
        );
    }

    #[test]
    fn mlkem_default_is_768() {
        assert_eq!(MlKemLevel::DEFAULT, MlKemLevel::MlKem768);
    }

    // ---- describe() ---------------------------------------------------

    #[test]
    fn describe_matches_the_two_underlying_calls() {
        let c = SecurityChoice {
            private: true,
            directed: true,
            passphrase_bits: Some(GENERATED_BITS),
            passphrase_verified: true,
            mlkem: None,
        };
        let (resistant, label) = describe(&c);
        assert_eq!(resistant, is_quantum_resistant(&c));
        assert_eq!(label, security_label(&c));
        assert!(resistant);
    }

    // ---- security_label / is_quantum_resistant (table-driven) -----------

    struct Row {
        name: &'static str,
        choice: SecurityChoice,
        quantum_resistant: bool,
        must_contain: &'static [&'static str],
        must_not_contain: &'static [&'static str],
    }

    #[test]
    fn security_label_and_quantum_resistance_matrix() {
        let rows = [
            Row {
                name: "public",
                choice: SecurityChoice {
                    private: false,
                    directed: false,
                    passphrase_bits: None,
                    passphrase_verified: false,
                    mlkem: None,
                },
                quantum_resistant: false,
                must_contain: &["anyone"],
                must_not_contain: &["quantum"],
            },
            Row {
                name: "private self-note",
                choice: SecurityChoice {
                    private: true,
                    directed: false,
                    passphrase_bits: None,
                    passphrase_verified: false,
                    mlkem: None,
                },
                quantum_resistant: true,
                must_contain: &["quantum-resistant", "seed"],
                must_not_contain: &["not quantum-resistant"],
            },
            Row {
                name: "directed, no layers",
                choice: SecurityChoice {
                    private: true,
                    directed: true,
                    passphrase_bits: None,
                    passphrase_verified: false,
                    mlkem: None,
                },
                quantum_resistant: false,
                must_contain: &["NOT quantum-resistant"],
                must_not_contain: &[],
            },
            // Spec change (orchestrator-approved, 2026-08-20): a passphrase
            // only counts toward quantum-resistance when it is BOTH
            // verified (app-generated, unedited) AND >= REQUIRED_BITS. This
            // row is the one that used to read "quantum-resistant" purely
            // off a >=128-bit estimate; it now must NOT, because nothing
            // about it says the phrase was app-generated.
            Row {
                name: "directed + high-estimate but UNVERIFIED (typed) passphrase",
                choice: SecurityChoice {
                    private: true,
                    directed: true,
                    passphrase_bits: Some(140.0),
                    passphrase_verified: false,
                    mlkem: None,
                },
                quantum_resistant: false,
                must_contain: &["unverifiable", "not counted as quantum-resistant"],
                must_not_contain: &["NOT quantum-resistant", "Quantum-resistant:"],
            },
            Row {
                name: "directed + verified generated passphrase",
                choice: SecurityChoice {
                    private: true,
                    directed: true,
                    passphrase_bits: Some(GENERATED_BITS),
                    passphrase_verified: true,
                    mlkem: None,
                },
                quantum_resistant: true,
                must_contain: &["quantum-resistant", "132"],
                must_not_contain: &["not quantum-resistant", "unverifiable"],
            },
            Row {
                name: "directed + weak passphrase (also unverified)",
                choice: SecurityChoice {
                    private: true,
                    directed: true,
                    passphrase_bits: Some(40.0),
                    passphrase_verified: false,
                    mlkem: None,
                },
                quantum_resistant: false,
                must_contain: &["unverifiable", "not counted as quantum-resistant"],
                must_not_contain: &["NOT quantum-resistant", "Quantum-resistant:"],
            },
            Row {
                name: "directed + ML-KEM only",
                choice: SecurityChoice {
                    private: true,
                    directed: true,
                    passphrase_bits: None,
                    passphrase_verified: false,
                    mlkem: Some(MlKemLevel::MlKem768),
                },
                quantum_resistant: true,
                must_contain: &["quantum-resistant", "ML-KEM-768"],
                must_not_contain: &["not quantum-resistant"],
            },
            Row {
                name: "directed + ML-KEM + verified strong passphrase",
                choice: SecurityChoice {
                    private: true,
                    directed: true,
                    passphrase_bits: Some(GENERATED_BITS),
                    passphrase_verified: true,
                    mlkem: Some(MlKemLevel::MlKem1024),
                },
                quantum_resistant: true,
                must_contain: &["quantum-resistant", "ML-KEM-1024", "132"],
                must_not_contain: &["not quantum-resistant"],
            },
            Row {
                name: "directed + ML-KEM + unverified passphrase",
                choice: SecurityChoice {
                    private: true,
                    directed: true,
                    passphrase_bits: Some(30.0),
                    passphrase_verified: false,
                    mlkem: Some(MlKemLevel::MlKem512),
                },
                quantum_resistant: true,
                must_contain: &["quantum-resistant", "ML-KEM-512", "unverified"],
                must_not_contain: &["NOT quantum-resistant"],
            },
        ];

        for row in rows {
            assert_eq!(
                is_quantum_resistant(&row.choice),
                row.quantum_resistant,
                "is_quantum_resistant mismatch for {}",
                row.name
            );
            let label = security_label(&row.choice);
            // Case-insensitive: sentence-initial "Quantum-resistant" vs.
            // mid-sentence "quantum-resistant" is a copy-editing detail,
            // not something these assertions should be sensitive to.
            let label_lc = label.to_lowercase();
            for needle in row.must_contain {
                assert!(
                    label_lc.contains(&needle.to_lowercase()),
                    "{}: label {label:?} missing expected substring {needle:?}",
                    row.name
                );
            }
            for needle in row.must_not_contain {
                assert!(
                    !label_lc.contains(&needle.to_lowercase()),
                    "{}: label {label:?} unexpectedly contains {needle:?}",
                    row.name
                );
            }
        }
    }
}
