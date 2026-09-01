//! Contract: the user-visible security copy for every state
//! `SecurityChoice` can represent — the compose screen's Security section
//! caption plus the quantum-resistance badge.
//!
//! WHY THIS FILE EXISTS (2026-09-01): the self-note rows of this policy
//! used to live as a hardcoded override in `src/lib.rs`'s
//! `refresh_compose_pq` — patched over `describe()`'s output at its only
//! call site — because `security_label` returned early for self-notes
//! before consulting `SecurityChoice::mlkem`. Three divergent copies of
//! the policy existed (this crate's, the lib.rs override, and
//! prime-graffito's `pq_security_label`). This table is now the single
//! source of truth: `security_label` must be TOTAL over `SecurityChoice`,
//! leaving the shell nothing to override. Strings are pinned copy — a
//! change here is a product decision, not a refactor.
//!
//! Provenance of each expected string:
//! - public/directed rows: `security_label` as shipped (pre-existing,
//!   unchanged, already covered by `passphrase.rs` unit tests).
//! - self-note layered rows: the `src/lib.rs` override as shipped in the
//!   PLAN-graffito-quantum-key.md builds, byte-for-byte, with ONE
//!   deliberate correction: the quantum-key rows said "the imported key",
//!   stale since `pqkeys::generate_native_private` ("My quantum key"
//!   generation) shipped in the same plan — a user who GENERATED their key
//!   was warned about an imported one. Now "your quantum key".

use app_core::passphrase::{
    describe, is_quantum_resistant, security_label, MlKemLevel, SecurityChoice, GENERATED_BITS,
    REQUIRED_BITS,
};

fn choice(
    private: bool,
    directed: bool,
    passphrase_bits: Option<f64>,
    passphrase_verified: bool,
    mlkem: Option<MlKemLevel>,
) -> SecurityChoice {
    SecurityChoice { private, directed, passphrase_bits, passphrase_verified, mlkem }
}

/// One row: choice -> (quantum-resistant badge, exact label).
fn assert_row(c: SecurityChoice, want_qr: bool, want_label: &str) {
    assert_eq!(
        is_quantum_resistant(&c),
        want_qr,
        "is_quantum_resistant mismatch for {c:?}"
    );
    assert_eq!(security_label(&c), want_label, "label mismatch for {c:?}");
    // describe() is defined as exactly the pair — keep it that way.
    assert_eq!(describe(&c), (want_qr, want_label.to_string()));
}

const KEM: Option<MlKemLevel> = Some(MlKemLevel::MlKem768);

// ---- public notes: never quantum-resistant, layers change nothing -------

#[test]
fn public_note() {
    assert_row(
        choice(false, false, None, false, None),
        false,
        "Public note: anyone can read it on the blockchain, forever.",
    );
}

#[test]
fn public_note_ignores_layers_and_direction() {
    // Unreachable from the compose UI (pq_compose_eligible requires
    // private), but the function is total: a public note stays labeled
    // public whatever else is set.
    for directed in [false, true] {
        for (bits, verified) in [(None, false), (Some(GENERATED_BITS), true)] {
            for mlkem in [None, KEM] {
                assert_row(
                    choice(false, directed, bits, verified, mlkem),
                    false,
                    "Public note: anyone can read it on the blockchain, forever.",
                );
            }
        }
    }
}

// ---- self-notes (private, not directed) ---------------------------------

#[test]
fn self_note_plain() {
    assert_row(
        choice(true, false, None, false, None),
        true,
        "Private note: sealed with a key derived from your seed. Already \
         quantum-resistant — no public-key material ever touches the chain.",
    );
}

#[test]
fn self_note_password_layer() {
    // Flat across verified/unverified and any bits value: the layer guards
    // a different threat (seed compromise / harvested xpub), so the label
    // warns about loss, not strength. (The device app distinguishes
    // verified strength here — unifying that copy is a follow-up product
    // decision, not this contract's.)
    for (bits, verified) in [
        (Some(GENERATED_BITS), true),
        (Some(GENERATED_BITS), false),
        (Some(30.0), false),
        (Some(REQUIRED_BITS), true),
    ] {
        assert_row(
            choice(true, false, bits, verified, None),
            true,
            "Password layer added — forgetting it loses this note forever, even \
             with your seed.",
        );
    }
}

#[test]
fn self_note_quantum_key_layer() {
    // DELIBERATE COPY CHANGE (2026-09-01): shipped shell said "losing the
    // imported key"; the key can be generated on-device since
    // PLAN-graffito-quantum-key.md, so the copy now says "your quantum key".
    for level in [MlKemLevel::MlKem512, MlKemLevel::MlKem768, MlKemLevel::MlKem1024] {
        assert_row(
            choice(true, false, None, false, Some(level)),
            true,
            "Quantum-key layer added — losing your quantum key loses this note \
             forever, even with your seed.",
        );
    }
}

#[test]
fn self_note_both_layers() {
    assert_row(
        choice(true, false, Some(GENERATED_BITS), true, KEM),
        true,
        "Password + quantum-key layer added — forgetting either the password \
         or the quantum key loses this note forever, even with your seed.",
    );
    // Same label regardless of passphrase verification state.
    assert_row(
        choice(true, false, Some(12.0), false, KEM),
        true,
        "Password + quantum-key layer added — forgetting either the password \
         or the quantum key loses this note forever, even with your seed.",
    );
}

// ---- directed notes: pre-existing policy, must never drift --------------

#[test]
fn directed_plain() {
    assert_row(
        choice(true, true, None, false, None),
        false,
        "Directed note: end-to-end encrypted (~128-bit ECDH), but NOT quantum-resistant.",
    );
}

#[test]
fn directed_verified_passphrase_counts() {
    assert_row(
        choice(true, true, Some(GENERATED_BITS), true, None),
        true,
        "Quantum-resistant: protected by a strong passphrase (~132 bits).",
    );
}

#[test]
fn directed_unverified_passphrase_does_not_count() {
    assert_row(
        choice(true, true, Some(200.0), false, None),
        false,
        "Passphrase added — strength unverifiable, not counted as quantum-resistant.",
    );
}

#[test]
fn directed_verified_but_below_bar_does_not_count() {
    // Defensive: verified yet under REQUIRED_BITS reads as not counting.
    assert_row(
        choice(true, true, Some(REQUIRED_BITS - 1.0), true, None),
        false,
        "Passphrase added — strength unverifiable, not counted as quantum-resistant.",
    );
}

#[test]
fn directed_mlkem() {
    assert_row(
        choice(true, true, None, false, KEM),
        true,
        "Quantum-resistant: protected by ML-KEM-768 hybrid encryption.",
    );
}

#[test]
fn directed_mlkem_plus_verified_passphrase() {
    assert_row(
        choice(true, true, Some(GENERATED_BITS), true, KEM),
        true,
        "Quantum-resistant: ML-KEM-768 hybrid encryption plus a strong passphrase (~132 bits).",
    );
}

#[test]
fn directed_mlkem_plus_unverified_passphrase() {
    assert_row(
        choice(true, true, Some(50.0), false, KEM),
        true,
        "Quantum-resistant via ML-KEM-768 hybrid encryption — passphrase layer added but unverified.",
    );
}
