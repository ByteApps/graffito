//! Entropy battery run against the REAL seed-generation pipeline, not just
//! the OS syscall in isolation.
//!
//! Prompted by a 2026 public disclosure of an RNG failure in a
//! shipped hardware wallet's firmware: a hardware wallet
//! shipped seed generation that silently used a deterministic PRNG, and a
//! reseed where only 4 of 32 bytes reached the generator (state space
//! capped at 2^32). `tests/common/entropy_battery.rs` is the shared
//! battery + negative controls (copied byte-identical across every repo
//! that generates key material — see its own doc comment for what it can
//! and cannot prove). This file is the port of the validated
//! `/dev/urandom` harness onto two sources:
//!
//!   1. the raw OS source (`getrandom::getrandom`) — the syscall
//!      `generate_mnemonic` calls, tested in isolation; and
//!   2. `identity::generate_mnemonic(24)` -> `to_entropy()` — the actual
//!      "create a new seed" door a user hits. This is the one that
//!      matters: it proves the whole pipeline (getrandom -> bip39 entropy
//!      encode -> decode back to bytes) never narrows the entropy on its
//!      way out, not merely that the underlying syscall is sound.
//!
//! Negative controls are ported unchanged from the validation harness:
//! they exist to prove this battery DISCRIMINATES (a battery that only
//! ever sees a good source cannot tell you it works), not to test our
//! code — see `tests/entropy_bip39.rs` for the bit-length/BIP-39 contract
//! tests that exercise `generate_mnemonic`'s own API surface.

#[path = "common/entropy_battery.rs"]
mod battery;

use app_core::identity::generate_mnemonic;
use battery::controls;

// ------------------------- sources -------------------------

fn os_source(out: &mut [u8]) {
    getrandom::getrandom(out).expect("OS CSPRNG must not fail");
}

fn os_source32(out: &mut [u8; 32]) {
    os_source(&mut out[..]);
}

/// The real "create a new seed" path: a fresh 24-word mnemonic, reduced
/// back to its 32-byte entropy. This is what actually reaches
/// `bip39::Mnemonic::from_entropy_in` inside `generate_mnemonic` — the
/// whole pipeline, not the `getrandom` call alone.
fn seed_path_source(out: &mut [u8]) {
    let m = generate_mnemonic(24).expect("generate_mnemonic(24) must succeed");
    let e = m.to_entropy();
    out.copy_from_slice(&e);
}

fn seed_path_source32(out: &mut [u8; 32]) {
    seed_path_source(&mut out[..]);
}

// ------------------------- positive: raw OS source -------------------------

#[test]
fn os_source_passes_battery() {
    let r = battery::battery_from(32, os_source);
    println!("{}", r.summary());
    r.assert_ok("getrandom (OS CSPRNG)");
}

#[test]
fn os_source_draw_sanity() {
    battery::draw_sanity(10_000, os_source32).assert_ok("getrandom draws");
}

#[test]
fn os_source_collision_free() {
    let t = std::time::Instant::now();
    let r = battery::collision_freedom(os_source32);
    println!("collision test took {:?}\n{}", t.elapsed(), r.summary());
    r.assert_ok("getrandom collisions");
}

// ------------------------- positive: the real seed path -------------------------

#[test]
fn seed_path_passes_battery() {
    let r = battery::battery_from(32, seed_path_source);
    println!("{}", r.summary());
    r.assert_ok("generate_mnemonic(24).to_entropy()");
}

#[test]
fn seed_path_draw_sanity() {
    battery::draw_sanity(10_000, seed_path_source32).assert_ok("generate_mnemonic(24) draws");
}

#[test]
fn seed_path_collision_free() {
    let t = std::time::Instant::now();
    let r = battery::collision_freedom(seed_path_source32);
    println!("collision test took {:?}\n{}", t.elapsed(), r.summary());
    r.assert_ok("generate_mnemonic(24) collisions");
}

// ------------------------- negative -------------------------

fn assert_fails(r: &battery::Report, expect: &[&str], what: &str) {
    assert!(!r.passed(), "{what} MUST fail the battery but passed:\n{}", r.summary());
    let failed = r.failed_names();
    for e in expect {
        assert!(
            failed.contains(e),
            "{what} should have tripped `{e}`; tripped {failed:?}\n{}",
            r.summary()
        );
    }
    println!("{what} correctly failed: {failed:?}");
}

#[test]
fn control_zeros_fails() {
    let r = battery::battery_from(32, controls::zeros);
    assert_fails(&r, &["not_degenerate", "monobit", "longest_run", "shannon_entropy"], "all-zero source");
}

#[test]
fn control_counter_fails() {
    let mut c = controls::Counter::default();
    let r = battery::battery_from(8, |o| c.fill(o));
    assert_fails(&r, &["byte_chi_square"], "counter source");
}

#[test]
fn control_truncated_fails() {
    // disclosure bug 2: 4 of every 32 bytes actually filled.
    let mut t = controls::Truncated { inner: os_source, kept: 4 };
    let r = battery::battery_from(32, |o| t.fill(o));
    assert_fails(&r, &["monobit", "shannon_entropy"], "4-of-32-bytes source");
}

#[test]
fn control_stuck_bit_fails() {
    let mut s = controls::StuckBit(os_source);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert_fails(&r, &["bit_position_bias"], "stuck-low-bit source");
}

#[test]
fn control_biased_fails() {
    let mut s = controls::Biased(os_source);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert_fails(&r, &["monobit", "bit_position_bias"], "7-bit masked source");
}

#[test]
fn control_repeating_page_fails() {
    let mut s = controls::RepeatingPage::new(os_source, 4096);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert_fails(&r, &["repeated_blocks"], "never-refilled page");
}

#[test]
fn control_reseed32_caught_only_by_collisions() {
    // A perfect CSPRNG with a 32-bit state: passes the distribution
    // battery, caught by the birthday test. This is the whole reason
    // collision_freedom exists.
    let mut s = controls::Reseed32::new(1);
    let dist = battery::battery_from(32, |o| s.fill(o));
    println!("reseed32 distribution report:\n{}", dist.summary());

    let mut s2 = controls::Reseed32::new(7);
    let t = std::time::Instant::now();
    let coll = battery::collision_freedom(|o| s2.draw32(o));
    println!("reseed32 collision test took {:?}\n{}", t.elapsed(), coll.summary());
    assert!(!coll.passed(), "32-bit-state generator MUST collide within {} draws", battery::COLLISION_DRAWS);
}

#[test]
fn control_fixed_seed_passes_and_that_is_the_point() {
    // disclosure bug 1: statistically perfect, undetectable here. The
    // detectors are the backend/graph contract tests and cross-boot
    // independence on hardware.
    let mut s = controls::FixedSeed::new(0x42);
    let r = battery::battery_from(32, |o| s.fill(o));
    assert!(
        r.passed(),
        "a fixed-seed CSPRNG is expected to PASS the statistics; if it now \
         fails, the battery changed meaning:\n{}",
        r.summary()
    );
    let mut a = controls::FixedSeed::new(0x42);
    let mut b = controls::FixedSeed::new(0x42);
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    a.fill(&mut x);
    b.fill(&mut y);
    assert_eq!(x, y, "two instances of a fixed-seed PRNG must agree — that IS the bug shape");
}
