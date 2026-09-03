//! Guards the one rule that makes `graffito-core` safe to pin as a git
//! dependency of the shelved Prime app (PLAN-graffito-arch.md, phase 2):
//! `[dependencies]` may contain ONLY `notes-core` and `serde` (optionally
//! `serde_derive`, if `serde`'s own `derive` feature is ever split out into
//! an explicit dep instead of a feature flag) — nothing else, ever, because
//! anything else becomes a new crate in the on-device build graph and the
//! workspace's RNG audit (RANDOMNESS-AUDIT-2026-08-01.md) assumes that
//! graph is closed. `[dev-dependencies]` (test-only, e.g. `serde_json`) is
//! unrestricted — it never ships.
//!
//! Reads `Cargo.toml` as plain text rather than pulling in a TOML-parsing
//! crate (which would mean adding a new *dev*-dependency just to test that
//! no new *runtime* dependency snuck in) — a small hand-rolled section
//! scanner is enough for this file's shape and keeps the guard itself
//! dependency-free.
//!
//! Mutation-tested: PLAN-graffito-arch.md's step 3 record has this test
//! failing when `serde_json` is temporarily added to `[dependencies]`, then
//! passing again once reverted.

use std::path::Path;

/// crate name before the first `=` or whitespace on a `key = value` TOML
/// line, skipping blanks and `#` comments.
fn dep_names_in_section(manifest: &str, section: &str) -> Vec<String> {
    let mut in_section = false;
    let mut names = Vec::new();
    for raw_line in manifest.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_section = line == section;
            continue;
        }
        if !in_section || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = line.split(['=', ' ', '\t']).next().unwrap_or("").trim();
        if !name.is_empty() {
            names.push(name.to_string());
        }
    }
    names
}

#[test]
fn dependencies_are_exactly_notes_core_and_serde() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));

    let mut deps = dep_names_in_section(&manifest, "[dependencies]");
    deps.sort();

    // serde_derive is allowed alongside serde (see module docs) but is not
    // required — filter it out before the exact-match assert so adding it
    // deliberately doesn't break this test, while anything else still does.
    deps.retain(|d| d != "serde_derive");

    assert_eq!(
        deps,
        vec!["notes-core".to_string(), "serde".to_string()],
        "graffito-core/Cargo.toml [dependencies] must contain ONLY notes-core \
         and serde (+ optional serde_derive) — found {deps:?}. Anything else \
         enters the Prime device build graph through this crate (see the \
         module doc comment in this test file and PLAN-graffito-arch.md \
         phase 2's dependency-minimal rule)."
    );
}

/// `[dev-dependencies]` is unrestricted (test-only, never shipped) — this
/// test exists only to document that the guard above is deliberately scoped
/// to `[dependencies]`, not to assert anything about dev-deps.
#[test]
fn dev_dependencies_are_unrestricted_by_this_guard() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    // Just prove the section scanner can see dev-dependencies too (so a
    // future edit that renames [dependencies] to something else can't
    // silently make the section scanner match nothing and pass vacuously).
    let dev_deps = dep_names_in_section(&manifest, "[dev-dependencies]");
    assert!(!dev_deps.is_empty(), "expected at least one dev-dependency (serde_json)");
}
