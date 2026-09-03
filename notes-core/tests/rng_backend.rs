//! Portable RNG contract tests for notes-core.
//!
//! notes-core routes ALL its entropy through `getrandom 0.2` (see
//! `Cargo.toml` and `pq.rs`'s RNG rule): on a Passport Prime that exact
//! version line is what the app's `[patch.crates-io]` swaps for the
//! vendored TRNG backend, so a dependency bump that dragged in a
//! `rand 0.9`-era consumer (getrandom 0.3/0.4) would silently route key
//! material around the hardware RNG. The device-side half of that guard
//! — that the patch is present and the vendored backend is hardened —
//! lives with the vendored crate in `prime-graffito/tests/rng_backend.rs`;
//! this file guards the half that is true wherever notes-core is built.
//!
//! Every assertion is a pure function over its input plus a thin wrapper
//! feeding it the real graph, so each contract is MUTATION-TESTED below.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

// =======================================================================
// 1. Dependency-graph guard: every getrandom reachable through NORMAL or
//    BUILD (non-dev) edges from notes-core is a 0.2.x — the only line the
//    device TRNG patch covers.
// =======================================================================

struct DepEdge<'a> {
    to: &'a str,
    /// NORMAL or BUILD edge (`dep_kinds` kind `null`/`"build"`): linked
    /// into a shipped build. DEV-only edges are never followed.
    linked: bool,
}

fn reachable_getrandom_ids<'a>(
    root: &'a str,
    edges: &HashMap<&'a str, Vec<DepEdge<'a>>>,
    pkg_name: &HashMap<&'a str, &'a str>,
) -> BTreeSet<&'a str> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut stack = vec![root];
    let mut found = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if pkg_name.get(id) == Some(&"getrandom") {
            found.insert(id);
        }
        if let Some(es) = edges.get(id) {
            for e in es {
                if e.linked {
                    stack.push(e.to);
                }
            }
        }
    }
    found
}

/// `found` must be non-empty (notes-core DOES draw entropy) and every
/// entry must be a 0.2.x release.
fn assert_only_0_2(found: &BTreeSet<&str>, version_of: &BTreeMap<&str, &str>) -> Result<(), String> {
    if found.is_empty() {
        return Err("no getrandom reachable at all — notes-core must draw entropy through getrandom 0.2".into());
    }
    let bad: Vec<String> = found
        .iter()
        .filter(|id| !version_of.get(*id).is_some_and(|v| v.starts_with("0.2.")))
        .map(|id| format!("{id} ({})", version_of.get(id).copied().unwrap_or("?")))
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!("getrandom other than 0.2.x reachable through linked edges: {bad:?}"))
    }
}

fn run_cargo_metadata() -> serde_json::Value {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let output = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1"])
        .current_dir(manifest_dir)
        .output()
        .expect("failed to spawn `cargo metadata`");
    assert!(
        output.status.success(),
        "cargo metadata failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata did not produce valid JSON")
}

fn edge_is_linked(dep_kinds: &serde_json::Value) -> bool {
    dep_kinds
        .as_array()
        .map(|kinds| {
            kinds
                .iter()
                .any(|k| matches!(k.get("kind").and_then(|v| v.as_str()), None | Some("build")))
        })
        .unwrap_or(false)
}

#[test]
fn contract_dependency_graph_reaches_only_getrandom_0_2() {
    let meta = run_cargo_metadata();
    let resolve = &meta["resolve"];
    let root = resolve["root"].as_str().expect("resolve.root missing — run from the notes-core manifest");

    let mut pkg_name: HashMap<&str, &str> = HashMap::new();
    let mut version_of: BTreeMap<&str, &str> = BTreeMap::new();
    for p in meta["packages"].as_array().expect("packages") {
        let id = p["id"].as_str().expect("package id");
        pkg_name.insert(id, p["name"].as_str().expect("package name"));
        version_of.insert(id, p["version"].as_str().expect("package version"));
    }
    assert!(pkg_name.get(root) == Some(&"notes-core"), "resolve.root is not notes-core: {root}");

    let mut edges: HashMap<&str, Vec<DepEdge>> = HashMap::new();
    for n in resolve["nodes"].as_array().expect("resolve.nodes") {
        let id = n["id"].as_str().expect("node id");
        let es = n["deps"]
            .as_array()
            .expect("node deps")
            .iter()
            .map(|d| DepEdge { to: d["pkg"].as_str().expect("dep pkg id"), linked: edge_is_linked(&d["dep_kinds"]) })
            .collect();
        edges.insert(id, es);
    }

    let found = reachable_getrandom_ids(root, &edges, &pkg_name);
    if let Err(msg) = assert_only_0_2(&found, &version_of) {
        panic!(
            "{msg}\n\ngetrandom 0.3.x/0.4.x may sit in Cargo.lock via dev-only paths (rust-bitcoin's \
             rand-std, tempfile, rand_core 0.9) but must NOT be reachable through a normal/build \
             edge from notes-core. If this trips after a dependency bump, a new normal dependency \
             now pulls a getrandom the Prime's TRNG patch does not cover."
        );
    }
}

fn graph<'a>(spec: &[(&'a str, &[(&'a str, bool)])]) -> HashMap<&'a str, Vec<DepEdge<'a>>> {
    spec.iter()
        .map(|(from, deps)| (*from, deps.iter().map(|(to, linked)| DepEdge { to, linked: *linked }).collect()))
        .collect()
}

#[test]
fn mutation_extra_reachable_getrandom_is_caught() {
    let names: HashMap<&str, &str> =
        [("nc", "notes-core"), ("k256", "k256"), ("gr2", "getrandom"), ("rand9", "rand"), ("gr3", "getrandom")].into();
    let versions: BTreeMap<&str, &str> =
        [("nc", "0.1.0"), ("k256", "0.13.4"), ("gr2", "0.2.17"), ("rand9", "0.9.4"), ("gr3", "0.3.4")].into();
    let edges = graph(&[("nc", &[("k256", true), ("gr2", true), ("rand9", true)]), ("rand9", &[("gr3", true)])]);
    let found = reachable_getrandom_ids("nc", &edges, &names);
    assert_eq!(found.len(), 2);
    assert!(assert_only_0_2(&found, &versions).is_err(), "a reachable getrandom 0.3 must fail");
}

#[test]
fn mutation_dev_only_edge_is_correctly_excluded() {
    let names: HashMap<&str, &str> = [("nc", "notes-core"), ("gr2", "getrandom"), ("bitcoin", "bitcoin"), ("gr3", "getrandom")].into();
    let versions: BTreeMap<&str, &str> = [("nc", "0.1.0"), ("gr2", "0.2.17"), ("bitcoin", "0.32.7"), ("gr3", "0.3.4")].into();
    let edges = graph(&[("nc", &[("gr2", true), ("bitcoin", false)]), ("bitcoin", &[("gr3", true)])]);
    let found = reachable_getrandom_ids("nc", &edges, &names);
    assert_eq!(found, BTreeSet::from(["gr2"]), "the dev-only bitcoin -> getrandom 0.3 path must not be followed");
    assert!(assert_only_0_2(&found, &versions).is_ok());
}

#[test]
fn mutation_no_getrandom_at_all_is_caught() {
    let versions: BTreeMap<&str, &str> = BTreeMap::new();
    assert!(assert_only_0_2(&BTreeSet::new(), &versions).is_err(), "a notes-core that draws no entropy is wrong, not clean");
}

#[test]
fn mutation_edge_is_linked_excludes_dev_kind() {
    let normal = serde_json::json!([{ "kind": null, "target": null }]);
    let build = serde_json::json!([{ "kind": "build", "target": null }]);
    let dev = serde_json::json!([{ "kind": "dev", "target": null }]);
    assert!(edge_is_linked(&normal));
    assert!(edge_is_linked(&build));
    assert!(!edge_is_linked(&dev));
}

// =======================================================================
// 2. `register_custom_getrandom!` appears nowhere in notes-core. That
//    macro rebinds getrandom's backend at link time; the ONLY legitimate
//    site is the vendored crate inside the Prime app, and a stray use
//    here would turn the device's fail-closed compile error into a
//    silent rebind.
// =======================================================================

fn files_matching<'a>(files: &'a [(String, String)], needle: &str, exclude_file_name: &str) -> Vec<&'a str> {
    files
        .iter()
        .filter(|(path, _)| !path.ends_with(exclude_file_name))
        .filter(|(_, content)| content.contains(needle))
        .map(|(path, _)| path.as_str())
        .collect()
}

fn collect_rust_files(root: &Path, skip_dir_names: &[&str]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            let path = entry.path();
            if file_type.is_dir() {
                let name = entry.file_name();
                if skip_dir_names.iter().any(|s| name == std::ffi::OsStr::new(s)) {
                    continue;
                }
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    out.push((path.to_string_lossy().into_owned(), content));
                }
            }
        }
    }
    out
}

#[test]
fn contract_no_register_custom_getrandom_in_notes_core() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = collect_rust_files(root, &[".git", "target"]);
    assert!(!files.is_empty(), "sanity: the crate scan found zero .rs files — the walker is broken, not the crate");
    let hits = files_matching(&files, "register_custom_getrandom", "rng_backend.rs");
    assert!(hits.is_empty(), "register_custom_getrandom! must not appear in notes-core, found in: {hits:?}");
}

#[test]
fn mutation_stray_register_custom_getrandom_is_caught() {
    let files = vec![
        ("src/lib.rs".to_string(), "fn boot() {}".to_string()),
        ("src/pq.rs".to_string(), "getrandom::register_custom_getrandom!(bad);".to_string()),
    ];
    assert_eq!(files_matching(&files, "register_custom_getrandom", "rng_backend.rs"), vec!["src/pq.rs"]);
}

#[test]
fn mutation_own_test_file_is_excluded_by_name_not_by_luck() {
    let files = vec![("tests/rng_backend.rs".to_string(), "register_custom_getrandom".to_string())];
    assert!(files_matching(&files, "register_custom_getrandom", "rng_backend.rs").is_empty());
    assert_eq!(files_matching(&files, "register_custom_getrandom", "other.rs").len(), 1);
}
