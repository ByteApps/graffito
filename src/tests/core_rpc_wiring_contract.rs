/// Every `.rs` file under `src/` (this crate's own shell code), excluding
/// `src/tests/` itself — re-walked at every test run, so this contract
/// always judges the ACTUAL source, mutation included. Unlike the
/// pre-U4 single-file version (`include_str!("../lib.rs")`), the shell now
/// spans `boot.rs`/`editops.rs`/`pending.rs`/`util.rs`/`screens/*.rs` too
/// (U4, PLAN-graffito-app-arch.md), so a call site this contract must catch
/// can live in ANY of them — walked at runtime (not `include_str!`, since
/// the file list isn't known at compile time) via `CARGO_MANIFEST_DIR`.
fn all_sources() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("core-rpc wiring contract: read_dir({dir:?}): {e}"));
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                if path.file_name().and_then(|n| n.to_str()) == Some("tests") {
                    continue; // this test file's own directory
                }
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let content = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("core-rpc wiring contract: read {path:?}: {e}"));
                let rel = path.strip_prefix(&root).unwrap_or(&path).to_string_lossy().to_string();
                out.push((rel, content));
            }
        }
    }
    out
}

/// Top-level functions whose reason for existing includes resolving
/// the identity's OWN addresses via something this test can't detect
/// by method name alone:
/// - `maybe_start_discovery` hands its client to
///   `app_core::chain::discover_indexes`, not a `ChainClient` method
///   call in this file.
/// - `spending_scan_async` calls `.scan_funding(`, which is ALSO
///   legitimately called with a THIRD-PARTY descriptor (the funding-
///   wallet sites, correctly on the plain constructor) — the two
///   uses are textually identical calls, distinguishable only by
///   which function they're in.
const NAMED_WATCH_SITES: &[&str] = &["maybe_start_discovery", "spending_scan_async"];

/// Skip a string or char literal, or a line/block comment, starting at
/// byte `i` (which must point at its first byte) — returns the index
/// just past it. Used so brace-matching below never gets confused by an
/// unbalanced `{`/`}` inside prose or inside a `cb:`-prefixed log line's
/// own format-string braces. Not a full lexer (no raw-string prefix
/// handling), but this crate's shell code doesn't use raw strings.
fn skip_atom(src: &str, i: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    match bytes[i] {
        b'/' if bytes.get(i + 1) == Some(&b'/') => {
            Some(src[i..].find('\n').map(|o| i + o).unwrap_or(src.len()))
        }
        b'/' if bytes.get(i + 1) == Some(&b'*') => {
            let mut depth = 1i32;
            let mut j = i + 2;
            while j < src.len() && depth > 0 {
                if src[j..].starts_with("/*") {
                    depth += 1;
                    j += 2;
                } else if src[j..].starts_with("*/") {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            Some(j)
        }
        b'"' => {
            let mut j = i + 1;
            while j < src.len() {
                if bytes[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if bytes[j] == b'"' {
                    j += 1;
                    break;
                }
                j += 1;
            }
            Some(j)
        }
        b'\'' => {
            // char literal: 'c' or '\n' or '\'' — only treat as one if a
            // closing quote follows within a few bytes (else it's a
            // lifetime, which this crate's shell code doesn't otherwise
            // use inside a fn body's top level anyway).
            if bytes.get(i + 1) == Some(&b'\\') {
                src[i + 2..].find('\'').filter(|&o| o <= 6).map(|o| i + 3 + o)
            } else if bytes.get(i + 2) == Some(&b'\'') {
                Some(i + 3)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Byte index just past the `{`/`}`-balanced block opening at `open`
/// (which must be the index of a `{`), skipping string/char literals and
/// comments per [`skip_atom`].
fn matching_brace(src: &str, open: usize) -> usize {
    debug_assert_eq!(src.as_bytes()[open], b'{');
    let mut depth = 0i32;
    let mut i = open;
    let n = src.len();
    while i < n {
        if let Some(next) = skip_atom(src, i) {
            i = next;
            continue;
        }
        match src.as_bytes()[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("core-rpc wiring contract: unbalanced braces from byte {open}");
}

/// The full text of the top-level `fn <name>` (a bare `fn` or a
/// `pub(crate) fn`/`pub fn` — U4 turned most of these into `impl State`
/// methods) anywhere under `src/`, from its `fn` keyword through its
/// matching closing brace. Panics — a hard test failure, never a silent
/// skip — when `name` no longer exists: a rename must update
/// `NAMED_WATCH_SITES` (or whatever call site added it), not go unnoticed.
fn fn_body(files: &[(String, String)], name: &str) -> String {
    let marker = format!("fn {name}(");
    for (_, content) in files {
        let mut from = 0usize;
        while let Some(rel) = content[from..].find(&marker) {
            let pos = from + rel;
            let line_start = content[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let prefix = content[line_start..pos].trim_start();
            // a genuine definition line starts (after indentation) with
            // "fn " or a visibility qualifier — never inside a doc comment
            // (starts with "///"/"//!") or a call site (starts with the
            // receiver expression).
            if prefix.is_empty() || prefix.starts_with("pub") {
                let open = content[pos..]
                    .find('{')
                    .map(|o| pos + o)
                    .expect("fn signature must open a brace body");
                let end = matching_brace(content, open);
                return content[pos..=end].to_string();
            }
            from = pos + marker.len();
        }
    }
    panic!(
        "core-rpc wiring contract: `fn {name}` not found as a top-level function under src/ \
         (renamed or moved and this contract not updated?) — update NAMED_WATCH_SITES / this \
         test to match."
    );
}

/// Every occurrence of `needle` (a call like `"open_client_watched("`)
/// inside `body`, each returned as its full call text from the callee
/// name through the matching closing paren (depth-tracked via
/// [`matching_brace`]'s sibling logic, so a nested call in an argument
/// wouldn't confuse it, though none of the call sites here actually nest
/// one).
fn find_calls<'a>(body: &'a str, needle: &str) -> Vec<&'a str> {
    let mut calls = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = body[from..].find(needle) {
        let start = from + rel;
        let paren = start + needle.len() - 1; // index of the call's '('
        let mut depth = 0i32;
        let mut i = paren;
        loop {
            match body.as_bytes()[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        calls.push(&body[start..=i]);
        from = i + 1;
    }
    calls
}

/// The nearest enclosing top-level `fn NAME` (bare or `pub(crate)`/`pub`)
/// before byte offset `pos` in `content` — the last definition line
/// before it. Closures (`move || { .. }`) never match (they're never a
/// `fn NAME(` definition line), so this always resolves to the real
/// enclosing function even when `pos` is inside a worker-thread closure's
/// body.
fn enclosing_fn_name(content: &str, pos: usize) -> String {
    let mut search_end = pos;
    loop {
        let line_start =
            content[..search_end].rfind('\n').map(|i| i + 1).unwrap_or(0);
        if line_start == 0 && search_end == 0 {
            panic!("core-rpc wiring contract: no enclosing top-level fn found before byte {pos}");
        }
        let line = &content[line_start..search_end.min(content.len())];
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("fn ").or_else(|| {
            trimmed
                .strip_prefix("pub(crate) fn ")
                .or_else(|| trimmed.strip_prefix("pub fn "))
        }) {
            let end = rest.find(|c: char| c == '(' || c.is_whitespace()).unwrap_or(rest.len());
            return rest[..end].to_string();
        }
        if line_start == 0 {
            panic!("core-rpc wiring contract: no enclosing top-level fn found before byte {pos}");
        }
        search_end = line_start - 1; // move before the '\n' and keep scanning backward
    }
}

/// A descriptor-list ARGUMENT that's a literal empty slice — the
/// second regression this contract exists to catch. `open_client_watched`
/// treats `descriptors.is_empty()` as "nothing to configure" (its own
/// doc comment above), so a call like
/// `open_client_watched(&base, network, creds, &[])` calls the right
/// FUNCTION but is behaviorally byte-identical to plain `open_client`
/// — the exact silent regression a reviewer skimming for
/// "does it say `_watched`" would miss.
fn passes_empty_descriptor_list(call: &str) -> bool {
    let trimmed = call.trim_end();
    let trimmed = trimmed.strip_suffix(')').unwrap_or(trimmed);
    trimmed.trim_end().ends_with("&[]")
}

/// The 6 sites the U7 commit wired deliberately (per its own commit
/// message — "Wired at the 6 call sites that actually look up the
/// identity's own addresses"). 4 of them (`.address_probe`/
/// `.build_bundle`, unambiguous method names) are caught generically
/// by `every_address_probe_and_build_bundle_call_uses_the_watched_client`
/// below; the other 2 need `NAMED_WATCH_SITES` because what makes
/// them "identity-own" isn't visible in the method name alone (see
/// its doc comment).
#[test]
fn named_watch_sites_use_watched_client_with_a_real_descriptor_list() {
    let files = all_sources();
    for &name in NAMED_WATCH_SITES {
        let body = fn_body(&files, name);
        assert!(
            body.contains("open_client_watched("),
            "core-rpc wiring contract: fn {name} no longer calls open_client_watched — it \
             resolves one of the identity's OWN addresses (see the U7 commit / \
             PLAN-chain-notes-app-core-rpc.md) and must build its ChainClient through the \
             watched constructor with a real descriptor list, or every address it touches \
             pays for a per-address genesis rescan instead of one ranged import per \
             descriptor family.",
        );
        assert!(
            !body.contains("open_client("),
            "core-rpc wiring contract: fn {name} ALSO calls the plain open_client — this \
             function resolves identity-owned addresses and must do so exclusively through \
             open_client_watched.",
        );
        for call in find_calls(&body, "open_client_watched(") {
            assert!(
                !passes_empty_descriptor_list(call),
                "core-rpc wiring contract: fn {name}'s open_client_watched call passes an \
                 EMPTY descriptor list — `{call}` — which is behaviorally identical to the \
                 plain open_client (watch_descriptors no-ops on an empty list). Pass the \
                 real `core_rpc_watch`/`st.core_rpc_watch` snapshot instead.",
            );
        }
    }
}

/// Generalizes past `NAMED_WATCH_SITES`: EVERY call to
/// `.address_probe(`/`.build_bundle(` anywhere under `src/` — present
/// or future, no list to keep in sync — must live in a function that
/// configures ranged watching via `open_client_watched`. Unlike
/// `scan_funding`, these two methods are never legitimately called
/// against a third-party descriptor anywhere in this app (only ever
/// against the active identity's own address), so the method name
/// alone is enough signal here.
#[test]
fn every_address_probe_and_build_bundle_call_uses_the_watched_client() {
    let files = all_sources();
    for (_, content) in &files {
        for needle in [".address_probe(", ".build_bundle("] {
            let mut from = 0usize;
            while let Some(rel) = content[from..].find(needle) {
                let pos = from + rel;
                from = pos + needle.len();
                let fname = enclosing_fn_name(content, pos);
                let body = fn_body(&files, &fname);
                assert!(
                    body.contains("open_client_watched("),
                    "core-rpc wiring contract: fn {fname} calls {needle} (an identity-own \
                     address lookup) but never configures ranged-descriptor watching via \
                     open_client_watched — build its ChainClient with \
                     open_client_watched(..., &st.core_rpc_watch) instead of the plain \
                     open_client, or every address it resolves pays for a per-address genesis \
                     rescan instead of one ranged import per descriptor family.",
                );
            }
        }
    }
}
