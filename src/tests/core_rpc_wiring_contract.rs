/// The current text of this very file — re-read at every compile, so
/// this test always judges the ACTUAL source, mutation included.
const SRC: &str = include_str!("../lib.rs");

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

/// The full text of the top-level `fn <name>` in `src` (its
/// signature through its matching closing brace), found by scanning
/// for the first subsequent line that is EXACTLY `}` at column 0 —
/// every top-level item in this rustfmt'd file closes that way, and
/// unlike counting every `{`/`}` byte in the body this is immune to
/// the (unbalanced, in general) braces that show up inside string
/// literals and prose comments. Panics — a hard test failure, never
/// a silent skip — when `name` no longer exists as a top-level `fn`:
/// a rename must update `NAMED_WATCH_SITES` (or whatever call site
/// added it), not go unnoticed.
fn fn_body<'a>(src: &'a str, name: &str) -> &'a str {
    let marker = format!("\nfn {name}(");
    let rel = src.find(&marker).unwrap_or_else(|| {
        panic!(
            "core-rpc wiring contract: `fn {name}` not found as a top-level function in \
             src/lib.rs (renamed or removed?) — update NAMED_WATCH_SITES / this test to match."
        )
    });
    let start = rel + 1; // land exactly on "fn ", past the newline we matched on
    let mut end = start;
    for line in src[start..].split_inclusive('\n') {
        end += line.len();
        if line.trim_end_matches('\n') == "}" {
            return &src[start..end];
        }
    }
    panic!("core-rpc wiring contract: no top-level closing `{{`}}` found for fn {name}");
}

/// Every occurrence of `needle` (a call like `"open_client_watched("`)
/// inside `body`, each returned as its full call text from the callee
/// name through the matching closing paren (depth-tracked, so a
/// nested call in an argument wouldn't confuse it, though none of the
/// call sites here actually nest one).
fn find_calls<'a>(body: &'a str, needle: &str) -> Vec<&'a str> {
    let bytes = body.as_bytes();
    let mut calls = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = body[from..].find(needle) {
        let start = from + rel;
        let paren = start + needle.len() - 1; // index of the call's '('
        let mut depth = 0i32;
        let mut i = paren;
        loop {
            match bytes[i] {
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

/// The nearest enclosing top-level `fn NAME` before byte offset `pos`
/// in `src` — the last `"\nfn "` before it, name read up to the next
/// `(`/whitespace. Closures (`move || { .. }`) never match `"\nfn "`
/// (they're never at column 0 as `fn`), so this always resolves to
/// the real enclosing function even when `pos` is inside a
/// worker-thread closure's body.
fn enclosing_fn_name(src: &str, pos: usize) -> String {
    let prefix = &src[..pos];
    let idx = prefix.rfind("\nfn ").unwrap_or_else(|| {
        panic!("core-rpc wiring contract: no enclosing top-level fn found before byte {pos}")
    });
    let after_fn = &prefix[idx + 4..]; // skip "\nfn "
    let end = after_fn.find(|c: char| c == '(' || c.is_whitespace()).unwrap_or(after_fn.len());
    after_fn[..end].to_string()
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
    for &name in NAMED_WATCH_SITES {
        let body = fn_body(SRC, name);
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
        for call in find_calls(body, "open_client_watched(") {
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
/// `.address_probe(`/`.build_bundle(` anywhere in this file — present
/// or future, no list to keep in sync — must live in a function that
/// configures ranged watching via `open_client_watched`. Unlike
/// `scan_funding`, these two methods are never legitimately called
/// against a third-party descriptor anywhere in this app (only ever
/// against the active identity's own address), so the method name
/// alone is enough signal here.
#[test]
fn every_address_probe_and_build_bundle_call_uses_the_watched_client() {
    for needle in [".address_probe(", ".build_bundle("] {
        let mut from = 0usize;
        while let Some(rel) = SRC[from..].find(needle) {
            let pos = from + rel;
            from = pos + needle.len();
            let fname = enclosing_fn_name(SRC, pos);
            let body = fn_body(SRC, &fname);
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
