use crate::*;
use app_core::chain::node_presets;
use app_core::chain::NodeStatus;
use std::cell::Cell;
use std::collections::HashMap;
use zeroize::Zeroizing;

#[test]
fn strips_inline_userinfo_from_core_url() {
    let (url, creds) = split_url_userinfo("bitcoind+http://alice:s3cr3t@192.168.1.10:8332");
    assert_eq!(url, "bitcoind+http://192.168.1.10:8332");
    assert_eq!(creds, Some(("alice".to_string(), "s3cr3t".to_string())));
}

#[test]
fn leaves_a_plain_url_untouched() {
    let (url, creds) = split_url_userinfo("bitcoind+http://192.168.1.10:8332");
    assert_eq!(url, "bitcoind+http://192.168.1.10:8332");
    assert_eq!(creds, None);
}

#[test]
fn leaves_esplora_urls_untouched() {
    let (url, creds) = split_url_userinfo("https://mempool.example/api");
    assert_eq!(url, "https://mempool.example/api");
    assert_eq!(creds, None);
}

#[test]
fn does_not_confuse_a_path_at_sign_for_userinfo() {
    // No userinfo here — the '@' (if any) would sit after a '/', which
    // this function must not treat as an authority separator.
    let (url, creds) = split_url_userinfo("http://127.0.0.1:3002/api@weird");
    assert_eq!(url, "http://127.0.0.1:3002/api@weird");
    assert_eq!(creds, None);
}

#[test]
fn empty_and_malformed_inputs_pass_through() {
    assert_eq!(split_url_userinfo(""), (String::new(), None));
    assert_eq!(split_url_userinfo("not-a-url"), ("not-a-url".to_string(), None));
}

// ---- U10: "Save credentials" switch ----

#[test]
fn persist_default_true_when_absent() {
    let map: HashMap<String, bool> = HashMap::new();
    assert!(core_rpc_persist_default_true(&map, "testnet4"));
}

#[test]
fn persist_default_respects_explicit_value() {
    let mut map = HashMap::new();
    map.insert("testnet4".to_string(), false);
    map.insert("mainnet".to_string(), true);
    assert!(!core_rpc_persist_default_true(&map, "testnet4"));
    assert!(core_rpc_persist_default_true(&map, "mainnet"));
    // A network never mentioned still defaults true.
    assert!(core_rpc_persist_default_true(&map, "signet"));
}

#[test]
fn resolve_creds_persist_on_uses_keychain_source() {
    let keychain = Some(("alice".to_string(), "s3cr3t".to_string()));
    let session = Some(("bob".to_string(), "wrongsource".to_string()));
    let got = resolve_core_rpc_creds("bitcoind+http://10.0.0.1:8332", true, keychain, session);
    assert_eq!(got, Some(("alice".to_string(), "s3cr3t".to_string())));
}

#[test]
fn resolve_creds_persist_off_uses_session_source() {
    let keychain = Some(("alice".to_string(), "s3cr3t".to_string()));
    let session = Some(("bob".to_string(), "sess-pass".to_string()));
    let got = resolve_core_rpc_creds("bitcoind+http://10.0.0.1:8332", false, keychain, session);
    assert_eq!(got, Some(("bob".to_string(), "sess-pass".to_string())));
}

#[test]
fn resolve_creds_esplora_base_short_circuits_regardless_of_switch() {
    // Neither source is consulted for a non-`bitcoind+` base — proves
    // Esplora never touches either the Keychain-shaped input or the
    // session-shaped input, whichever the switch would otherwise pick.
    let some_creds = Some(("alice".to_string(), "s3cr3t".to_string()));
    assert_eq!(
        resolve_core_rpc_creds(
            "https://mempool.example/api",
            true,
            some_creds.clone(),
            some_creds.clone()
        ),
        None
    );
    assert_eq!(
        resolve_core_rpc_creds("https://mempool.example/api", false, some_creds.clone(), some_creds),
        None
    );
}

#[test]
fn route_creds_persist_on_calls_keychain_store_not_session() {
    let mut session: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
    let stored: Cell<Option<(String, String)>> = Cell::new(None);
    let deleted = Cell::new(false);
    let result = route_core_rpc_creds(
        true,
        "testnet4",
        "alice",
        "s3cr3t",
        &mut session,
        |u, p| {
            stored.set(Some((u.to_string(), p.to_string())));
            Ok(())
        },
        || {
            deleted.set(true);
            Ok(())
        },
    );
    assert!(result.is_ok());
    assert_eq!(stored.into_inner(), Some(("alice".to_string(), "s3cr3t".to_string())));
    assert!(!deleted.get());
    assert!(session.is_empty(), "persist-on must never touch the session slot");
}

#[test]
fn route_creds_persist_on_clearing_both_fields_deletes() {
    let mut session: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
    let stored = Cell::new(false);
    let deleted = Cell::new(false);
    let result = route_core_rpc_creds(
        true,
        "testnet4",
        "",
        "",
        &mut session,
        |_, _| {
            stored.set(true);
            Ok(())
        },
        || {
            deleted.set(true);
            Ok(())
        },
    );
    assert!(result.is_ok());
    assert!(deleted.get());
    assert!(!stored.get());
}

#[test]
fn route_creds_persist_off_never_touches_keychain() {
    let mut session: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
    let touched = Cell::new(false);
    let result = route_core_rpc_creds(
        false,
        "testnet4",
        "alice",
        "s3cr3t",
        &mut session,
        |_, _| {
            touched.set(true);
            Ok(())
        },
        || {
            touched.set(true);
            Ok(())
        },
    );
    assert!(result.is_ok());
    assert!(!touched.get(), "persist-off must never call a Keychain op");
    let entry = session.get("testnet4").expect("session slot populated");
    assert_eq!(entry.0, "alice");
    assert_eq!(entry.1.as_str(), "s3cr3t");
}

#[test]
fn route_creds_persist_off_clearing_both_fields_clears_session_only() {
    let mut session: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
    session.insert("testnet4".to_string(), ("alice".to_string(), Zeroizing::new("s3cr3t".to_string())));
    let touched = Cell::new(false);
    let result = route_core_rpc_creds(
        false,
        "testnet4",
        "",
        "",
        &mut session,
        |_, _| {
            touched.set(true);
            Ok(())
        },
        || {
            touched.set(true);
            Ok(())
        },
    );
    assert!(result.is_ok());
    assert!(!touched.get());
    assert!(!session.contains_key("testnet4"));
}

/// The load-bearing invariant: turning the switch OFF must
/// unconditionally delete whatever the Keychain holds — this is what a
/// mutation test should catch first. Also proves `store` is never
/// called on the OFF path.
#[test]
fn toggle_off_always_deletes_the_stored_keychain_item() {
    let deleted = Cell::new(false);
    let stored = Cell::new(false);
    let result = apply_core_rpc_persist_toggle(
        false,
        "alice",
        "s3cr3t",
        || {
            deleted.set(true);
            Ok(())
        },
        |_, _| {
            stored.set(true);
            Ok(())
        },
    );
    assert!(deleted.get(), "OFF must delete the stored Keychain item");
    assert!(!stored.get());
    match result {
        Ok(Some((u, p))) => {
            assert_eq!(u, "alice");
            assert_eq!(p.as_str(), "s3cr3t");
        }
        other => panic!("expected the on-screen fields handed back for the session slot, got {other:?}"),
    }
}

#[test]
fn toggle_off_with_blank_fields_still_deletes_and_leaves_session_empty() {
    // Blank on-screen fields don't imply "nothing to delete" — a
    // previously saved credential from an earlier session could still
    // be sitting in the Keychain (this app never pre-populates the
    // fields from anywhere but Settings-open), so deletion must fire
    // unconditionally on every ON→OFF transition.
    let deleted = Cell::new(false);
    let result = apply_core_rpc_persist_toggle(
        false,
        "",
        "",
        || {
            deleted.set(true);
            Ok(())
        },
        |_, _| Ok(()),
    );
    assert!(deleted.get());
    assert_eq!(result.unwrap(), None);
}

#[test]
fn toggle_off_propagates_a_keychain_delete_error() {
    let result = apply_core_rpc_persist_toggle(
        false,
        "alice",
        "s3cr3t",
        || Err("keychain busy".to_string()),
        |_, _| Ok(()),
    );
    assert_eq!(result, Err("keychain busy".to_string()));
}

#[test]
fn toggle_on_persists_the_on_screen_fields_and_clears_session() {
    let stored: Cell<Option<(String, String)>> = Cell::new(None);
    let deleted = Cell::new(false);
    let result = apply_core_rpc_persist_toggle(
        true,
        "alice",
        "s3cr3t",
        || {
            deleted.set(true);
            Ok(())
        },
        |u, p| {
            stored.set(Some((u.to_string(), p.to_string())));
            Ok(())
        },
    );
    assert!(!deleted.get());
    assert_eq!(stored.into_inner(), Some(("alice".to_string(), "s3cr3t".to_string())));
    assert_eq!(result.unwrap(), None);
}

#[test]
fn toggle_on_with_nothing_typed_stores_nothing() {
    let stored = Cell::new(false);
    let result = apply_core_rpc_persist_toggle(
        true,
        "",
        "",
        || Ok(()),
        |_, _| {
            stored.set(true);
            Ok(())
        },
    );
    assert!(!stored.get());
    assert_eq!(result.unwrap(), None);
}

/// `parse_core_rpc_save_creds` round trip in isolation — a hand-built
/// `Value`, not the real `State::config_payload()`. This is READ-side
/// coverage only (the boot-time parse); the actual WRITE side is
/// covered by `config_payload_never_carries_session_credentials`
/// below, which drives the production method instead of mirroring its
/// shape.
#[test]
fn save_creds_preference_round_trips_through_config_json_never_carrying_secrets() {
    let mut before: HashMap<String, bool> = HashMap::new();
    before.insert("testnet4".to_string(), false);
    before.insert("mainnet".to_string(), true);
    let json = serde_json::json!({ "core_rpc_save_creds": before.clone() });
    let text = json.to_string();
    assert!(!text.contains("s3cr3t"));
    assert!(!text.contains("core_rpc_session_creds"));
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid json");
    let after = parse_core_rpc_save_creds(&parsed);
    assert_eq!(after, before);
}

#[test]
fn save_creds_preference_absent_key_parses_to_empty_map() {
    let parsed: serde_json::Value = serde_json::json!({ "network": "testnet4" });
    assert!(parse_core_rpc_save_creds(&parsed).is_empty());
}

/// The load-bearing regression test: drives the REAL
/// `State::config_payload()` (what `save_config` actually serializes,
/// after this review's extraction) with a distinctive username AND
/// password sitting in `core_rpc_session_creds` — the exact plaintext
/// a leak would carry — and asserts neither appears anywhere in the
/// output, while the boolean preference map and the other expected
/// keys still do. A hand-built mirror of the payload shape (as the
/// prior version of this test was) cannot catch `save_config` drifting
/// to leak a new field; this asserts on bytes the production method
/// itself produced.
#[test]
fn config_payload_never_carries_session_credentials() {
    let mut save_creds: HashMap<String, bool> = HashMap::new();
    save_creds.insert("testnet4".to_string(), false);
    let mut session_creds: HashMap<String, (String, Zeroizing<String>)> = HashMap::new();
    session_creds.insert(
        "testnet4".to_string(),
        (
            "SENTINEL_USER_do_not_leak".to_string(),
            Zeroizing::new("SENTINEL_PASS_do_not_leak".to_string()),
        ),
    );
    let state = State::test_stub(
        Network::Testnet4,
        HashMap::new(),
        HashMap::new(),
        save_creds,
        session_creds,
    );
    let text = state.config_payload().to_string();
    assert!(!text.contains("SENTINEL_USER_do_not_leak"), "leaked the session username: {text}");
    assert!(!text.contains("SENTINEL_PASS_do_not_leak"), "leaked the session password: {text}");
    assert!(!text.contains("core_rpc_session_creds"), "leaked the session-creds field name: {text}");
    // The boolean preference map DOES round-trip (it's a preference,
    // not a secret) — and a couple of the other expected keys, so this
    // test would also fail loudly if `config_payload` lost fields
    // rather than gained one.
    assert!(text.contains("core_rpc_save_creds"));
    assert!(text.contains("testnet4"));
    assert!(text.contains("\"network\":\"testnet4\""));
}

// ---- U11: node-health caption copy (defect 2) ----

/// The exact nonsense the review caught: `prune_height` of `Some(0)`
/// used to render "pruned below block 0 — notes/history before it
/// can't be recovered", which claims something is unrecoverable when
/// NOTHING has actually been pruned yet. Zero must read as informational
/// (no warn tint), not the strong warning.
#[test]
fn prune_height_zero_is_not_alarming() {
    let status = NodeStatus { pruned: true, prune_height: Some(0), txindex: true, ..Default::default() };
    let (text, warn) = format_node_status(&status);
    assert!(!warn, "prune height 0 must not set the warn tint: {text}");
    assert!(!text.contains("can't be recovered"), "prune height 0 must not claim data is lost: {text}");
    assert!(text.contains("nothing pruned"), "expected an honest not-yet-pruned note: {text}");
}

/// Same honesty rule for the ABSENT case (`prune_height: None` while
/// `pruned` is true) — bitcoind only populates `pruneheight` once it has
/// pruned at least once, so `None` means the same "nothing pruned yet"
/// state as `Some(0)`, never "unknown, assume the worst."
#[test]
fn prune_height_absent_is_not_alarming() {
    let status = NodeStatus { pruned: true, prune_height: None, txindex: true, ..Default::default() };
    let (text, warn) = format_node_status(&status);
    assert!(!warn, "absent prune height must not set the warn tint: {text}");
    assert!(!text.contains("can't be recovered"), "absent prune height must not claim data is lost: {text}");
}

/// A REAL nonzero prune height keeps the strong wording and the warn
/// tint — the fix must narrow the false-positive case, not silence the
/// real one.
#[test]
fn prune_height_nonzero_still_warns() {
    let status = NodeStatus { pruned: true, prune_height: Some(500), txindex: true, ..Default::default() };
    let (text, warn) = format_node_status(&status);
    assert!(warn, "a real prune height must still warn: {text}");
    assert!(text.contains("pruned below block 500"), "expected the real height named: {text}");
    assert!(text.contains("can't be recovered"), "expected the strong wording for a real prune: {text}");
}

/// The exact scenario a locally-running pruned bitcoind hits moments
/// after `-prune` is turned on: pruned (height 0, not yet alarming) AND
/// no txindex (a real warning) in the SAME status. The overall `warn`
/// flag must still be true (txindex alone earns it), the join must not
/// leave a dangling `· ` separator, and the non-alarming prune note must
/// still be present alongside the real txindex warning.
#[test]
fn pruned_zero_plus_no_txindex_warns_from_txindex_only() {
    let status = NodeStatus { pruned: true, prune_height: Some(0), txindex: false, ..Default::default() };
    let (text, warn) = format_node_status(&status);
    assert!(warn, "missing txindex alone must still warn: {text}");
    assert!(text.contains("nothing pruned"));
    assert!(text.contains("no txindex"));
    assert!(!text.trim_end().ends_with('·'), "no dangling separator: {text:?}");
    assert!(!text.contains("  "), "no doubled-up spacing from an empty joined part: {text:?}");
}

/// A fully healthy node — the "previously invisible" one-line case
/// (defect 1's UI symptom): no parts pushed at all, so the fallback
/// "connected · tip N" line is used, and it must never warn.
#[test]
fn healthy_node_reports_connected_and_never_warns() {
    let status = NodeStatus { tip_height: 123_456, txindex: true, ..Default::default() };
    let (text, warn) = format_node_status(&status);
    assert!(!warn);
    assert_eq!(text, "connected · tip 123,456");
}

/// A rescanning wallet must never look like a quiet/empty one — still
/// warns.
#[test]
fn wallet_scanning_warns() {
    let status = NodeStatus { txindex: true, wallet_scanning: Some(true), ..Default::default() };
    let (text, warn) = format_node_status(&status);
    assert!(warn, "{text}");
    assert!(text.contains("rescanning"));
}

// ---- U11: strip inline creds from a LOADED config.json (defect 3) ----

#[test]
fn migrate_strips_inline_creds_from_a_loaded_node_url() {
    let mut node_urls = HashMap::new();
    node_urls.insert(
        "mainnet".to_string(),
        "bitcoind+http://alice:s3cr3t@203.0.113.5:8332".to_string(),
    );
    let found = migrate_inline_node_creds(&mut node_urls);
    assert_eq!(found, vec![("mainnet".to_string(), "alice".to_string(), "s3cr3t".to_string())]);
    assert_eq!(node_urls.get("mainnet").map(String::as_str), Some("bitcoind+http://203.0.113.5:8332"));
}

#[test]
fn migrate_leaves_a_clean_loaded_url_untouched() {
    let mut node_urls = HashMap::new();
    node_urls.insert("testnet4".to_string(), "bitcoind+http://10.0.0.5:8332".to_string());
    let found = migrate_inline_node_creds(&mut node_urls);
    assert!(found.is_empty());
    assert_eq!(node_urls.get("testnet4").map(String::as_str), Some("bitcoind+http://10.0.0.5:8332"));
}

#[test]
fn migrate_handles_multiple_networks_independently() {
    let mut node_urls = HashMap::new();
    node_urls.insert(
        "mainnet".to_string(),
        "bitcoind+http://alice:s3cr3t@203.0.113.5:8332".to_string(),
    );
    node_urls.insert("testnet4".to_string(), "https://mempool.example/api".to_string());
    node_urls.insert(
        "signet".to_string(),
        "bitcoind+http://bob:hunter2@198.51.100.9:8332".to_string(),
    );
    let mut found = migrate_inline_node_creds(&mut node_urls);
    found.sort();
    assert_eq!(
        found,
        vec![
            ("mainnet".to_string(), "alice".to_string(), "s3cr3t".to_string()),
            ("signet".to_string(), "bob".to_string(), "hunter2".to_string()),
        ]
    );
    assert_eq!(node_urls.get("mainnet").map(String::as_str), Some("bitcoind+http://203.0.113.5:8332"));
    assert_eq!(node_urls.get("testnet4").map(String::as_str), Some("https://mempool.example/api"));
    assert_eq!(node_urls.get("signet").map(String::as_str), Some("bitcoind+http://198.51.100.9:8332"));
}

#[test]
fn migrate_on_an_empty_map_is_a_noop() {
    let mut node_urls: HashMap<String, String> = HashMap::new();
    assert!(migrate_inline_node_creds(&mut node_urls).is_empty());
    assert!(node_urls.is_empty());
}

// ---- U12: node picker — "Bitcoin Core" row, prefix-free UI ----

#[test]
fn confirmed_default_rpc_ports_per_network() {
    // Straight from the installed bitcoind v30.2.0's own
    // `-help-debug` text (verified 2026-07-29):
    //   -rpcport=<port> … (default: 8332, testnet3: 18332,
    //   testnet4: 48332, signet: 38332, regtest: 18443)
    // This app has no Testnet3 variant, so only the other four apply.
    assert_eq!(core_rpc_default_port(Network::Mainnet), 8332);
    assert_eq!(core_rpc_default_port(Network::Testnet4), 48332);
    assert_eq!(core_rpc_default_port(Network::Signet), 38332);
    assert_eq!(core_rpc_default_port(Network::Regtest), 18443);
}

// (input, network, expected stored URL, expected inline creds)
type ComposeCoreUrlCase = (&'static str, Network, &'static str, Option<(&'static str, &'static str)>);

#[test]
fn compose_core_url_normalization_table() {
    let cases: &[ComposeCoreUrlCase] = &[
        // bare host -> default scheme + default port for the network
        ("192.168.1.10", Network::Mainnet, "bitcoind+http://192.168.1.10:8332", None),
        ("umbrel.local", Network::Testnet4, "bitcoind+http://umbrel.local:48332", None),
        ("node.example", Network::Signet, "bitcoind+http://node.example:38332", None),
        ("127.0.0.1", Network::Regtest, "bitcoind+http://127.0.0.1:18443", None),
        // host:port -> default scheme, given port honored verbatim
        ("192.168.1.10:8332", Network::Mainnet, "bitcoind+http://192.168.1.10:8332", None),
        ("umbrel.local:9998", Network::Testnet4, "bitcoind+http://umbrel.local:9998", None),
        // explicit http:// / https:// -> scheme honored, port defaults
        // or is honored the same way
        ("http://192.168.1.10", Network::Mainnet, "bitcoind+http://192.168.1.10:8332", None),
        (
            "https://node.example:8332",
            Network::Mainnet,
            "bitcoind+https://node.example:8332",
            None,
        ),
        ("https://umbrel.local", Network::Signet, "bitcoind+https://umbrel.local:38332", None),
        // whitespace tolerated
        ("  192.168.1.10:8332  ", Network::Mainnet, "bitcoind+http://192.168.1.10:8332", None),
        // pasted `bitcoind+…` (backward compat / Sparrow-style paste)
        // re-normalizes exactly like the bare forms above
        (
            "bitcoind+http://192.168.1.10:8332",
            Network::Mainnet,
            "bitcoind+http://192.168.1.10:8332",
            None,
        ),
        (
            "bitcoind+https://node.example",
            Network::Signet,
            "bitcoind+https://node.example:38332",
            None,
        ),
        (
            "bitcoind+http://alice:s3cr3t@192.168.1.10:8332",
            Network::Mainnet,
            "bitcoind+http://192.168.1.10:8332",
            Some(("alice", "s3cr3t")),
        ),
        // inline creds on a bare paste (no bitcoind+, no scheme)
        (
            "alice:s3cr3t@192.168.1.10:8332",
            Network::Mainnet,
            "bitcoind+http://192.168.1.10:8332",
            Some(("alice", "s3cr3t")),
        ),
    ];
    for (input, net, expect_url, expect_creds) in cases {
        let (url, creds) = compose_core_url(input, *net)
            .unwrap_or_else(|e| panic!("expected {input:?} to parse, got err {e:?}"));
        assert_eq!(url, *expect_url, "input={input:?}");
        assert_eq!(
            creds,
            expect_creds.map(|(u, p)| (u.to_string(), p.to_string())),
            "input={input:?}"
        );
    }
}

#[test]
fn compose_core_url_rejects_malformed_input() {
    let bad: &[&str] = &[
        "",
        "   ",
        "bitcoind+",
        "192.168.1.10:not-a-port",
        "192.168.1.10:99999999",
        "ftp://192.168.1.10:8332",
        "192.168.1.10:8332/wallet/foo", // path not allowed on this field
        "http://",
        "http://:8332", // empty host
    ];
    for input in bad {
        assert!(
            compose_core_url(input, Network::Mainnet).is_err(),
            "expected {input:?} to be rejected"
        );
    }
}

#[test]
fn compose_core_url_error_messages_are_useful() {
    let err = compose_core_url("ftp://host:21", Network::Mainnet).unwrap_err();
    assert!(err.contains("scheme"), "message should mention the bad scheme: {err}");
    let err = compose_core_url("", Network::Mainnet).unwrap_err();
    assert!(err.contains("host"), "message should ask for a host: {err}");
}

#[test]
fn display_core_url_elides_default_http_scheme_but_keeps_https() {
    assert_eq!(display_core_url("bitcoind+http://192.168.1.10:8332"), "192.168.1.10:8332");
    assert_eq!(
        display_core_url("bitcoind+https://node.example:8332"),
        "https://node.example:8332"
    );
}

#[test]
fn compose_then_display_round_trips_to_the_same_text() {
    // What gets shown after a successful commit must, if resubmitted
    // unchanged, reproduce the exact same stored URL — an elided
    // scheme must never silently flip http<->https on a second save.
    for (typed, net) in [
        ("192.168.1.10:8332", Network::Mainnet),
        ("umbrel.local", Network::Testnet4),
        ("https://node.example:8332", Network::Mainnet),
        ("https://umbrel.local", Network::Signet),
    ] {
        let (stored1, _) = compose_core_url(typed, net).unwrap();
        let shown = display_core_url(&stored1);
        let (stored2, _) = compose_core_url(&shown, net).unwrap();
        assert_eq!(stored1, stored2, "typed={typed:?} shown={shown:?}");
    }
}

#[test]
fn fill_node_round_trip_core_base_selects_core_row_no_prefix_no_creds() {
    let net = Network::Mainnet;
    let presets = node_presets(net);
    let (opts, idx, esplora_text, core_text) =
        fill_node(presets.clone(), Some("bitcoind+http://192.168.1.10:8332"));
    // Row order: <presets…>, "Bitcoin Core", "Custom…" — Core is
    // second-to-last regardless of how many presets a network has.
    assert_eq!(opts[opts.len() - 2], "Bitcoin Core");
    assert_eq!(opts[opts.len() - 1], "Custom…");
    assert_eq!(idx as usize, presets.len()); // the "Bitcoin Core" row
    assert_eq!(esplora_text, "");
    assert_eq!(core_text, "192.168.1.10:8332"); // no prefix, no creds
}

#[test]
fn fill_node_round_trip_preset_esplora_base_selects_that_preset() {
    let net = Network::Mainnet;
    let presets = node_presets(net);
    // Blockstream is a real preset on mainnet with an explicit URL.
    let (label, url) =
        presets.iter().find(|(_, u)| u.is_some()).expect("mainnet has an explicit preset");
    let (opts, idx, esplora_text, core_text) = fill_node(presets.clone(), *url);
    assert_eq!(opts[idx as usize], *label);
    assert_eq!(esplora_text, "");
    assert_eq!(core_text, "");
}

#[test]
fn fill_node_round_trip_custom_esplora_base_selects_custom_row() {
    let net = Network::Mainnet;
    let presets = node_presets(net);
    let (opts, idx, esplora_text, core_text) =
        fill_node(presets.clone(), Some("https://my-own-node.example/api"));
    assert_eq!(opts[idx as usize], "Custom…");
    assert_eq!(idx as usize, presets.len() + 1);
    assert_eq!(esplora_text, "https://my-own-node.example/api");
    assert_eq!(core_text, "");
}

#[test]
fn fill_node_regtest_has_exactly_core_then_custom() {
    // node_presets(Regtest) is empty — the dropdown must still resolve
    // to exactly "Bitcoin Core", "Custom…" with correct index math.
    let net = Network::Regtest;
    let presets = node_presets(net);
    assert!(presets.is_empty());
    let (opts, idx, _, core_text) =
        fill_node(presets.clone(), Some("bitcoind+http://127.0.0.1:18443"));
    assert_eq!(opts.len(), 2);
    assert_eq!(opts[0], "Bitcoin Core");
    assert_eq!(opts[1], "Custom…");
    assert_eq!(idx, 0);
    assert_eq!(core_text, "127.0.0.1:18443");

    // No configured value at all (default network base, None) selects
    // Custom on regtest — there is no Esplora preset for it to match.
    let (opts2, idx2, esplora_text2, core_text2) = fill_node(presets, None);
    assert_eq!(opts2.len(), 2);
    assert_eq!(idx2, 1); // "Custom…"
    assert_eq!(esplora_text2, "");
    assert_eq!(core_text2, "");
}

#[test]
fn credentials_typed_into_node_address_field_never_reach_the_stored_url() {
    // The node-address field's own composer must never let a
    // credential survive into the value that gets written to
    // config.json — same invariant `split_url_userinfo` enforces for
    // the Custom field's paste path, proven here end-to-end through
    // `compose_core_url` for every accepted input shape that could
    // carry one.
    for input in [
        "alice:s3cr3t@192.168.1.10:8332",
        "http://alice:s3cr3t@192.168.1.10:8332",
        "https://alice:s3cr3t@192.168.1.10",
        "bitcoind+http://alice:s3cr3t@192.168.1.10:8332",
    ] {
        let (url, creds) = compose_core_url(input, Network::Mainnet).unwrap();
        assert!(!url.contains("s3cr3t"), "stored url leaked a credential: {url}");
        assert!(!url.contains('@'), "stored url carries userinfo syntax: {url}");
        assert_eq!(creds, Some(("alice".to_string(), "s3cr3t".to_string())));
        // And the round-trip display of that stored URL is equally
        // creds-free (belt and suspenders — display never re-derives
        // creds from anywhere, but prove it never echoes the input).
        assert!(!display_core_url(&url).contains("s3cr3t"));
    }
}
