use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
const WATCH_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";

fn activated_stub(tag: &str, material: &str) -> State {
    let mut st =
        State::test_stub(Network::Mainnet, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("cn-activate-watch-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    activate(&mut st, material, false).unwrap_or_else(|e| panic!("activate({tag}) failed: {e}"));
    st
}

/// A hierarchical (mnemonic) identity gets BOTH families: the account's
/// notebook `tr()` descriptor and its `wpkh()` spending descriptor
/// (`can_derive_spending` is true for any hierarchical material) — this
/// is the len == 2 case every one of the 6 watched call sites relies on
/// actually being non-empty, or `open_client_watched` degrades to the
/// exact same per-address fallback the plain constructor uses (its own
/// doc comment: `if !descriptors.is_empty()`).
#[test]
fn hierarchical_mnemonic_populates_both_descriptor_families() {
    let st = activated_stub("mnemonic", MNEMONIC);
    assert_eq!(
        st.core_rpc_watch.len(),
        2,
        "activate() must populate core_rpc_watch with the notebook + spending \
         descriptor families for hierarchical material — got {:?}",
        st.core_rpc_watch
    );
    assert!(st.core_rpc_watch[0].descriptor.starts_with("tr("));
    assert!(st.core_rpc_watch[1].descriptor.starts_with("wpkh("));
}

/// A single-key (WIF) identity has exactly ONE address — nothing to
/// range over — so `core_rpc_watch` must stay empty and every lookup
/// keeps going through the per-address `addr()` fallback, unchanged.
/// An accidental non-empty result here would be silently harmless today
/// (the fallback still works) but would mean `identity_watch_descriptors`
/// no longer matches its own doc comment's single-key case.
#[test]
fn single_key_wif_leaves_core_rpc_watch_empty() {
    let st = activated_stub("wif", WIF);
    assert!(
        st.core_rpc_watch.is_empty(),
        "single-key (WIF) material must not populate core_rpc_watch — got {:?}",
        st.core_rpc_watch
    );
}

/// Watch-only (ranged xpub) gets exactly the ONE notebook family — no
/// spending descriptor, since `can_derive_spending` requires a private
/// hierarchical key this identity doesn't have. The descriptor text
/// itself is the bare xpub verbatim (`keyexport::export_formats`'s
/// `watch_only_yields_descriptor_no_private` test pins the same
/// behavior) — `FundingSource::parse`/`watch_descriptors` wrap a bare
/// xpub in `tr(.../<0;1>/*)` themselves, so this is not re-wrapped here.
#[test]
fn watch_only_xpub_populates_exactly_one_descriptor_family() {
    let st = activated_stub("xpub", WATCH_XPUB);
    assert_eq!(
        st.core_rpc_watch.len(),
        1,
        "watch-only xpub material must populate exactly one (notebook) descriptor \
         family — got {:?}",
        st.core_rpc_watch
    );
    assert_eq!(st.core_rpc_watch[0].descriptor, WATCH_XPUB);
}
