// ---------------------------------------------------------------------------
// In-process UI-flow tests: compose-simplify
// (PLAN-graffito-compose-simplify.md, 2026-09-07).
// ---------------------------------------------------------------------------
//
// Covers the plan's Verification §1 list: Settings "Compose defaults"
// round-trips through config.json (+ the `pq_mlkem_off` migration), a
// per-note override is applied to the live compose session and is GONE on
// the next compose, the gift dust gate refuses 329 and accepts 330 in BOTH
// Settings and the sheet, the gear card's override flags reflect an
// override, and the quantum status-pill states for keyed / unkeyed /
// partially-keyed recipients.

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn funded_stub(tag: &str) -> (State, AppWindow) {
    i_slint_backend_testing::init_no_event_loop();
    let node_urls = HashMap::from([("regtest".to_string(), "http://127.0.0.1:1".to_string())]);
    let mut st = State::test_stub(Network::Regtest, node_urls, HashMap::new(), HashMap::new(), HashMap::new());
    let dir = std::env::temp_dir().join(format!("graffito-ui-composedefaults-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st.store.as_mut().unwrap().utxos.push(app_core::store::LedgerUtxo {
        txid: "aa".repeat(32),
        vout: 0,
        value: 100_000,
        height: Some(100),
        pending_spend: false,
    });
    st.fees_fetched_at = Some(std::time::Instant::now());
    let app = AppWindow::new().expect("AppWindow");
    (st, app)
}

// ---------------------------------------------------------------------------
// 1. Settings "Compose defaults" round-trips through config.json, and the
//    legacy top-level `pq_mlkem_off` migrates into `compose.pq_mlkem_off`.
// ---------------------------------------------------------------------------

#[test]
fn fresh_state_serializes_compose_defaults_and_drops_the_legacy_top_level_key() {
    let st = State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    let payload = st.config_payload();
    assert!(payload.get("pq_mlkem_off").is_none(), "the legacy top-level key must never be written again");
    let compose = payload.get("compose").expect("config_payload must carry a \"compose\" object");
    assert_eq!(compose["visibility_private"], serde_json::json!(true));
    assert_eq!(compose["fee_tier"], serde_json::json!(1));
    assert_eq!(compose["gift_sats"], serde_json::json!(330));
    assert_eq!(compose["pay_from"], serde_json::json!("notebook"));
    assert_eq!(compose["coins"], serde_json::json!("fewest"));
    assert_eq!(compose["pq_mlkem_off"], serde_json::json!(false));
}

#[test]
fn compose_defaults_round_trip_through_json() {
    let mut st = State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    st.compose_defaults.visibility_private = false;
    st.compose_defaults.fee_tier = 3;
    st.compose_defaults.fee_rate = "7.5".to_string();
    st.compose_defaults.gift_sats = 5_000;
    st.compose_defaults.pay_from = "spending".to_string();
    st.compose_defaults.coins = "consolidate".to_string();
    st.compose_defaults.pq_mlkem_off = true;
    let payload = st.config_payload();
    let round_tripped = ComposeDefaults::from_json(payload.get("compose").unwrap());
    assert_eq!(round_tripped, st.compose_defaults);
}

#[test]
fn legacy_config_migrates_pq_mlkem_off_and_defaults_everything_else() {
    let legacy = serde_json::json!({ "network": "regtest", "pq_mlkem_off": true });
    let migrated = crate::boot::compose_defaults_from_config(&legacy);
    assert!(migrated.pq_mlkem_off, "the legacy bool must migrate into the new field");
    let defaults = ComposeDefaults::default();
    assert_eq!(migrated.visibility_private, defaults.visibility_private);
    assert_eq!(migrated.fee_tier, defaults.fee_tier);
    assert_eq!(migrated.gift_sats, defaults.gift_sats);
    assert_eq!(migrated.pay_from, defaults.pay_from);
    assert_eq!(migrated.coins, defaults.coins);
}

#[test]
fn a_config_with_no_compose_key_and_no_legacy_key_is_the_plain_default() {
    let fresh = serde_json::json!({ "network": "regtest" });
    let d = crate::boot::compose_defaults_from_config(&fresh);
    assert_eq!(d, ComposeDefaults::default());
}

#[test]
fn new_style_compose_object_is_read_field_by_field_never_the_legacy_key() {
    // A config carrying BOTH the new "compose" object and the stale legacy
    // key (e.g. one that upgraded then a bug re-wrote the old key by hand)
    // must prefer the new object entirely — the legacy key is a migration
    // source only for configs that have NOTHING newer.
    let cfg = serde_json::json!({
        "pq_mlkem_off": true,
        "compose": { "pq_mlkem_off": false, "gift_sats": 999 },
    });
    let d = crate::boot::compose_defaults_from_config(&cfg);
    assert!(!d.pq_mlkem_off, "the new object's value must win over the legacy key");
    assert_eq!(d.gift_sats, 999);
}

// ---------------------------------------------------------------------------
// 2. A per-note override is applied to the live session and is GONE on the
//    next fresh compose (the exact bug the plan calls out: "the Private and
//    ML-KEM switches persist across composes").
// ---------------------------------------------------------------------------

#[test]
fn fee_and_gift_overrides_apply_this_note_and_are_gone_on_the_next_compose() {
    let (mut st, app) = funded_stub("override");
    st.pick_contact_core(&app, "self");
    assert_eq!(app.global::<Compose>().get_fee_tier(), 1, "default tier is normal");
    assert!(!app.global::<Compose>().get_ov_fee());
    assert!(!app.global::<Compose>().get_has_overrides());

    st.on_set_fee_tier(&app, 2); // "fast" — a per-note override
    assert_eq!(app.global::<Compose>().get_fee_tier(), 2);
    assert!(app.global::<Compose>().get_ov_fee(), "the fee pill/card row must show the quiet override marker");
    assert!(app.global::<Compose>().get_has_overrides());

    // A self-note has no gift field in the UI, but the override plumbing
    // itself doesn't care — this proves it independently of `Ui.directed`.
    st.on_set_compose_gift(&app, "5000".into());
    assert_eq!(app.global::<Compose>().get_gift_sats().as_str(), "5000");
    assert!(app.global::<Compose>().get_ov_gift());

    // A fresh compose session (picking a recipient again) must NOT carry
    // either override forward — they die with the note they were made for.
    st.pick_contact_core(&app, "self");
    assert_eq!(app.global::<Compose>().get_fee_tier(), 1, "the next note starts from the Settings default again");
    assert_eq!(app.global::<Compose>().get_gift_sats().as_str(), "330", "gift resets to the dust default too");
    assert!(!app.global::<Compose>().get_ov_fee());
    assert!(!app.global::<Compose>().get_ov_gift());
    assert!(!app.global::<Compose>().get_has_overrides());
}

#[test]
fn quantum_toggle_off_is_session_only_never_sticky_across_composes() {
    // Ports the plan's called-out bug directly: `pq_mlkem_user_off` used to
    // persist in config.json and leak into the NEXT compose session.
    let (mut st, app) = funded_stub("pq-sticky");
    let r = app_core::notes_core::bundle::Identity::from_app_seed(&[9u8; 32]).unwrap().address(Network::Regtest);
    st.on_pick_contact(&app, r.clone().into());
    app.global::<Compose>().set_compose_private(true);
    let kp = app_core::notes_core::pq::MlKemKeypair::generate(app_core::notes_core::pq::MlKemAlg::MlKem768).unwrap();
    let armor = app_core::pqkeys::export_public_armor(&kp);
    let contact = st.contacts.iter_mut().find(|c| c.address == r).unwrap();
    app_core::pqkeys::set_contact_pq_key(contact, &armor).unwrap();
    // `pick_contact_core`'s own `refresh_compose` already ran (with no key
    // yet) and cached the miss by address — invalidate it, exactly what a
    // real recipient re-resolution does, so THIS refresh sees the new key
    // (the cache recomputes on address change; it's not meant to notice a
    // key added mid-session to the SAME already-cached address).
    st.pq_recipient_cache = None;
    st.refresh_compose_pq(&app);
    assert!(app.global::<Compose>().get_pq_mlkem_enabled(), "ML-KEM defaults ON once a key is available");

    // The real Switch's two-way binding sets `pq-mlkem-enabled` BEFORE
    // firing `toggled` — mirror that (the handler itself only tracks the
    // sticky opt-out flag, same as the production Switch's wiring).
    app.global::<Compose>().set_pq_mlkem_enabled(false);
    st.on_pq_mlkem_toggled(&app, false); // per-note opt-out
    assert!(st.pq_mlkem_user_off);
    assert!(app.global::<Compose>().get_ov_quantum());

    // Fresh compose, same recipient: must NOT inherit the opt-out.
    st.on_pick_contact(&app, r.into());
    assert!(
        !st.pq_mlkem_user_off,
        "quantum encryption's per-note opt-out must not survive into the next note"
    );
    assert!(!app.global::<Compose>().get_ov_quantum());
}

// ---------------------------------------------------------------------------
// 3. The gift dust gate (330 sats) — Settings refuses to SAVE below it, the
//    sheet refuses to KEEP it, both accept exactly 330.
// ---------------------------------------------------------------------------

#[test]
fn settings_gift_default_refuses_below_dust_accepts_dust() {
    i_slint_backend_testing::init_no_event_loop();
    let mut st = State::test_stub(Network::Regtest, HashMap::new(), HashMap::new(), HashMap::new(), HashMap::new());
    // `on_set_compose_default_gift` calls `save_config()` — give it a
    // throwaway directory so it never writes into the repo's CWD.
    let dir = std::env::temp_dir().join(format!("graffito-ui-composedefaults-settingsgift-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    let app = AppWindow::new().expect("AppWindow");

    st.on_set_compose_default_gift(&app, "329".into());
    assert_eq!(st.compose_defaults.gift_sats, 330, "a below-dust value must never be saved");
    assert!(!app.global::<Settings>().get_compose_default_gift_error().is_empty());

    st.on_set_compose_default_gift(&app, "330".into());
    assert_eq!(st.compose_defaults.gift_sats, 330);
    assert!(app.global::<Settings>().get_compose_default_gift_error().is_empty());

    st.on_set_compose_default_gift(&app, "5000".into());
    assert_eq!(st.compose_defaults.gift_sats, 5_000);
}

#[test]
fn compose_gift_sheet_refuses_below_dust_and_disables_sign_accepts_dust() {
    let (mut st, app) = funded_stub("giftgate");
    st.pick_contact_core(&app, "self");
    // Turn this into a directed note so the gift field is meaningful.
    let r = app_core::notes_core::bundle::Identity::from_app_seed(&[11u8; 32]).unwrap().address(Network::Regtest);
    st.on_pick_contact(&app, r.into());
    assert_eq!(app.global::<Compose>().get_gift_sats().as_str(), "330");
    assert!(app.global::<Compose>().get_gift_valid());

    st.on_set_compose_gift(&app, "150".into());
    assert_eq!(
        app.global::<Compose>().get_gift_sats().as_str(),
        "330",
        "a refused value must not replace what was there"
    );
    assert!(!app.global::<Compose>().get_gift_valid(), "Sign must be gated off while the typed value is below dust");
    assert!(!app.global::<Compose>().get_gift_error().is_empty());

    st.on_set_compose_gift(&app, "330".into());
    assert!(app.global::<Compose>().get_gift_valid());
    assert!(app.global::<Compose>().get_gift_error().is_empty());
    // 330 is the Settings default (compose_defaults.gift_sats) — landing
    // back on it must NOT count as an override (2026-09-07 follow-up).
    assert!(!app.global::<Compose>().get_ov_gift());

    st.on_set_compose_gift(&app, "888".into());
    assert_eq!(app.global::<Compose>().get_gift_sats().as_str(), "888");
    assert!(app.global::<Compose>().get_gift_valid());
    assert!(app.global::<Compose>().get_ov_gift(), "888 differs from the 330-sat default — this IS an override");
}

// ---------------------------------------------------------------------------
// 4. The gear card's override flags reflect an override, and "Reset this
//    note to defaults" clears every one of them back to the Settings policy.
// ---------------------------------------------------------------------------

#[test]
fn reset_overrides_restores_every_field_and_clears_the_card_flags() {
    let (mut st, app) = funded_stub("reset");
    st.pick_contact_core(&app, "self");

    st.on_set_compose_visibility(&app, false); // override to Public
    st.on_set_fee_tier(&app, 0); // override to economy
    assert!(app.global::<Compose>().get_ov_visibility());
    assert!(app.global::<Compose>().get_ov_fee());
    assert!(app.global::<Compose>().get_has_overrides());
    assert!(!app.global::<Compose>().get_compose_private());
    assert_eq!(app.global::<Compose>().get_fee_tier(), 0);

    st.on_compose_reset_overrides(&app);
    assert!(!app.global::<Compose>().get_has_overrides());
    assert!(!app.global::<Compose>().get_ov_visibility());
    assert!(!app.global::<Compose>().get_ov_fee());
    assert!(app.global::<Compose>().get_compose_private(), "visibility reset to the Settings default (private)");
    assert_eq!(app.global::<Compose>().get_fee_tier(), 1, "fee reset to the Settings default (normal)");
}

// ---------------------------------------------------------------------------
// 5. The quantum status pill for keyed / unkeyed / partially-keyed
//    recipients (single AND multi-recipient).
// ---------------------------------------------------------------------------

#[test]
fn quantum_pill_states_single_recipient_keyed_and_unkeyed() {
    let (mut st, app) = funded_stub("pillsingle");
    let r = app_core::notes_core::bundle::Identity::from_app_seed(&[21u8; 32]).unwrap().address(Network::Regtest);
    st.on_pick_contact(&app, r.clone().into());
    app.global::<Compose>().set_compose_private(true);
    st.refresh_compose_pq(&app);

    let (label, muted, eligible) = st.pq_pill_state(&app);
    assert_eq!(label, "no PQ key");
    assert!(muted);
    assert!(eligible, "PQ still applies to this note — the sheet explains the missing key");

    let kp = app_core::notes_core::pq::MlKemKeypair::generate(app_core::notes_core::pq::MlKemAlg::MlKem768).unwrap();
    let armor = app_core::pqkeys::export_public_armor(&kp);
    let contact = st.contacts.iter_mut().find(|c| c.address == r).unwrap();
    app_core::pqkeys::set_contact_pq_key(contact, &armor).unwrap();
    // Invalidate the per-address resolution cache — see the sibling test's
    // comment for why this (not a production bug) is needed here.
    st.pq_recipient_cache = None;
    st.refresh_compose_pq(&app);
    let (label, muted, eligible) = st.pq_pill_state(&app);
    assert_eq!(label, "PQ 768", "defaults ON once a key is available");
    assert!(!muted);
    assert!(eligible);

    app.global::<Compose>().set_pq_mlkem_enabled(false); // mirrors the Switch's two-way binding
    st.on_pq_mlkem_toggled(&app, false);
    let (label, muted, eligible) = st.pq_pill_state(&app);
    assert_eq!(label, "PQ off");
    assert!(!muted);
    assert!(eligible);
}

#[test]
fn quantum_pill_not_eligible_for_a_public_note() {
    let (mut st, app) = funded_stub("pillpublic");
    let r = app_core::notes_core::bundle::Identity::from_app_seed(&[22u8; 32]).unwrap().address(Network::Regtest);
    st.on_pick_contact(&app, r.into());
    app.global::<Compose>().set_compose_private(false); // public — PQ can't apply
    st.refresh_compose_pq(&app);
    let (_label, muted, eligible) = st.pq_pill_state(&app);
    assert!(muted);
    assert!(!eligible, "a public note must not offer a live PQ pill at all");
}

#[test]
fn quantum_pill_states_multi_recipient_partial_then_full_keying() {
    let (mut st, app) = funded_stub("pillmulti");
    let r1 = app_core::notes_core::bundle::Identity::from_app_seed(&[31u8; 32]).unwrap().address(Network::Regtest);
    let r2 = app_core::notes_core::bundle::Identity::from_app_seed(&[32u8; 32]).unwrap().address(Network::Regtest);
    app.global::<Ui>().set_pick_mode("compose".into());
    st.on_pick_contact(&app, r1.clone().into());
    st.on_add_recipient_open(&app);
    st.on_pick_contact(&app, r2.clone().into());
    app.global::<Compose>().set_compose_private(true);
    st.refresh_compose_pq(&app);

    let (label, muted, eligible) = st.pq_pill_state(&app);
    assert_eq!(label, "no PQ key · 0 of 2");
    assert!(muted);
    assert!(eligible);

    let kp1 = app_core::notes_core::pq::MlKemKeypair::generate(app_core::notes_core::pq::MlKemAlg::MlKem768).unwrap();
    let armor1 = app_core::pqkeys::export_public_armor(&kp1);
    let c1 = st.contacts.iter_mut().find(|c| c.address == r1).unwrap();
    app_core::pqkeys::set_contact_pq_key(c1, &armor1).unwrap();
    st.refresh_compose_pq(&app);
    let (label, muted, eligible) = st.pq_pill_state(&app);
    assert_eq!(label, "no PQ key · 1 of 2");
    assert!(muted);
    assert!(eligible);

    let kp2 = app_core::notes_core::pq::MlKemKeypair::generate(app_core::notes_core::pq::MlKemAlg::MlKem1024).unwrap();
    let armor2 = app_core::pqkeys::export_public_armor(&kp2);
    let c2 = st.contacts.iter_mut().find(|c| c.address == r2).unwrap();
    app_core::pqkeys::set_contact_pq_key(c2, &armor2).unwrap();
    st.refresh_compose_pq(&app);
    let (label, muted, eligible) = st.pq_pill_state(&app);
    assert_eq!(label, "PQ 768+1024", "both recipients keyed — mixed levels joined");
    assert!(!muted);
    assert!(eligible);
}

// ---------------------------------------------------------------------------
// 6. Gear-card row text, Format C exactly (2026-09-07, refined twice the
//    same day): on states render just the state name ("Private", "Strong",
//    "768"/"768+1024"), off states render the bare "None" (or the other
//    named state, "Public") — no ✓ (removed as redundant once the value
//    speaks for itself; `MenuValueRow` keeps its chevron + tap-to-sheet
//    behavior). The row's OWN label ("Passphrase", "Quantum encryption")
//    already says what the value is, so the value must not repeat it
//    either. Value strings are asserted verbatim since the wording itself
//    is exactly what the plan/Sal pinned.
// ---------------------------------------------------------------------------

#[test]
fn card_visibility_row_on_vs_off_text() {
    let (mut st, app) = funded_stub("card-visibility");
    st.pick_contact_core(&app, "self");

    assert_eq!(app.global::<Compose>().get_card_visibility_value().as_str(), "Private");

    st.on_set_compose_visibility(&app, false);
    assert_eq!(app.global::<Compose>().get_card_visibility_value().as_str(), "Public");
}

#[test]
fn card_passphrase_row_on_vs_off_text() {
    let (mut st, app) = funded_stub("card-passphrase");
    st.pick_contact_core(&app, "self");

    assert_eq!(app.global::<Compose>().get_card_passphrase_value().as_str(), "None");

    app.global::<Compose>().set_pq_passphrase_enabled(true); // mirrors the sheet's Switch
    st.on_set_passphrase_enabled(&app, true);
    assert_eq!(
        app.global::<Compose>().get_card_passphrase_value().as_str(),
        "Strong",
        "default cost is Strong; the row's own label already says \"Passphrase\" — no ✓, the value speaks for itself"
    );

    app.global::<Compose>().set_pq_passphrase_enabled(false);
    st.on_set_passphrase_enabled(&app, false);
    assert_eq!(app.global::<Compose>().get_card_passphrase_value().as_str(), "None");
}

#[test]
fn card_quantum_row_on_off_and_no_key_text() {
    let (mut st, app) = funded_stub("card-quantum");
    let r = app_core::notes_core::bundle::Identity::from_app_seed(&[41u8; 32]).unwrap().address(Network::Regtest);
    st.on_pick_contact(&app, r.clone().into());
    app.global::<Compose>().set_compose_private(true);
    st.refresh_compose_pq(&app);
    st.refresh_compose_pills(&app); // card-quantum-* is set here, not by refresh_compose_pq

    // No key on file: grey "no PQ key".
    let (val, muted) = (
        app.global::<Compose>().get_card_quantum_value().to_string(),
        app.global::<Compose>().get_card_quantum_muted(),
    );
    assert_eq!(val, "no PQ key");
    assert!(muted);

    // Key present: defaults ON -> "768", not muted (the row's own label
    // already reads "Quantum encryption" — the value is just the level, no
    // "PQ " prefix and no ✓).
    let kp = app_core::notes_core::pq::MlKemKeypair::generate(app_core::notes_core::pq::MlKemAlg::MlKem768).unwrap();
    let armor = app_core::pqkeys::export_public_armor(&kp);
    let contact = st.contacts.iter_mut().find(|c| c.address == r).unwrap();
    app_core::pqkeys::set_contact_pq_key(contact, &armor).unwrap();
    st.pq_recipient_cache = None; // see the sibling tests' comment on this cache
    st.refresh_compose_pq(&app);
    st.refresh_compose_pills(&app);
    let (val, muted) = (
        app.global::<Compose>().get_card_quantum_value().to_string(),
        app.global::<Compose>().get_card_quantum_muted(),
    );
    assert_eq!(val, "768");
    assert!(!muted);

    // Turned off for this note: "None", not muted.
    app.global::<Compose>().set_pq_mlkem_enabled(false);
    st.on_pq_mlkem_toggled(&app, false);
    let (val, muted) = (
        app.global::<Compose>().get_card_quantum_value().to_string(),
        app.global::<Compose>().get_card_quantum_muted(),
    );
    assert_eq!(val, "None");
    assert!(!muted);
}

// ---------------------------------------------------------------------------
// 7. The fee pill shows the EFFECTIVE RATE, never the tier name
//    (2026-09-07 follow-up 4); the gear card keeps the fuller
//    "tier · rate · cost" form. `cb: fee-tier N rate=R` stays byte-identical.
// ---------------------------------------------------------------------------

#[test]
fn fee_pill_shows_effective_rate_not_tier_name() {
    assert_eq!(format_rate_sat_vb("1"), "1 sat/vB");
    assert_eq!(format_rate_sat_vb("1.0"), "1 sat/vB");
    assert_eq!(format_rate_sat_vb("1.5"), "1.5 sat/vB");
    assert_eq!(format_rate_sat_vb("12.34"), "12.3 sat/vB");

    let (mut st, app) = funded_stub("fee-pill");
    st.pick_contact_core(&app, "self");
    app.global::<Compose>().set_compose_text("fee pill test".into());
    st.refresh_compose(&app);

    // "normal" tier's live rate is whatever `st.fees.hour` resolved to
    // (funded_stub leaves `st.fees` at its Default, i.e. all-zero rates
    // floored to 1.0 by `on_set_fee_tier`'s `.max(1.0)` — this asserts the
    // PILL never shows the bare tier name, whatever the number is).
    let pill = app.global::<Compose>().get_pill_fee().to_string();
    assert!(pill.ends_with("sat/vB"), "fee pill must show a rate, not a tier name: {pill}");
    assert_ne!(pill, "normal", "the tier name alone must never appear in the pill");

    let card = app.global::<Compose>().get_card_fee_value().to_string();
    assert!(card.starts_with("normal · "), "the gear card keeps the tier name: {card}");
    assert!(card.contains("sat/vB"), "the gear card names the rate too: {card}");

    // A custom rate — the pill tracks it exactly, formatted per the rule.
    st.on_set_fee_rate(&app, "2.5".into());
    assert_eq!(app.global::<Compose>().get_pill_fee().as_str(), "2.5 sat/vB");
    assert!(app.global::<Compose>().get_ov_fee(), "a custom rate is a per-note override — accent tint stays");
    let card = app.global::<Compose>().get_card_fee_value().to_string();
    assert!(card.starts_with("custom · 2.5 sat/vB · "), "gear card: {card}");
}

// ---------------------------------------------------------------------------
// 8. The fee line's USD parenthetical is hidden entirely when no price is
//    known — never a "$0.00"/"$-0.00" placeholder (2026-09-07 follow-up 3).
// ---------------------------------------------------------------------------

#[test]
fn usd_suffix_hides_on_no_price_and_never_shows_zero_or_negative() {
    assert_eq!(usd_suffix(None, 239), "", "no price known (Core/Electrum) — hidden entirely");
    assert_eq!(usd_suffix(Some(0.0), 239), "", "a zero price must never render \"$0.00\"");
    assert_eq!(usd_suffix(Some(-0.0), 239), "", "negative zero must never render \"$-0.00\"");
    assert_eq!(usd_suffix(Some(-65_000.0), 239), "", "a negative price must never render a negative dollar figure");
    assert_eq!(usd_suffix(Some(65_000.0), 0), "", "a zero fee must never render \"$0.00\"");
    assert_eq!(usd_suffix(Some(65_000.0), 239), " (~$0.16)");
}

// ---------------------------------------------------------------------------
// 9. An override that lands back on the DEFAULT value must not count as an
//    override (2026-09-07 follow-up). Repro: passphrase switch on, then off
//    again — the pill/card must not stay tinted and the "Reset this note to
//    defaults" row (gated on `Compose.has-overrides`) must not stay visible,
//    even though `compose_overrides` briefly held the key. Also covers fee
//    tier and visibility landing back on their Settings defaults.
// ---------------------------------------------------------------------------

#[test]
fn override_then_revert_to_default_clears_tint_and_reset_row() {
    let (mut st, app) = funded_stub("revert");
    st.pick_contact_core(&app, "self");
    assert!(!app.global::<Compose>().get_has_overrides());

    // Passphrase: the exact repro from the coordinator's report.
    app.global::<Compose>().set_pq_passphrase_enabled(true);
    st.on_set_passphrase_enabled(&app, true);
    assert!(app.global::<Compose>().get_ov_passphrase(), "on IS an override — off is the only default");
    assert!(app.global::<Compose>().get_has_overrides(), "the reset row must show while an override exists");

    app.global::<Compose>().set_pq_passphrase_enabled(false);
    st.on_set_passphrase_enabled(&app, false);
    assert!(!app.global::<Compose>().get_ov_passphrase(), "back at the default (off) — no tint");
    assert!(!app.global::<Compose>().get_has_overrides(), "no override left — the reset row must not show");

    // Fee tier: override to "fast", then explicitly back to "normal" (the
    // Settings default) — not via reset, via the SAME picker tap a real
    // change of mind would use.
    st.on_set_fee_tier(&app, 2);
    assert!(app.global::<Compose>().get_ov_fee());
    assert!(app.global::<Compose>().get_has_overrides());

    st.on_set_fee_tier(&app, 1);
    assert!(!app.global::<Compose>().get_ov_fee(), "tier 1 (normal) is the default — no tint");
    assert!(!app.global::<Compose>().get_has_overrides());

    // Visibility: Public, then back to Private (the default).
    st.on_set_compose_visibility(&app, false);
    assert!(app.global::<Compose>().get_ov_visibility());
    assert!(app.global::<Compose>().get_has_overrides());

    st.on_set_compose_visibility(&app, true);
    assert!(!app.global::<Compose>().get_ov_visibility(), "private is the default — no tint");
    assert!(!app.global::<Compose>().get_has_overrides());
}

// ---------------------------------------------------------------------------
// 10. "Make this my default" checkbox (2026-09-07 round 3): checking it and
//     tapping Done on a per-note sheet ALSO writes the Settings default
//     (through the same `on_set_compose_default_*` handler/log line the
//     Settings row itself uses), then drops the note's own override key
//     since its value now equals what the default just became.
// ---------------------------------------------------------------------------

#[test]
fn fee_promoted_via_checkbox_updates_default_and_next_compose_starts_untinted() {
    let (mut st, app) = funded_stub("promote-fee");
    st.pick_contact_core(&app, "self");
    assert_eq!(st.compose_defaults.fee_tier, 1, "starts at the plain default (normal)");

    // Override this note to "fast" — same as any per-note fee-sheet edit.
    st.on_set_fee_tier(&app, 2);
    assert!(app.global::<Compose>().get_ov_fee());

    // Open the fee sheet and check "Make this my default" (unchecked by
    // default on every sheet open — `on_compose_card_row` resets it).
    st.on_compose_card_row(&app, "fee".into());
    assert!(!app.global::<Compose>().get_promote_default(), "unchecked every time a sheet opens");
    app.global::<Compose>().set_promote_default(true);

    st.on_compose_sheet_done(&app);

    // The SAME handler/log line the Settings row uses ran: config.json (the
    // in-memory mirror of it) now shows "fast" as the default.
    assert_eq!(st.compose_defaults.fee_tier, 2, "config.json's compose default must show the promoted tier");
    let payload = st.config_payload();
    assert_eq!(payload["compose"]["fee_tier"], serde_json::json!(2));

    // The sheet closed normally (promotion succeeds, unlike the gift gate).
    assert_eq!(app.global::<Compose>().get_sheet_kind().as_str(), "");
    assert!(!app.global::<Compose>().get_promote_default(), "cleared after Done");

    // Because the note's value now EQUALS the (freshly promoted) default,
    // Round D's is-default path must have dropped the override.
    assert!(!app.global::<Compose>().get_ov_fee(), "no tint — the note is exactly at its (new) default");
    assert!(!app.global::<Compose>().get_has_overrides());

    // A fresh compose session must start with the promoted default, untinted.
    st.pick_contact_core(&app, "self");
    assert_eq!(app.global::<Compose>().get_fee_tier(), 2, "the next note starts from the newly promoted default");
    assert!(!app.global::<Compose>().get_ov_fee());
    assert!(!app.global::<Compose>().get_has_overrides());
}

#[test]
fn gift_promotion_below_dust_is_refused_and_default_unchanged() {
    let (mut st, app) = funded_stub("promote-gift");
    st.pick_contact_core(&app, "self");
    let r = app_core::notes_core::bundle::Identity::from_app_seed(&[22u8; 32]).unwrap().address(Network::Regtest);
    st.on_pick_contact(&app, r.into());
    assert_eq!(st.compose_defaults.gift_sats, 330);

    // Type a below-dust value directly into the (two-way-bound) field, as a
    // real TextInput edit would leave it sitting there without ever having
    // gone through `on_set_compose_gift`'s validation.
    app.global::<Compose>().set_gift_sats("329".into());

    st.on_compose_card_row(&app, "gift".into());
    assert!(!app.global::<Compose>().get_promote_default());
    app.global::<Compose>().set_promote_default(true);

    st.on_compose_sheet_done(&app);

    // Refused: the Settings default must not move, the sheet stays open
    // (never closes on refusal), and the compose-side error is populated.
    assert_eq!(st.compose_defaults.gift_sats, 330, "a below-dust promotion must never reach the default");
    let payload = st.config_payload();
    assert_eq!(payload["compose"]["gift_sats"], serde_json::json!(330));
    assert_eq!(app.global::<Compose>().get_sheet_kind().as_str(), "gift", "refusal keeps the sheet open");
    assert!(!app.global::<Compose>().get_gift_error().is_empty());
    assert!(!app.global::<Compose>().get_gift_valid());
}
