// ---------------------------------------------------------------------------
// In-process UI-flow test, history-scaling U-notes-window: Home's notes
// list must scale to thousands of notes without instantiating thousands of
// Slint rows. Drives the exact production path (`update_home` /
// `update_home_notes` / `on_notes_load_more`) headless against a seeded
// store, asserting on `Ui.notes`/`Home.notes-total`/`Home.notes-more`
// instead of pixels.
// ---------------------------------------------------------------------------

use crate::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// A minimal seeded note — every `NoteRecord` field the type needs, with
/// only what this suite varies exposed as parameters. `received`/`sender`
/// model an externally-sent note (for the hidden-sender test); the default
/// self-authored shape (`received: false, sender: None`) resolves through
/// `Store::sender_key` to the notebook's own address, same as a real
/// composed note.
fn note(
    id: &str,
    status: NoteStatus,
    received: bool,
    sender: Option<&str>,
) -> app_core::store::NoteRecord {
    app_core::store::NoteRecord {
        note_id: id.to_string(),
        status,
        text: Some(format!("note {id}")),
        private: false,
        directed: false,
        received,
        sender: sender.map(str::to_string),
        recipient: None,
        recipients: Vec::new(),
        txids: vec![id.to_string()],
        height: (status == NoteStatus::Confirmed).then_some(100),
        blocktime: None,
        created_at: Some(0),
        spent: Vec::new(),
        raw_hex: None,
        fee: None,
        vsize: None,
        change_to: None,
        gift_amount: None,
        funded_by: None,
        dropped: false,
        pq_flags: 0,
        locked: None,
        locked_multi: None,
    }
}

/// A 64-hex-char txid-shaped id, distinct per `i` — `NoteRecord.note_id`
/// is the canonical txid since the PNTE redesign, and every note here
/// needs a unique one.
fn txid(i: u32) -> String {
    format!("{i:064x}")
}

fn stub(tag: &str) -> State {
    let mut st = State::test_stub(
        Network::Regtest,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
    );
    let dir = std::env::temp_dir()
        .join(format!("graffito-ui-home-window-{tag}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    st
}

#[test]
fn thousand_notes_window_and_load_more() {
    i_slint_backend_testing::init_no_event_loop();
    let mut st = stub("main");

    // 1000 confirmed notes, THEN 5 unconfirmed ones appended last.
    // `Store.notes` iterates newest-last; `update_home_notes` reverses it
    // (newest first) before the stable unconfirmed-first sort — so these
    // 5 land at the very front of the sorted list, ahead of all 1000
    // confirmed notes, before any windowing happens.
    {
        let store = st.store.as_mut().unwrap();
        for i in 0..1000u32 {
            store.notes.push(note(&txid(i), NoteStatus::Confirmed, false, None));
        }
        for i in 1000..1005u32 {
            store.notes.push(note(&txid(i), NoteStatus::Pending, false, None));
        }
    }

    let app = AppWindow::new().expect("AppWindow");
    st.update_home(&app);

    assert_eq!(
        app.global::<Ui>().get_notes().row_count(),
        200,
        "initial window is exactly NOTES_WINDOW rows"
    );
    assert_eq!(app.global::<Home>().get_notes_total(), 1005, "total is every filtered note");
    assert_eq!(app.global::<Home>().get_notes_more(), 805, "805 rows not yet shown");

    // The sort holds across the window boundary: all 5 unconfirmed notes
    // lead the WINDOW, not just the full (unwindowed) list.
    let notes = app.global::<Ui>().get_notes();
    for i in 0..5 {
        assert_eq!(
            notes.row_data(i).unwrap().badge.as_str(),
            "pending",
            "row {i} of the window must be one of the 5 unconfirmed notes"
        );
    }
    assert_eq!(notes.row_data(5).unwrap().badge.as_str(), "confirmed");

    // Load more: 200 -> 300 rows, 805 -> 705 remaining — and it must be an
    // APPEND: every already-shown row stays exactly where it was.
    let before: Vec<SharedString> = (0..200).map(|i| notes.row_data(i).unwrap().id).collect();
    st.on_notes_load_more(&app);
    let notes = app.global::<Ui>().get_notes();
    assert_eq!(notes.row_count(), 300, "one load-more reveals exactly NOTES_WINDOW_STEP more rows");
    assert_eq!(app.global::<Home>().get_notes_total(), 1005);
    assert_eq!(app.global::<Home>().get_notes_more(), 705);
    for i in 0..200 {
        assert_eq!(notes.row_data(i).unwrap().id, before[i], "load-more must not reorder shown rows");
    }
}

#[test]
fn short_list_reports_no_more_rows() {
    i_slint_backend_testing::init_no_event_loop();
    let mut st = stub("short");
    {
        let store = st.store.as_mut().unwrap();
        for i in 0..30u32 {
            store.notes.push(note(&txid(i), NoteStatus::Confirmed, false, None));
        }
    }
    let app = AppWindow::new().expect("AppWindow");
    st.update_home(&app);
    assert_eq!(app.global::<Ui>().get_notes().row_count(), 30, "every note fits inside one window");
    assert_eq!(app.global::<Home>().get_notes_total(), 30);
    assert_eq!(
        app.global::<Home>().get_notes_more(),
        0,
        "nothing left to load — the footer row must not render"
    );
}

#[test]
fn hidden_sender_excludes_from_the_total() {
    i_slint_backend_testing::init_no_event_loop();
    let mut st = stub("sender");
    let sender_addr = "bcrt1qexternalsenderxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    {
        let store = st.store.as_mut().unwrap();
        for i in 0..1000u32 {
            store.notes.push(note(&txid(i), NoteStatus::Confirmed, false, None));
        }
        for i in 1000..1010u32 {
            store.notes.push(note(&txid(i), NoteStatus::Confirmed, true, Some(sender_addr)));
        }
    }
    let app = AppWindow::new().expect("AppWindow");
    st.update_home(&app);
    assert_eq!(app.global::<Home>().get_notes_total(), 1010, "baseline: every note counted");

    // Same toggle the Senders filter panel drives (`Home.toggle-sender`'s
    // handler mutates the store the same way, then repaints via
    // update_home — exercised directly here).
    st.store.as_mut().unwrap().set_excluded(sender_addr, true);
    st.update_home(&app);
    assert_eq!(
        app.global::<Home>().get_notes_total(),
        1000,
        "the excluded sender's 10 notes drop out of the total"
    );
    assert_eq!(app.global::<Ui>().get_notes().row_count(), 200, "window stays at NOTES_WINDOW");
}

#[test]
fn switching_notebooks_resets_the_window() {
    i_slint_backend_testing::init_no_event_loop();
    let mut st = stub("switch");
    {
        let store = st.store.as_mut().unwrap();
        for i in 0..1000u32 {
            store.notes.push(note(&txid(i), NoteStatus::Confirmed, false, None));
        }
    }
    // Persist so notebook 0's notes survive the round trip through
    // notebook 1 and back — `activate()` reloads a notebook's store from
    // disk.
    st.save_store();

    let app = AppWindow::new().expect("AppWindow");
    st.update_home(&app);
    st.on_notes_load_more(&app);
    st.on_notes_load_more(&app);
    assert_eq!(
        app.global::<Ui>().get_notes().row_count(),
        400,
        "expanded to NOTES_WINDOW + 2*NOTES_WINDOW_STEP via two load-mores"
    );

    // Open a second (empty) notebook of the SAME identity — the exact
    // `activate()` call `on_open_notebook` makes (see
    // ui_flow_app_notebooks.rs's header for why this test stays
    // network-free and drives activate() directly instead of the full
    // callback).
    st.ensure_notebook(1);
    let material = st.material.as_ref().unwrap().to_string();
    st.nb_index = 1;
    st.activate(&material, false).expect("open notebook 1");
    st.update_home(&app);
    assert_eq!(app.global::<Ui>().get_notes().row_count(), 0, "fresh notebook has no notes");

    // Back to notebook 0 — the window must have been reset to
    // NOTES_WINDOW on that activate(), not left at the 400 rows the
    // PREVIOUS activation of it was expanded to.
    st.nb_index = 0;
    st.activate(&material, false).expect("reopen notebook 0");
    st.update_home(&app);
    assert_eq!(
        app.global::<Ui>().get_notes().row_count(),
        200,
        "reactivating notebook 0 starts collapsed at NOTES_WINDOW again"
    );
}

/// Not a test: a FIXTURE STAGER for looking at the windowed list in the
/// real Mac window. `STAGE_DIR=<dir> cargo test -p graffito --lib
/// stage_home_window_fixture -- --ignored` writes a regtest store with 300
/// notes (5 pending) for the standard test mnemonic into `<dir>` through
/// the app's own serializer; then launch `target/debug/graffito` with
/// `APP_DATA_DIR=<dir> APP_KEY="<MNEMONIC>" APP_NETWORK=regtest` and the
/// Home list shows 200 rows plus the "Showing 200 of 300 · Load more"
/// footer. Ignored so the normal suite never touches a caller's directory.
#[test]
#[ignore]
fn stage_home_window_fixture() {
    let Ok(dir) = std::env::var("STAGE_DIR") else {
        eprintln!("STAGE_DIR not set; nothing staged");
        return;
    };
    i_slint_backend_testing::init_no_event_loop();
    let mut st = State::test_stub(
        Network::Regtest,
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
    );
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).expect("STAGE_DIR");
    st.data_dir = dir;
    st.activate(MNEMONIC, false).expect("activate");
    const TEXTS: [&str; 12] = [
        "Coffee with Ana at the harbour, 9am",
        "Block 6,500 — the node finally caught up",
        "Remember: renew the domain before October",
        "Weekend plan: bike to the lighthouse",
        "Recipe idea — miso butter on roasted squash",
        "Quote of the day: measure, then cut",
        "Bought the blue notebook, finally",
        "Pi node uptime 42 days",
        "Grandma's birthday is the 14th",
        "Fixed the squeaky door hinge",
        "Sunset at 19:41, clear sky",
        "Try the new bakery on Elm street",
    ];
    {
        let store = st.store.as_mut().unwrap();
        for i in 0..295u32 {
            let mut n = note(&txid(i), NoteStatus::Confirmed, false, None);
            n.text = Some(format!("{} #{}", TEXTS[(i as usize) % TEXTS.len()], i + 1));
            n.height = Some(6000 + i as u64);
            n.blocktime = Some(1_789_000_000 + i as u64 * 600);
            store.notes.push(n);
        }
        for i in 295..300u32 {
            let mut n = note(&txid(i), NoteStatus::Pending, false, None);
            n.text = Some(format!("{} #{}", TEXTS[(i as usize) % TEXTS.len()], i + 1));
            store.notes.push(n);
        }
    }
    st.save_store();
    eprintln!("staged 300 notes into {}", st.data_dir.display());
}
