//! Screen.notebooks — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
/// The create-notebook flavor of the picker: 5-per-page NOTEBOOK ADDRESS
/// rows (receive indexes of the active account), plus a "notebook" pill
/// for indexes already in the index file and — when a node is configured —
/// a used/new pill with the address's current balance, so recovering an
/// already-used address is a visible, deliberate choice.
pub(crate) fn show_notebook_picker(&self, w: &AppWindow, page: u32, mode: &str) {
    let st = self;
    if st.material.is_none() {
        return;
    }
    // Paint immediately with local data — the "notebook" pill for indexes
    // already in the index file, plain rows otherwise. The used/new probe
    // is network, so it runs OFF the main thread below; before this, tapping
    // "+ New notebook" hung the UI on up to 5 blocking HTTP calls
    // (Sal 2026-07-13).
    let mut rows = st.index_rows(page);
    let mut to_probe: Vec<(u32, String)> = Vec::new(); // (receive index, address)
    for row in &mut rows {
        let index = row.index as u32;
        if st.notebooks.as_ref().and_then(|ix| ix.get(st.account, index)).is_some() {
            row.pill = "notebook".into();
        } else {
            to_probe.push((index, row.address.to_string()));
        }
    }
    w.global::<AccountPicker>().set_account_page(page as i32);
    w.global::<AccountPicker>().set_accounts(VecModel::from_slice(&rows));
    w.global::<AccountPicker>().set_account_pick_mode(mode.into());
    w.global::<Ui>().set_screen(Screen::AccountPicker);

    // Probe used/new on a worker thread; results fill the pills in via the
    // apply-pending-picker-probe trampoline (offline / no rows → plain rows).
    let Some(base) = st.base_url() else { return };
    if to_probe.is_empty() {
        return;
    }
    let network = st.network;
    let account = st.account;
    let creds = st.core_rpc_creds_for(&base, network);
    let watch = st.core_rpc_watch.clone();
    let weak = w.as_weak();
    std::thread::spawn(move || {
        let _net_guard = NetOpGuard::new(weak.clone());
        let mut results: Vec<(u32, &'static str, String)> = Vec::new();
        // A malformed node URL degrades exactly like "offline" below (empty
        // results → plain rows) rather than a new error path.
        if let Ok(client) = open_client_watched(&base, network, creds, &watch) {
            for (index, addr) in &to_probe {
                if let Ok((used, balance)) = client.address_probe(addr) {
                    let pill = if used { "used" } else { "new" };
                    let bal = if used { format!("{} sats", commas(balance)) } else { String::new() };
                    results.push((*index, pill, bal));
                }
            }
        }
        PICKER_PROBE_RESULTS
            .lock()
            .expect("picker probe mutex")
            .push(PickerProbeResult { account, page, rows: results });
        let _ = weak.upgrade_in_event_loop(|w| w.global::<Ui>().invoke_apply_pending_picker_probe());
    });
}

/// Deliberate notebook creation for receive `index` of the ACTIVE
/// account: add it to the index file (if missing), persist, and extend
/// the address cache. The ONLY entry points are user intent — the create
/// dialog, an import's account pick (notebook 0), and APP_KEY automation
/// boots (their index choice is explicit config).
pub(crate) fn ensure_notebook(&mut self, index: u32) {
    let st = self;
    let account = st.account;
    let Some(ix) = st.notebooks.as_mut() else { return };
    if !ix.ensure(account, index) {
        return;
    }
    st.save_notebooks();
    if !st.nb_addrs.iter().any(|(a, ..)| *a == index) {
        if let Some(material_str) = st.material.as_deref() {
            if let Ok(material) = parse_key_material(material_str, st.network) {
                if let Ok(i) = realize(&material, st.network, account, index) {
                    st.nb_addrs.push((
                        index,
                        i.address.clone(),
                        hex::encode(&i.output_x()[..4]),
                    ));
                }
            }
        }
    }
}

/// Build the notebook-list rows (screen 17) from the index plus each
/// notebook's store on disk. Snippet and unread respect that notebook's
/// sender filter, so the row preview matches what opening it reveals.
pub(crate) fn update_notebook_list(&self, w: &AppWindow) {
    let st = self;
    let Some(ix) = &st.notebooks else { return };
    w.global::<Notebooks>().set_can_create_notebook(
        st.material
            .as_deref()
            .map(|m| is_multi_notebook(m, st.network))
            .unwrap_or(false),
    );
    let mut active_rows: Vec<NotebookItem> = Vec::new();
    let mut archived_rows: Vec<NotebookItem> = Vec::new();
    for meta in ix.books(st.account) {
        let Some((_, address, _)) = st.nb_addrs.iter().find(|(a, ..)| *a == meta.index) else {
            continue;
        };
        let store = st.notebook_store(meta.index);
        let (snippet, meta_line, unread) = match &store {
            Some(s) => {
                let visible: Vec<&app_core::store::NoteRecord> = s.visible_notes().collect();
                let snippet = visible
                    .last()
                    .map(|n| {
                        n.text
                            .as_deref()
                            .map(str::trim)
                            .filter(|t| !t.is_empty())
                            .unwrap_or("(encrypted)")
                            .to_string()
                    })
                    .unwrap_or_else(|| "No notes yet".into());
                let meta_line = format!(
                    "{} · {} sats · {} note{}",
                    addr_short(address),
                    commas(s.balance()),
                    visible.len(),
                    if visible.len() == 1 { "" } else { "s" }
                );
                (snippet, meta_line, s.unread_visible_count())
            }
            None => ("No notes yet".into(), format!("{} · not scanned yet", addr_short(address)), 0),
        };
        let row = NotebookItem {
            index: meta.index as i32,
            name: st.notebook_display_name(meta.index).into(),
            snippet: snippet.into(),
            meta: meta_line.into(),
            unread: match unread {
                0 => "".into(),
                1 => "1 new".into(),
                n => format!("{n} new").into(),
            },
            active: st.ident.as_ref().map(|i| i.index) == Some(meta.index),
        };
        if meta.archived {
            archived_rows.push(row);
        } else {
            active_rows.push(row);
        }
    }
    println!("cb: notebooks list n={} archived={}", active_rows.len(), archived_rows.len());
    w.global::<Ui>().set_notebooks(VecModel::from_slice(&active_rows));
    w.global::<Notebooks>().set_archived_notebooks(VecModel::from_slice(&archived_rows));
    w.global::<Notebooks>().set_archived_toggle_label(
        if archived_rows.is_empty() {
            String::new()
        } else {
            format!("Archived ({})", archived_rows.len())
        }
        .into(),
    );
}
}
