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

impl State {
#[allow(unused_variables)]
pub(crate) fn on_settings_open(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        w.global::<Ui>().set_return_screen(if w.global::<Ui>().get_screen() == Screen::Notebooks { Screen::Notebooks } else { Screen::Home });
        println!("cb: settings-open");
        s.clear_reveal(w);
        w.global::<Ui>().set_status("".into());
        w.global::<Settings>().set_chunk_custom(false);
        s.load_backend_settings(w);
        s.refresh_node_health(w);
        // Settings shows identity/network/note-size fields that used to be set
        // only by update_home; onboarding now lands on the list (not a home),
        // so populate them here too or the "Change account…" row (gated on
        // settings-hierarchical) is missing on the first Settings visit.
        s.update_settings_identity(w);
        s.update_spending_ui(w);
        if s.spending_capable
            && s.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false)
            && !s.spending_scanned
        {
            s.spending_refresh_async(w);
        }
        // Fresh entry from the list starts at the top; returning from a Settings
        // sub-screen (via nav-back, which doesn't call this) keeps its position.
        w.global::<Settings>().set_settings_scroll_y(0.0);
        w.global::<Ui>().set_screen(Screen::Settings);
    }

#[allow(unused_variables)]
pub(crate) fn on_open_notebook(&mut self, w: &AppWindow, index: i32) {
    #[allow(unused_mut)]
    let mut s = self;
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        s.nb_index = index.max(0) as u32;
        println!("cb: open-notebook index={}", s.nb_index);
        match s.activate(&material, false) {
            Ok(()) => {
                s.update_home(w);
                w.global::<Ui>().set_screen(Screen::Home); // paint first — the scan runs in the background
                s.refresh_async(w);
                s.spending_refresh_async(w); // CHANGE 5: was missing — Sal's finding
            }
            Err(e) => w.global::<Ui>().set_status(e.to_string().into()),
        }
    }

#[allow(unused_variables)]
pub(crate) fn on_create_notebook(&mut self, w: &AppWindow) {
    #[allow(unused_mut)]
    let mut s = self;
        // Address-first, then name-first: "+ New notebook" opens the
        // account picker (used/new pills + balances) so recovering a used
        // address is a visible choice; the naming dialog follows the pick.
        // Nothing is derived or persisted until the dialog's Create.
        let Some(material) = s.material.as_ref().map(|z| String::from(z.as_str())) else {
            return;
        };
        if !is_multi_notebook(&material, s.network) {
            return; // button is hidden; a stray call must not add phantom rows
        }
        println!("cb: create-notebook picker open");
        w.global::<AccountPicker>().set_nb_create_name("".into());
        s.show_notebook_picker(w, 0, "notebook");
    }

#[allow(unused_variables)]
pub(crate) fn on_nb_rename_start(&mut self, w: &AppWindow, index: i32, _display: SharedString) {
    #[allow(unused_mut)]
    let mut s = self;
        let _ = &mut s;
        // Prefill the RAW local name (the display name may be the address
        // short form, which must not become a name by accident).
        let raw = s
            .notebooks
            .as_ref()
            .and_then(|ix| ix.get(s.account, index.max(0) as u32))
            .map(|m| m.name.clone())
            .unwrap_or_default();
        w.global::<Modals>().set_nb_rename_input(raw.into());
        w.global::<Ui>().set_nb_rename_index(index);
    }

#[allow(unused_variables)]
pub(crate) fn on_nb_archive(&mut self, w: &AppWindow, index: i32, archived: bool) {
    #[allow(unused_mut)]
    let mut s = self;
        let index = index.max(0) as u32;
        if s.notebooks.is_none() {
            return;
        }
        if archived {
            // One guard only: funds never disappear from view silently —
            // sweep first. Archiving EVERY notebook is allowed (the list
            // shows its empty state); Restore brings any of them back.
            let balance = s.notebook_store(index).map(|st2| st2.balance()).unwrap_or(0);
            if balance > 0 {
                w.global::<Ui>().set_status(
                    format!(
                        "this notebook holds {} sats — consolidate the wallet first (Coins)",
                        commas(balance)
                    )
                    .into(),
                );
                return;
            }
        }
        let account = s.account;
        if let Some(ix) = s.notebooks.as_mut() {
            ix.set_archived(account, index, archived);
            s.save_notebooks();
            println!("cb: archive-notebook index={index} archived={archived}");
        }
        w.global::<Ui>().set_status("".into());
        s.update_notebook_list(w);
    }
}
