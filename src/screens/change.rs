//! Screen.change — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

impl State {
/// Recompute the Change screen/nav-row's resolved destination — respects an
/// explicit `change_choice` pick made this session; otherwise applies
/// `app_core::mixed::resolve_change_default` (Sal's rule: spending wallet
/// enabled + participating wins, else a single participating external
/// wallet, else the notebook).
pub(crate) fn update_change_label(&mut self, w: &AppWindow) {
    let st = self;
    let sources: std::collections::HashSet<&str> =
        st.mixed_selected.iter().map(|(s, _, _)| s.as_str()).collect();
    let spending_enabled =
        st.spending_capable && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false);
    let spending_participates = sources.contains("spending") || st.payfrom_active_source == "spending";
    // Taproot-change unit 5: a "change" source key lands in this list too
    // (it's neither "notebook" nor "spending"), but `strip_prefix("wallet:")`
    // below always fails for it, so `only_external` correctly stays `None`
    // whenever change participates — resolve_change_default then falls back
    // to Notebook, same as a notebook coin would (both are this identity's
    // own coin; no code change needed here beyond this note).
    let non_notebook_spending: Vec<&str> =
        sources.iter().filter(|s| **s != "notebook" && **s != "spending").copied().collect();
    let only_external: Option<String> = if !sources.contains("notebook")
        && !sources.contains("spending")
        && non_notebook_spending.len() == 1
    {
        non_notebook_spending[0].strip_prefix("wallet:").map(String::from)
    } else {
        None
    };
    let default = app_core::mixed::resolve_change_default(
        spending_enabled,
        spending_participates,
        only_external.as_deref(),
    );

    let default_str = match &default {
        app_core::mixed::ChangeDefault::Spending => "spending".to_string(),
        app_core::mixed::ChangeDefault::Notebook => "notebook".to_string(),
        app_core::mixed::ChangeDefault::Wallet(id) => format!("wallet:{id}"),
    };
    w.global::<Change>().set_change_default_choice(default_str.clone().into());
    let default_reason = match &default {
        app_core::mixed::ChangeDefault::Spending => "the spending wallet is paying".to_string(),
        app_core::mixed::ChangeDefault::Notebook => "no spending wallet enabled".to_string(),
        app_core::mixed::ChangeDefault::Wallet(id) => {
            let label = st
                .funding_wallets
                .iter()
                .find(|fw| &fw.id == id)
                .map(|fw| fw.label.clone())
                .unwrap_or_else(|| id.clone());
            format!("{label} is paying")
        }
    };
    w.global::<Change>().set_change_default_reason(default_reason.into());
    let notebook_line = addr_short(&st.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default());
    w.global::<Change>().set_change_notebook_line(notebook_line.into());
    let spending_line = if st.spending_capable && spending_enabled {
        if let (Some(src), Some(store)) = (st.spending_source.as_ref(), st.store.as_ref()) {
            src.derive(1, store.spending.next_change)
                .ok()
                .map(|d| format!("{} · change #{}", addr_short(&d.address), store.spending.next_change))
                .unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    w.global::<Change>().set_change_spending_line(spending_line.into());
    // An explicit pick this session (including "custom") always wins; the
    // default only applies while `change_choice` is unset.
    let choice = if st.change_choice.is_empty() { default_str } else { st.change_choice.clone() };
    w.global::<Ui>().set_change_choice(choice.clone().into());

    let label = if choice == "spending" {
        "a fresh spending address".to_string()
    } else if choice == "notebook" {
        "your notebook address".to_string()
    } else if choice == "custom" {
        let addr = w.global::<Ui>().get_change_address().to_string();
        if addr.trim().is_empty() {
            "custom address".to_string()
        } else {
            format!("{}…", &addr[..14.min(addr.len())])
        }
    } else if let Some(id) = choice.strip_prefix("wallet:") {
        st.funding_wallets
            .iter()
            .find(|fw| fw.id == id)
            .map(|fw| format!("{} change", fw.label))
            .unwrap_or_else(|| "external wallet".to_string())
    } else {
        "your address".to_string()
    };
    w.global::<Ui>().set_change_dest_label(label.into());
}
}
