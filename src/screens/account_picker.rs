//! Screen.account-picker — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// One picker page: 5 ACCOUNTS, each shown by its notebook-0 address.
pub(crate) fn account_rows(
    material_str: &str,
    network: Network,
    page: u32,
    active: Option<u32>,
) -> Vec<AccountItem> {
    let Ok(material) = parse_key_material(material_str, network) else { return vec![] };
    (page * 5..page * 5 + 5)
        .filter_map(|i| {
            let ident = realize(&material, network, i, 0).ok()?;
            Some(AccountItem {
                index: i as i32,
                address: ident.address.into(),
                active: active == Some(i),
                pill: "".into(),
                balance: "".into(),
            })
        })
        .collect()
}

pub(crate) fn show_account_picker(w: &AppWindow, material: &str, network: Network, page: u32, active: Option<u32>) {
    w.global::<AccountPicker>().set_account_page(page as i32);
    w.global::<AccountPicker>().set_accounts(VecModel::from_slice(&account_rows(material, network, page, active)));
    w.global::<Ui>().set_screen(Screen::AccountPicker);
}

impl State {
/// One picker page: 5 NOTEBOOK ADDRESSES — receive-chain indexes `0/i`
/// of the ACTIVE account (create-notebook / consolidate-destination
/// rows).
pub(crate) fn index_rows(&self, page: u32) -> Vec<AccountItem> {
    let st = self;
    let Some(material_str) = st.material.as_deref() else { return vec![] };
    let Ok(material) = parse_key_material(material_str, st.network) else { return vec![] };
    let active = st.ident.as_ref().map(|i| i.index);
    (page * 5..page * 5 + 5)
        .filter_map(|i| {
            let ident = realize(&material, st.network, st.account, i).ok()?;
            Some(AccountItem {
                index: i as i32,
                address: ident.address.into(),
                active: active == Some(i),
                pill: "".into(),
                balance: "".into(),
            })
        })
        .collect()
}
}
