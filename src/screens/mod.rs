//! One module per screen, mirroring `ui/screens/*.slint` (U4,
//! PLAN-graffito-app-arch.md). `pub(crate) use X::*;` keeps a
//! module's free helpers/statics/types visible crate-wide without
//! per-caller imports; a module holding only `impl State` methods
//! needs no re-export (inherent methods are visible everywhere).

mod account_picker;
mod activity;
mod backup_words;
mod change;
mod coins;
mod compose;
mod confirm;
mod contacts;
mod dice;
mod entropy_source;
mod export_psbt;
mod funding_wallet;
mod funding_wallets;
mod home;
mod import_key;
mod import_signed_psbt;
mod info;
mod modals;
mod note;
mod notebooks;
mod onboarding;
mod pay_from;
mod private_keys;
mod quantum_keys;
mod quiz;
mod settings;
mod sweep;
mod terms;
mod ui;

pub(crate) use account_picker::*;
pub(crate) use compose::*;
pub(crate) use confirm::*;
pub(crate) use contacts::*;
pub(crate) use funding_wallets::*;
pub(crate) use info::*;
pub(crate) use note::*;
pub(crate) use onboarding::*;
pub(crate) use quantum_keys::*;
pub(crate) use settings::*;
pub(crate) use ui::*;
