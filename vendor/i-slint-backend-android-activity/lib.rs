// Copyright © SixtyFPS GmbH <info@slint.dev>
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0

// cSpell: ignore androidwindowadapter javahelper
#![doc = include_str!("README.md")]
#![doc(html_logo_url = "https://slint.dev/logo/slint-logo-square-light.svg")]
#![cfg_attr(not(target_os = "android"), allow(rustdoc::broken_intra_doc_links))]
#![cfg_attr(slint_nightly_test, feature(non_exhaustive_omitted_patterns_lint))]
#![cfg_attr(slint_nightly_test, warn(non_exhaustive_omitted_patterns))]

// graffito patch (2026-09-19): this crate used to gate its ENTIRE content
// behind one `#![cfg(target_os = "android")]` on the crate root. That
// strips the whole crate when false -- verified empirically with a
// throwaway rustc test, not just inferred from the reference -- so a
// `pub mod` declared after it, even with no cfg of its own, would still be
// unreachable on every non-Android host. The android-only implementation
// (unchanged in substance) moved to `android_impl.rs` so the gate can sit
// on it alone, leaving `keymap`/`geom` -- the new pure, host-testable
// helpers backing the graffito key-input and keyboard-dismiss fixes --
// compiled and `cargo test`-able on macOS/iOS/every host, per
// `vendor/i-slint-backend-android-activity/NOTES.md`.
#[cfg(target_os = "android")]
mod android_impl;
#[cfg(target_os = "android")]
pub use android_impl::*;

/// Pure, host-testable Android key-event text resolution (shift/AltGr/meta
/// state via the device's `KeyCharacterMap`, falling back to the static
/// keycode table) -- graffito patch (2026-09-19), see NOTES.md.
pub mod keymap;
/// Pure, host-testable "is this tap outside that rectangle" geometry
/// helper, used to dismiss the on-screen keyboard on an outside tap --
/// graffito patch (2026-09-19), see NOTES.md.
pub mod geom;
