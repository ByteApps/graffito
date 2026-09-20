// Copyright © SixtyFPS GmbH <info@slint.dev>
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0

//! graffito patch (2026-09-19): pure key-text resolution, split out of
//! `androidwindowadapter.rs` so it compiles (and is unit-testable) on every
//! host, not just `target_os = "android")` -- see the crate's `NOTES.md`.
//!
//! `androidwindowadapter.rs`'s `map_key_event` used to resolve a key's text
//! ONLY through a static `Keycode -> &str` table (`map_key_code`), which
//! ignores `meta_state()` entirely -- so `Shift+;` always produced `;`, never
//! `:`, on a hardware/Bluetooth keyboard or `adb shell input text`.
//!
//! `android-activity` 0.6.1 exposes the real per-device mapping:
//! `AndroidApp::device_key_character_map(device_id)` ->
//! `KeyCharacterMap::get(key_code, meta_state)` -> `KeyMapChar::{Unicode,
//! CombiningAccent, None}`. `androidwindowadapter.rs` now resolves that
//! FIRST and asks this module's `key_text_from_unicode` whether to use it or
//! fall back to the static table. `KeyMapChar`/`Keycode`/`SharedString` are
//! android-only types (their crates are `cfg(target_os = "android")`
//! dependencies -- see the crate's Cargo.toml -- so they don't exist on a
//! host build at all), so the decision itself is expressed over a bare
//! `Option<char>` here and the android-only call site converts both ways.

/// Decide whether a `KeyCharacterMap::get()` result should be used as a key
/// event's text, or whether the caller should fall back to the static
/// keycode table instead.
///
/// `unicode` is:
/// - `Some(c)` for `KeyMapChar::Unicode(c)` -- a real printable character
///   for this key + meta-state combination (e.g. `Shift+;` -> `Some(':')`).
/// - `None` for `KeyMapChar::None` (no Unicode mapping -- most special
///   keys), `KeyMapChar::CombiningAccent(_)` (a dead key; not resolved into
///   text until combined with the next keystroke), or a failed/absent
///   `KeyCharacterMap` lookup (no physical keyboard for this device id, or
///   `device_id == 0`, the "non-physical" synthetic id the underlying API
///   explicitly rejects).
///
/// Returns `Some(c)` when `c` should be used verbatim as the key's text.
/// Returns `None` when the caller must fall back to the static keycode
/// table -- this is also the safety net for a device whose `KeyCharacterMap`
/// maps a non-printable key (Enter, say) to a control character rather than
/// `KeyMapChar::None`: routing Back/arrows/Enter/Delete/etc. through the KCM
/// result would bypass Slint's `Key::…` mapping for them, so any resolved
/// character that is a control character is treated the same as no mapping.
pub fn key_text_from_unicode(unicode: Option<char>) -> Option<char> {
    match unicode {
        Some(c) if !c.is_control() => Some(c),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unicode_char_wins_over_the_static_fallback_table() {
        // Shift+Semicolon on a US layout: KeyCharacterMap.get() returns ':',
        // which must win over map_key_code(Keycode::Semicolon) == ";".
        assert_eq!(key_text_from_unicode(Some(':')), Some(':'));
    }

    #[test]
    fn uppercase_letter_is_preserved_verbatim() {
        // Shift+A: KeyCharacterMap.get() returns 'A' (not lowercased).
        assert_eq!(key_text_from_unicode(Some('A')), Some('A'));
    }

    #[test]
    fn control_character_falls_back_to_the_static_table() {
        // Enter's KeyCharacterMap mapping is commonly '\r'/'\n' (control
        // characters) -- must fall back so Slint still gets Key::Return
        // rather than a literal CR/LF character in the text field.
        assert_eq!(key_text_from_unicode(Some('\r')), None);
        assert_eq!(key_text_from_unicode(Some('\n')), None);
        assert_eq!(key_text_from_unicode(Some('\u{7f}')), None); // Delete/Backspace-shaped
    }

    #[test]
    fn no_mapping_falls_back_to_the_static_table() {
        // KeyMapChar::None / KeyMapChar::CombiningAccent / a failed lookup
        // are all normalized to `None` by the android-only call site before
        // reaching here -- confirm the fallback decision for that case.
        assert_eq!(key_text_from_unicode(None), None);
    }
}
