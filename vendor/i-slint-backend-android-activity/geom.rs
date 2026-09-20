// Copyright © SixtyFPS GmbH <info@slint.dev>
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0

//! graffito patch (2026-09-19): pure "is this tap outside that rectangle"
//! decision, split out of `androidwindowadapter.rs` so it compiles (and is
//! unit-testable) on every host -- see the crate's `NOTES.md`.
//!
//! Backs the "tap anywhere that isn't a text field dismisses the keyboard"
//! rule: on a pointer-up that was a tap (not a drag), the caller computes
//! the focused `TextInput`'s window-space rectangle (the same way
//! `androidwindowadapter.rs`'s pre-existing `long_press_timeout` already
//! does: `focus_item.geometry().translate(focus_item.map_to_window(..)
//! .to_vector())`) and asks this module whether the tap point falls
//! outside it.

/// `rect` is `(x, y, width, height)`; `tap` is `(x, y)`. Both must be in the
/// same coordinate space (the caller uses logical window space, matching
/// the pointer positions it already computes with the display offset and
/// scale factor applied).
///
/// Matches `euclid::Rect::contains`'s half-open convention (a point exactly
/// on the right/bottom edge is OUTSIDE) so this agrees with the geometry
/// Slint itself uses to decide hit-testing.
pub fn tap_outside(rect: (f32, f32, f32, f32), tap: (f32, f32)) -> bool {
    let (x, y, w, h) = rect;
    let (tx, ty) = tap;
    tx < x || ty < y || tx >= x + w || ty >= y + h
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELD: (f32, f32, f32, f32) = (10.0, 20.0, 100.0, 40.0); // x,y,w,h

    #[test]
    fn tap_inside_the_field_is_not_outside() {
        assert!(!tap_outside(FIELD, (50.0, 40.0)));
    }

    #[test]
    fn tap_on_the_top_left_corner_is_inside() {
        assert!(!tap_outside(FIELD, (10.0, 20.0)));
    }

    #[test]
    fn tap_just_left_of_the_field_is_outside() {
        assert!(tap_outside(FIELD, (9.999, 40.0)));
    }

    #[test]
    fn tap_just_above_the_field_is_outside() {
        assert!(tap_outside(FIELD, (50.0, 19.999)));
    }

    #[test]
    fn tap_on_the_right_or_bottom_edge_is_outside() {
        // Half-open: [x, x+w) x [y, y+h) -- matches euclid::Rect::contains.
        assert!(tap_outside(FIELD, (110.0, 40.0))); // x + w
        assert!(tap_outside(FIELD, (50.0, 60.0))); // y + h
    }

    #[test]
    fn tap_far_below_the_field_is_outside() {
        assert!(tap_outside(FIELD, (50.0, 200.0)));
    }
}
