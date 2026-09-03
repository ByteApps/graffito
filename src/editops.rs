//! `EditOps` global wiring: UTF-8 byte-offset text helpers + platform
//! clipboard for the EditField/EditArea widgets (offsets come from
//! TextInput's cursor API and are always char boundaries; clamp
//! defensively anyway). Moved verbatim out of `run()` (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

pub(crate) fn wire(window: &AppWindow) {
        fn clamp_boundary(t: &str, mut i: usize) -> usize {
            i = i.min(t.len());
            while i > 0 && !t.is_char_boundary(i) {
                i -= 1;
            }
            i
        }
        fn range(t: &str, s: i32, e: i32) -> (usize, usize) {
            let s = clamp_boundary(t, s.max(0) as usize);
            let e = clamp_boundary(t, e.max(0) as usize);
            (s.min(e), s.max(e))
        }
        let is_word = |c: char| c.is_alphanumeric() || c == '_';
        let ops = window.global::<EditOps>();
        ops.on_slice(|t, s, e| {
            let (s, e) = range(t.as_str(), s, e);
            t.as_str()[s..e].into()
        });
        ops.on_splice(|t, s, e, ins| {
            let (s, e) = range(t.as_str(), s, e);
            let mut out = String::with_capacity(t.len() + ins.len());
            out.push_str(&t.as_str()[..s]);
            out.push_str(ins.as_str());
            out.push_str(&t.as_str()[e..]);
            out.into()
        });
        ops.on_byte_len(|t| t.len() as i32);
        ops.on_word_start(move |t, off| {
            let t = t.as_str();
            let mut i = clamp_boundary(t, off.max(0) as usize);
            // if the char at the offset isn't a word char, try the one before
            if !t[i..].chars().next().map(is_word).unwrap_or(false)
                && !t[..i].chars().next_back().map(is_word).unwrap_or(false)
            {
                return i as i32;
            }
            while let Some(c) = t[..i].chars().next_back() {
                if is_word(c) {
                    i -= c.len_utf8();
                } else {
                    break;
                }
            }
            i as i32
        });
        ops.on_word_end(move |t, off| {
            let t = t.as_str();
            let mut i = clamp_boundary(t, off.max(0) as usize);
            if !t[i..].chars().next().map(is_word).unwrap_or(false)
                && !t[..i].chars().next_back().map(is_word).unwrap_or(false)
            {
                // not on a word: select the single char under the cursor (if any)
                if let Some(c) = t[i..].chars().next() {
                    return (i + c.len_utf8()) as i32;
                }
                return i as i32;
            }
            while let Some(c) = t[i..].chars().next() {
                if is_word(c) {
                    i += c.len_utf8();
                } else {
                    break;
                }
            }
            i as i32
        });
        ops.on_clip_set(|t| {
            let ok = platform::set_clipboard_text(t.as_str());
            println!("cb: edit-clip-set bytes={} ok={ok}", t.len());
        });
        ops.on_clip_get(|| {
            let t = platform::clipboard_text().unwrap_or_default();
            println!("cb: edit-clip-get bytes={}", t.len());
            t.into()
        });
        #[cfg(any(target_os = "ios", target_os = "android"))]
        ops.set_touch(true);
        #[cfg(target_os = "ios")]
        ops.set_ios(true);
}
