//! Source contract: EVERY `font-size` in the Slint UI multiplies by
//! `Metrics.type-scale` (ui/theme.slint), so the phone type scale reaches
//! every glyph. A bare `font-size: 12px;` is a site the OS font-size setting
//! silently misses — the rewrite of 2026-09-05 was scripted precisely so
//! none survive; this keeps it that way for new code.

use std::path::Path;

fn slint_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).expect("read ui dir") {
        let p = e.expect("dir entry").path();
        if p.is_dir() {
            // `ui/ui` is the SDK symlink in Prime apps; graffito has none, but
            // never descend into symlinks regardless.
            if !p.symlink_metadata().map(|m| m.file_type().is_symlink()).unwrap_or(false) {
                slint_files(&p, out);
            }
        } else if p.extension().and_then(|s| s.to_str()) == Some("slint") {
            out.push(p);
        }
    }
}

#[test]
fn every_font_size_is_type_scaled() {
    let ui = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
    let mut files = Vec::new();
    slint_files(&ui, &mut files);
    assert!(files.len() > 10, "found only {} slint files under {}", files.len(), ui.display());
    let mut bad = Vec::new();
    let mut sites = 0usize;
    for f in &files {
        let src = std::fs::read_to_string(f).expect("read slint");
        for (i, line) in src.lines().enumerate() {
            let mut rest = line;
            while let Some(pos) = rest.find("font-size:") {
                sites += 1;
                let tail = &rest[pos..];
                let stmt = tail.split(';').next().unwrap_or(tail);
                if !stmt.contains("Metrics.type-scale") {
                    bad.push(format!("{}:{}: {}", f.strip_prefix(&ui).unwrap().display(), i + 1, stmt.trim()));
                }
                rest = &rest[pos + "font-size:".len()..];
            }
        }
    }
    assert!(sites >= 100, "expected the ~136 font-size sites, found {sites}");
    assert!(bad.is_empty(), "font-size sites not multiplied by Metrics.type-scale:\n{}", bad.join("\n"));
}

#[test]
fn theme_declares_type_scale_default_one() {
    let theme = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("ui/theme.slint")).unwrap();
    assert!(theme.contains("in-out property <float> type-scale: 1.0;"), "Metrics.type-scale must default to 1.0 (desktop byte-identity)");
}
