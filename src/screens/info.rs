//! Screen.info — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// About-screen body, built at runtime so the version line is what the
/// STORE shipped, read from the bundle/package (`platform::app_version` +
/// `platform::build_number`): "Version 1.0 (68)" on iOS/macOS, "Version
/// 0.1.9 (12)" on Android. The Cargo version is only the fallback for a
/// host/dev binary that has no bundle — it is not kept in step with the
/// store versions and must never be shown on a shipped build.
pub(crate) fn about_body() -> String {
    let v = platform::app_version().unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    let version = match platform::build_number() {
        Some(build) => format!("Version {v} ({build})"),
        None => format!("Version {v}"),
    };
    format!("{ABOUT_INTRO}\n\n{version}\n\n{ABOUT_FOOTER}")
}
