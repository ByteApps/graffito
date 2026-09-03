//! Screen.info — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// About-screen body, built at runtime so the version line can carry the
/// bundle's build number (`platform::build_number`) — "Version 0.1.0 (30)"
/// on a real build, "Version 0.1.0" on a host/dev binary with no bundle.
pub(crate) fn about_body() -> String {
    let version = match platform::build_number() {
        Some(build) => format!("Version {} ({build})", env!("CARGO_PKG_VERSION")),
        None => format!("Version {}", env!("CARGO_PKG_VERSION")),
    };
    format!("{ABOUT_INTRO}\n\n{version}\n\n{ABOUT_FOOTER}")
}
