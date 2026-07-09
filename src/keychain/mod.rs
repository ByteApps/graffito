//! SecretStore backend (PLAN "Key storage"), dispatched by platform:
//! - Apple (macOS + iOS): Keychain + LAContext — `apple`.
//! - Android: AES-GCM key in the hardware-backed AndroidKeyStore wrapping
//!   the material blob at rest — `android`.
//!
//! Both expose the same surface: `store_secret_protected`, `is_synced`,
//! `load_secret_protected`, `reveal_secret`, `delete_secret`, plus the
//! `--spike` helpers (`spike`, `spike_auth`).

#[cfg(target_vendor = "apple")]
mod apple;
#[cfg(target_vendor = "apple")]
pub use apple::*;

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::*;
