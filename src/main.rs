//! Thin desktop/iOS entry point. All logic lives in the library crate
//! (`src/lib.rs`) so the Android cdylib can share it via `android_main`.
//! On Android this bin is a no-op — cargo-ndk builds the cdylib instead.

#[cfg(not(target_os = "android"))]
fn main() {
    chain_notes_app::run();
}

#[cfg(target_os = "android")]
fn main() {}
