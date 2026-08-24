fn main() {
    let mut config = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
    // Element-tree introspection for the in-process UI tests
    // (i-slint-backend-testing ElementHandle — tests/ui_harness_*.rs, the
    // graffito-mac-ui-key-window memory). Opt-in via SLINT_EMIT_DEBUG_INFO=1
    // so it never bloats a release binary; the test harness sets it.
    if std::env::var("SLINT_EMIT_DEBUG_INFO").as_deref() == Ok("1") {
        config = config.with_debug_info(true);
    }
    println!("cargo:rerun-if-env-changed=SLINT_EMIT_DEBUG_INFO");
    slint_build::compile_with_config("ui/app.slint", config).expect("slint compile");

    // Android camera backend (camera_android.rs) links the NDK Camera2 +
    // AImageReader + ANativeWindow libraries.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-lib=camera2ndk");
        println!("cargo:rustc-link-lib=mediandk");
        println!("cargo:rustc-link-lib=android");
    }
}
