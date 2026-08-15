# Third-party libraries

Direct dependencies of this app and its `app-core` library. The complete transitive list (with exact versions) is pinned in [`Cargo.lock`](Cargo.lock).

## Core

| Library | Version | License | Used for |
|---|---|---|---|
| [notes-core](https://github.com/ByteApps/prime-graffito) | pinned git rev | MIT OR Apache-2.0 | The PNTE protocol: envelope, sealing, ECDH, taproot tx build/sign — shared with the Passport Prime app |
| [bitcoin](https://crates.io/crates/bitcoin) (rust-bitcoin) | 0.32 | CC0-1.0 | BIP-32/86 derivation, WIF/xprv parsing, PSBT |
| [miniscript](https://crates.io/crates/miniscript) | 12 | CC0-1.0 | Output-descriptor parsing for watch-only identities |
| [bip39](https://crates.io/crates/bip39) | 2 | CC0-1.0 | BIP-39 mnemonic handling |
| [foundation-ur](https://crates.io/crates/foundation-ur) | 0.4 | MIT | Animated UR (BC-UR) QR framing — the exact codec the KeyOS scanner runs |
| [ciborium](https://crates.io/crates/ciborium) | 0.2 | Apache-2.0 | CBOR decode for hardware-wallet account-export QRs (crypto-account / crypto-hdkey) |
| [hkdf](https://crates.io/crates/hkdf) / [sha2](https://crates.io/crates/sha2) | 0.12 / 0.10 | MIT OR Apache-2.0 | Key derivation |
| [zeroize](https://crates.io/crates/zeroize) | 1 | Apache-2.0 OR MIT | Wiping secrets from memory |
| [hex](https://crates.io/crates/hex) | 0.4 | MIT OR Apache-2.0 | Hex encoding |
| [getrandom](https://crates.io/crates/getrandom) | 0.2 | MIT OR Apache-2.0 | OS entropy |
| [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) | 1 | MIT OR Apache-2.0 | Store/config persistence, esplora JSON |
| [reqwest](https://crates.io/crates/reqwest) | 0.12 | MIT OR Apache-2.0 | HTTPS chain sync + broadcast (rustls) |

## UI & QR

| Library | Version | License | Used for |
|---|---|---|---|
| [slint](https://slint.dev) (+ slint-build) | 1.17.1 (pinned) | GPL-3.0-only OR Slint Royalty-free OR Slint commercial | The UI toolkit (used here under GPL-compatible terms with this repo's MIT/Apache-2.0 code) |
| [qrcode](https://crates.io/crates/qrcode) | 0.14 | MIT OR Apache-2.0 | QR rendering (addresses, signed txs, backups) |
| [rqrr](https://crates.io/crates/rqrr) | 0.7 | MIT OR Apache-2.0 | QR decoding from camera frames |
| [png](https://crates.io/crates/png) | 0.17 | MIT OR Apache-2.0 | PNG encode for `--render` snapshots (dev tool) |

## macOS

| Library | Version | License | Used for |
|---|---|---|---|
| [nokhwa](https://crates.io/crates/nokhwa) | 0.10 | Apache-2.0 | Camera capture (AVFoundation) |
| [rfd](https://crates.io/crates/rfd) | 0.14 | MIT | Native file dialogs |

## Apple platforms (macOS + iOS)

| Library | Version | License | Used for |
|---|---|---|---|
| [security-framework](https://crates.io/crates/security-framework) (+ -sys) | 3 / 2 | MIT OR Apache-2.0 | Keychain storage |
| [core-foundation](https://crates.io/crates/core-foundation) (+ -sys) | 0.10 / 0.8 | MIT OR Apache-2.0 | CoreFoundation interop |
| [objc2](https://crates.io/crates/objc2) family (foundation, local-authentication, ui-kit, av-foundation, core-media, core-video, core-foundation) | 0.3–0.6 | MIT (some Zlib OR Apache-2.0 OR MIT) | Touch ID / LAContext, iOS camera, pasteboard, safe-area insets |
| [block2](https://crates.io/crates/block2) | 0.6 | MIT | Objective-C block interop |
| [dispatch2](https://crates.io/crates/dispatch2) | 0.3 | Zlib OR Apache-2.0 OR MIT | Grand Central Dispatch interop |

## Android

| Library | Version | License | Used for |
|---|---|---|---|
| [jni](https://crates.io/crates/jni) | 0.21 | MIT OR Apache-2.0 | Keystore, clipboard, intents via JNI |
| [ndk-context](https://crates.io/crates/ndk-context) | 0.1 | MIT OR Apache-2.0 | JavaVM/Activity handles from the NativeActivity |

## Dev dependencies

| Library | Version | License | Used for |
|---|---|---|---|
| [bip85-core](https://github.com/ObjSal/prime-bip85) | pinned git rev | MIT OR Apache-2.0 | Parity-test fixture generator (real BIP-85 outputs feed the importer tests) |

## Patched dependencies

| Library | Version | License | Why it is patched |
|---|---|---|---|
| [winit](https://github.com/ObjSal/winit/tree/v0.30.13-no-private-apple-apis) | 0.30.13 + 1 commit | Apache-2.0 | Pulled in by slint. Upstream's macOS backend declares Apple's **private** `CGSSetWindowBackgroundBlurRadius` / `CGSMainConnectionID` and calls them from `WindowDelegate::set_blur`. Slint never calls `Window::set_blur`, but the reference alone lands in the binary's undefined symbol table and App Review rejects on it. The fork deletes both entry points and makes `set_blur` a no-op; upstream master gates them behind a non-default `private-apple-apis` feature that does not exist on the 0.30 branch. Pinned by revision in `Cargo.toml`'s `[patch.crates-io]`. |
