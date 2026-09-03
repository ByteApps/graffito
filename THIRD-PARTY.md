# Third-party libraries

Direct dependencies of this app and its `app-core` library. The complete transitive list (with exact versions) is pinned in [`Cargo.lock`](Cargo.lock).

## Core

| Library | Version | License | Used for |
|---|---|---|---|
| [notes-core](notes-core/) | workspace member | MIT OR Apache-2.0 | The PNTE protocol: envelope, sealing, ECDH, taproot tx build/sign — shared with the Passport Prime app |
| [graffito-core](graffito-core/) | workspace member | MIT OR Apache-2.0 | Shared UI-free policy (compose Security copy, `seclabel`) rendered identically by both apps |
| [bitcoin](https://crates.io/crates/bitcoin) (rust-bitcoin) | 0.32 | CC0-1.0 | BIP-32/86 derivation, WIF/xprv parsing, PSBT |
| [miniscript](https://crates.io/crates/miniscript) | 12 | CC0-1.0 | Output-descriptor parsing for watch-only identities |
| [bip39](https://crates.io/crates/bip39) | 2 | CC0-1.0 | BIP-39 mnemonic handling |
| [pgp](https://crates.io/crates/pgp) (rpgp) | 0.20 | MIT OR Apache-2.0 | Importing ML-KEM keys from RFC 9980 OpenPGP certificates (quantum-key import) |
| [zxcvbn](https://crates.io/crates/zxcvbn) | 3 | MIT | Passphrase-strength estimation for the post-quantum note passphrase (display only — certification requires a generated phrase) |
| [base64](https://crates.io/crates/base64) | 0.21 | MIT OR Apache-2.0 | Armored ML-KEM key parsing |
| [foundation-ur](https://crates.io/crates/foundation-ur) | 0.4 | MIT | Animated UR (BC-UR) QR framing — the exact codec the KeyOS scanner runs |
| [ciborium](https://crates.io/crates/ciborium) | 0.2 | Apache-2.0 | CBOR decode for hardware-wallet account-export QRs (crypto-account / crypto-hdkey) |
| [hkdf](https://crates.io/crates/hkdf) / [sha2](https://crates.io/crates/sha2) | 0.12 / 0.10 | MIT OR Apache-2.0 | Key derivation |
| [zeroize](https://crates.io/crates/zeroize) | 1 | Apache-2.0 OR MIT | Wiping secrets from memory |
| [hex](https://crates.io/crates/hex) | 0.4 | MIT OR Apache-2.0 | Hex encoding |
| [getrandom](https://crates.io/crates/getrandom) | 0.2 | MIT OR Apache-2.0 | OS entropy |
| [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) | 1 | MIT OR Apache-2.0 | Store/config persistence, esplora JSON |
| [reqwest](https://crates.io/crates/reqwest) | 0.12 | MIT OR Apache-2.0 | HTTPS chain sync + broadcast (rustls) |

## notes-core & graffito-core (workspace members, MIT OR Apache-2.0)

Both crates moved here from the Passport Prime app repo on 2026-09-02; the Prime app pins them as git dependencies of this repo. Pure-Rust by rule (C does not cross-compile to the Prime's `armv7a-unknown-xous-elf`). `graffito-core` adds nothing beyond `notes-core` + `serde`.

| Library | Version | License | Used for |
|---|---|---|---|
| [k256](https://crates.io/crates/k256) | 0.13 | Apache-2.0 OR MIT | secp256k1 math: BIP341 taproot tweak, BIP340 Schnorr signing, ECDH, and (`ecdsa` feature) RFC6979 deterministic ECDSA for BIP143 P2WPKH spending-wallet signing |
| [sha2](https://crates.io/crates/sha2) | 0.10 | MIT OR Apache-2.0 | SHA-256 (sighashes, tagged hashes) |
| [hkdf](https://crates.io/crates/hkdf) / [hmac](https://crates.io/crates/hmac) | 0.12 | MIT OR Apache-2.0 | Key derivation (identity, encryption, directed-note keys) |
| [pbkdf2](https://crates.io/crates/pbkdf2) | 0.12 | MIT OR Apache-2.0 | BIP-39 mnemonic → seed (recovery seeds) |
| [ripemd](https://crates.io/crates/ripemd) | 0.1 | MIT OR Apache-2.0 | BIP-32 key fingerprints (recovery seeds) |
| [chacha20poly1305](https://crates.io/crates/chacha20poly1305) | 0.10 | Apache-2.0 OR MIT | XChaCha20-Poly1305 sealing of private notes |
| [ml-kem](https://crates.io/crates/ml-kem) | 0.2 | Apache-2.0 OR MIT | FIPS 203 ML-KEM (512/768/1024) — the optional post-quantum hybrid layer on private notes (`pq.rs`; deterministic APIs only, entropy via `getrandom`) |
| [argon2](https://crates.io/crates/argon2) | 0.5 | MIT OR Apache-2.0 | Argon2id passphrase stretching for the optional password layer on private notes |
| [base64](https://crates.io/crates/base64) | 0.22 | MIT OR Apache-2.0 | Armored ML-KEM key import/export |
| [bech32](https://crates.io/crates/bech32) | 0.11 | MIT | Taproot addresses (BIP350) |
| [bs58](https://crates.io/crates/bs58) | 0.5 | MIT/Apache-2.0 | Base58check for WIF / xprv / xpub key export |
| [getrandom](https://crates.io/crates/getrandom) | 0.2 | MIT OR Apache-2.0 | Entropy source — on a Prime, the version line its TRNG override patches (`notes-core/tests/rng_backend.rs` guards it) |
| [miniz_oxide](https://crates.io/crates/miniz_oxide) | 0.8 | MIT OR Zlib OR Apache-2.0 | Deflate decompression of scanned bundle payloads |
| [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) | 1 | MIT OR Apache-2.0 | Sync-bundle JSON |
| [zeroize](https://crates.io/crates/zeroize) | 1 | Apache-2.0 OR MIT | Wiping secrets from memory |
| [hex](https://crates.io/crates/hex) | 0.4 | MIT OR Apache-2.0 | Hex encoding (txids, exports) |
| [bitcoin](https://crates.io/crates/bitcoin) (dev) | 0.32 | CC0-1.0 | Host-test cross-check of tx serialization/sighashes/signatures against libsecp256k1 — never a device dependency |
| [foundation-ur](https://crates.io/crates/foundation-ur) (dev) | 0.4 | MIT | Verifies the companion's UR encoder against the exact decoder the KeyOS scanner runs |
| [bip39](https://crates.io/crates/bip39) (dev) | 2 | CC0-1.0 | Host-test cross-check of the ported BIP-39 against an independent implementation |

## UI & QR

| Library | Version | License | Used for |
|---|---|---|---|
| [slint](https://slint.dev) (+ slint-build) | 1.17.1 (pinned) | GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0 | The UI toolkit. **This app elects the Royalty-free license** — see the note below |
| [qrcode](https://crates.io/crates/qrcode) | 0.14 | MIT OR Apache-2.0 | QR rendering (addresses, signed txs, backups) |
| [rqrr](https://crates.io/crates/rqrr) | 0.7 | MIT OR Apache-2.0 | QR decoding from camera frames |
| [png](https://crates.io/crates/png) | 0.17 | MIT OR Apache-2.0 | PNG encode for `--render` snapshots (dev tool) |

### Which Slint license this app uses

Slint is offered under three licenses and a user picks one. This app is
distributed under the **Slint Royalty-free Desktop, Mobile, and Web
Applications License 2.0**, *not* the GPL — deliberately, because the GPL
option would conflict with the App Store's terms of distribution and would
also be incompatible with keeping this repo Apache-2.0.

That license is conditional. Section 2 grants it only if the application
either displays the `AboutSlint` widget in an About screen reachable from the
top level, or shows the Slint attribution badge on a public page where the app
can be found. **This app elects the widget branch**: `AboutSlint` renders on
Settings → About & help → About (`ui/app.slint`, gated by `info-show-slint`).
That widget is the load-bearing attribution — removing it ends the grant, so
treat it as a build requirement rather than decoration.

Section 3 of the same license excludes embedded systems, which is why the
Passport Prime peer app ([prime-graffito](https://github.com/ByteApps/prime-graffito))
cannot use it and is GPL-3.0-or-later instead.

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
| [bip85-core](https://github.com/ByteApps/prime-bip85) | pinned git rev | MIT OR Apache-2.0 | Parity-test fixture generator (real BIP-85 outputs feed the importer tests) |

## Patched dependencies

| Library | Version | License | Why it is patched |
|---|---|---|---|
| [winit](https://github.com/ByteApps/winit/tree/v0.30.13-no-private-apple-apis) | 0.30.13 + 1 commit | Apache-2.0 | Pulled in by slint. Upstream's macOS backend declares Apple's **private** `CGSSetWindowBackgroundBlurRadius` / `CGSMainConnectionID` and calls them from `WindowDelegate::set_blur`. Slint never calls `Window::set_blur`, but the reference alone lands in the binary's undefined symbol table and App Review rejects on it. The fork deletes both entry points and makes `set_blur` a no-op; upstream master gates them behind a non-default `private-apple-apis` feature that does not exist on the 0.30 branch. Pinned by revision in `Cargo.toml`'s `[patch.crates-io]`. |
