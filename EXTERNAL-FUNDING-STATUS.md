# External funding (PSBT) — implementation status & continuation notes

Feature: optionally fund a note tx from an **external wallet** (output descriptor
/ xpub, not a private key). App builds a PSBT → external wallet signs (file or
animated `crypto-psbt` QR) → app validates, shows a Sparrow-style confirmation,
finalizes, and broadcasts. Design + decisions: `~/.claude/plans/indexed-gliding-nova.md`.

## Status: backend + transport + integration DONE and TESTED. GUI remains.

All host tests pass in the SDK Nix shell; the regtest e2e passes against real
bitcoind. Nothing committed/pushed — all in working trees.

### Done (with tests)
- **notes-core `bundle.rs`** — candidate-key decoder: received directed-private
  notes decrypt by trying every taproot key in the tx (inputs + dust-to-self
  output), attributed to the true author; symmetric `open_sent` fallback so an
  author who funded externally recovers their own note. No wire/protocol change.
  Scanners emit `OnchainTx.author_candidates` (desktop `chain.rs`, companion
  `index.html`). 26 roundtrip tests.
- **notes-core `psbt.rs`** (NEW) — pure-Rust BIP-174 codec (parse/serialize/sign/
  finalize, taproot key-path subset, preserves unknown fields). For the Prime
  signer (device can't use rust-bitcoin). 4 rust-bitcoin cross-checks. Also
  `bundle::sealed_note_payloads` — shared note-output builder.
- **app-core `funding.rs`** (NEW) — `FundingSource::parse` (tr/wpkh, multipath,
  bare xpub), `derive`, `definite` (for PSBT origins); `chain.rs::scan_funding`
  (gap-limited coin aggregation + next change index). 5 tests (BIP-86 vectors).
- **app-core `psbt_build.rs`** (NEW) — `build_funding_psbt`: OP_RETURN payloads +
  dust→recipient + dust→self + change→funding; wraps to `bitcoin::Psbt` with
  witness_utxo + tap/bip32 origins (miniscript `update_with_descriptor_unchecked`).
  3 tests incl. full build-and-decode-by-recipient.
- **app-core `psbt_finalize.rs`** (NEW) — `parse_psbt`, `summarize` (Sparrow-style
  `PsbtSummary`: labeled outputs + decoded note text + input addrs/amounts/fee),
  `validate_signed`, `finalize_extract`. 4 tests incl. hermetic
  build→external-sign→finalize pipeline.
- **app-core `ur.rs`** (NEW) — animated `crypto-psbt` UR framing via `foundation-ur`
  (`encode_psbt` → frames; `PsbtUrDecoder` reassembles). Byte-compatible with the
  KeyOS scanner. 2 roundtrip tests.
- **app-core `examples/cli.rs`** — `fund-keygen/build/sign/finalize` commands
  (in-process xprv simulates the external/hardware signer).
- **`scripts/regtest-e2e.sh`** — external-funding block: build → sign → finalize →
  broadcast to real bitcoind → prime-core decrypts over the wire. PASSES.

### DEV PATCH — must undo before shipping
`chain-notes-app/Cargo.toml` has a `[patch]` pointing `notes-core` at the local
working tree so desktop builds pick up the notes-core changes without a publish.
Ship-prep: push notes-core (ObjSal/prime-chain-notes), bump the `rev` in
`app-core/Cargo.toml`, delete the patch. Requires the user's go-ahead to push.

## Gotchas discovered (save the next session time)
- `bitcoin` 0.32 needs `features=["base64"]` for `Psbt` <-> base64 string.
- `foundation-ur` 0.4: `Encoder::next_part()` returns `UR` (Display → `.to_string()`);
  `Decoder::message()` returns `Result<Option<&[u8]>>` (borrow → `.map(<[u8]>::to_vec)`).
- `crypto-psbt` UR is CBOR-identical to `bytes`, so `Encoder::start("crypto-psbt", psbt_bytes, frag)` is spec-correct.
- Regtest e2e: the companion `server.py` genesis-rescans each newly-watched
  address (`ensure_address_watched`, `timestamp:0`), so the funding scan is slow
  with a big gap. The script sets `CN_FUND_GAP=0` (coin is at 0/0) and runs the
  funding block EARLY (small chain) + after wipe-recovery (so note counts hold).
- miniscript resolved to 12.3.7; pairs with bitcoin 0.32.

## Remaining work (GUI — needs a running-app run/screenshot loop)

### UI/UX consistency — REQUIRED (user directive)
New screens must look native to the app, reusing the existing design system in
`ui/app.slint` — do NOT invent new styling:
- **Palette**: the `Pal` global; bitcoin-orange accent `#F7931A`; dark card theme.
- **Components**: reuse `Card`, `PrimaryButton`, `GhostButton`, `IconButton`,
  `SelectPill`, `Dropdown`, `SettingsCard`, `DoorCard`, `Badge`, and the
  `H1/Body/Caption/Mono` text styles. Model new screens on existing ones —
  especially compose (screen 6) with its **collapsible coin-control** and
  **collapsible custom-change** sections (`ui/app.slint:~897-1090`), the send-to
  picker (screen 7), and settings dropdowns (screen 8).
- **Icons**: femtovg has NO font fallback → non-Latin glyphs render as tofu. Use
  SVG assets in `ui/icons/*.svg` via `@image-url` + `colorize` (resvg). Only
  "×", "‹", "Aa" may be typed as text. The scan button, QR frame, and confirm
  screen icons must be SVGs.
- **Structure**: integer `screen` state machine; register new screens/props/
  callbacks the same way; every callback emits a `cb:` log line (test grep
  target). Overlays/modals go as the LAST children of the window root. Keep
  keyboard-aware layouts compact (compose controls live in the top ~400px).
- The confirmation screen should read like Sparrow's review but in THIS app's
  card idiom (input/output rows as `Card`s, amounts in `Mono`, note text in
  `Body`, fee summary in a `Caption`/`Badge`).
- Match the Prime app's own design system for the M5 signer screens
  (`prime-chain-notes/ui/app.slint`) — see `[[prime-ui-gotchas]]`.


### M2/M3/M4 desktop UI (`src/main.rs` cb! callbacks + `ui/app.slint` screens)
Wire to the already-built app-core functions:
1. Compose: a **"Pay with external wallet"** toggle. When on, a funding-source
   entry (paste/scan an output descriptor or xpub) → `FundingSource::parse`;
   `ChainClient::scan_funding` → reuse the existing coin-control list
   (`SpendCoin` struct, `ui/app.slint:~897-1090`) over `FundingUtxo`s.
2. **Build + export**: `build_funding_psbt` → new screen: `.psbt` file via `rfd`
   (`BuiltPsbt::to_base64`/`to_bytes`) + animated UR-QR — `ur::encode_psbt` →
   render each frame with `src/qr.rs::qr_image`, cycle via a Slint `Timer`.
3. **Import + confirm + broadcast**: import `.psbt` via `rfd`, or camera —
   extend `src/camera.rs` (currently single-frame `rqrr`) to feed
   `ur::PsbtUrDecoder` until `is_complete()`. Then `psbt_finalize::parse_psbt`
   + `validate_signed` + `summarize` → new **Sparrow-style confirmation screen**
   (render `PsbtSummary`), gate broadcast; `finalize_extract` →
   `ChainClient::broadcast`; record in the store/Activity (reuse `NoteRecord`).
   NOTE: an externally-funded authored note classifies as "received" on the
   author's own rescan (handled in-decoder), so record it locally at broadcast.

### M5 Prime signer (`prime-chain-notes/src/main.rs` + `ui/*.slint`)
- Move `foundation-ur` to runtime deps; use `notes_core::psbt`.
- "Sign PSBT" flow: `open_qr_scanner` → `ScanQrResult::Ur2` (crypto-psbt) →
  `Psbt::deserialize` → for each input where `input_p2tr_output_x == identity.output_x`,
  `sign_taproot_key_path(i, &identity.tweaked_seckey, &aux)` → confirmation
  display (decode OP_RETURN note) → export signed PSBT as animated crypto-psbt UR
  QR (single frame if small, else animate) + Airlock file. Log `cb: sign-psbt …`.
  Skips non-taproot inputs.

### M6 remainder
- Prime-sim optical QR loop (`ui-automation/tests/chain-notes-app-psbt.sh`):
  desktop renders UR QR → sim webcam scans → sign → sim shows signed UR QR →
  desktop webcam scans → finalize + broadcast (regtest). Then testnet4 live.

### Ship-prep (task #8)
Publish notes-core, bump pin, drop the dev `[patch]`.

## Verify commands (SDK Nix shell)
```
nix develop ~/.foundation/sdk/current --command cargo test -p notes-core
nix develop ~/.foundation/sdk/current --command cargo test -p app-core
nix develop ~/.foundation/sdk/current --command bash scripts/regtest-e2e.sh
nix develop ~/.foundation/sdk/current --command cargo run     # the Mac app
```
