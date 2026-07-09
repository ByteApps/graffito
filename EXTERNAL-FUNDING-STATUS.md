# External funding (PSBT) — shipped

Optionally fund a note tx from an **external wallet** (an output descriptor /
xpub, never a private key). The app builds an unsigned PSBT → the external wallet
signs it (file or animated `crypto-psbt` QR) → the app validates, shows a
Sparrow-style confirmation, finalizes, and broadcasts. The note still belongs to
the app identity (a dust-to-self output keeps it discoverable), and directed-
private notes work with **no wire/protocol change** — a decoder enhancement
recovers the author key from the dust-to-self output. Design + decisions:
`~/.claude/plans/indexed-gliding-nova.md` and `../PLAN-chain-notes-app.md`.

## Status: DONE — shipped, committed, and pushed.

Backend, transport, **GUI**, the Prime signer, and ship-prep are all complete.
The dev `[patch]` is gone: `notes-core` is a published pinned git dependency, so
app txs are byte-identical to the Prime's by construction. All host tests pass,
the regtest e2e passes against real bitcoind for **both funding address types**,
and the QR paths are verified optically.

## Where the code lives

- **notes-core `bundle.rs`** — candidate-key decoder: a received directed-private
  note decrypts by trying every taproot key in the tx (inputs **and** the
  dust-to-self output), attributed to the true author; symmetric `open_sent`
  fallback so an author who funded externally recovers their own note. Scanners
  emit `OnchainTx.author_candidates` (desktop `chain.rs`, companion/viewer).
- **notes-core `psbt.rs`** — pure-Rust BIP-174 codec (parse/serialize/sign/
  finalize, taproot key-path subset) for the Prime signer (device can't use
  rust-bitcoin). Cross-checked byte-for-byte against `bitcoin::Psbt`.
- **app-core `funding.rs`** — `FundingSource::parse` (tr/wpkh, multipath, bare
  xpub), `derive`, `definite`; `FundingWallet` manager (create/list/rename/
  remove). `chain.rs::scan_funding` (gap-limited coin aggregation + change index).
- **app-core `psbt_build.rs`** — `build_funding_psbt`: OP_RETURN payloads +
  dust→recipient + dust→self + change→funding; wraps to `bitcoin::Psbt` with
  witness_utxo + tap/bip32 origins so hardware wallets can sign.
- **app-core `psbt_finalize.rs`** — `parse_psbt`, `summarize` (Sparrow-style
  `PsbtSummary`), `validate_signed`, `finalize_extract`.
- **app-core `ur.rs` / `ur_account.rs`** — animated `crypto-psbt` UR framing
  (`encode_psbt`, `PsbtUrDecoder`) and hardware-wallet account import
  (`crypto-account`/`crypto-output-descriptor`/`crypto-hdkey`, `UrDecoder`).
  The `crypto-psbt` message is a CBOR bstr wrapping the PSBT (BCR-2020-006) — the
  app adds/strips that wrapper, matching Passport firmware, so QRs interoperate.
- **app-core `examples/cli.rs`** — `fund-keygen [tr|wpkh]` / `fund-build` /
  `fund-sign` / `fund-finalize` (an in-process xprv stands in for the external
  signer in the regtest e2e).
- **desktop GUI** (`src/main.rs` + `ui/app.slint`) — compose "Pay from another
  wallet" toggle, the funding-wallet manager (add via typed/file/QR incl. UR
  account import), coin control over funding UTXOs, PSBT export (file + animated
  UR-QR), camera import (single- + multi-frame), the Sparrow-style confirmation
  screen, finalize + broadcast. All QR scanning runs through one shared camera
  overlay with a live preview and multi-frame progress bar (`src/camera.rs`).
- **Prime signer** (`prime-chain-notes`) — a "Sign PSBT" flow that scans a
  `crypto-psbt` UR, signs matching taproot inputs, and exports the signed PSBT.

## Signer interop (empirically verified)

| Signer | OP_RETURN | segwit input | taproot input |
|---|---|---|---|
| Passport Prime (stock Bitcoin Wallet) | ✅ | ✅ | ✅ |
| Taproot-capable signer firmware | ✅ | ✅ | ✅ |
| Segwit-only signer firmware | ✅ | ✅ | ❌ (needs taproot support) |
| Sparrow / bitcoin-cli | ✅ | ✅ | ✅ |

OP_RETURN is never the blocker; the only axis is taproot-input support. See
`ui-automation/tests/bitcoin-wallet-psbt.sh` and `signer-psbt.sh`.

## Verification

- **Host tests**: `cargo test -p notes-core`, `cargo test -p app-core`.
- **Regtest e2e** (`scripts/regtest-e2e.sh`): hermetic build → external-sign →
  finalize → broadcast to real bitcoind → prime-core decrypts over the wire, for
  **both P2TR and P2WPKH** funding descriptors.
- **Optical (lens loop)**: the desktop camera decodes SeedQR, taproot addresses,
  animated 4-frame UR crypto-account import, and single-frame descriptors, with a
  live preview at ~30 fps (release build — the debug build's per-pixel decode is
  ~100× slower).
- **Live testnet4**: a directed-private externally-funded note broadcast and
  decoded back by prime-core.

## Gotchas worth remembering

- `bitcoin` 0.32 needs `features=["base64"]` for `Psbt` ↔ base64. miniscript 12.3.7
  pairs with it.
- `foundation-ur` 0.4: `Encoder::next_part()` returns `UR` (Display);
  `Decoder::message()` returns `Result<Option<&[u8]>>`.
- `crypto-psbt` UR wraps the PSBT in a CBOR byte string — not the raw PSBT.
- Regtest: the companion `server.py` genesis-rescans each newly-watched address,
  so the funding scan is slow with a big gap — the e2e sets `CN_FUND_GAP=0` (the
  coin is at 0/0) and runs the funding block on a small chain.
- **Test the camera on the release `.app`, not `cargo run`** — the debug build's
  unoptimized image decode makes the scanner crawl (~2 fps) even though the code
  is correct.

## Verify commands (SDK Nix shell)

```
nix develop ~/.foundation/sdk/current --command cargo test -p notes-core
nix develop ~/.foundation/sdk/current --command cargo test -p app-core
nix develop ~/.foundation/sdk/current --command bash scripts/regtest-e2e.sh
nix develop ~/.foundation/sdk/current --command bash scripts/bundle-mac.sh   # release .app
```
