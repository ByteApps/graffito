# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

**chain-notes-app** — a native, **online** Mac (later iOS/Android) app
that is a full peer of `prime-chain-notes`: compose/encrypt/sign PNTE
notes, **broadcast directly**, and read them back from the chain. It
holds the notes private key — created in-app (12/24 BIP-39 with backup
flow) or imported (BIP-39 / xprv / WIF / 32-byte hex; every format via
typed text, QR, or file; SeedQR supported). Flagship import path: a
dedicated **BIP-85 child from `prime-bip85`**. Also the standalone
on-ramp for users with no Prime or hardware wallet at all.

Design doc + milestone plan (M0–M7): **`../PLAN-chain-notes-app.md`** in
the prime workspace (this repo is a workspace submodule sibling of the
Prime apps). Protocol invariants live in
`../prime-chain-notes/CLAUDE.md` — frozen there, honored here.

## Layout

```
app-core/               # UI-free core: cargo test -p app-core
  src/identity.rs       # create/import: bip39 | xprv | wif | hex (M1)
  src/derive.rs         # BIP-32/86 + FROZEN enc-key rule (M1)
  src/seedqr.rs         # SeedQR standard+compact, both directions (M1)
  src/chain.rs          # esplora → in-memory SyncBundle (M2)
  src/store.rs          # notes + UTXO ledger + contacts (M3)
  src/compose.rs        # orchestration over notes-core compose (M3)
src/main.rs             # Slint shell (stub until M5)
```

## Invariants

- **notes-core is a pinned git dependency** (`ObjSal/prime-chain-notes`)
  and the ONLY producer of on-chain bytes: envelope, sealing, dm ECDH,
  tx build/sign all go through it — never reimplement, so app txs stay
  byte-identical to the Prime's by construction. Bump the pin
  deliberately and re-run the full test suite.
- **FROZEN once shipped**: enc key = HKDF-SHA256(leaf internal-key
  secret, salt `chain-notes-app/enc/v1`, info `note-enc/v1`) — same rule
  for all four import formats. Derivation: BIP-39/xprv → BIP-86
  `m/86'/{coin}'/0'/0/0` (xprv depth 0 or 3 only); WIF/hex → raw key,
  BIP-341 tweak, P2TR directly.
- notes-core's `[patch]` getrandom/TRNG override does NOT propagate here
  — correct and intended (host OS randomness).
- **Key storage is a cross-platform SPEC** (PLAN doc, "Key storage"
  section): the original key material verbatim, in the platform
  keychain/keystore ONLY (macOS/iOS Keychain ThisDeviceOnly + no sync,
  Android Keystore) behind app-core's `SecretStore` trait; reveal always
  re-authenticates; derived keys recomputed on unlock, never persisted.
- No secrets in logs: the `cb:` log contract carries lengths and
  fingerprints, never key material. `zeroize` on secrets.

## Build / test

No system Rust on this machine — use the Foundation SDK's Nix shell as a
plain host toolchain (ssh-agent passes through; `.cargo/config.toml`
forces git-CLI fetch for the ssh:// dep):

```bash
nix develop ~/.foundation/sdk/current --command cargo test -p app-core
nix develop ~/.foundation/sdk/current --command cargo run
```
