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
src/main.rs             # Slint shell + --spike modes (M5); screens at M6
src/{camera,keychain,qr}.rs  # Mac glue: nokhwa→rqrr, Keychain, QR-out
ui/app.slint            # window (M5 skeleton)
scripts/bundle-mac.sh   # minimal .app (TCC camera permission needs a bundle)
scripts/regtest-e2e.sh  # M4 interop matrix
```

M5 platform facts: **slint is pinned `=1.16.1`** — 1.17 needs rustc
1.92 and the SDK nix shell ships 1.91-nightly; bump the pin only with a
newer toolchain. Camera spike: `cargo run -- --spike camera [secs]`
(first run pops the TCC prompt; 1080p Luma frames → rqrr). Keychain
spike: `--spike keychain` (plain round-trip, automation-safe) and
`--spike keychain-auth` (interactive user-presence round-trip).
Layered protection is DONE: SecAccessControl/UserPresence item when the
build is entitled (properly signed → OS-enforced), else automatic
fallback to a plain item whose reads are gated by an LAContext
DeviceOwnerAuthentication prompt (unsigned dev builds hit
errSecMissingEntitlement -34018 — both SecItemAdd paths force the
data-protection keychain once kSecAttrAccessControl is present). Boot
prompts once (material cached in-session; APP_KEY env bypasses for
automation); Reveal prompts fresh every time.
`tests/qr_roundtrip.rs` proves render→decode without optics.

**Icon rule:** femtovg (the default renderer) has no font fallback —
non-Latin glyphs (✎ ✕ ▦ ＋ emoji) render as tofu. Icons are SVG assets
in `ui/icons/` via `@image-url` + `colorize` (resvg ships in slint's
default features); only universally-safe chars ("×", "‹", "Aa") may be
typed as text.

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
nix develop ~/.foundation/sdk/current --command bash scripts/regtest-e2e.sh  # app↔Prime interop matrix vs real bitcoind
nix develop ~/.foundation/sdk/current --command cargo run
```

The e2e script reuses ../prime-chain-notes' `companion/server.py
--regtest` (manages its own throwaway bitcoind; auto-mines on POST /tx
and /faucet) and drives BOTH cores: `examples/cli.rs` as the app
(identity via `APP_KEY` env — any accepted format) and prime's
`notes_cli` (via `NOTES_APP_SEED`). The `cli bundle` command emits
SyncBundle JSON for any address — the two cores share the serde, so it
feeds notes_cli's scan directly.

## CLI log contract (grep targets)

`cli: init kind=<k> network=<n> address=<a>` ·
`cli: scan notes=<n> new=<k> orphaned=<o> balance=<b> tip=<h>` ·
`cli: compose id=<hex8> txid=<t> fee=<f> vsize=<v> to=<addr|self>
private=<b> broadcast=ok` ·
`note id=<hex8> status=<pending|confirmed|orphaned> private=<b>
directed=<b> received=<b> from=<a|-> to=<a|-> text=<t|->` ·
`cli: bundle address=<a> txs=<n> utxos=<n> -> <path>`

Esplora-shape gotcha (baked into chain.rs, don't regress): server.py
prevouts carry ONLY `scriptpubkey_address` (no script hex, no type) and
its vout types are Core-style (`witness_v1_taproot`), while real esplora
uses `v1_p2tr` — so taproot detection goes by address prefix
(bc1p/tb1p/bcrt1p, the chain-scan.js P2TR_RE rule), never type strings,
and every EsploraOut field is serde-default.
