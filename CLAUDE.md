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
  src/identity.rs       # create/import: bip39 | xprv | wif | hex; realize(material, network, account)
  src/derive.rs         # BIP-32/86 (account-aware) + FROZEN enc-key rule
  src/seedqr.rs         # SeedQR standard+compact, both directions
  src/chain.rs          # esplora → in-memory SyncBundle
  src/store.rs          # notes + UTXO ledger + contacts
  src/compose.rs        # orchestration over notes-core compose
  examples/cli.rs       # app role for scripts (APP_KEY/APP_ACCOUNT env)
  examples/fund.rs      # test-funding tool (P2WPKH spend from FUND_WIF)
src/main.rs             # all screen callbacks + --spike modes
src/{camera,keychain,qr}.rs  # Mac glue: nokhwa→rqrr, Keychain+LAContext, QR-out
ui/app.slint            # design system (Pal palette, Card/PrimaryButton/
                        #   GhostButton/SelectPill/Dropdown/SettingsCard/DoorCard/Badge,
                        #   fluent-dark std widgets) + 10 screens + modals
ui/icons/*.svg          # icon assets (@image-url + colorize — see icon rule)
scripts/bundle-mac.sh   # minimal .app (TCC camera permission needs a bundle)
scripts/regtest-e2e.sh  # app↔Prime interop matrix (host CLIs vs bitcoind)
```

Two UI e2e suites in `../ui-automation/tests/` (simtap on the real Mac
window): `chain-notes-app.sh` (compose→sign→broadcast smoke) and
`chain-notes-app-matrix.sh` (full journey: hex/WIF/mnemonic import +
account picker + settings account-switch + reset; create-seed →
backup/quiz → fund → fee-tier directed private note decrypted by a CLI
identity → contact rename/remove → chunk/network pills → coins list +
consolidate → activity). Point offsets are calibrated to the current
layout — recalibrate from screenshots when app.slint moves controls.

Screens (`screen` property): 0 onboarding (3 doors) · 1 import (typed/
QR/file, live format feedback + word autocomplete) · 2 backup words ·
3 quiz · 4 home (balance card, QR, notes list w/ badge pills) · 5 note
view (+ web-viewer permalink link, hidden on regtest) · 6 compose
(picker-first, Private default, live cost line; economy/normal/fast/**custom**
fee tiers where the sat/vB field is revealed only when Custom is selected;
collapsible **coin
control** — spendable UTXOs sorted low→high, auto-suggests CONFIRMED
coins only [unconfirmed spendable but manual] via a **fewest-coins vs
consolidate** strategy toggle [largest- vs smallest-first],
tap-to-toggle, live total, ↻ refresh, per-coin mempool txid pill, Sign
gated on sufficiency; a collapsible **custom change address** with live
validation; and — for **directed notes only** — a collapsible **Gift ·
N sats** panel [numeric input, default/min = dust 330, live cost
"+ N sats to recipient"] that sets how much the recipient output carries)
· 7 send-to (Self card,
address input + QR-icon scan [scan-to-pick] + Use, recents w/ pencil-
rename dialog + confirmed remove) · 8 settings (Identity card w/
account switch + reset, network/chunk pills, **Bitcoin node** +
**Block explorer** dropdowns [network-aware presets + a "Custom…" row
that reveals a URL text field — the `Dropdown` component in app.slint,
a PopupWindow-backed picker; on regtest both lists are Custom-only;
these two live in config.json keyed by network (device-level, NOT the
per-identity store), so switching identity keeps them],
Coins card, Funds/sweep, Touch ID reveal — Flickable-scrollable) · 9 account
picker (paginated, 5/page, current badge) · 10 coins (spendable UTXO
list + consolidate-to-self) · 11 activity (all note + sweep/consolidate
txs; pending get Bump-fee/Rebroadcast/Explorer). Modals
(overlays as LAST children of the window root): rename, remove-confirm,
reset-confirm, sweep-confirm, consolidate-confirm.

**Identity lifecycle:** key material verbatim in the keychain; BIP-86
account chosen on a paginated picker after hierarchical imports and
switchable later from Settings without re-import (each account = its
own address AND enc key). Store files are per-identity:
`store-<network>-<fp8>.json` — switching keys/accounts never mixes
notebooks. `config.json` is device-level and persists {network, account,
nodes{net→url}, explorers{net→url}} — the Bitcoin-node / block-explorer
choices live here (per network, not per identity) so they survive
identity switches; base_url()/explorer_base() read them, the Settings
dropdowns write them via save_config(). A legacy per-identity node URL
(old `esplora`/`node_url` store field) is migrated into config on load.
Reset ("Switch identity") deletes the keychain item and returns to
onboarding; notes recover from chain on re-import.

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
default features); only universally-safe chars ("×", "Aa") may be typed
as text ("‹" and "₿" both burned us — now `chevron-left.svg` /
`bitcoin.svg`). Android's Roboto is the strictest renderer; check new
glyphs there first.

**Header back-chevron alignment** is per-platform: the title `Text`
sits high in its row (fonts reserve descent space), and the offset
differs per font/renderer. The `Metrics` global in `app.slint` carries
`back-dy` — Apple `-1.25px` (default), Android `+1.5px` (set from Rust
in `run()`). Values were calibrated by measuring rendered ink centers
from screenshots; don't eyeball them. Related Android gotcha: without
`theme = "@android:style/Theme.DeviceDefault.NoActionBar"` in the
cargo-apk manifest, the NativeActivity content rect includes a phantom
56dp ActionBar and `safe_area_insets` over-pads the top of every screen
(boot logs `cb: safe-area top=… bottom=… scale=…` for a quick check —
the Pixel 6 emulator's true status bar is ~48.8dp).

## Invariants

- **Extending notes-core is ADDITIVE**: coin control + custom change
  needed new tx builders — added `build_note_tx_with_change` /
  `_exact` and `compose_*_with_change` / `_exact`; the original
  no-arg functions delegate (change=self, auto-select) so every
  existing caller stays byte-identical. Bump the pin, re-run all tests.
  The **gift amount** followed the same pattern: `recipient_amount: u64`
  on the tx builders + `compose_directed_note_with_change_amount` /
  `_exact_amount`; the non-`_amount` variants delegate with `DUST_LIMIT`.
  `ComposeRequest.gift_amount: Option<u64>` (None = dust) plumbs it;
  `NoteRecord.gift_amount` (serde default) persists it so RBF preserves
  the gift. notes-core rev `8fb7255` ships this on prime main — the
  Prime app can adopt it the same way (see prime-chain-notes/CLAUDE.md).
- Compose input paths: default = notes-core auto-select (largest-first);
  coin control = `compose_*_exact` spending EXACTLY the selected coins
  (change = leftover). Custom change goes to any spk and is NOT tracked
  as an own coin; the destination is stored on the note so RBF preserves
  it. Unconfirmed coins are spendable (scan keeps height=None, only
  pending-locked are excluded) — never auto-suggested. The live
  cost/change preview (`note_est`) sizes the REAL change output — a
  custom non-taproot change spk corrects the estimate by `spk_len - 34`
  vB (estimate_note_cost assumes a 34-byte taproot change).
- Sweep/consolidate txs are tracked in `store.txs` (`TxRecord`) so they
  get the same pending→confirmed lifecycle, rebroadcast, and RBF
  (`bump_raw_tx`) as notes; confirmed when their inputs vanish on a full
  scan. Notes' own RBF is `bump_fee` (same note_id, same inputs). The
  Activity screen (11) shows per-tx sat/vB + fee, a "replaced N×" badge
  after a bump, and a Speed-up dialog enforcing the BIP-125 +1 sat/vB
  minimum with a live new-fee preview.
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

## UI log contract additions (src/main.rs `cb:` lines)

`cb: identity kind=<k> account=<n> network=<n> address=<a>` ·
`cb: refresh notes=… balance=… tip=…` · `cb: compose … broadcast=ok` ·
`cb: pick-contact to=<a|self>` · `cb: rename-start/save-contact/
confirm-remove/remove-contact` · `cb: import hierarchical → account
picker` · `cb: pick-account <n>` · `cb: account-picker open` ·
`cb: set-network <net>` · `cb: set-chunk-size <n> ok` ·
`cb: set-node-preset <name|custom>` · `cb: set-node-custom <url|default>` ·
`cb: set-explorer-preset <name|custom>` · `cb: set-explorer-custom <url|default>` ·
`cb: reveal-backup ok|cancelled` · `cb: reset-identity` ·
`cb: open-note-web url=…` · `cb: toggle-coin selected=<n>` ·
`cb: refresh-coins` · `cb: act-explorer` · `cb: bump-open`/`act-bump`.
UI e2e:
`../ui-automation/tests/chain-notes-app.sh` (simtap point offsets from
the window origin — recalibrate from screenshots when app.slint moves
controls; simtap also has `scroll <x> <y> <dy>`).

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
