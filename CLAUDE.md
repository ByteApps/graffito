# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

**chain-notes-app** — a native, **online** Mac (later iOS/Android) app
that is a full peer of `prime-chain-notes`: compose/encrypt/sign PNTE
notes, **broadcast directly**, and read them back from the chain. It
holds the notes private key — created in-app (12/18/24 BIP-39 with
backup flow) or imported (BIP-39 12/18/24 words / xprv / WIF / 32-byte hex; every
format via typed text, QR, or file; SeedQR supported, incl. 18-word/
24-byte forms). Flagship import path: a
dedicated **BIP-85 child from `prime-bip85`**. Also the standalone
on-ramp for users with no Prime or hardware wallet at all.

**Watch-only identities**: importing an account-level xpub (depth 3 —
the hardened 86' path makes a master xpub underivable), a key-origin
xpub (`[fp/86'/…]xpub…`, the hardware-wallet export form), or a `tr()`
descriptor makes a key-less notebook — same address as the full key,
public notes and balance/coins/activity readable, every private body
sealed ("key not on this device"), compose hidden (`watch-only` slint
property; Rust callbacks gate via `AppIdentity::full()` — never
fabricate zero keys). `KeyMaterial::Xpub(FundingSource)` →
`IdentityKeys::Watch { output_x, source }` in app-core; scans go through
notes-core's additive `extract_notes_watch` / store's
`apply_bundle_watch`. The material is stored in the keychain verbatim
(iCloud backup applies) like any key. **Spends still work** — sweep,
consolidate, and Speed-up (RBF) build unsigned PSBTs
(`build_watch_spend_psbt` / `build_watch_bump_psbt`, key origins from
the descriptor so hardware wallets recognize their inputs) and route
through the SAME sign screen (13) + review/broadcast (14) external
funding uses (`State.watch_spend` carries post-broadcast bookkeeping;
bump fetches the pending tx via `ChainClient::fetch_tx_io` since
chain-recovered records have no raw hex); Rebroadcast is keyless via
`fetch_tx_hex`. Import an origin-full descriptor for signers
that check the master fingerprint; bare xpubs still view fine. Verified:
`ui-automation/tests/chain-notes-watch-signer.sh` (the signer sim
signs consolidate+sweep on regtest, headless) and a live testnet4 pass
(app-UI sweep signed by the CC sim incl. RBF replacement through
mempool.space). `cli xpub|spend-build|bump-build|spend-broadcast`
subcommands feed the e2e. **Compose works watch-only for PUBLIC notes**
(self or directed, gift supported): the compose screen stays available
with Private and pay-from-another-wallet hidden, and Sign becomes
"Build transaction to sign" — `build_watch_note_psbt` (self-funded:
OP_RETURNs via `envelope::encode_chunks` — no key needed for public
flags — then optional recipient output + change-to-self, own-note rule
holds since the tx spends from self); the broadcast records the note
Pending exactly like a keyed compose (`record_watch_note`). `cli
note-build` + a CC e2e leg prove a watch identity can POST a note.
"Pay from another wallet" works in watch mode too
(`build_watch_funded_note_psbt`: funding coins pay, dust-to-self keeps
the note discoverable, gift supported; `cli note-funded-build` + CC e2e
leg 6) — with the FROZEN-SCAN caveat asserted there: an externally
funded PUBLIC note re-scans as RECEIVED from the funder (ownership is
only provable for directed-private; the local record keeps it own; true
for keyed identities as well). Directed-PRIVATE can never work
watch-only — the ECDH needs the identity key at compose time.

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
assets/icon/            # app icon: icon.svg master (same design as the Prime
                        #   app's resources/icon.svg) + generated mac/AppIcon.icns
                        #   and android/res mipmaps — scripts/gen-icon-assets.sh
                        #   regenerates all of them (+ the iOS appiconset PNG)
scripts/bundle-mac.sh   # minimal .app (TCC camera permission needs a bundle)
scripts/regtest-e2e.sh  # app↔Prime interop matrix (host CLIs vs bitcoind)
```

Three e2e suites in `../ui-automation/tests/`: `chain-notes-app.sh`
(simtap smoke: compose→sign→broadcast + the sweep flow: Settings button
→ destination picker → screen 16 → confirm → broadcast) and
`chain-notes-app-matrix.sh` (full simtap journey: hex/WIF/mnemonic
import + account picker + settings account-switch + reset; create-seed
→ backup/quiz → fund → fee-tier directed private note decrypted by a
CLI identity → contact rename/remove → chunk/network pills → coins
list + consolidate via screen 16 → activity) drive the real Mac window
— point offsets are calibrated to the current layout; recalibrate from
screenshots when app.slint moves controls. The headless
`chain-notes-watch-signer.sh` drives the hardware-signer sim over its
socket: watch import → consolidate → sweep → funded sweep →
public-note compose (self- and fee-wallet-funded), every tx
signer-signed against live regtest coins.

**Product screenshots** (`screenshots/{home,compose,activity}.png`, wired
into README.md): capture the real Mac window — pin it first
(`set frontmost` + `set position {60,60}` via System Events, bounds via
`get {position, size} of window 1`), then
`screencapture -x -R "$X,$Y,$W,$H"` (system python3 has no Quartz module,
so window-id capture isn't scriptable; the native title bar in a region
capture is fine — only the Prime device frame was unwanted). Stage
realistic state the same way the e2e does: `server.py <port> --regtest`
+ `POST /regtest/api/faucet`, launch with `APP_DATA_DIR=<fresh tmp>
APP_KEY=<mnemonic> APP_NETWORK=regtest`, set the node through Settings
(no env override exists), then compose real notes through the UI so
home/Activity show confirmed cards. Recapture with this recipe whenever
app.slint moves things. (Prime-app READMEs use the simulator control
window's Screenshot button with Capture=Screen instead — see the
workspace CLAUDE.md.)

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
picker (paginated, 5/page, current badge) · 10 coins (viewer-first:
spendable UTXO list with ONE "Consolidate into one coin…" button on top
that opens 16) · 11 activity (all note + sweep/consolidate txs; pending
get Bump-fee/Rebroadcast/Explorer) · 16 sweep/consolidate (compose-like,
shared via `sweep-kind`: destination line, fee tier pills + custom
field, live cost line, "Pay the fee from another wallet", READ-ONLY
inputs collapsible; sweep is reached from Settings→Funds through the
send-to picker in `pick-mode` "sweep" — no Self card — consolidate from
Coins with dest = self; keyed unfunded routes to the classic confirm
modals, watch or fee-funded to the external-sign screen 13) · 17
**notebooks** (the MAIN screen since the notebooks feature — boot lands
here; one row per notebook [name, filter-respecting snippet + note
count, "N new" unread badge, balance, active accent border, pencil-
rename + archive icons], "+ New notebook" [hierarchical identities
only], collapsed "Archived (N)" section with Restore). Home (4) is one
notebook's view: back chevron → 17, title = notebook name, and a
**sender filter** under the compose button ("Senders" caret when >1
sender) — checklist rows labeled contact-name / "Self · <notebook>" /
addr-short, tap to exclude; exclusions persist per notebook (the
EXCLUSION set, so new senders always show), a "N senders hidden" warn
pill flags active filters, and the notes list + list-row previews
respect them. Modals (overlays as LAST children of the window root):
rename, nb-rename, remove-confirm, reset-confirm, sweep-confirm,
consolidate-confirm.

**Notebooks** (design: `../PLAN-chain-notes-notebooks.md`): notebook =
BIP-86 account. `notebooks-<net>-<masterfp8>.json` (app-core
`notebooks.rs`) maps account → {name, archived}; the master fingerprint
key (`identity::index_fp8`) is shared across accounts, so one identity
= one index. Store gains `excluded_senders` + `seen_received` (unread =
received notes not yet seen; `mark_seen` fires when LEAVING home for
the list, so the badge only counts what arrived since). Create is ONE
SCREEN (Sal 2026-07-11): "+ New notebook" opens the account picker
(screen 9, `account-pick-mode == "notebook"`) with an INLINE name field
on top (`nb-create-name`; no second dialog — the rename dialog is
rename-only, `nb-rename-account >= 0`); rows carry a pill — grey
"notebook" (already in the index, row DISABLED + dimmed), amber "used"
(on-chain history, balance shown — `ChainClient::address_probe`, two
cheap requests; offline → plain rows) or green "new" — so recovering a
used address is a visible choice that adopts its notes. Tapping an
enabled address creates immediately with the typed name; NOTHING is
derived or persisted before that tap, so backing out leaves no phantom
row. Notebook creation is
DELIBERATE everywhere: activate() only auto-adds for pre-notebooks
migration (no index file + existing store → "Main") and non-hierarchical
identities (single intrinsic notebook); explicit `ensure_notebook` runs
at the import account pick, the create dialog, and APP_KEY automation
boots. Onboarding a NEW seed lands on the EMPTY list (`go_home_or_list`
sends "home" to the list while the active account is unlisted). ONE
archive guard: a notebook holding sats refuses (sweep first). ZERO
active notebooks is legitimate — archive-all allowed, empty-state
captions, boot never resurrects archived entries. reset-identity
deletes notebooks-*.json alongside stores.

**Sweep destinations** (Sal 2026-07-11): the sweep picker (screen 7,
`pick-mode == "sweep"`) offers, top to bottom: the address input
(other address), a "My notebooks" section (`sweep-notebooks` — every
ACTIVE notebook except the current one, name + addr short + balance)
and "+ New notebook…" (`sweep-new-notebook` → the create picker with
`State.create_for_sweep`, which adds the notebook WITHOUT switching the
active account — the sweep spends the CURRENT notebook's coins — and
routes straight back to screen 16 with the new address as dest), then
the recents. All destinations funnel through `set_sweep_dest`: notebook
dests get an "Everything to: <name> · <short>" label, the amber
on-chain-linkage caveat (`sweep-dest-note`), and NO contacts pollution;
external dests keep the contact-name label + recents behavior.

**Consolidate is WALLET-level** (Sal 2026-07-11, superseding the
per-notebook framing): Settings → "Consolidate wallet…"
(`consolidate-wallet-open`) snapshots every ACTIVE notebook's spendable
coins (`State.wconsol`; needs 2+ coins total), opens the account picker
in `"wconsol"` mode — title "Consolidate to", ALL rows enabled, inline
name field; picking a non-notebook address CREATES it, an archived one
UN-archives (the coin must never land hidden) — then a confirm modal
(`show-wconsol-confirm`: coins/notebooks/dest/fee summary + the
all-addresses-link warning) and ONE multi-key tx via notes-core's
additive `build_sweep_tx_multi` (each input signed by its own account's
key; pin bumped to rev 0440ac5). Bookkeeping spans stores: sources'
inputs lock pending, the destination store (created if needed) gets the
TxRecord + the unconfirmed coin, the active store reloads via
activate(), and the flow lands on the notebook LIST (the wallet-level
home). Watch-only routes to the old self-consolidate external-sign flow
(`open_notebook_consolidate` — one notebook is all watch has). The
Coins screen (10) is a pure per-notebook viewer now; Settings keeps
per-notebook "View this notebook's coins…" and "Sweep this notebook's
funds…" rows, and the "Change account…" row is GONE (the notebook list
IS the account switcher). Wallet-consolidate RBF caveat: the TxRecord's
Speed-up would re-sign with only the dest key and fail broadcast
harmlessly; Rebroadcast works.

**Identity lifecycle:** key material verbatim in the keychain; BIP-86
account chosen on a paginated picker after hierarchical imports; later
switching = the notebook list (each account = its own address AND enc
key; the old settings Change-account row is gone). Store files are per-identity:
`store-<network>-<fp8>.json` — switching keys/accounts never mixes
notebooks. `config.json` is device-level and persists {network, account,
nodes{net→url}, explorers{net→url}} — the Bitcoin-node / block-explorer
choices live here (per network, not per identity) so they survive
identity switches; base_url()/explorer_base() read them, the Settings
dropdowns write them via save_config(). A legacy per-identity node URL
(old `esplora`/`node_url` store field) is migrated into config on load.
Reset ("Switch identity") deletes the keychain item and returns to
onboarding; notes recover from chain on re-import.

M5 platform facts: **slint is pinned `=1.17.1`** (bumped from 1.16.1 on
2026-07-10 for the text-input work — 1.17.1 fixed Mac TextEdit
double/triple-click selection and iOS TextEdit tap-focus/caret/keyboard;
see ../PLAN-chain-notes-app-text-input.md for the per-platform behavior
matrix). 1.17 needs rustc 1.92, so host builds moved off the SDK nix
shell (1.91-nightly) onto the standalone rustup.

**Text-input layer (2026-07-10):** all fields are the app's own
`EditField`/`EditArea` components (ui/app.slint) wrapping a raw
`TextInput` — NOT std LineEdit/TextEdit — so the app can use the
byte-offset cursor API. They provide: desktop right-click Cut/Copy/Paste/
Select-All menu; on iOS/Android a floating **edit bubble** (Select all/
Copy/Paste/Cut, actions through `EditOps`, Rust-backed in lib.rs) with
NATIVE-iOS trigger rules — never on plain focus, tap ON the resting
caret toggles it, double-tap selects the word, triple-tap selects all,
typing hides it (350 ms tap window, text-equality guard makes fast
typing/tap-then-type safe), Copy/Paste/Cut dismiss it, content-fit pill
centered above the caret line, clamped to the FIELD's left edge and the
screen's right, flipping below the line when out of room (Sal-approved
2026-07-10 — keep these semantics); paste-at-cursor (compose header
Paste calls `note-edit.paste-clip()`); and a fluent-style ✕ clear button
(`icons/dismiss.svg` — SVG, not a glyph). Still missing vs native:
draggable selection dot-handles (needs a pixel→byte-offset API upstream
slint doesn't expose; drag-across-text selection works). Clipboard routing: native TextInput cut/copy/paste everywhere
EXCEPT iOS (winit's iOS clipboard is a no-op) where `EditOps.clip-*` uses
the UIPasteboard shim + splicing; natives also keep undo coherent —
programmatic `text =` splices corrupt the undo stack, which is why the
iOS-only gate exists. iOS paste triggers the standard system paste
prompt (allow once, or Settings → app → Paste from Other Apps).
Upstream findings + retractions live in UPSTREAM-ISSUES.md (policy: file
nothing upstream until we carry a proper fix). Camera spike: `cargo run -- --spike camera [secs]`
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

**Mobile parity (platform shims + gating).** `src/platform.rs` is the one
place platform behavior forks: file dialogs (rfd) are macOS-only and every
file-only button ("From file…", "Load from file…", "Save .psbt",
"Load .psbt file") is hidden behind the `desktop-platform` slint property
(set from `cfg!(target_os = "macos")`; captions adapt too) — QR + clipboard
carry those flows on mobile. `set_clipboard_text` (pbcopy / UIPasteboard /
JNI ClipboardManager) and `open_url` (`open` / UIApplication
openURL:options: / JNI ACTION_VIEW intent) are implemented on ALL three
platforms — never call `pbcopy`/`open` directly. Glyph rule reminder: ↻ and
⚙ are emulator-proven on Android; ✓ → ⟳ ⚠ tofu — keep glyphs out of caption
text and use the SVG icons.

**Android system back** (button AND gesture — both arrive as slint
`Key.Back`; unhandled key events finish the NativeActivity, which used to
quit the app from any screen): `back-scope`, a FocusScope wrapping every
window child in app.slint, feeds `root.nav-back()` — the single source of
truth the header chevrons call too. Order: topmost modal closes first,
then the current screen navigates exactly like its chevron; screens 0/4
return false → the key is rejected → Android's default runs (activity
finishes cleanly to the launcher, process stays cached — relaunch into
that cached process re-runs `android_main` and is verified working).
Logs `cb: sys-back handled=<b> screen=<n>` (screen = AFTER navigating).
Two invariants keep it alive: (1) key events are only delivered while
SOMETHING has focus, so back-scope takes focus at init, on `changed
screen`, and when the two self-focusing rename dialogs close — NEVER call
`clear-focus()` anywhere, focus `back-scope` instead (the compose "Done"
button does this); (2) the Up half of the key pair must replay the Down's
accept/reject verdict (`back-eaten`) or Android's tracked-back detection
misfires. With the keyboard up, the IME consumes the first Back itself
(that's why the e2e's `keyevent 4` keyboard-dismiss still works).

**iOS launch-path rule (watchdog).** NOTHING network-bound may run before
the first frame: the boot-identity sync runs from a 300 ms single-shot
timer after the scene attaches (`8927e6c`). Blocking launch on HTTP got
the app killed by the iOS launch watchdog on a home-screen tap (black
screen → `0x8badf00d`) — and devicectl/Xcode launches RELAX the watchdog,
so the bug is invisible from tooling; always confirm a device build by
tapping the icon. Verified working on Satoshi's iPhone.

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
  the gift. notes-core rev `5c6d23a` ships this on prime main — the
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

ALL builds (host + mobile) use the **standalone rustup** stable
(`~/.cargo/bin`, 1.96.1) — switched from the SDK Nix shell 2026-07-10 when
slint was bumped to 1.17.1 (needs rustc 1.92; the Nix shell's fixed
nightly is 1.91). ssh-agent + `.cargo/config.toml`'s git-CLI fetch cover
the ssh:// notes-core dep as before:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test -p app-core
bash scripts/regtest-e2e.sh   # app↔Prime interop matrix vs real bitcoind
cargo run
```

(The Foundation SDK Nix shell still works as a host toolchain for
anything that fits its rustc; it just can't build slint ≥1.17.)

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
`cb: refresh-coins` · `cb: act-explorer` · `cb: bump-open`/`act-bump` ·
`cb: sys-back handled=<b> screen=<n>` (Android system back; screen is
where back landed us) ·
`cb: notebooks list n=<n> archived=<n>` · `cb: open-notebook
account=<n>` · `cb: create-notebook picker open[ (sweep dest)]` ·
`cb: create-notebook account=<n>` · `cb: rename-notebook account=<n>` ·
`cb: archive-notebook account=<n> archived=<b>` · `cb: toggle-sender
excluded=<b> hidden=<n>` · `cb: sweep-pick to=<a>[ (notebook <n>)]` ·
`cb: wallet-consolidate open coins=<n> notebooks=<m>` ·
`cb: wallet-consolidate txid=<t> coins=<n> notebooks=<m> value=<v>
fee=<f>`.
UI e2e:
`../ui-automation/tests/chain-notes-app.sh` (simtap point offsets from
the window origin — recalibrate from screenshots when app.slint moves
controls; simtap also has `scroll <x> <y> <dy>`). Both simtap suites are
notebooks-aware (2026-07-11): `chain-notes-app.sh` taps the Main row
after boot (boot lands on the LIST, screen 17) and ends with a
create→name→open→archive notebooks leg; the matrix suite needed no tap
changes (its sessions start from onboarding, and import/quiz flows land
directly on home) plus a notebooks-*.json wipe assert in reset.

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
