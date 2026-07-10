# Upstream Slint issues found here (NOT yet filed)

Findings from the text-input work (see `../PLAN-chain-notes-app-text-input.md`
for the full behavior matrix). Per project policy these are NOT filed
upstream until we have a proper fix to attach — each entry below is kept in
ready-to-file shape (title / versions / repro / expected vs actual) so filing
later is copy-paste.

Status legend: **OPEN** = reproduced, no fix; **WORKAROUND** = we ship an
app-side workaround (noted); **FIXED-UPSTREAM** = went away on a bump.

---

## 1. Android: text-selection toolbar (Cut/Copy/Paste/Select all) only ever appears once per app run — OPEN

**Would-be title:** `Android: selection context toolbar is one-shot — never
re-summoned after its first appearance`

- **Slint:** reproduced on 1.16.1 and 1.17.1, `backend-android-activity-06`,
  `renderer-skia`, NativeActivity (`Theme.DeviceDefault.NoActionBar`).
- **Device:** Pixel 6 emulator, API 34 (arm64), release APK.

**Repro**
1. Focus a `TextEdit` (std-widgets, fluent style), type `alpha bravo charlie`.
2. Long-press a word → selection + two selection handles + the floating
   Cut/Copy/Paste/Select-all toolbar appear. Everything in the toolbar works
   (Copy reaches the system clipboard; Paste replaces the selection from the
   system clipboard — verified with the "app pasted from your clipboard" OS
   toast).
3. Dismiss it (tap a toolbar action, or tap elsewhere).
4. Long-press again — **selection may appear, but the toolbar never does
   again** for the lifetime of the process. Tapping a selection handle or
   the selection itself doesn't summon it either (stock Android shows the
   toolbar for all of those). At 1.17.1 a second long-press sometimes fails
   to even select — it just moves the cursor + cursor-handle.

**Expected:** every long-press on text (and taps on handles/selection)
re-shows the toolbar, like a native `EditText`.

**Impact:** after the first use, copy/paste inside a field is impossible on
Android without app-side buttons.

**Suspected area:** the Java-side `PopupWindow`/InputHandle glue in
`i-slint-backend-android-activity` — looks like a shown-once flag or a
listener that isn't re-armed after the popup closes.

**Evidence:** screenshots `a2/a10/a13` (1.16.1) and `a17-lp1/a17-lp2`
(1.17.1) in the 2026-07-10 session; PLAN matrix rows.

---

## 2. RETRACTED — "iOS: LineEdit never takes tap focus" was our own test-harness miscalibration

**What we believed (baseline + first re-run):** std `LineEdit` (and later our
custom single-line field) never took tap focus on the iOS simulator, while
`TextEdit` did.

**What was actually wrong (found 2026-07-10):** the simtap window→device
coordinate mapping inherited from PLAN-chain-notes-app-phase4.md
(`x0≈663, y0≈100, scale 932/874`) was ~20-30 pt off vertically for this
Simulator window. Every tap landed 20-30 pt ABOVE the intended point:
large targets (buttons, cards, the 150 px note editor) still hit, the
32 px text fields never did. Recalibrating empirically (dual capture:
`simctl io screenshot` + `screencapture` of the window, matching an
orange UI fiducial) gave `screen = (677.6, 141.5) + 0.994 × device-pt` —
essentially 1:1 points — and with corrected taps a **single-line raw
TextInput focuses fine on iOS 1.17.1**, std-LineEdit-style fields
included. No upstream issue exists; nothing to file.

**Still true:** upstream iOS has no long-press edit menu / selection
handles / magnifier (tracking issue slint#47) — that gap is real and is
covered by the app's own touch toolbar + double-tap selection layer.

---

## 3. RESOLVED (iOS system UX, not a bug) — UIPasteboard reads hit the iOS paste-permission prompt

The app's Paste paths (in-app Paste buttons and the touch toolbar's Paste)
read `UIPasteboard.generalPasteboard.string` via src/platform.rs. On iOS
16+ every read of pasteboard content that came from ANOTHER app triggers
the system "would like to paste from …" prompt (per change of pasteboard
ownership) until the user picks Allow — or flips the per-app Settings
option "Paste from Other Apps" to Allow. On the simulator with
`simctl pbcopy` feeding the pasteboard, EVERY new pbcopy re-prompts,
which is what made Paste look like a silent no-op in earlier runs (the
prompt is also easy to miss/auto-dismiss under automation).

Verified working end-to-end 2026-07-10: toolbar **Copy → UIPasteboard**
round-trips (`simctl pbpaste` shows the field text; `cb: edit-clip-set
bytes=… ok=true` logged), and the Paste path correctly raises the system
prompt. On the real iPhone this is the standard one-time prompt every
iOS app gets. Nothing to file; no code change needed.

## Fixed by upgrading (for the record, nothing to file)

- **macOS: TextEdit double/triple-click selection dead at 1.16.1** (femtovg,
  fluent style; LineEdit was fine) — fixed by Slint 1.17.1.
- **iOS: no caret + no auto keyboard on TextEdit focus at 1.16.1** — fixed by
  Slint 1.17.1 ("focus input fields on tap release").
