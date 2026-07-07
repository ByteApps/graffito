# Signing & Notarizing chain-notes-app for Distribution

Goal: make `Chain Notes.app` open cleanly on **other** Macs (no "damaged / Apple
cannot check it for malware" Gatekeeper block).

## Current state

`scripts/bundle-mac.sh` builds `target/Chain Notes.app` and **ad-hoc signs** it:

```bash
codesign --force --deep --sign - "$APP" 2>/dev/null || true
```

Ad-hoc (`--sign -`) runs fine on the build machine but is quarantined and blocked
on any other Mac. To distribute we need **Developer ID signing + notarization +
stapling**.

Bundle facts (already correct, no change needed):
- Bundle id: `com.objsal.chain-notes-app`
- `Info.plist` already has `NSCameraUsageDescription` and `NSHighResolutionCapable`
- Keychain service `com.objsal.chain-notes-app`, ACL `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  + `kSecAccessControlUserPresence` (Touch ID). App is **not** App-Sandboxed.

## One-time setup

1. **Apple Developer Program — $99/year.** Hard requirement. No free path to
   notarization exists. (Unsigned fallback for tech friends is at the bottom.)

2. **Developer ID Application certificate.** Create via Xcode (Settings → Accounts
   → Manage Certificates → +) or developer.apple.com. Verify:
   ```bash
   security find-identity -v -p codesigning
   # want: "Developer ID Application: Your Name (TEAMID)"
   ```

3. **notarytool credential profile** (app-specific password from appleid.apple.com):
   ```bash
   xcrun notarytool store-credentials "chain-notes-notary" \
     --apple-id "you@appleid.com" \
     --team-id "YOURTEAMID" \
     --password "abcd-efgh-ijkl-mnop"   # app-specific password, not your Apple ID pw
   ```

## Per-build flow

```bash
IDENTITY="Developer ID Application: Your Name (TEAMID)"
APP="target/Chain Notes.app"

# 1. build + bundle (existing bundle-mac.sh)

# 2. sign with Developer ID + HARDENED RUNTIME (required for notarization)
codesign --force --deep --options runtime --timestamp \
  --sign "$IDENTITY" \
  --entitlements chain-notes-app.entitlements \   # optional; see note below
  "$APP"

# 3. zip for submission (ticket can't be stapled into a zip — this zip is only for the notary)
ditto -c -k --keepParent "$APP" "target/ChainNotes.zip"

# 4. notarize (blocks ~1-2 min)
xcrun notarytool submit "target/ChainNotes.zip" \
  --keychain-profile "chain-notes-notary" --wait

# 5. staple ticket onto the .app (so it verifies offline)
xcrun stapler staple "$APP"

# 6. package the STAPLED app for distribution (re-zip, or build a .dmg)
ditto -c -k --keepParent "$APP" "target/ChainNotes-dist.zip"
```

Verify before shipping:
```bash
codesign --verify --deep --strict --verbose=2 "$APP"
spctl -a -vvv --type execute "$APP"        # should say: accepted, source=Notarized Developer ID
xcrun stapler validate "$APP"
```

If distributing a `.dmg` instead of a zip: notarize **and** staple the `.dmg`
itself (same submit + `stapler staple ChainNotes.dmg`).

## Entitlements — keep minimal

App is **not** sandboxed (Developer ID distribution), so most capability keys are
sandbox-only and unnecessary. Common mistakes to avoid:

- **Hardened runtime is NOT an entitlement** — it's the `--options runtime`
  codesign flag. Do not put a `hardened-runtime` key in the plist.
- **Camera** works via the existing `NSCameraUsageDescription` (TCC prompt). Do
  NOT add `com.apple.security.device.camera` (that's sandbox-only).
- **Keychain / Touch ID**: an app reading its *own* keychain items needs no
  entitlement. `keychain-access-groups` is only for sharing between apps.

=> Realistically **no entitlements file is needed at all**. Start without one; add
a minimal plist only if a notarization/runtime issue demands it (e.g.
`com.apple.security.cs.disable-library-validation` if a dylib fails validation).

Side benefit: once properly Developer-ID-signed with hardened runtime, the keychain
ACL (`kSecAccessControlUserPresence`) works for real and the
`errSecMissingEntitlement -34018` dev fallback in `src/keychain.rs` stops firing.

## Implementation plan for the repo

- Add `scripts/sign-notarize-mac.sh` (or extend `bundle-mac.sh`):
  - Read `SIGN_IDENTITY` env var. If **unset**, keep current ad-hoc path (dev default).
  - If set, run steps 2–6 above; profile name via `NOTARY_PROFILE` (default
    `chain-notes-notary`).
  - Optional `MAKE_DMG=1` to produce a `.dmg` (notarize + staple the dmg).
- No `Info.plist` changes required.
- Only add `chain-notes-app.entitlements` if a build actually needs it.

## Free (no-$99) fallback

Distribute the ad-hoc-signed app; each recipient clears quarantine manually:
```bash
xattr -dr com.apple.quarantine "/path/Chain Notes.app"
```
or System Settings → Privacy & Security → "Open Anyway" after the first blocked
launch. **macOS 15 (Sequoia)**: the old right-click → Open bypass no longer works —
Settings pane only. Fine for a few technical friends; poor UX for anyone else, and
weak trust signal for a Bitcoin key-holding app. Notarize for real distribution.
