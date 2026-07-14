#!/usr/bin/env bash
# Archive the Mac App Store build and upload it to App Store Connect / TestFlight.
#
# STATUS: stub. Mac TestFlight / App Store distribution requires the app to be
# App-SANDBOXED and signed with an "Apple Distribution" cert + a Mac App Store
# provisioning profile. chain-notes-app currently ships a NON-sandboxed
# Developer-ID/ad-hoc Mac build (scripts/bundle-mac.sh), so this path is not
# wired yet. See the follow-up plan: sandbox entitlements (App Sandbox + camera
# + user-selected files + network client + keychain), a proper .app target for
# the Mac App Store, then archive/export/upload here (mirrors ios-archive-upload.sh).
set -euo pipefail
cat >&2 <<'MSG'
mac-archive-upload.sh is not implemented yet.

Mac App Store / TestFlight needs the app App-Sandboxed and Mac-App-Store-signed.
That is the follow-up phase (see the workspace CLAUDE.md / task list). Until then
the Mac app is distributed via Developer-ID + notarization (SIGNING-NOTARIZATION.md).
MSG
exit 2
