#!/usr/bin/env bash
# Attach a TestFlight build (both platforms) to the Public Beta group and
# submit it for Beta App Review, once App Store Connect finishes processing.
#
# Generalizes this session's one-off build-75 script
# (/var/folders/…/T/tf75-attach.sh) into a reusable command: give it a
# version number and a whatsNew text file, and it polls ASC until each
# platform's (IOS, MAC_OS) build of that version reaches
# processingState=VALID, PATCHes whatsNew onto its betaBuildLocalization,
# POSTs it onto the Public Beta group, and POSTs a betaAppReviewSubmission —
# then prints each platform's resulting betaReviewState.
#
# Idempotent: a platform already in the Public Beta group, or already under
# review, is SKIPPED rather than re-POSTed (ASC 409s on a duplicate group
# attach and refuses a second review submission for the same build) — each
# is checked by querying the build's relationships first.
#
# No secrets live here: auth is the App Store Connect API key held by
# asc.py/asc_patch.py/asc_post.py under this repo's private appstore/
# symlink (../private/graffito/appstore/asc-tools — same dir
# ios-archive-upload.sh's TEAM_ID/ASC_KEY_* config lives under, one level up).
#
# Usage (from the repo root):
#   scripts/testflight-attach.sh <build-version> <whatsNew-file>
# e.g.
#   scripts/testflight-attach.sh 76 fastlane/metadata/android/en-US/changelogs/20.txt
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$REPO/appstore/asc-tools"   # -> ../private/graffito/appstore/asc-tools

[ -d "$TOOLS" ] || { echo "!! $TOOLS missing — is private/graffito checked out (see ../private/graffito/appstore)?" >&2; exit 1; }

VERSION="${1:-}"
NOTES_FILE="${2:-}"
if [ -z "$VERSION" ] || [ -z "$NOTES_FILE" ]; then
    echo "usage: $0 <build-version> <whatsNew-file>" >&2
    exit 2
fi
[ -s "$NOTES_FILE" ] || { echo "!! whatsNew file missing or empty: $NOTES_FILE" >&2; exit 1; }
NOTES_FILE="$(cd "$(dirname "$NOTES_FILE")" && pwd)/$(basename "$NOTES_FILE")"

APP=6802850392
GROUP=f6af1aa2-c91d-47f4-82f0-cffcf125cf01   # Public Beta group

cd "$TOOLS" || exit 1
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

NOTES="$(python3 -c "import json,sys;print(json.dumps(open(sys.argv[1],encoding='utf-8').read().strip()))" "$NOTES_FILE")"

# Prints one line per build of this app+version:
#   PLATFORM  BUILD_ID  PROCESSING_STATE  LOC_ID|-  GROUP_NAMES|-  REVIEW_STATE|-
query() {
    python3 asc.py "/v1/builds?filter[app]=$APP&filter[version]=$VERSION&include=preReleaseVersion,betaBuildLocalizations,betaAppReviewSubmission,betaGroups&fields[builds]=processingState,preReleaseVersion,betaBuildLocalizations,betaAppReviewSubmission,betaGroups&fields[preReleaseVersions]=platform&fields[betaBuildLocalizations]=locale&fields[betaAppReviewSubmissions]=betaReviewState&fields[betaGroups]=name" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
inc = {(i["type"], i["id"]): i for i in d.get("included", [])}
for b in d["data"]:
    r = b.get("relationships", {})
    pr = (r.get("preReleaseVersion") or {}).get("data")
    plat = inc[("preReleaseVersions", pr["id"])]["attributes"]["platform"] if pr and ("preReleaseVersions", pr["id"]) in inc else "?"
    locs = [l["id"] for l in (r.get("betaBuildLocalizations") or {}).get("data", [])]
    groups = [inc[("betaGroups", g["id"])]["attributes"]["name"]
              for g in (r.get("betaGroups") or {}).get("data", [])
              if ("betaGroups", g["id"]) in inc]
    review = (r.get("betaAppReviewSubmission") or {}).get("data")
    state = inc[("betaAppReviewSubmissions", review["id"])]["attributes"]["betaReviewState"] if review and ("betaAppReviewSubmissions", review["id"]) in inc else "-"
    print(plat, b["id"], b["attributes"]["processingState"], "|".join(locs) or "-", "|".join(groups) or "-", state)
'
}

process() { # plat build_id loc_id groups review_state
    local plat="$1" bid="$2" loc="$3" groups="$4" state="$5"

    printf '{"data":{"type":"betaBuildLocalizations","id":"%s","attributes":{"whatsNew":%s}}}' "$loc" "$NOTES" > "$T/wn-$plat.json"
    python3 asc_patch.py "/v1/betaBuildLocalizations/$loc" "$T/wn-$plat.json" 2>&1 | grep -oE 'OK [0-9]+|error[^}]{0,120}' | head -1 | sed "s/^/$plat whatsNew: /"

    if printf '%s' "$groups" | grep -qi 'public beta'; then
        echo "$plat attach: already in Public Beta group — skipped"
    else
        printf '{"data":[{"type":"builds","id":"%s"}]}' "$bid" > "$T/att-$plat.json"
        python3 asc_post.py "/v1/betaGroups/$GROUP/relationships/builds" "$T/att-$plat.json" 2>&1 | grep -oE 'OK [0-9]+|error[^}]{0,120}' | head -1 | sed "s/^/$plat attach: /"
    fi

    if [ "$state" != "-" ]; then
        echo "$plat review: already submitted (state=$state) — skipped"
    else
        printf '{"data":{"type":"betaAppReviewSubmissions","relationships":{"build":{"data":{"type":"builds","id":"%s"}}}}}' "$bid" > "$T/rev-$plat.json"
        python3 asc_post.py /v1/betaAppReviewSubmissions "$T/rev-$plat.json" 2>&1 | grep -oE 'OK [0-9]+|error[^}]{0,160}' | head -1 | sed "s/^/$plat review: /"
    fi

    sleep 5
    python3 asc.py "/v1/builds/$bid?include=betaAppReviewSubmission&fields[betaAppReviewSubmissions]=betaReviewState" 2>/dev/null \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); print("'"$plat"' state:", [i["attributes"] for i in d.get("included", [])])'
}

done_ios=0
done_mac=0
for _ in $(seq 1 90); do
    while read -r plat bid state loc groups review; do
        [ "$state" = VALID ] || continue
        if [ "$plat" = IOS ] && [ "$done_ios" = 0 ] && [ "$loc" != "-" ]; then
            process IOS "$bid" "$loc" "$groups" "$review"
            done_ios=1
        fi
        if [ "$plat" = MAC_OS ] && [ "$done_mac" = 0 ] && [ "$loc" != "-" ]; then
            process MAC_OS "$bid" "$loc" "$groups" "$review"
            done_mac=1
        fi
    done < <(query)
    [ "$done_ios" = 1 ] && [ "$done_mac" = 1 ] && { echo TFDONE; exit 0; }
    sleep 60
done
echo "TFTIMEOUT ios=$done_ios mac=$done_mac"
exit 1
