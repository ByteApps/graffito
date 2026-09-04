#!/usr/bin/env python3
"""Print every Play track's releases + status for the app, read-only.

    scripts/play-track-status.py [package] [json-key]

Defaults: com.byteapps.graffito, play/play-supply-key.json (the same
service-account key fastlane supply uses). Opens an edit, reads the tracks,
deletes the edit — nothing is changed on Play.

What the API can and cannot say (verified 2026-09-04): a release's `status`
is draft / inProgress / halted / completed, and `halted` means a release
that was HALTED (rollout stopped). A track PAUSE — the console's "This track
is paused / Testers are not receiving this release" — is NOT exposed: the
paused open-testing track's release still reads `completed` here. Google's
REVIEW state ("in review" / rejected) is not exposed either. So this script
answers "which version codes are on which track, and is any rollout
halted"; whether a track is paused or a change is in review is readable
ONLY in the console (Test and release > Testing > Open testing, and
Publishing overview).

Auth: JWT-bearer grant with the service account (PyJWT + cryptography, both
already required by appstore/asc-tools).
"""
import json
import sys
import time
import urllib.parse
import urllib.request

import jwt  # PyJWT

PKG = sys.argv[1] if len(sys.argv) > 1 else "com.byteapps.graffito"
KEY = sys.argv[2] if len(sys.argv) > 2 else "play/play-supply-key.json"
SCOPE = "https://www.googleapis.com/auth/androidpublisher"
API = "https://androidpublisher.googleapis.com/androidpublisher/v3/applications"


def token(sa: dict) -> str:
    now = int(time.time())
    assertion = jwt.encode(
        {"iss": sa["client_email"], "scope": SCOPE, "aud": sa["token_uri"], "iat": now, "exp": now + 600},
        sa["private_key"],
        algorithm="RS256",
    )
    body = urllib.parse.urlencode(
        {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion}
    ).encode()
    with urllib.request.urlopen(urllib.request.Request(sa["token_uri"], data=body)) as r:
        return json.load(r)["access_token"]


def call(tok: str, method: str, path: str):
    req = urllib.request.Request(f"{API}/{PKG}/{path}", method=method, headers={"Authorization": f"Bearer {tok}"})
    if method == "POST":
        req.data = b"{}"
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def main() -> int:
    with open(KEY, encoding="utf-8") as f:
        sa = json.load(f)
    tok = token(sa)
    edit = call(tok, "POST", "edits")["id"]
    try:
        tracks = call(tok, "GET", f"edits/{edit}/tracks").get("tracks", [])
    finally:
        try:
            call(tok, "DELETE", f"edits/{edit}")
        except Exception:  # noqa: BLE001 — read-only; a dangling edit expires by itself
            pass
    label = {"internal": "internal", "alpha": "closed (alpha)", "beta": "OPEN testing", "production": "production"}
    for t in tracks:
        name = t["track"]
        rels = t.get("releases") or []
        if not rels:
            print(f"{label.get(name, name):16} —")
            continue
        for r in rels:
            status = r.get("status", "?")
            note = " (PAUSED track — testers get nothing)" if status == "halted" else ""
            codes = ",".join(r.get("versionCodes") or [])
            print(f"{label.get(name, name):16} {r.get('name', '?'):8} codes [{codes}] {status}{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
