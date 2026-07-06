# chain-notes-app

Native Mac (later iOS/Android) peer for **chain notes** — personal notes
on the bitcoin blockchain (PNTE protocol, shared with
[prime-chain-notes](https://github.com/ObjSal/prime-chain-notes)).
Compose public or encrypted notes, send directed notes to other taproot
addresses, broadcast directly, and rebuild the whole notebook from the
chain plus your key alone.

Keys: create a 12/24-word seed in-app, or import BIP-39 / xprv / WIF /
hex — by typing, QR (incl. SeedQR), or file. Recommended for Passport
Prime owners: import a dedicated BIP-85 child from `prime-bip85`.

Status: M0 (bootstrap). Plan: `PLAN-chain-notes-app.md` in the parent
workspace. UI: Slint (Rust end-to-end).
