# chain-notes-app

Native Mac + mobile app for **chain notes** (the iOS/Android port is
merged and runs on real hardware — iPhone-verified; Android green on the
emulator; see `../PLAN-chain-notes-app-phase4.md` in the prime workspace):
personal notes on the bitcoin blockchain (PNTE protocol, shared with
[prime-chain-notes](https://github.com/ObjSal/prime-chain-notes)).
Compose public or encrypted notes, send directed private notes to other
taproot addresses, broadcast directly, and rebuild the whole notebook
from the chain plus your key alone.

- **Keys**: create a 12/24-word seed in-app (backup + quiz flow), or
  import BIP-39 / xprv / WIF / hex — typed (with word autocomplete),
  QR (incl. SeedQR via the Mac camera), or file. Hierarchical keys get
  a paginated BIP-86 account picker; accounts are switchable later in
  Settings. Key material lives in the macOS Keychain; reveal and unlock
  ask for Touch ID.
- **Watch-only**: import an account xpub, a key-origin xpub
  (`[fp/86'/…]xpub…`), or a `tr()` descriptor instead — same address as
  the full key, public notes and balance visible, private bodies sealed.
  Everything that needs a signature still works: sweep, consolidate,
  RBF speed-up, and PUBLIC-note compose build PSBTs signed on your
  hardware wallet (verified with a real signer), with an optional separate
  fee wallet ("Pay from another wallet").
- **Compose**: public or private notes, directed notes to other taproot
  addresses, live cost/change preview, fee-tier picker, coin control
  (pick exactly which UTXOs to spend, incl. unconfirmed), an optional
  custom change address, and a **gift amount** for directed notes
  (choose how many sats reach the recipient; default/minimum is dust).
- **Manage**: an Activity screen listing every transaction with retry
  (rebroadcast) and RBF fee-bump for stuck ones; a viewer-first Coins
  screen whose Consolidate button opens the same compose-like flow as
  Sweep (fee tiers, live cost line, read-only inputs, optional fee
  wallet); sweep-all picks its destination like a contact; per-coin/
  -note links to the tx in your chosen block explorer and to notes in
  the web viewer.
- **Settings**: a **Bitcoin node** dropdown (mempool.space / Blockstream
  / your own Esplora-compatible node) selects the API used for scans and
  broadcasts; a separate **Block explorer** dropdown (mempool.space /
  Blockstream / a self-hosted mempool) selects where "Explorer" links
  open. Both offer a Custom URL, are set entirely through the UI, and are
  remembered per network at the device level — so switching identity (or
  account) keeps them.
- **Networks**: mainnet · testnet4 · signet · regtest (point the Bitcoin
  node at any Esplora/mempool-compatible endpoint). Verified live on
  testnet4 — including a directed private note decrypted by the Passport
  Prime app's own core — and hermetically against bitcoind -regtest.
  Mainnet deliberately untested (user decision; testnet4 + regtest are
  the acceptance bar).
- **UI**: Slint (Rust end-to-end), dark card-based design, driven by a
  scripted CGEvents e2e (`../ui-automation/tests/chain-notes-app.sh`).

Build/test (nix shell as host toolchain — see CLAUDE.md):

```bash
nix develop ~/.foundation/sdk/current --command cargo test -p app-core
nix develop ~/.foundation/sdk/current --command bash scripts/regtest-e2e.sh
nix develop ~/.foundation/sdk/current --command cargo run
```

Design + milestones: `PLAN-chain-notes-app.md` in the parent workspace.
