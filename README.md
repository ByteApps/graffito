# chain-notes-app

Native Mac app (iOS/Android planned — phase 4) for **chain notes**:
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
- **Compose**: public or private notes, directed notes to other taproot
  addresses, live cost/change preview, fee-tier picker, coin control
  (pick exactly which UTXOs to spend, incl. unconfirmed), and an
  optional custom change address.
- **Manage**: an Activity screen listing every transaction with retry
  (rebroadcast) and RBF fee-bump for stuck ones; a Coins screen to view
  and consolidate UTXOs; sweep-all; per-coin/-note links to the tx on
  mempool.space and to notes in the web viewer.
- **Networks**: mainnet · testnet4 · signet · regtest (custom esplora
  endpoint supported). Verified live on testnet4 — including a directed
  private note decrypted by the Passport Prime app's own core — and
  hermetically against bitcoind -regtest. Mainnet deliberately untested
  (user decision; testnet4 + regtest are the acceptance bar).
- **UI**: Slint (Rust end-to-end), dark card-based design, driven by a
  scripted CGEvents e2e (`../ui-automation/tests/chain-notes-app.sh`).

Build/test (nix shell as host toolchain — see CLAUDE.md):

```bash
nix develop ~/.foundation/sdk/current --command cargo test -p app-core
nix develop ~/.foundation/sdk/current --command bash scripts/regtest-e2e.sh
nix develop ~/.foundation/sdk/current --command cargo run
```

Design + milestones: `PLAN-chain-notes-app.md` in the parent workspace.
