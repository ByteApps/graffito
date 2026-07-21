# <img src="assets/icon/icon.svg" alt="" width="42" align="top" /> Chain Notes

**Bitcoin · Notes · Mac / iOS / Android** — your notebooks on the bitcoin blockchain, in a native app that goes where you go.

Chain Notes writes personal notes into real bitcoin transactions — public ones anyone can read, private ones only your key can open, and directed notes delivered to any taproot address like unstoppable mail. This is the online, full-featured peer of the [Passport Prime app](https://github.com/ObjSal/prime-chain-notes): the same protocol, byte-identical transactions, but with its own keys, direct broadcasting, and a native interface on Mac, iPhone, and Android. Keep as many **notebooks** as you like — each its own address from the same seed, with its own notes, balance, and name. Lose the device, keep the key — every notebook rebuilds itself from the chain.

<p align="center">
  <img src="screenshots/home.png" alt="Notebooks — your list of them, each an address with its own notes and balance" width="290">
  &nbsp;
  <img src="screenshots/compose.png" alt="Compose — live cost preview, fee tiers, coin control" width="290">
  &nbsp;
  <img src="screenshots/activity.png" alt="Activity — every notebook's transactions in one wallet-wide feed" width="290">
</p>

## Features

- **Notebooks** — one seed, many notebooks: the main screen is your list of them, each its own address (with its own encryption key) inside one account, with its own notes, name, and balance. Create one and pick a fresh or already-used address, archive it when it's done, and filter a notebook's notes by who sent them. Power users can keep whole separate wallets too — switch BIP-86 accounts from Settings.
- **Your key, your way** — create a 12/18/24-word seed in-app with a backup-and-quiz flow, or import what you have: BIP-39 words (12/18/24, with autocomplete), xprv, WIF, or raw hex — typed, scanned from QR (SeedQR included), or loaded from file. Hierarchical keys open as notebooks you switch between anytime.
- **Keys live in the platform vault** — the macOS Keychain behind Touch ID, iOS Keychain, Android Keystore. Reveal always re-authenticates.
- **Back up and export on your terms** — when you need to move or back up an identity, Settings reveals it in every importable format: recovery words, account xpub/xprv, a `tr()` descriptor, or a single notebook's hex/WIF — split into **public** (watch-only, safe to share) and **private** (keep secret), each with one-tap copy and a reminder to reveal away from cameras.
- **Watch-only mode** — import just an xpub or descriptor for a key-less notebook: balance and public notes visible, private bodies sealed. Everything that needs a signature — sweep, consolidate, fee bumps, even public-note compose — builds a PSBT your hardware wallet signs (verified against a real signer implementation), with an optional separate fee wallet.
- **Serious compose tools** — live cost and change preview, fee tiers plus custom rates, full **coin control** with per-coin explorer links, a custom change address, and a **gift amount** to send chosen sats along with a directed note.
- **A synced address book** — save the people you write to as named contacts, tagged by network. Choose which ones sync privately over iCloud between your iPhone and Mac — a cloud badge shows each one's status, renames and deletes carry across, and they restore on reinstall. Nothing ever leaves your own iCloud.
- **Stay on top of your transactions** — a wallet-wide Activity feed across every notebook with rebroadcast and RBF speed-up for stuck transactions, a wallet-wide Coins screen, one-tap consolidate that gathers the whole wallet into a single coin, and a guided sweep that empties every notebook to an address you pick.
- **Your infrastructure or theirs** — pick your Bitcoin node (mempool.space, Blockstream, or your own Esplora-compatible endpoint) and your block explorer, per network, right in Settings.
- **Every network** — mainnet, testnet4, signet, and regtest. Verified live on testnet4, including a directed private note decrypted by the Passport Prime app's own core.

## Compatible by construction

The app reuses the Prime app's `notes-core` as a pinned dependency — envelope, encryption, and transaction signing are the same code, so notes from either app are interchangeable on-chain. The [web viewer](https://objsal.github.io/chain-notes-companion/) renders both.

## Get it running

```bash
cargo run
```

See **[DEVELOPMENT.md](DEVELOPMENT.md)** for toolchain setup, mobile builds, and the test suites.

## Learn more

- [DEVELOPMENT.md](DEVELOPMENT.md) — building (desktop + mobile), testing, architecture pointers
- [THIRD-PARTY.md](THIRD-PARTY.md) — libraries this app is built on
- `PLAN-chain-notes-app.md` (workspace repo) — design document and milestones

## Support

If this app is useful to you, a small bitcoin donation is always appreciated — entirely optional.

<div align="center">

<img src="donate-qr.png" alt="Donate bitcoin" width="200">

**`bc1qrfagrsfrm8erdsmrku3fgq5yc573zyp2q3uje8`**

</div>

Donations help cover development costs and keep more open-source bitcoin tools coming. No VC funding, no ads, no tracking.

## License & disclaimer

Licensed under the [Apache License 2.0](LICENSE-APACHE). It disclaims all warranty and liability; the notes below restate that in plain language.

This is experimental software and it has **not been independently audited**.
It is provided **"as is", without warranty of any kind**, express or implied,
including but not limited to the warranties of merchantability, fitness for a
particular purpose, and non-infringement.

**Use it at your own risk.** To the maximum extent permitted by law, in no
event shall the authors, copyright holders, or contributors be liable for any
claim, damages, or other liability — including, without limitation,
**loss of bitcoin or other funds, loss of keys or seeds, or loss of data** — whether in an action of contract, tort, or
otherwise, arising from, out of, or in connection with this software or its
use.

Nothing in this project is financial, investment, legal, or tax advice. You
are solely responsible for verifying addresses, amounts, fees, and backups
before moving funds, and for complying with the laws of your jurisdiction.
Test on test networks, or with amounts you can afford to lose, first.

Everything this app writes to the blockchain is **public and permanent** — including the transaction metadata around encrypted notes (addresses, timing, amounts). Notes cannot be edited or deleted once broadcast. Do not put anything on-chain you may later need gone.
