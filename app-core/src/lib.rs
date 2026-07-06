//! app-core — UI-free core for chain-notes-app.
//!
//! Wraps notes-core (the frozen PNTE protocol, pinned by rev) with what a
//! native online app adds: identity create/import (BIP-39 / xprv / WIF /
//! hex → one taproot notes address), the frozen leaf-secret HKDF
//! note-encryption rule, an esplora chain client that assembles in-memory
//! SyncBundles, the local store, and compose orchestration.
//!
//! Milestones and design: ../../PLAN-chain-notes-app.md (prime workspace).

pub use notes_core;
