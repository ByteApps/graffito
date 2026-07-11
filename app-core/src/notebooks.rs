//! Notebook index: which BIP-86 accounts of one identity exist as
//! notebooks, their local names, and archive flags. One JSON file per
//! (network, master identity) — `notebooks-<net>-<masterfp8>.json` —
//! sitting NEXT to the per-account store files it points into, so
//! switching identities can never mix indexes.
//!
//! Everything here is local metadata (the store tier of contact names):
//! it survives rescans but is NOT chain-recoverable after an identity
//! reset. Notes themselves recover per address; the index is rebuilt by
//! account-gap discovery plus whatever the user renames again.
//! Design: ../../PLAN-chain-notes-notebooks.md (prime workspace).

use serde::{Deserialize, Serialize};

use crate::Error;

/// One notebook = one BIP-86 account of the identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookMeta {
    pub account: u32,
    /// Local display name; empty = unnamed (rows fall back to the
    /// address short form).
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub archived: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookIndex {
    pub version: u32,
    pub notebooks: Vec<NotebookMeta>,
}

/// The default name the FIRST notebook of an identity gets on migration
/// (an existing single-account identity becomes notebook "Main").
pub const FIRST_NOTEBOOK_NAME: &str = "Main";

impl NotebookIndex {
    pub fn new() -> Self {
        NotebookIndex { version: 1, notebooks: Vec::new() }
    }

    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::Store(e.to_string()))?;
        serde_json::from_str(&text).map_err(|e| Error::Store(e.to_string()))
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), Error> {
        let text = serde_json::to_string_pretty(self).map_err(|e| Error::Store(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| Error::Store(e.to_string()))?;
        std::fs::rename(&tmp, path).map_err(|e| Error::Store(e.to_string()))
    }

    pub fn get(&self, account: u32) -> Option<&NotebookMeta> {
        self.notebooks.iter().find(|n| n.account == account)
    }

    /// Make sure `account` exists in the index; the identity's very first
    /// notebook is named [`FIRST_NOTEBOOK_NAME`] (the migration rule),
    /// later ones start unnamed. Returns true when it was added.
    pub fn ensure(&mut self, account: u32) -> bool {
        if self.get(account).is_some() {
            return false;
        }
        let name = if self.notebooks.is_empty() { FIRST_NOTEBOOK_NAME.to_string() } else { String::new() };
        self.notebooks.push(NotebookMeta { account, name, archived: false });
        self.notebooks.sort_by_key(|n| n.account);
        true
    }

    /// The account a "create notebook" gets: one past the highest known.
    pub fn next_account(&self) -> u32 {
        self.notebooks.iter().map(|n| n.account + 1).max().unwrap_or(0)
    }

    pub fn rename(&mut self, account: u32, name: &str) {
        if let Some(n) = self.notebooks.iter_mut().find(|n| n.account == account) {
            n.name = name.trim().to_string();
        }
    }

    pub fn set_archived(&mut self, account: u32, archived: bool) {
        if let Some(n) = self.notebooks.iter_mut().find(|n| n.account == account) {
            n.archived = archived;
        }
    }

    pub fn active(&self) -> impl Iterator<Item = &NotebookMeta> {
        self.notebooks.iter().filter(|n| !n.archived)
    }

    pub fn archived_count(&self) -> usize {
        self.notebooks.iter().filter(|n| n.archived).count()
    }
}

impl Default for NotebookIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_names_first_main_and_sorts() {
        let mut ix = NotebookIndex::new();
        assert!(ix.ensure(3));
        assert!(ix.ensure(0));
        assert!(!ix.ensure(3)); // idempotent
        assert_eq!(ix.notebooks.len(), 2);
        // First-added (account 3) got the migration name, later ones none.
        assert_eq!(ix.get(3).unwrap().name, FIRST_NOTEBOOK_NAME);
        assert_eq!(ix.get(0).unwrap().name, "");
        // Sorted by account regardless of insertion order.
        assert_eq!(ix.notebooks[0].account, 0);
        assert_eq!(ix.next_account(), 4);
    }

    #[test]
    fn archive_and_rename() {
        let mut ix = NotebookIndex::new();
        ix.ensure(0);
        ix.ensure(1);
        ix.rename(1, "  Receipts  ");
        assert_eq!(ix.get(1).unwrap().name, "Receipts");
        ix.set_archived(0, true);
        assert_eq!(ix.active().count(), 1);
        assert_eq!(ix.archived_count(), 1);
        ix.set_archived(0, false);
        assert_eq!(ix.archived_count(), 0);
    }

    #[test]
    fn roundtrips_on_disk() {
        let dir = std::env::temp_dir().join(format!("nbix-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notebooks-regtest-00112233.json");
        let mut ix = NotebookIndex::new();
        ix.ensure(0);
        ix.ensure(2);
        ix.rename(2, "Trips");
        ix.set_archived(0, true);
        ix.save(&path).unwrap();
        let back = NotebookIndex::load(&path).unwrap();
        assert_eq!(back.notebooks.len(), 2);
        assert_eq!(back.get(2).unwrap().name, "Trips");
        assert!(back.get(0).unwrap().archived);
        std::fs::remove_dir_all(&dir).ok();
    }
}
