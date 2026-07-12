//! Notebook index: which receive-chain address indexes exist as
//! notebooks, per BIP-86 account, with their local names and archive
//! flags. One JSON file per (network, identity) —
//! `notebooks-<net>-<fp8>.json` — sitting NEXT to the per-notebook store
//! files it points into, so switching identities can never mix indexes.
//!
//! Rev 3 (2026-07-12): a notebook is an ADDRESS INDEX
//! (`m/86'/coin'/account'/0/{index}`), not an account. The account is a
//! Settings-level wallet context; each account carries its own notebook
//! list. Version-1 files (accounts-as-notebooks) migrate on load: each
//! v1 account becomes that account's notebook 0 — same leaf, same
//! address, same store file, so only this metadata is re-shelved.
//!
//! Everything here is local metadata (the store tier of contact names):
//! it survives rescans but is NOT chain-recoverable after an identity
//! reset. Notes themselves recover per address; the index is rebuilt by
//! receive-chain gap discovery plus whatever the user renames again.
//! Design: ../../PLAN-chain-notes-notebooks.md (prime workspace).

use serde::{Deserialize, Serialize};

use crate::Error;

/// One notebook = one receive-chain address index of an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookMeta {
    pub index: u32,
    /// Local display name; empty = unnamed (rows fall back to the
    /// address short form).
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub archived: bool,
}

/// One account's notebook list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountBooks {
    pub account: u32,
    pub notebooks: Vec<NotebookMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookIndex {
    pub version: u32,
    pub accounts: Vec<AccountBooks>,
}

/// The name a pre-notebooks identity's existing store gets when it is
/// MIGRATED into a fresh index (the only auto-created notebook — every
/// other notebook is created deliberately and starts unnamed).
pub const FIRST_NOTEBOOK_NAME: &str = "Main";

/// The shipped v1 shape (accounts-as-notebooks), read for migration only.
#[derive(Deserialize)]
struct V1Meta {
    account: u32,
    #[serde(default)]
    name: String,
    #[serde(default)]
    archived: bool,
}

#[derive(Deserialize)]
struct V1Index {
    #[allow(dead_code)]
    version: u32,
    notebooks: Vec<V1Meta>,
}

impl NotebookIndex {
    pub fn new() -> Self {
        NotebookIndex { version: 2, accounts: Vec::new() }
    }

    /// Load, migrating a v1 (accounts-as-notebooks) file: each v1 account
    /// entry becomes that account's notebook 0 (the SAME leaf/address).
    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::Store(e.to_string()))?;
        let probe: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| Error::Store(e.to_string()))?;
        if probe.get("version").and_then(|v| v.as_u64()).unwrap_or(1) >= 2 {
            return serde_json::from_str(&text).map_err(|e| Error::Store(e.to_string()));
        }
        let v1: V1Index = serde_json::from_str(&text).map_err(|e| Error::Store(e.to_string()))?;
        let mut ix = NotebookIndex::new();
        for m in v1.notebooks {
            ix.ensure(m.account, 0);
            ix.rename(m.account, 0, &m.name);
            ix.set_archived(m.account, 0, m.archived);
        }
        Ok(ix)
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), Error> {
        let text = serde_json::to_string_pretty(self).map_err(|e| Error::Store(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| Error::Store(e.to_string()))?;
        std::fs::rename(&tmp, path).map_err(|e| Error::Store(e.to_string()))
    }

    fn account(&self, account: u32) -> Option<&AccountBooks> {
        self.accounts.iter().find(|a| a.account == account)
    }

    /// One account's notebooks (empty when the account has none yet).
    pub fn books(&self, account: u32) -> &[NotebookMeta] {
        self.account(account).map(|a| a.notebooks.as_slice()).unwrap_or(&[])
    }

    pub fn get(&self, account: u32, index: u32) -> Option<&NotebookMeta> {
        self.account(account)?.notebooks.iter().find(|n| n.index == index)
    }

    /// Make sure notebook `index` exists under `account`, unnamed (naming
    /// is the caller's business — the create dialog, or the migration
    /// rule). Returns true when it was added.
    pub fn ensure(&mut self, account: u32, index: u32) -> bool {
        if self.get(account, index).is_some() {
            return false;
        }
        let books = match self.accounts.iter_mut().find(|a| a.account == account) {
            Some(a) => a,
            None => {
                self.accounts.push(AccountBooks { account, notebooks: Vec::new() });
                self.accounts.sort_by_key(|a| a.account);
                self.accounts.iter_mut().find(|a| a.account == account).expect("just added")
            }
        };
        books.notebooks.push(NotebookMeta { index, name: String::new(), archived: false });
        books.notebooks.sort_by_key(|n| n.index);
        true
    }

    /// The index a "create notebook" gets: one past the account's highest.
    pub fn next_index(&self, account: u32) -> u32 {
        self.books(account).iter().map(|n| n.index + 1).max().unwrap_or(0)
    }

    pub fn rename(&mut self, account: u32, index: u32, name: &str) {
        if let Some(a) = self.accounts.iter_mut().find(|a| a.account == account) {
            if let Some(n) = a.notebooks.iter_mut().find(|n| n.index == index) {
                n.name = name.trim().to_string();
            }
        }
    }

    pub fn set_archived(&mut self, account: u32, index: u32, archived: bool) {
        if let Some(a) = self.accounts.iter_mut().find(|a| a.account == account) {
            if let Some(n) = a.notebooks.iter_mut().find(|n| n.index == index) {
                n.archived = archived;
            }
        }
    }

    pub fn active(&self, account: u32) -> impl Iterator<Item = &NotebookMeta> {
        self.books(account).iter().filter(|n| !n.archived)
    }

    pub fn archived_count(&self, account: u32) -> usize {
        self.books(account).iter().filter(|n| n.archived).count()
    }

    /// Accounts that have at least one notebook (the Settings switcher's
    /// "used" hint, and the legacy-record RBF owner set).
    pub fn accounts_used(&self) -> Vec<u32> {
        self.accounts.iter().filter(|a| !a.notebooks.is_empty()).map(|a| a.account).collect()
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
    fn ensure_adds_unnamed_and_sorts() {
        let mut ix = NotebookIndex::new();
        assert!(ix.ensure(0, 3));
        assert!(ix.ensure(0, 0));
        assert!(!ix.ensure(0, 3)); // idempotent
        assert_eq!(ix.books(0).len(), 2);
        // ensure() never names — naming belongs to the caller (create
        // dialog / migration).
        assert_eq!(ix.get(0, 3).unwrap().name, "");
        assert_eq!(ix.get(0, 0).unwrap().name, "");
        // Sorted by index regardless of insertion order.
        assert_eq!(ix.books(0)[0].index, 0);
        assert_eq!(ix.next_index(0), 4);
        // Separate accounts have separate lists.
        assert!(ix.ensure(2, 0));
        assert_eq!(ix.books(2).len(), 1);
        assert_eq!(ix.next_index(2), 1);
        assert_eq!(ix.next_index(7), 0);
        assert_eq!(ix.accounts_used(), vec![0, 2]);
    }

    #[test]
    fn archive_and_rename() {
        let mut ix = NotebookIndex::new();
        ix.ensure(0, 0);
        ix.ensure(0, 1);
        ix.rename(0, 1, "  Receipts  ");
        assert_eq!(ix.get(0, 1).unwrap().name, "Receipts");
        ix.set_archived(0, 0, true);
        assert_eq!(ix.active(0).count(), 1);
        assert_eq!(ix.archived_count(0), 1);
        ix.set_archived(0, 0, false);
        assert_eq!(ix.archived_count(0), 0);
    }

    #[test]
    fn roundtrips_on_disk() {
        let dir = std::env::temp_dir().join(format!("nbix-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notebooks-regtest-00112233.json");
        let mut ix = NotebookIndex::new();
        ix.ensure(0, 0);
        ix.ensure(0, 2);
        ix.rename(0, 2, "Trips");
        ix.set_archived(0, 0, true);
        ix.save(&path).unwrap();
        let back = NotebookIndex::load(&path).unwrap();
        assert_eq!(back.books(0).len(), 2);
        assert_eq!(back.get(0, 2).unwrap().name, "Trips");
        assert!(back.get(0, 0).unwrap().archived);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migrates_v1_accounts_to_index_zero() {
        let dir = std::env::temp_dir().join(format!("nbix-v1-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notebooks-regtest-00112233.json");
        std::fs::write(
            &path,
            r#"{"version":1,"notebooks":[
                {"account":0,"name":"Main","archived":false},
                {"account":1,"name":"Trips","archived":false},
                {"account":4,"name":"","archived":true}
            ]}"#,
        )
        .unwrap();
        let ix = NotebookIndex::load(&path).unwrap();
        assert_eq!(ix.version, 2);
        // Each v1 account becomes that account's notebook 0.
        assert_eq!(ix.get(0, 0).unwrap().name, "Main");
        assert_eq!(ix.get(1, 0).unwrap().name, "Trips");
        assert!(ix.get(4, 0).unwrap().archived);
        assert_eq!(ix.books(0).len(), 1);
        assert_eq!(ix.accounts_used(), vec![0, 1, 4]);
        // Saving writes v2; loading again is a no-op migration-wise.
        ix.save(&path).unwrap();
        let back = NotebookIndex::load(&path).unwrap();
        assert_eq!(back.get(1, 0).unwrap().name, "Trips");
        std::fs::remove_dir_all(&dir).ok();
    }
}
