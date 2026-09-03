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

/// The spending wallet's local bookkeeping (funding-unification M2/M3):
/// next unused receive/change indexes, plus every address actually handed
/// out — enough to (a) hand out fresh addresses, (b) build the self-spk SET
/// for scanning ([`SpendingSection::self_spks`]), and (c) survive a
/// restart without re-deriving.
///
/// ACCOUNT-level (funding-unification M3.1, Sal's 2026-07-16 fix): the
/// spending wallet is one BIP-84 branch (`m/84'/coin'/account'/…`) shared
/// by every notebook of an account (PLAN-chain-notes-funding-unification.md,
/// "Derivation"), so this section lives HERE — in the per-identity
/// notebooks index, keyed by account, next to the notebook metadata that's
/// already scoped the same way — rather than per notebook store. Living
/// per-notebook was the M2/M3 bug: enabling the wallet in one notebook
/// didn't show enabled in a sibling, and two notebooks could independently
/// hand out the SAME receive/change index — an address-reuse bug in the
/// feature whose whole point is fresh addresses. Nothing shipped with the
/// old per-notebook shape, so no migration is needed; SERDE-DEFAULT keeps
/// every pre-M3.1 index file loading with `enabled: false` and an empty
/// `used` list. Key bytes never live here (key storage spec) — only
/// indexes and addresses; the spending keys themselves are re-derived on
/// unlock.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub next_receive: u32,
    #[serde(default)]
    pub next_change: u32,
    #[serde(default)]
    pub used: Vec<SpendingAddr>,
}

/// One address the spending wallet has handed out (receive OR change).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingAddr {
    /// 0 = receive chain, 1 = change chain.
    pub chain: u32,
    pub index: u32,
    pub address: String,
    /// Raw scriptPubKey, hex — feeds the self-spk SET directly (no address
    /// re-decoding needed at scan time).
    #[serde(default)]
    pub script_pubkey_hex: String,
}

impl SpendingSection {
    /// Merge a freshly derived spending address into the used list
    /// (idempotent by (chain, index)) and bump the matching next-index past
    /// it — fresh-address discipline (funding-unification PLAN): the NEXT
    /// unused index always comes after every address actually handed out or
    /// discovered.
    pub fn mark_used(&mut self, addr: SpendingAddr) {
        let bump = addr.index + 1;
        if addr.chain == 0 {
            self.next_receive = self.next_receive.max(bump);
        } else {
            self.next_change = self.next_change.max(bump);
        }
        if !self.used.iter().any(|u| u.chain == addr.chain && u.index == addr.index) {
            self.used.push(addr);
        }
    }

    /// The spending wallet's self-spk SET: every used address's
    /// scriptPubKey — fed to `extract_notes_multi`/`_watch_multi` alongside
    /// a notebook's own spk so a spending-wallet-funded note scans back as
    /// OWN for every notebook of the account. Empty when the section has
    /// never been used, which keeps scan behavior identical to pre-M2
    /// stores.
    pub fn self_spks(&self) -> Vec<Vec<u8>> {
        self.used.iter().filter_map(|u| hex::decode(&u.script_pubkey_hex).ok()).collect()
    }

    /// Merge a gap-scan's findings (`chain::discover_spending`) into the
    /// section: every discovered used address, plus each chain's next-
    /// unused index raised (never lowered — an unconfirmed local spend the
    /// scan can't see yet must not un-advance the index).
    pub fn apply_discovery(&mut self, used: Vec<SpendingAddr>, next_receive: u32, next_change: u32) {
        for addr in used {
            self.mark_used(addr);
        }
        self.next_receive = self.next_receive.max(next_receive);
        self.next_change = self.next_change.max(next_change);
    }
}

/// One account's persisted spending-wallet section — the [`NotebookIndex`]
/// entry mirroring [`AccountBooks`]'s (account, notebooks) shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountSpending {
    pub account: u32,
    #[serde(default)]
    pub spending: SpendingSection,
}

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
    /// Spending-wallet section per account (funding-unification M3.1) —
    /// see [`SpendingSection`]'s doc for why it lives here. Serde-default
    /// so every file predating this fix (including plain v1 files) loads
    /// with an empty map; nothing shipped with a spending section anywhere
    /// else, so there is no old data to migrate.
    #[serde(default)]
    pub spending: Vec<AccountSpending>,
}

/// The name a pre-notebooks identity's existing store gets when it is
/// MIGRATED into a fresh index (the one notebook that does NOT take the
/// `default_name` — it predates the index entirely).
pub const FIRST_NOTEBOOK_NAME: &str = "Main";

/// The name every notebook gets unless the user typed one: **"Notebook
/// <index+1>"** — 1-based, so the first notebook (receive index 0) reads
/// "Notebook 1" (Sal 2026-07-26, all platforms and every creation path:
/// the create button, an import/restore, chain gap-discovery, a fresh
/// key). Also the display fallback for entries that predate this rule.
pub fn default_name(index: u32) -> String {
    format!("Notebook {}", index + 1)
}

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
        NotebookIndex { version: 2, accounts: Vec::new(), spending: Vec::new() }
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
            // An unnamed v1 entry keeps `ensure`'s default name rather
            // than being renamed back to empty.
            if !m.name.trim().is_empty() {
                ix.rename(m.account, 0, &m.name);
            }
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

    /// Make sure notebook `index` exists under `account`, carrying the
    /// DEFAULT name (`default_name` — "Notebook <index+1>"). A caller with
    /// a better name (the create dialog's field, the migration rule)
    /// renames right after. Returns true when it was added.
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
        books.notebooks.push(NotebookMeta { index, name: default_name(index), archived: false });
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

    /// This account's spending-wallet section — a clone, since callers
    /// stamp it onto a runtime cache (`Store.spending`) rather than borrow
    /// it. Defaults empty/disabled when the account has never touched the
    /// spending wallet, byte-identical to a fresh [`SpendingSection`].
    pub fn spending_for(&self, account: u32) -> SpendingSection {
        self.spending.iter().find(|s| s.account == account).map(|s| s.spending.clone()).unwrap_or_default()
    }

    /// Replace this account's spending-wallet section (creating the entry
    /// if this is its first mutation) — the write-back half of the
    /// stamp-then-write-back pattern every mutating call site uses: mutate
    /// a `SpendingSection` copy (e.g. via `Store::spending_mark_used`),
    /// then call this + [`Self::save`] so every OTHER notebook of the same
    /// account sees the update the next time it activates.
    pub fn set_spending(&mut self, account: u32, section: SpendingSection) {
        match self.spending.iter_mut().find(|s| s.account == account) {
            Some(s) => s.spending = section,
            None => {
                self.spending.push(AccountSpending { account, spending: section });
                self.spending.sort_by_key(|s| s.account);
            }
        }
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
    fn ensure_default_names_and_sorts() {
        let mut ix = NotebookIndex::new();
        assert!(ix.ensure(0, 3));
        assert!(ix.ensure(0, 0));
        assert!(!ix.ensure(0, 3)); // idempotent
        assert_eq!(ix.books(0).len(), 2);
        // ensure() applies the 1-based default name; a caller with a
        // better one (create dialog / migration) renames after.
        assert_eq!(ix.get(0, 3).unwrap().name, "Notebook 4");
        assert_eq!(ix.get(0, 0).unwrap().name, "Notebook 1");
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

    #[test]
    fn spending_defaults_empty_and_disabled() {
        let ix = NotebookIndex::new();
        let s = ix.spending_for(0);
        assert!(!s.enabled);
        assert_eq!(s.next_receive, 0);
        assert_eq!(s.next_change, 0);
        assert!(s.used.is_empty());
        assert!(s.self_spks().is_empty());
    }

    #[test]
    fn spending_mark_used_advances_indexes_and_dedupes() {
        let mut s = SpendingSection::default();
        s.mark_used(SpendingAddr {
            chain: 0,
            index: 0,
            address: "bc1qreceive0".into(),
            script_pubkey_hex: "0014aa".into(),
        });
        s.mark_used(SpendingAddr {
            chain: 1,
            index: 2,
            address: "bc1qchange2".into(),
            script_pubkey_hex: "0014bb".into(),
        });
        assert_eq!(s.next_receive, 1);
        assert_eq!(s.next_change, 3);
        assert_eq!(s.used.len(), 2);
        assert_eq!(s.self_spks(), vec![hex::decode("0014aa").unwrap(), hex::decode("0014bb").unwrap()]);

        // Re-marking the same (chain, index) is idempotent and never lowers
        // an index a later observation already advanced past.
        s.mark_used(SpendingAddr {
            chain: 0,
            index: 0,
            address: "bc1qreceive0".into(),
            script_pubkey_hex: "0014aa".into(),
        });
        assert_eq!(s.used.len(), 2);
        assert_eq!(s.next_receive, 1);
    }

    #[test]
    fn spending_apply_discovery_merges_and_never_lowers_indexes() {
        let mut s = SpendingSection { next_change: 5, ..Default::default() };
        s.apply_discovery(
            vec![
                SpendingAddr { chain: 0, index: 0, address: "r0".into(), script_pubkey_hex: "00".into() },
                SpendingAddr { chain: 0, index: 2, address: "r2".into(), script_pubkey_hex: "01".into() },
            ],
            3,
            1,
        );
        assert_eq!(s.used.len(), 2);
        assert_eq!(s.next_receive, 3);
        // Discovery's next_change=1 must not un-advance the local 5.
        assert_eq!(s.next_change, 5);
    }

    #[test]
    fn spending_set_get_round_trips_on_disk_and_old_files_load_unchanged() {
        let dir = std::env::temp_dir().join(format!("nbix-spending-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("notebooks-regtest-aabbccdd.json");
        let mut ix = NotebookIndex::new();
        let mut s = SpendingSection { enabled: true, ..Default::default() };
        s.mark_used(SpendingAddr {
            chain: 0,
            index: 0,
            address: "bc1qreceive0".into(),
            script_pubkey_hex: "0014aa".into(),
        });
        ix.set_spending(0, s.clone());
        ix.save(&path).unwrap();
        let back = NotebookIndex::load(&path).unwrap();
        assert_eq!(back.spending_for(0), s);
        assert!(back.spending_for(0).enabled);

        // A pre-M3.1 index file (accounts + notebooks, no "spending" key at
        // all) loads with every account's section defaulted, not an error.
        let legacy_path = dir.join("notebooks-regtest-legacy.json");
        std::fs::write(
            &legacy_path,
            r#"{"version":2,"accounts":[{"account":0,"notebooks":[{"index":0,"name":"Main","archived":false}]}]}"#,
        )
        .unwrap();
        let legacy = NotebookIndex::load(&legacy_path).unwrap();
        assert!(!legacy.spending_for(0).enabled);
        assert!(legacy.spending_for(0).used.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spending_shared_across_notebooks_of_the_same_account() {
        // The whole point of moving this to the notebooks index: TWO
        // notebooks of the SAME account (different receive indexes) read
        // and write ONE section — no notebook-scoped state anywhere.
        let mut ix = NotebookIndex::new();
        ix.ensure(0, 0); // "Main"
        ix.ensure(0, 1); // a sibling notebook, same account

        // Notebook 0 enables the wallet and hands out a receive address.
        let mut section = ix.spending_for(0);
        section.enabled = true;
        section.mark_used(SpendingAddr {
            chain: 0,
            index: 0,
            address: "bc1qreceive0".into(),
            script_pubkey_hex: "0014aa".into(),
        });
        ix.set_spending(0, section);

        // Notebook 1 (same account) re-reads and sees the SAME enabled
        // flag, index, and used list.
        let seen_by_sibling = ix.spending_for(0);
        assert!(seen_by_sibling.enabled);
        assert_eq!(seen_by_sibling.next_receive, 1);
        assert_eq!(seen_by_sibling.used.len(), 1);

        // A mark-used via notebook 1 advances the SAME index notebook 0
        // will see next — no independent, colliding indexes.
        let mut section = seen_by_sibling;
        section.mark_used(SpendingAddr {
            chain: 0,
            index: 1,
            address: "bc1qreceive1".into(),
            script_pubkey_hex: "0014bb".into(),
        });
        ix.set_spending(0, section);
        let seen_by_main = ix.spending_for(0);
        assert_eq!(seen_by_main.next_receive, 2);
        assert_eq!(seen_by_main.used.len(), 2);

        // A different account's section is untouched.
        ix.ensure(1, 0);
        assert!(!ix.spending_for(1).enabled);
    }
}
