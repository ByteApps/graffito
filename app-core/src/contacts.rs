//! iCloud key-value contacts sync — pure, host-testable helpers only. No
//! platform/Apple deps here (those live in the app crate's `src/icloud.rs`);
//! this module is just the merge rule + the blob (de)serialization shape, so
//! it can be exercised with `cargo test -p app-core`.
//!
//! Contacts are DEVICE-LEVEL (global, shared across every notebook/identity/
//! network on this device — see `State.contacts` in the app crate), and the
//! KV blob mirrors that: ONE JSON blob under the key `contacts-v1`, not a
//! per-notebook map.
//!
//! Identity is the **(address, network) pair**, not the address alone:
//! testnet4 and signet addresses share the same `tb1…` HRP, so the same
//! string can legitimately be two distinct contacts — one per network. An
//! empty `network` (pre-network-tag legacy data) is treated as its own
//! distinct tag here (not a wildcard) — the wildcard/wildcard-upgrade
//! behavior lives in the app crate's `State::touch_contact` (matching
//! rules for reads/writes against the live device list); this module's
//! merge only needs exact-tuple equality to decide "is this the same
//! synced entry".
//!
//! # Tombstone-based cross-device deletion (2026-07-20)
//!
//! The original merge was a pure UNION with no concept of deletion: a
//! contact removed on device A reappeared the instant device B's list
//! (which still had it) synced back up. [`merge_state`] fixes this by
//! carrying [`Tombstone`]s alongside contacts — a deletion is now a
//! first-class synced event, not just "absence from a list".
//!
//! **Wall-clock assumption**: every conflict [`merge_state`] resolves
//! (which contact/name wins, whether a deletion or a re-add wins) is
//! decided by comparing `updated_at`/`deleted_at` MILLISECOND timestamps
//! across devices. This assumes the two devices' clocks are roughly
//! NTP-synced — if one device's clock is badly skewed, a genuinely later
//! edit or deletion from that device can lose to a genuinely earlier one
//! from the other. This module never produces the timestamps itself (see
//! below); it only compares whatever the impure caller supplies.
//!
//! **90-day tombstone retention**: a tombstone is GC'd out of the merged
//! state once it's older than [`TOMBSTONE_RETENTION_MS`]. This bounds how
//! long the synced blob grows, but it's a real tradeoff: a device that
//! stays offline (or simply never observes an iCloud sync) for longer than
//! the retention window can miss a deletion entirely — if it still has the
//! contact locally when it finally reconnects, the tombstone that would
//! have deleted it is already gone, and the contact "resurrects" on the
//! other device the next time they merge. 90 days is the deliberate bound
//! (long enough to cover any plausible offline gap for a personal contacts
//! list, short enough to keep the synced blob from accumulating tombstones
//! forever).
//!
//! Timestamps are produced ONLY in the impure app crate (`src/lib.rs`, via
//! `std::time::SystemTime::now()` → unix milliseconds) — every function
//! here takes `now_ms`/the timestamps already stamped on its inputs as
//! plain parameters, so this module stays clock-free and fully
//! host-testable with canned inputs.

use crate::store::Contact;
use serde::{Deserialize, Serialize};

/// Cap applied to a merge result — recents beyond this are noise. Larger
/// than the old per-notebook cap (20) since this is now one device-wide
/// list spanning every notebook/identity/network.
pub const MERGE_CAP: usize = 100;

/// How long a tombstone survives in merged state before it's GC'd — see
/// the module doc's "90-day tombstone retention" section for the tradeoff.
pub const TOMBSTONE_RETENTION_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// A deletion of one `(address, network)` contact — the synced record of
/// "this was removed", so a device that still has an older copy of the
/// contact knows to drop it instead of resurrecting it on the next merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    pub address: String,
    pub network: String,
    /// Unix MILLISECONDS the contact was removed — the clock `merge_state`
    /// weighs against a live contact's `updated_at` for the same key (see
    /// the module doc). Produced by the impure app crate, never here.
    pub deleted_at: u64,
}

/// The full synced payload: the contact list plus every known deletion.
/// This is what round-trips through BOTH `contacts.json` on disk and the
/// iCloud KV blob (`serialize_contacts_blob`/`parse_contacts_blob`) — see
/// their docs for the v1/v2 back-compat shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactState {
    pub contacts: Vec<Contact>,
    pub tombstones: Vec<Tombstone>,
}

impl ContactState {
    /// The subset of this state that's allowed to leave the device: only
    /// contacts with `synced == true`, plus tombstones. Used to build the
    /// iCloud KV blob (`save_blob`'s payload) — the LOCAL `contacts.json`
    /// keeps serializing the FULL state (this method is never used for
    /// that file). See the module doc for the opt-in-sync rule.
    ///
    /// Tombstones are NOT filtered by anything — ALL of them are included.
    /// A tombstone means "this contact was deleted," and we can't always
    /// tell in hindsight whether the deleted contact used to be synced, so
    /// the pragmatic and simplest-to-reason-about rule is to include every
    /// tombstone: a stray tombstone for a never-synced contact is harmless
    /// noise in the cloud blob, whereas dropping a tombstone that WAS
    /// needed would cause a deleted-but-still-synced contact to resurrect
    /// on another device.
    pub fn synced_only(&self) -> ContactState {
        ContactState {
            contacts: self.contacts.iter().filter(|c| c.synced).cloned().collect(),
            tombstones: self.tombstones.clone(),
        }
    }
}

/// The v2 blob shape (`{"v":2,"contacts":[...],"tombstones":[...]}`) —
/// only used for (de)serialization, not held anywhere as app state.
#[derive(Serialize)]
struct BlobV2Ref<'a> {
    v: u32,
    contacts: &'a [Contact],
    tombstones: &'a [Tombstone],
}

#[derive(Deserialize)]
struct BlobV2Owned {
    #[serde(default)]
    contacts: Vec<Contact>,
    #[serde(default)]
    tombstones: Vec<Tombstone>,
}

/// Merge two [`ContactState`]s — the core of tombstone-based cross-device
/// deletion. `local` is this device's current state, `incoming` is
/// whatever the other device last synced (from the KV blob); `now_ms` is
/// the current wall-clock time in unix milliseconds (used only for the
/// tombstone GC pass — see below). Deterministic: same inputs always
/// produce the same output.
///
/// Steps:
/// 1. **Union contacts** by `(address, network)`: `local`'s entries come
///    first in their existing order (this device's own recency ordering
///    is preserved), then any incoming-only pair is appended in
///    `incoming`'s order. For a pair present on BOTH sides, the entry with
///    the greater `updated_at` wins outright (name included); on a tie,
///    local wins, except a non-empty incoming name is adopted over an
///    empty local one (never let a tie-break blank out a name).
///    `synced` rides along with whichever side's `Contact` value wins a
///    given key — there is no separate merge for it. In particular, when
///    a contact arrives from the iCloud blob and its caller has stamped
///    it `synced = true` before calling `merge_state` (the app's own
///    responsibility — every contact that reached the KV blob is synced
///    BY DEFINITION), that flag is preserved if `incoming` wins the
///    tie/greater-timestamp check, or if `incoming` is a brand-new entry
///    not present locally. If the caller does NOT pre-stamp incoming
///    contacts as synced before merging, a previously-synced contact's
///    flag could be lost across devices — pre-stamping is a caller
///    invariant, not something `merge_state` enforces itself.
/// 2. **Union tombstones** by `(address, network)`: same shape, keeping
///    whichever side's `deleted_at` is greater for a shared key.
/// 3. **Resolve contact-vs-tombstone conflicts**: for any `(address,
///    network)` present as BOTH a live contact (after step 1) and a
///    tombstone (after step 2) — this happens when one device deleted a
///    contact the other device still has — compare `contact.updated_at`
///    to `tombstone.deleted_at`. If the contact is newer, it was
///    re-added/touched AFTER the deletion, so it wins and the (now-stale)
///    tombstone is dropped. Otherwise the deletion is authoritative: the
///    contact is dropped and the tombstone survives.
/// 4. **GC old tombstones**: drop any tombstone with
///    `deleted_at < now_ms - TOMBSTONE_RETENTION_MS` — see the module
///    doc's retention tradeoff.
/// 5. **Cap** the surviving contact list at [`MERGE_CAP`], applied AFTER
///    conflict resolution (so a deletion always has the chance to take
///    effect before the cap ever gets to trim anything).
///
/// Output ordering is deterministic: contacts preserve local-first/
/// incoming-appended order (same as before tombstones existed);
/// tombstones are sorted by `(address, network)` so two merges of the same
/// inputs are byte-identical regardless of internal hash/iteration order.
pub fn merge_state(local: &ContactState, incoming: &ContactState, now_ms: u64) -> ContactState {
    // 1. Union contacts, local order first, then incoming-only appended.
    let mut contacts: Vec<Contact> = local.contacts.clone();
    for inc in &incoming.contacts {
        match contacts.iter_mut().find(|c| c.address == inc.address && c.network == inc.network) {
            Some(existing) => {
                if inc.updated_at > existing.updated_at {
                    *existing = inc.clone();
                } else if inc.updated_at == existing.updated_at
                    && existing.name.is_empty()
                    && !inc.name.is_empty()
                {
                    existing.name = inc.name.clone();
                }
            }
            None => contacts.push(inc.clone()),
        }
    }

    // 2. Union tombstones, keeping the greater deleted_at for a shared key.
    let mut tombstones: Vec<Tombstone> = local.tombstones.clone();
    for inc in &incoming.tombstones {
        match tombstones.iter_mut().find(|t| t.address == inc.address && t.network == inc.network)
        {
            Some(existing) => {
                if inc.deleted_at > existing.deleted_at {
                    existing.deleted_at = inc.deleted_at;
                }
            }
            None => tombstones.push(inc.clone()),
        }
    }

    // 3. Resolve contact-vs-tombstone conflicts for keys present as both.
    let mut resolved_contacts: Vec<Contact> = Vec::with_capacity(contacts.len());
    let mut stale_tombstone_keys: Vec<(String, String)> = Vec::new();
    for c in contacts {
        match tombstones.iter().find(|t| t.address == c.address && t.network == c.network) {
            Some(t) if c.updated_at > t.deleted_at => {
                // Contact was (re)touched after the deletion — it wins,
                // and the tombstone is stale (drop it).
                stale_tombstone_keys.push((c.address.clone(), c.network.clone()));
                resolved_contacts.push(c);
            }
            Some(_) => {
                // Tombstone wins — drop the contact, keep the tombstone.
            }
            None => resolved_contacts.push(c),
        }
    }
    tombstones.retain(|t| {
        !stale_tombstone_keys.iter().any(|(a, n)| *a == t.address && *n == t.network)
    });

    // 4. GC tombstones past the retention window.
    let cutoff = now_ms.saturating_sub(TOMBSTONE_RETENTION_MS);
    tombstones.retain(|t| t.deleted_at >= cutoff);

    // 5. Cap contacts, applied after resolution.
    resolved_contacts.truncate(MERGE_CAP);

    // Deterministic tombstone ordering.
    tombstones.sort_by(|a, b| {
        (a.address.as_str(), a.network.as_str()).cmp(&(b.address.as_str(), b.network.as_str()))
    });

    ContactState { contacts: resolved_contacts, tombstones }
}

/// Parse the KV store's/`contacts.json`'s blob into a [`ContactState`].
/// Accepts BOTH shapes:
/// - **v2**: `{"v":2,"contacts":[...],"tombstones":[...]}` — the current
///   format this module writes.
/// - **v1**: a bare JSON array of contacts (`[{...}, {...}]`) — what's on
///   disk / in iCloud for every existing user today. Parses to a
///   `ContactState` with an empty tombstone list (nobody has deleted
///   anything yet under the new scheme).
///
/// Tolerant by design — the payload can be absent, stale-shaped (an old
/// per-notebook-map version, or a future schema change), or outright
/// garbage (first run, nothing ever written): all of those return an
/// empty [`ContactState`] rather than an error, since the caller's merge
/// is a no-op against an empty state and there's nothing sane to surface
/// to the user for a background sync hiccup.
pub fn parse_contacts_blob(blob: &str) -> ContactState {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(blob) else {
        return ContactState::default();
    };
    match value {
        serde_json::Value::Array(_) => serde_json::from_value::<Vec<Contact>>(value)
            .map(|contacts| ContactState { contacts, tombstones: Vec::new() })
            .unwrap_or_default(),
        serde_json::Value::Object(_) => serde_json::from_value::<BlobV2Owned>(value)
            .map(|b| ContactState { contacts: b.contacts, tombstones: b.tombstones })
            .unwrap_or_default(),
        _ => ContactState::default(),
    }
}

/// Serialize a [`ContactState`] to the v2 KV blob shape. Deterministic
/// (input order preserved; `merge_state` already gives tombstones a
/// stable sort).
pub fn serialize_contacts_blob(state: &ContactState) -> String {
    serde_json::to_string(&BlobV2Ref { v: 2, contacts: &state.contacts, tombstones: &state.tombstones })
        .unwrap_or_else(|_| r#"{"v":2,"contacts":[],"tombstones":[]}"#.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper for tests that don't care about the network tag — both
    /// sides get the same (empty) tag, so tuple equality behaves exactly
    /// like the old address-only key. `updated_at` defaults to 0,
    /// `synced` defaults to false.
    fn c(address: &str, name: &str) -> Contact {
        cnt(address, name, "", 0, false)
    }

    fn cn(address: &str, name: &str, network: &str) -> Contact {
        cnt(address, name, network, 0, false)
    }

    fn cnt(address: &str, name: &str, network: &str, updated_at: u64, synced: bool) -> Contact {
        Contact {
            address: address.to_string(),
            name: name.to_string(),
            network: network.to_string(),
            updated_at,
            synced,
            mlkem_ek: None,
        }
    }

    fn ts(address: &str, network: &str, deleted_at: u64) -> Tombstone {
        Tombstone { address: address.to_string(), network: network.to_string(), deleted_at }
    }

    fn state(contacts: Vec<Contact>, tombstones: Vec<Tombstone>) -> ContactState {
        ContactState { contacts, tombstones }
    }

    #[test]
    fn merge_unions_by_address_local_first_then_new_incoming() {
        let local = state(vec![c("addr-a", "Alice"), c("addr-b", "")], vec![]);
        let incoming = state(vec![c("addr-b", ""), c("addr-c", "Carol")], vec![]);
        let merged = merge_state(&local, &incoming, 0);
        assert_eq!(
            merged.contacts,
            vec![c("addr-a", "Alice"), c("addr-b", ""), c("addr-c", "Carol")]
        );
        assert!(merged.tombstones.is_empty());
    }

    #[test]
    fn merge_prefers_greater_updated_at_regardless_of_side() {
        let local = state(vec![cnt("addr-a", "Alice (mine, stale)", "", 100, false)], vec![]);
        let incoming = state(vec![cnt("addr-a", "Alice (theirs, fresh)", "", 200, false)], vec![]);
        let merged = merge_state(&local, &incoming, 0);
        assert_eq!(merged.contacts, vec![cnt("addr-a", "Alice (theirs, fresh)", "", 200, false)]);
    }

    /// A rename propagates across devices by last-write-wins on
    /// `updated_at`: device 1 named a contact "A" at t1; device 2 renamed
    /// the same (address, network) to "B" at a later t2 and synced it up.
    /// Merging device-2's fresher copy into device-1's local state must
    /// adopt "B" (the newer name wins). This is exactly what
    /// `name_contact`'s `updated_at = now_ms()` bump buys the rename flow.
    #[test]
    fn rename_propagates_by_updated_at() {
        let device1 = state(vec![cnt("addr-a", "A", "", 1_000, false)], vec![]);
        let device2 = state(vec![cnt("addr-a", "B", "", 2_000, false)], vec![]);
        let merged = merge_state(&device1, &device2, 0);
        assert_eq!(merged.contacts.len(), 1);
        assert_eq!(merged.contacts[0].name, "B", "the newer rename must win");
    }

    #[test]
    fn merge_tie_prefers_local_but_keeps_nonempty_name_over_empty() {
        // Same updated_at on both sides: local wins outright...
        let local = state(vec![cnt("addr-a", "Alice (mine)", "", 100, false)], vec![]);
        let incoming = state(vec![cnt("addr-a", "Alice (theirs)", "", 100, false)], vec![]);
        let merged = merge_state(&local, &incoming, 0);
        assert_eq!(merged.contacts, vec![cnt("addr-a", "Alice (mine)", "", 100, false)]);

        // ...unless local's name is empty and incoming's isn't.
        let local2 = state(vec![cnt("addr-a", "", "", 100, false)], vec![]);
        let incoming2 = state(vec![cnt("addr-a", "Alice", "", 100, false)], vec![]);
        let merged2 = merge_state(&local2, &incoming2, 0);
        assert_eq!(merged2.contacts, vec![cnt("addr-a", "Alice", "", 100, false)]);
    }

    #[test]
    fn merge_caps_at_merge_cap_preserving_local_order_first() {
        let local: Vec<Contact> = (0..80).map(|i| c(&format!("local-{i}"), "")).collect();
        let incoming: Vec<Contact> = (0..80).map(|i| c(&format!("incoming-{i}"), "")).collect();
        let merged = merge_state(&state(local, vec![]), &state(incoming, vec![]), 0);
        assert_eq!(merged.contacts.len(), MERGE_CAP);
        for i in 0..80 {
            assert_eq!(merged.contacts[i].address, format!("local-{i}"));
        }
        for i in 0..20 {
            assert_eq!(merged.contacts[80 + i].address, format!("incoming-{i}"));
        }
    }

    #[test]
    fn merge_is_deterministic_and_order_stable() {
        let local = state(vec![c("a", "A"), c("b", "B")], vec![]);
        let incoming = state(vec![c("c", "C"), c("a", "ignored")], vec![]);
        let m1 = merge_state(&local, &incoming, 0);
        let m2 = merge_state(&local, &incoming, 0);
        assert_eq!(m1, m2);
        assert_eq!(m1.contacts, vec![c("a", "A"), c("b", "B"), c("c", "C")]);
    }

    /// Identity is (address, network), not address alone: testnet4 and
    /// signet share the `tb1…` HRP, so the same address string tagged for
    /// each network must survive a merge as TWO distinct contacts, and
    /// each carries its own name independently (no cross-network
    /// clobbering).
    #[test]
    fn merge_keeps_same_address_on_different_networks_distinct() {
        let local = state(vec![cn("tb1pSHARED", "Testnet Alice", "testnet4")], vec![]);
        let incoming = state(vec![cn("tb1pSHARED", "Signet Alice", "signet")], vec![]);
        let merged = merge_state(&local, &incoming, 0);
        assert_eq!(merged.contacts.len(), 2, "same address, different networks — must not collapse to one");
        assert!(merged.contacts.contains(&cn("tb1pSHARED", "Testnet Alice", "testnet4")));
        assert!(merged.contacts.contains(&cn("tb1pSHARED", "Signet Alice", "signet")));

        // Merging again (round 2, roles swapped) must not merge the two
        // network-tagged entries into each other — each keeps its own name.
        let merged2 = merge_state(&merged, &merged, 0);
        assert_eq!(merged2, merged);
    }

    #[test]
    fn blob_v2_round_trips_through_parse_and_serialize() {
        let s = state(
            vec![c("tb1p-alice", "Alice"), c("bc1p-bob", "")],
            vec![ts("tb1p-old", "mainnet", 12345)],
        );
        let blob = serialize_contacts_blob(&s);
        assert!(blob.contains("\"v\":2"));
        let back = parse_contacts_blob(&blob);
        assert_eq!(back, s);
    }

    /// A contact's post-quantum `mlkem_ek` (graffito-native public armor)
    /// rides along through the blob round-trip AND `merge_state` exactly
    /// like `name`/`synced` — no separate merge rule was needed for it
    /// (the module doc's "rides along with whichever side's `Contact`
    /// value wins" claim, specifically for this field).
    #[test]
    fn mlkem_ek_round_trips_through_blob_and_merge() {
        let armor = "-----BEGIN GRAFFITO ML-KEM PUBLIC KEY-----\ntest-payload\n-----END GRAFFITO ML-KEM PUBLIC KEY-----\n";
        let mut with_key = cnt("addr-a", "Alice", "", 100, true);
        with_key.mlkem_ek = Some(armor.to_string());

        // Blob round-trip: the field survives serialize -> parse verbatim.
        let s = state(vec![with_key.clone()], vec![]);
        let blob = serialize_contacts_blob(&s);
        assert!(blob.contains("mlkem_ek"));
        let back = parse_contacts_blob(&blob);
        assert_eq!(back, s);
        assert_eq!(back.contacts[0].mlkem_ek.as_deref(), Some(armor));

        // Merge: incoming (with a pq key, newer updated_at) beats a local
        // copy with none — the whole Contact value wins, key included.
        let local = state(vec![cnt("addr-a", "Alice (no key)", "", 50, false)], vec![]);
        let incoming = state(vec![with_key.clone()], vec![]);
        let merged = merge_state(&local, &incoming, 0);
        assert_eq!(merged.contacts.len(), 1);
        assert_eq!(merged.contacts[0].mlkem_ek.as_deref(), Some(armor));

        // Merge the other direction: local already has the pq key and is
        // newer — an incoming stale/keyless copy must never blank it out.
        let local_with_key = state(vec![with_key.clone()], vec![]);
        let incoming_stale = state(vec![cnt("addr-a", "Alice (stale)", "", 10, false)], vec![]);
        let merged2 = merge_state(&local_with_key, &incoming_stale, 0);
        assert_eq!(merged2.contacts[0].mlkem_ek.as_deref(), Some(armor));
    }

    #[test]
    fn v1_bare_array_blob_parses_to_empty_tombstones() {
        // Exactly what's on disk / in iCloud for every existing user today
        // (pre-tombstones): a bare JSON array, no "v"/"tombstones" wrapper.
        let legacy_blob = r#"[{"address":"tb1p-alice","name":"Alice","network":"testnet4"}]"#;
        let parsed = parse_contacts_blob(legacy_blob);
        assert!(parsed.tombstones.is_empty());
        assert_eq!(parsed.contacts.len(), 1);
        assert_eq!(parsed.contacts[0].address, "tb1p-alice");
        assert_eq!(parsed.contacts[0].updated_at, 0); // legacy entries default to 0
    }

    #[test]
    fn parse_tolerates_garbage_absent_and_stale_shaped_input() {
        assert_eq!(parse_contacts_blob(""), ContactState::default());
        assert_eq!(parse_contacts_blob("not json at all"), ContactState::default());
        assert_eq!(parse_contacts_blob("null"), ContactState::default());
        // A stale per-notebook-map shape (pre-global-contacts) is NOT a
        // Vec<Contact> nor a v2 object with a "v" key — must not error,
        // just come back empty.
        assert_eq!(
            parse_contacts_blob(r#"{"testnet4:aa": [{"address":"x","name":""}]}"#),
            ContactState::default()
        );
        assert_eq!(
            parse_contacts_blob(r#"[{"address":"x","name":"not-a-bool"}, 5]"#),
            ContactState::default()
        );
    }

    #[test]
    fn parse_empty_array_is_empty() {
        assert_eq!(parse_contacts_blob("[]"), ContactState::default());
    }

    // ---- Tombstone-based cross-device deletion ----

    /// Deleting a contact locally (removing it from `contacts`, adding a
    /// tombstone) and then merging with a state that doesn't know about
    /// the deletion at all (e.g. re-merging with itself, or an incoming
    /// blob that's simply stale-empty) must keep it deleted — the
    /// tombstone alone is enough to suppress any resurrection.
    #[test]
    fn delete_then_merge_keeps_it_deleted() {
        let after_delete = state(vec![], vec![ts("tb1p-alice", "testnet4", 1_000)]);
        let merged = merge_state(&after_delete, &ContactState::default(), 5_000);
        assert!(merged.contacts.is_empty());
        assert_eq!(merged.tombstones, vec![ts("tb1p-alice", "testnet4", 1_000)]);
    }

    /// The core cross-device scenario: device A deletes a contact (tombstone
    /// with a later timestamp); device B never deleted it and still has an
    /// OLDER copy of the contact. Merging A's tombstone against B's stale
    /// contact must drop the contact — the newer tombstone wins.
    #[test]
    fn delete_on_a_propagates_to_b_older_contact_loses() {
        let device_a = state(vec![], vec![ts("tb1p-alice", "testnet4", 2_000)]);
        let device_b = state(vec![cnt("tb1p-alice", "Alice", "testnet4", 1_000, false)], vec![]);
        let merged = merge_state(&device_b, &device_a, 5_000);
        assert!(merged.contacts.is_empty(), "B's older contact must lose to A's newer tombstone");
        assert_eq!(merged.tombstones, vec![ts("tb1p-alice", "testnet4", 2_000)]);
    }

    /// Intentional re-add: touching/naming a contact again AFTER it was
    /// tombstoned stamps a fresh `updated_at` greater than the tombstone's
    /// `deleted_at` — the contact must resurrect, and the stale tombstone
    /// must be dropped (not retained to fight the next merge too).
    #[test]
    fn intentional_readd_after_deletion_resurrects() {
        let deleted_elsewhere = state(vec![], vec![ts("tb1p-alice", "testnet4", 1_000)]);
        let readded_here = state(vec![cnt("tb1p-alice", "Alice", "testnet4", 2_000, false)], vec![]);
        let merged = merge_state(&readded_here, &deleted_elsewhere, 5_000);
        assert_eq!(merged.contacts, vec![cnt("tb1p-alice", "Alice", "testnet4", 2_000, false)]);
        assert!(merged.tombstones.is_empty(), "the stale tombstone must be dropped once the contact wins");
    }

    /// GC: a tombstone older than the retention window is dropped from
    /// merged state (it no longer needs to keep fighting resurrection —
    /// see the module doc's tradeoff).
    #[test]
    fn gc_drops_a_tombstone_past_the_retention_window() {
        let old_deleted_at = 1_000;
        let now = old_deleted_at + TOMBSTONE_RETENTION_MS + 1;
        let local = state(vec![], vec![ts("tb1p-old", "mainnet", old_deleted_at)]);
        let merged = merge_state(&local, &ContactState::default(), now);
        assert!(merged.tombstones.is_empty(), "a tombstone past the retention window must be GC'd");

        // Just inside the window: survives.
        let now_inside = old_deleted_at + TOMBSTONE_RETENTION_MS;
        let merged_inside = merge_state(&local, &ContactState::default(), now_inside);
        assert_eq!(merged_inside.tombstones, vec![ts("tb1p-old", "mainnet", old_deleted_at)]);
    }

    /// The (address, network) key keeps testnet4 vs signet independent
    /// under deletion: deleting the testnet4 entry must never touch a
    /// signet contact sharing the same address string.
    #[test]
    fn deletion_key_keeps_testnet4_and_signet_independent() {
        let local = state(
            vec![
                cnt("tb1pSHARED", "Testnet Alice", "testnet4", 1_000, false),
                cnt("tb1pSHARED", "Signet Alice", "signet", 1_000, false),
            ],
            vec![],
        );
        // Incoming: testnet4 copy was deleted elsewhere (later timestamp);
        // signet was never touched there.
        let incoming = state(vec![], vec![ts("tb1pSHARED", "testnet4", 2_000)]);
        let merged = merge_state(&local, &incoming, 5_000);
        assert_eq!(merged.contacts, vec![cnt("tb1pSHARED", "Signet Alice", "signet", 1_000, false)]);
        assert_eq!(merged.tombstones, vec![ts("tb1pSHARED", "testnet4", 2_000)]);
    }

    /// The cap (100) still holds after tombstone resolution — deletions
    /// free up room but the surviving list is never allowed past
    /// `MERGE_CAP`.
    #[test]
    fn cap_still_holds_after_tombstone_resolution() {
        let local: Vec<Contact> =
            (0..60).map(|i| cnt(&format!("local-{i}"), "", "", 0, false)).collect();
        let incoming_contacts: Vec<Contact> =
            (0..60).map(|i| cnt(&format!("incoming-{i}"), "", "", 0, false)).collect();
        // A handful of tombstones among the incoming contacts too, just to
        // prove resolution + cap compose correctly.
        let incoming_tombstones = vec![ts("local-0", "", 10), ts("local-1", "", 10)];
        let merged = merge_state(
            &state(local, vec![ts("local-0", "", 5), ts("local-1", "", 5)]),
            &state(incoming_contacts, incoming_tombstones),
            100,
        );
        assert!(merged.contacts.len() <= MERGE_CAP);
        assert_eq!(merged.contacts.len(), MERGE_CAP);
    }

    // ---- Per-contact opt-in sync (`synced`, 2026-07-20) ----

    /// Simulates a contact arriving from the iCloud blob: the caller
    /// pre-stamps it `synced = true` before calling `merge_state` (per the
    /// module doc's caller invariant). It has a newer `updated_at` than the
    /// local (unsynced) copy, so it wins the union outright — and its
    /// `synced` flag rides along with it, since the whole `Contact` value
    /// is adopted on that branch.
    #[test]
    fn synced_flag_survives_merge_when_incoming_wins() {
        let local = state(vec![cnt("addr-a", "Alice (local, stale)", "", 100, false)], vec![]);
        let incoming = state(vec![cnt("addr-a", "Alice (from icloud)", "", 200, true)], vec![]);
        let merged = merge_state(&local, &incoming, 0);
        assert_eq!(merged.contacts.len(), 1);
        assert!(merged.contacts[0].synced, "incoming won the tie and must bring its synced=true along");
    }

    /// The reverse: local is already synced and newer, incoming is a stale
    /// unsynced copy (older `updated_at`). Local wins outright, keeping its
    /// own `synced = true` — merge must never flip a contact's synced
    /// status to false just because a stale incoming copy said so.
    #[test]
    fn synced_flag_preserved_when_local_wins() {
        let local = state(vec![cnt("addr-a", "Alice (synced)", "", 200, true)], vec![]);
        let incoming = state(vec![cnt("addr-a", "Alice (stale, unsynced)", "", 100, false)], vec![]);
        let merged = merge_state(&local, &incoming, 0);
        assert_eq!(merged.contacts.len(), 1);
        assert!(merged.contacts[0].synced, "local won and must keep its own synced=true");
    }

    /// `synced_only()` keeps only synced contacts, includes ALL tombstones
    /// unconditionally, and preserves original order.
    #[test]
    fn synced_only_excludes_unsynced_contacts() {
        let s = state(
            vec![
                cnt("addr-a", "Synced Alice", "", 1, true),
                cnt("addr-b", "Unsynced Bob", "", 1, false),
                cnt("addr-c", "Synced Carol", "", 1, true),
            ],
            vec![ts("addr-x", "testnet4", 5), ts("addr-b", "", 6)],
        );
        let filtered = s.synced_only();
        assert_eq!(
            filtered.contacts,
            vec![cnt("addr-a", "Synced Alice", "", 1, true), cnt("addr-c", "Synced Carol", "", 1, true)]
        );
        // ALL tombstones included, regardless of whether their contact was
        // ever synced (addr-b's tombstone survives even though addr-b
        // itself was unsynced and filtered out above).
        assert_eq!(filtered.tombstones, s.tombstones);
    }

    /// `synced_only()`'s output is just a `ContactState`, so it round-trips
    /// through the same blob (de)serialization as any other state.
    #[test]
    fn synced_only_output_round_trips_through_blob() {
        let s = state(
            vec![cnt("addr-a", "Synced Alice", "", 1, true), cnt("addr-b", "Unsynced Bob", "", 1, false)],
            vec![ts("addr-old", "mainnet", 42)],
        );
        let filtered = s.synced_only();
        let blob = serialize_contacts_blob(&filtered);
        let back = parse_contacts_blob(&blob);
        assert_eq!(back, filtered);
        assert_eq!(back.contacts.len(), 1);
        assert!(back.contacts[0].synced);
    }
}
