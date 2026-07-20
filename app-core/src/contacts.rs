//! iCloud key-value contacts sync — pure, host-testable helpers only. No
//! platform/Apple deps here (those live in the app crate's `src/icloud.rs`);
//! this module is just the merge rule + the blob (de)serialization shape, so
//! it can be exercised with `cargo test -p app-core`.
//!
//! Contacts are DEVICE-LEVEL (global, shared across every notebook/identity/
//! network on this device — see `State.contacts` in the app crate), and the
//! KV blob mirrors that: ONE JSON array of `{address,name,network}` under
//! the key `contacts-v1`, not a per-notebook map.
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

use crate::store::Contact;

/// Cap applied to a merge result — recents beyond this are noise. Larger
/// than the old per-notebook cap (20) since this is now one device-wide
/// list spanning every notebook/identity/network.
pub const MERGE_CAP: usize = 100;

/// Union two contact lists by (address, network): `local`'s entries come
/// first, in their existing order (this device's own recency ordering is
/// preserved), then any (address, network) pair not already present is
/// appended (in `incoming`'s order). For a pair present in BOTH lists, the
/// local name wins when non-empty — a device keeps its own naming of a
/// contact; the incoming name is adopted only when the local entry is
/// unnamed.
///
/// This means a rename pushed from the OTHER device only propagates to a
/// contact THIS device has never named — acceptable for v1 (documented
/// limitation; a real "last write wins" rename sync would need a
/// timestamp, which the existing `Contact` shape doesn't carry). Likewise
/// a REMOVAL on one device never propagates as a removal on the other —
/// merge is a pure union, so a contact deleted on device A reappears the
/// next time device B's list (still containing it) syncs up; there is no
/// tombstone concept here (v1 limitation, documented for the same reason).
///
/// Deterministic: same inputs always produce the same output. Result is
/// capped at [`MERGE_CAP`].
pub fn merge_contacts(local: &[Contact], incoming: &[Contact]) -> Vec<Contact> {
    let mut out: Vec<Contact> = Vec::with_capacity(local.len() + incoming.len());
    for c in local {
        out.push(c.clone());
    }
    for inc in incoming {
        match out.iter_mut().find(|c| c.address == inc.address && c.network == inc.network) {
            Some(existing) => {
                if existing.name.is_empty() && !inc.name.is_empty() {
                    existing.name = inc.name.clone();
                }
            }
            None => out.push(inc.clone()),
        }
    }
    out.truncate(MERGE_CAP);
    out
}

/// Parse the KV store's single JSON blob (a `Vec<Contact>` array) into
/// contacts. Tolerant by design — the payload can be absent, stale-shaped
/// (an old per-notebook-map version, or a future schema change), or
/// outright garbage (first run, nothing ever written): all of those
/// return an empty list rather than an error, since the caller's merge is
/// a no-op against an empty list and there's nothing sane to surface to
/// the user for a background sync hiccup.
pub fn parse_contacts_blob(blob: &str) -> Vec<Contact> {
    serde_json::from_str(blob).unwrap_or_default()
}

/// Serialize the contact list back to the KV blob's JSON shape.
/// Deterministic (plain array, input order preserved).
pub fn serialize_contacts_blob(contacts: &[Contact]) -> String {
    serde_json::to_string(contacts).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper for tests that don't care about the network tag — both
    /// sides get the same (empty) tag, so tuple equality behaves exactly
    /// like the old address-only key.
    fn c(address: &str, name: &str) -> Contact {
        cn(address, name, "")
    }

    fn cn(address: &str, name: &str, network: &str) -> Contact {
        Contact { address: address.to_string(), name: name.to_string(), network: network.to_string() }
    }

    #[test]
    fn merge_unions_by_address_local_first_then_new_incoming() {
        let local = vec![c("addr-a", "Alice"), c("addr-b", "")];
        let incoming = vec![c("addr-b", ""), c("addr-c", "Carol")];
        let merged = merge_contacts(&local, &incoming);
        assert_eq!(
            merged,
            vec![c("addr-a", "Alice"), c("addr-b", ""), c("addr-c", "Carol")]
        );
    }

    #[test]
    fn merge_prefers_local_nonempty_name_over_incoming() {
        let local = vec![c("addr-a", "Alice (mine)")];
        let incoming = vec![c("addr-a", "Alice (theirs)")];
        let merged = merge_contacts(&local, &incoming);
        assert_eq!(merged, vec![c("addr-a", "Alice (mine)")]);
    }

    #[test]
    fn merge_adopts_incoming_name_when_local_is_unnamed() {
        let local = vec![c("addr-a", "")];
        let incoming = vec![c("addr-a", "Alice")];
        let merged = merge_contacts(&local, &incoming);
        assert_eq!(merged, vec![c("addr-a", "Alice")]);
    }

    #[test]
    fn merge_caps_at_merge_cap_preserving_local_order_first() {
        let local: Vec<Contact> = (0..80).map(|i| c(&format!("local-{i}"), "")).collect();
        let incoming: Vec<Contact> = (0..80).map(|i| c(&format!("incoming-{i}"), "")).collect();
        let merged = merge_contacts(&local, &incoming);
        assert_eq!(merged.len(), MERGE_CAP);
        // Every local entry survives (80 < cap); incoming fills the rest.
        for i in 0..80 {
            assert_eq!(merged[i].address, format!("local-{i}"));
        }
        for i in 0..20 {
            assert_eq!(merged[80 + i].address, format!("incoming-{i}"));
        }
    }

    #[test]
    fn merge_is_deterministic_and_order_stable() {
        let local = vec![c("a", "A"), c("b", "B")];
        let incoming = vec![c("c", "C"), c("a", "ignored")];
        let m1 = merge_contacts(&local, &incoming);
        let m2 = merge_contacts(&local, &incoming);
        assert_eq!(m1, m2);
        assert_eq!(m1, vec![c("a", "A"), c("b", "B"), c("c", "C")]);
    }

    /// Identity is (address, network), not address alone: testnet4 and
    /// signet share the `tb1…` HRP, so the same address string tagged for
    /// each network must survive a merge as TWO distinct contacts, and
    /// each carries its own name independently (no cross-network
    /// clobbering).
    #[test]
    fn merge_keeps_same_address_on_different_networks_distinct() {
        let local = vec![cn("tb1pSHARED", "Testnet Alice", "testnet4")];
        let incoming = vec![cn("tb1pSHARED", "Signet Alice", "signet")];
        let merged = merge_contacts(&local, &incoming);
        assert_eq!(merged.len(), 2, "same address, different networks — must not collapse to one");
        assert!(merged.contains(&cn("tb1pSHARED", "Testnet Alice", "testnet4")));
        assert!(merged.contains(&cn("tb1pSHARED", "Signet Alice", "signet")));

        // Merging again (round 2, roles swapped) must not merge the two
        // network-tagged entries into each other — each keeps its own name.
        let merged2 = merge_contacts(&merged, &merged);
        assert_eq!(merged2, merged);
    }

    #[test]
    fn blob_round_trips_through_parse_and_serialize() {
        let contacts = vec![c("tb1p-alice", "Alice"), c("bc1p-bob", "")];
        let blob = serialize_contacts_blob(&contacts);
        let back = parse_contacts_blob(&blob);
        assert_eq!(back, contacts);
    }

    #[test]
    fn parse_tolerates_garbage_absent_and_stale_shaped_input() {
        assert!(parse_contacts_blob("").is_empty());
        assert!(parse_contacts_blob("not json at all").is_empty());
        assert!(parse_contacts_blob("null").is_empty());
        // A stale per-notebook-map shape (pre-global-contacts) is NOT a
        // Vec<Contact> — must not error, just come back empty.
        assert!(parse_contacts_blob(r#"{"testnet4:aa": [{"address":"x","name":""}]}"#).is_empty());
        assert!(parse_contacts_blob(r#"[{"address":"x","name":"not-a-bool"}, 5]"#).is_empty());
    }

    #[test]
    fn parse_empty_array_is_empty() {
        assert!(parse_contacts_blob("[]").is_empty());
    }
}
