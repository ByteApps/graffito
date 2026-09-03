//! Screen.settings — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// [`load_backend_settings`]'s node-dropdown counterpart to its local
/// `fill` — the node picker gets an extra UI-managed row `fill` doesn't
/// (the explorer picker has no "Bitcoin Core" concept, so it stays on the
/// plain two-row-tail `fill`): `<presets…>, "Bitcoin Core", "Custom…"`.
/// U12 (`PLAN-chain-notes-app-core-rpc.md` §2.5) moves the `bitcoind+`
/// storage prefix out of user-facing text — a stored Core base now selects
/// the dedicated row and displays as bare `host:port` (`display_core_url`),
/// never the raw prefixed string; anything else follows the original
/// preset-or-Custom matching unchanged. Returns
/// `(options, selected_index, esplora_custom_text, core_address_text)` —
/// exactly one of the last two is ever non-empty.
pub(crate) fn fill_node(
    presets: Vec<(&'static str, Option<&'static str>)>,
    cur: Option<&str>,
) -> (Vec<SharedString>, i32, SharedString, SharedString) {
    let mut opts: Vec<SharedString> = presets.iter().map(|(l, _)| (*l).into()).collect();
    let core_row = presets.len();
    let custom_row = presets.len() + 1;
    opts.push("Bitcoin Core".into());
    opts.push("Custom…".into());

    if let Some(u) = cur {
        if u.starts_with("bitcoind+") {
            return (opts, core_row as i32, "".into(), display_core_url(u).into());
        }
    }
    let idx = presets.iter().position(|(_, u)| match (u, cur) {
        (None, None) => true,
        (Some(a), Some(b)) => *a == b,
        _ => false,
    });
    match idx {
        Some(i) => (opts, i as i32, "".into(), "".into()),
        None => (opts, custom_row as i32, cur.unwrap_or("").into(), "".into()),
    }
}

/// Default Bitcoin Core `-rpcport` per network — confirmed against the
/// installed `bitcoind` v30.2.0's own `-help-debug` text: `-rpcport=<port>
/// … (default: 8332, testnet3: 18332, testnet4: 48332, signet: 38332,
/// regtest: 18443)`. This app has no Testnet3 variant.
pub(crate) fn core_rpc_default_port(network: Network) -> u16 {
    match network {
        Network::Mainnet => 8332,
        Network::Testnet4 => 48332,
        Network::Signet => 38332,
        Network::Regtest => 18443,
    }
}

/// Normalize what a person types into the Settings "Bitcoin Core" node-
/// address field into the stored `bitcoind+http(s)://host:port` form (U12,
/// `PLAN-chain-notes-app-core-rpc.md` §2.5) — the ONLY thing that changes is
/// how the field is spelled; `AnyTransport::new`/`node_backend_label` in
/// app-core/src/chain.rs still read/produce exactly this prefix, untouched.
/// Strips inline `user:pass@` userinfo first, same authority-vs-path guard
/// [`split_url_userinfo`] uses (that function needs a `://` to anchor on,
/// so it can't be reused directly on a bare `host` or `host:port` input —
/// this reimplements the same rule on the post-scheme authority instead),
/// and returns it separately so the caller can route it through
/// `route_core_rpc_creds` exactly like a typed credential — a credential
/// pasted here must never reach `config.json` either.
///
/// Accepted shapes (network default port fills in whenever none is given):
///   `host`                   -> `bitcoind+http://host:<default>`
///   `host:port`               -> `bitcoind+http://host:port`
///   `http://host[:port]`      -> `bitcoind+http://host:<port|default>`
///   `https://host[:port]`     -> `bitcoind+https://host:<port|default>`
///   `bitcoind+http(s)://…`    -> re-normalized the same way (paste-tolerant
///                                — a Sparrow-style export, or the app's own
///                                stored string, both still work if pasted)
/// Anything else (empty, a path component, an unsupported scheme, a
/// non-numeric port) is rejected with a message meant to be shown verbatim.
pub(crate) fn compose_core_url(input: &str, network: Network) -> Result<(String, Option<(String, String)>), String> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("enter a host, e.g. 192.168.1.10 or umbrel.local:8332".to_string());
    }
    // Paste-tolerant: a full `bitcoind+…` base (this app's own stored
    // shape, or a Sparrow-style export) re-normalizes the same as a bare
    // host would.
    let raw = raw.strip_prefix("bitcoind+").unwrap_or(raw);
    if raw.is_empty() {
        return Err("enter a host, e.g. 192.168.1.10 or umbrel.local:8332".to_string());
    }

    let (scheme, rest) = if let Some(r) = raw.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = raw.strip_prefix("http://") {
        ("http", r)
    } else if let Some((s, _)) = raw.split_once("://") {
        return Err(format!("unsupported scheme {s:?} — use http:// or https://"));
    } else {
        ("http", raw)
    };

    // Strip inline `user:pass@` userinfo before touching the authority —
    // an '@' that belongs to a path segment is not userinfo (mirrors
    // `split_url_userinfo`'s guard).
    let (authority, creds) = match rest.find('@') {
        Some(at) if !rest[..at].contains('/') => {
            let (userinfo, hostpart) = rest.split_at(at);
            let hostpart = &hostpart[1..]; // drop '@'
            let creds = userinfo.split_once(':').map(|(u, p)| (u.to_string(), p.to_string()));
            (hostpart, creds)
        }
        _ => (rest, None),
    };

    let authority = authority.trim_end_matches('/');
    if authority.is_empty() {
        return Err("enter a host, e.g. 192.168.1.10 or umbrel.local:8332".to_string());
    }
    if authority.contains('/') {
        return Err("node address must be host[:port] only, no path".to_string());
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal, e.g. `[::1]:8332`.
        let Some(end) = rest.find(']') else {
            return Err("unterminated IPv6 literal — missing ']'".to_string());
        };
        let (h, after) = rest.split_at(end);
        if h.is_empty() {
            return Err("enter a host, e.g. 192.168.1.10 or umbrel.local:8332".to_string());
        }
        let after = &after[1..]; // drop ']'
        let port = if after.is_empty() {
            None
        } else if let Some(p) = after.strip_prefix(':') {
            if p.is_empty() {
                return Err("empty port after ':'".to_string());
            }
            Some(p.parse::<u16>().map_err(|_| format!("invalid port {p:?}"))?)
        } else {
            return Err(format!("unexpected text after IPv6 literal: {after:?}"));
        };
        (format!("[{h}]"), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() => {
                let port = p.parse::<u16>().map_err(|_| format!("invalid port {p:?}"))?;
                (h.to_string(), Some(port))
            }
            Some(("", _)) => {
                return Err("enter a host, e.g. 192.168.1.10 or umbrel.local:8332".to_string())
            }
            _ => (authority.to_string(), None),
        }
    };
    let port = port.unwrap_or_else(|| core_rpc_default_port(network));
    Ok((format!("bitcoind+{scheme}://{host}:{port}"), creds))
}

/// The inverse of [`compose_core_url`] for display: a stored `bitcoind+
/// http(s)://host:port` base back into what the node-address field shows —
/// bare `host:port` for the (default) `http` scheme, `https://host:port`
/// when the scheme is `https` (kept explicit so redisplaying then
/// resubmitting the SAME text round-trips to the SAME stored URL — eliding
/// it would silently downgrade an https node back to http on next save).
/// Never called with credentials still embedded: every producer of a stored
/// node URL (`compose_core_url`, `migrate_inline_node_creds`) strips them
/// first, so there is nothing left to redact here.
pub(crate) fn display_core_url(base: &str) -> String {
    let rest = base.strip_prefix("bitcoind+").unwrap_or(base);
    if let Some(host_port) = rest.strip_prefix("http://") {
        host_port.trim_end_matches('/').to_string()
    } else if let Some(host_port) = rest.strip_prefix("https://") {
        format!("https://{}", host_port.trim_end_matches('/'))
    } else {
        rest.to_string()
    }
}

/// Render one [`app_core::chain::NodeStatus`] preflight (plan §2.2/§2.3) as
/// a single honest caption line, plus whether it should use the warning
/// tint. Every condition here is a WARNING, never something this app
/// silently works around or hides — a pruned node's missing history, a
/// missing txindex's degraded sender attribution, and an in-progress
/// rescan (which must never be mistaken for an empty wallet) all get named
/// explicitly. An all-clear reports the tip height so "it's actually
/// talking to your node" is visible too.
///
/// `prune_height` of `0` (or absent while `pruned` is true) means the node
/// is pruned-CAPABLE but hasn't actually deleted any blocks yet — a very
/// common state right after `-prune` is turned on, since Core only starts
/// deleting once it's past its target size. Telling the user "history
/// before block 0 can't be recovered" there is nonsense (nothing is
/// missing) and actively misleading, so that case gets an honest,
/// non-alarming note instead of the strong warning; only a real nonzero
/// prune height gets the "can't be recovered" wording and the warn tint.
pub(crate) fn format_node_status(status: &NodeStatus) -> (String, bool) {
    let mut parts: Vec<String> = Vec::new();
    let mut warn = false;
    if status.pruned {
        match status.prune_height {
            Some(h) if h > 0 => {
                warn = true;
                parts.push(format!(
                    "pruned below block {} — notes/history before it can't be recovered",
                    commas(h)
                ));
            }
            _ => parts.push(
                "pruned-capable — nothing pruned yet, all history still available".to_string(),
            ),
        }
    }
    if !status.txindex {
        warn = true;
        parts.push("no txindex — sender names on external notes may be missing".to_string());
    }
    if status.initial_block_download {
        warn = true;
        parts.push("still syncing to the chain tip (initial block download)".to_string());
    }
    if status.wallet_scanning == Some(true) {
        warn = true;
        parts.push("rescanning — balances/notes may be incomplete until it finishes".to_string());
    }
    if parts.is_empty() {
        parts.push(format!("connected · tip {}", commas(status.tip_height)));
    }
    // `parts` never contains an empty string, but filter defensively so a
    // future condition that pushes "" can never leave a dangling `· `
    // separator in the joined caption.
    (
        parts.into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join(" · "),
        warn,
    )
}

/// Task #14: one PENDING record's dropped-check inputs, snapshotted on the
/// UI thread (cheap field reads) before handing off to a worker that does
/// the actual HTTP round trips. `current_txid` is the record's LATEST txid
/// (an RBF bump supersedes the original — only the current attempt going
/// missing counts as "dropped"); `first_input` is what
/// `ChainClient::outpoint_unspent` checks.
pub(crate) struct DroppedCheck {
    pub(crate) current_txid: String,
    pub(crate) first_input: (String, u32),
}

/// Pure form of `State::core_rpc_should_persist`: default true (an absent
/// entry — every pre-U10 config, and every network nobody has touched the
/// switch for) else whatever was explicitly stored. A free function so the
/// default rule is testable without constructing a `State` (plan §2.4 /
/// U10).
pub(crate) fn core_rpc_persist_default_true(save_creds: &HashMap<String, bool>, network_key: &str) -> bool {
    save_creds.get(network_key).copied().unwrap_or(true)
}

/// Parse the "Save credentials" per-network preference map out of a loaded
/// config.json `Value` — mirrors the boot loader's `str_map` closure for
/// `node_urls`/`explorers` but for booleans, factored into a free function
/// so the config round-trip is unit-testable (plan §2.4 / U10). An absent
/// or malformed key yields an empty map, matching `core_rpc_persist_default_true`'s
/// default-true-when-absent behavior for every entry.
pub(crate) fn parse_core_rpc_save_creds(config: &serde_json::Value) -> HashMap<String, bool> {
    config
        .get("core_rpc_save_creds")
        .and_then(|v| v.as_object())
        .map(|o| o.iter().filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b))).collect())
        .unwrap_or_default()
}

/// Pure decision: resolve Bitcoin Core RPC credentials for a `base` given
/// the "Save credentials" switch state and both possible sources —
/// extracted from [`core_rpc_creds_for`] so the switch logic is testable
/// without a live Keychain (plan §2.4 / U10). A non-`bitcoind+` base always
/// resolves to `None`, regardless of either input (Esplora never touches
/// either source). Otherwise: `persist == true` returns whatever the
/// Keychain lookup found (today's unconditional behavior, byte-identical
/// for every user who never touches the new switch); `persist == false`
/// returns the in-session slot instead — the Keychain is not consulted at
/// all in that branch, by construction of the caller only doing the lookup
/// when `persist` is true (see `core_rpc_creds_for`).
pub(crate) fn resolve_core_rpc_creds(
    base: &str,
    persist: bool,
    keychain_creds: Option<(String, String)>,
    session_creds: Option<(String, String)>,
) -> Option<(String, String)> {
    if !base.starts_with("bitcoind+") {
        return None;
    }
    if persist { keychain_creds } else { session_creds }
}

/// Where a freshly typed/pasted RPC credential is written, given the
/// current "Save credentials" switch state (plan §2.4 / U10) — shared by
/// `on_set_node_core_creds` and `on_set_node_custom`'s inline-userinfo
/// path so a pasted `user:pass@host` can't become a persisted credential
/// behind the user's back just because it arrived via a different field.
/// `store`/`delete` are the Keychain operations, injected so this is
/// testable without a live Keychain: for `persist == false` neither is
/// ever called — the credential goes straight into `session_creds`
/// instead, and clearing both fields removes the session entry the same
/// way it deletes the Keychain item on the `persist == true` side.
pub(crate) fn route_core_rpc_creds(
    persist: bool,
    network_key: &str,
    user: &str,
    pass: &str,
    session_creds: &mut HashMap<String, (String, Zeroizing<String>)>,
    store: impl FnOnce(&str, &str) -> Result<(), String>,
    delete: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if persist {
        if user.is_empty() && pass.is_empty() { delete() } else { store(user, pass) }
    } else {
        if user.is_empty() && pass.is_empty() {
            session_creds.remove(network_key);
        } else {
            session_creds
                .insert(network_key.to_string(), (user.to_string(), Zeroizing::new(pass.to_string())));
        }
        Ok(())
    }
}

/// Core logic for flipping the "Save credentials" switch for one network —
/// factored out of the `on_set_node_core_save_creds` UI callback so the
/// ON→OFF deletion (design invariant: leaving a stale secret behind after
/// the user says "don't save" is worse than not having the feature) is
/// testable without a live Keychain. `delete`/`store` are injected exactly
/// like [`route_core_rpc_creds`]. Turning OFF unconditionally deletes
/// whatever the Keychain holds for this network and returns the fields
/// currently on screen so the caller can seed the session slot with them
/// (continuity — the user doesn't lose what they just typed, only where
/// it lives); turning ON persists those same fields if either is non-empty
/// and returns `None` (nothing left to hold in session). Returns the
/// delete/store `Err` untouched so the caller can revert the UI toggle
/// rather than claim success.
pub(crate) fn apply_core_rpc_persist_toggle(
    enabled: bool,
    current_user: &str,
    current_pass: &str,
    delete: impl FnOnce() -> Result<(), String>,
    store: impl FnOnce(&str, &str) -> Result<(), String>,
) -> Result<Option<(String, Zeroizing<String>)>, String> {
    if enabled {
        if !current_user.is_empty() || !current_pass.is_empty() {
            store(current_user, current_pass)?;
        }
        Ok(None)
    } else {
        delete()?;
        if current_user.is_empty() && current_pass.is_empty() {
            Ok(None)
        } else {
            Ok(Some((current_user.to_string(), Zeroizing::new(current_pass.to_string()))))
        }
    }
}

/// Strip an inline `user:pass@` userinfo out of a node URL before it can
/// reach `config.json`, a `cb:` log line, or the Settings text field (plan
/// §2.4 — "the stored node URL must contain NO credentials"). Handles both
/// `bitcoind+http(s)://user:pass@host:port` (the Sparrow-style paste this
/// app's Custom field should tolerate) and a plain `http(s)://` Esplora URL
/// (unusual, but stripping it is still correct — this app never sends an
/// Esplora request with basic auth). Returns the creds-free URL plus the
/// parsed `(user, pass)` if any were present.
pub(crate) fn split_url_userinfo(url: &str) -> (String, Option<(String, String)>) {
    let Some(scheme_end) = url.find("://") else { return (url.to_string(), None) };
    let (scheme, rest) = url.split_at(scheme_end + 3);
    let Some(at) = rest.find('@') else { return (url.to_string(), None) };
    // An '@' that belongs to a PATH segment (after the authority) is not
    // userinfo — bail rather than mis-parse.
    if rest[..at].contains('/') {
        return (url.to_string(), None);
    }
    let (userinfo, hostpart) = rest.split_at(at);
    let hostpart = &hostpart[1..]; // drop the '@' itself
    let creds = userinfo.split_once(':').map(|(u, p)| (u.to_string(), p.to_string()));
    (format!("{scheme}{hostpart}"), creds)
}

/// U11 defense-in-depth: `on_set_node_custom`'s inline-userinfo stripping
/// only ran on a URL typed/pasted THIS session — a `config.json` already
/// on disk (hand-edited, migrated from an older build, or written before
/// that stripping shipped) can still carry `bitcoind+http://user:pass@
/// host:port` verbatim, and would otherwise be loaded, used, and displayed
/// in the Settings field with the credential in plain sight. Applies
/// [`split_url_userinfo`] to every entry of a just-loaded `node_urls` map,
/// rewriting it in place to the creds-free form, and returns the
/// `(network, user, pass)` triples found — in the SAME shape
/// `on_set_node_custom` routes through `route_core_rpc_creds`, so the
/// caller can treat a migrated credential exactly like a freshly typed
/// one. Pure / host-testable; does not touch the Keychain (the boot path
/// must make zero Keychain calls — see `flush_core_rpc_migration`).
pub(crate) fn migrate_inline_node_creds(node_urls: &mut HashMap<String, String>) -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for (net, url) in node_urls.iter_mut() {
        let (clean, creds) = split_url_userinfo(url);
        if let Some((user, pass)) = creds {
            found.push((net.clone(), user, pass));
            *url = clean;
        }
    }
    found
}

/// Snapshot every PENDING record (sweep/consolidate txs AND notes) in
/// `store` into the (current-txid, first-input) pairs a worker thread needs
/// — shared by both the async and synchronous refresh paths so they exhibit
/// identical dropped-detection behavior.
pub(crate) fn gather_dropped_checks(store: &Store) -> Vec<DroppedCheck> {
    let tx_checks = store.txs.iter().filter(|t| t.status == NoteStatus::Pending).filter_map(|t| {
        let current_txid = t.txids.last()?.clone();
        let first = t.inputs.first()?;
        Some(DroppedCheck { current_txid, first_input: (first.txid.clone(), first.vout) })
    });
    let note_checks = store.notes.iter().filter(|n| n.status == NoteStatus::Pending).filter_map(|n| {
        let current_txid = n.txids.last()?.clone();
        let first = n.spent.first()?;
        Some(DroppedCheck { current_txid, first_input: (first.txid.clone(), first.vout) })
    });
    tx_checks.chain(note_checks).collect()
}

/// The worker-thread half of task #14: run `checks` (see
/// [`gather_dropped_checks`]) against a live `client`, returning the two
/// maps `RefreshResult` carries — `tx_lookup_status` once per DISTINCT
/// current txid, `outpoint_unspent` only for the ones that came back
/// `NotFound` (the common "still pending"/"confirmed" cases never pay for
/// the extra round trip).
pub(crate) fn fetch_dropped_checks(
    client: &ChainClient<AnyTransport>,
    address: &str,
    checks: &[DroppedCheck],
) -> (HashMap<String, TxLookupStatus>, HashMap<(String, u32), bool>) {
    let mut lookup = HashMap::new();
    let mut unspent = HashMap::new();
    for c in checks {
        let status = *lookup
            .entry(c.current_txid.clone())
            .or_insert_with(|| client.tx_lookup_status(&c.current_txid));
        if status == TxLookupStatus::NotFound {
            unspent.entry(c.first_input.clone()).or_insert_with(|| {
                client
                    .outpoint_unspent(address, &c.first_input.0, c.first_input.1)
                    .unwrap_or(false)
            });
        }
    }
    (lookup, unspent)
}

/// The UI-thread half: apply the two maps `fetch_dropped_checks` gathered
/// against `store`'s pending txs AND notes, logging `cb: tx-dropped
/// txid=<t>` once per NEW transition into dropped (task #14's log
/// contract).
pub(crate) fn apply_dropped_checks(
    store: &mut Store,
    lookup: &HashMap<String, TxLookupStatus>,
    unspent: &HashMap<(String, u32), bool>,
) {
    let lookup_fn = |txid: &str| lookup.get(txid).copied().unwrap_or(TxLookupStatus::Unknown);
    let unspent_fn = |_addr: &str, txid: &str, vout: u32| {
        unspent.get(&(txid.to_string(), vout)).copied()
    };
    let mut newly = store.resolve_dropped_tx(lookup_fn, unspent_fn);
    newly.extend(store.resolve_dropped_notes(lookup_fn, unspent_fn));
    for txid in newly {
        println!("cb: tx-dropped txid={txid}");
    }
}

impl State {
/// Populate the Settings node + explorer dropdown models, selected indices,
/// and custom-URL text from the device-level config (this network's entry).
/// The value is matched against the network's presets; a non-preset value
/// selects the trailing "Custom…" row and prefills its text field. An absent
/// entry (None) matches the first preset (mempool.space, the network default).
pub(crate) fn load_backend_settings(&self, w: &AppWindow) {
    let st = self;
    fn fill(
        presets: Vec<(&'static str, Option<&'static str>)>,
        cur: Option<&str>,
    ) -> (Vec<SharedString>, i32, SharedString) {
        let mut opts: Vec<SharedString> = presets.iter().map(|(l, _)| (*l).into()).collect();
        opts.push("Custom…".into());
        let idx = presets
            .iter()
            .position(|(_, u)| match (u, cur) {
                (None, None) => true,
                (Some(a), Some(b)) => *a == b,
                _ => false,
            })
            .unwrap_or(presets.len());
        let custom = if idx == presets.len() { cur.unwrap_or("") } else { "" };
        (opts, idx as i32, custom.into())
    }

    let net = st.network;
    let (n_opts, n_idx, n_custom, n_core_addr) =
        fill_node(node_presets(net), st.node_urls.get(net.as_str()).map(String::as_str));
    w.global::<Ui>().set_node_options(VecModel::from_slice(&n_opts));
    w.global::<Ui>().set_node_index(n_idx);
    w.global::<Settings>().set_node_custom_text(n_custom);
    w.global::<Ui>().set_node_address_text(n_core_addr);

    let (e_opts, e_idx, e_custom) =
        fill(explorer_presets(net), st.explorers.get(net.as_str()).map(String::as_str));
    w.global::<Settings>().set_explorer_options(VecModel::from_slice(&e_opts));
    w.global::<Settings>().set_explorer_index(e_idx);
    w.global::<Settings>().set_explorer_custom_text(e_custom);
}

/// Populate the Bitcoin Core section of the node card (backend label + RPC
/// credential fields) from the CURRENT node config — called only from
/// Settings interactions (open, or a node/credentials edit while Settings
/// is open), never from `update_home`/the refresh paths, which call
/// [`load_backend_settings`] above on every repaint. That separation is
/// what keeps RPC-credential Keychain reads off the hot path: this is the
/// "Settings opened" lazy-load point the plan's §2.4 asks for
/// (`PLAN-chain-notes-app-core-rpc.md`), not something that runs on boot or
/// on every scan.
pub(crate) fn update_node_backend_ui(&self, w: &AppWindow) {
    let st = self;
    let base = st.base_url();
    let is_core = base.as_deref().is_some_and(|b| b.starts_with("bitcoind+"));
    w.global::<Ui>().set_node_is_core(is_core);
    w.global::<Ui>().set_node_backend_label(base.as_deref().map(node_backend_label).unwrap_or("Esplora").into());
    // "Save credentials" switch (plan §2.4 / U10): a device-level per-network
    // preference, so it's meaningful even for an Esplora base (set it before
    // the early return) — the user may flip it before ever pointing at a
    // Core node.
    let persist = st.core_rpc_should_persist(st.network);
    w.global::<Settings>().set_node_core_save_creds(persist);
    if !is_core {
        // Only the HEALTH line is about the active backend. The credential
        // fields are NOT: U12 reveals them as soon as "Bitcoin Core" is
        // picked in the dropdown (`node-core-row-selected`), which is
        // before any address has been submitted — so `is_core` is still
        // false while the user is filling them in. Blanking them here
        // wiped what they had just typed the moment anything called this,
        // most visibly the "Save credentials" button (Sal 2026-08-01):
        // it saves, then refreshes health, and the refresh emptied both
        // fields even though the save had succeeded.
        w.global::<Settings>().set_node_health_text("".into());
        w.global::<Ui>().set_node_health_warn(false);
    }
    // Credentials are per-NETWORK and independent of which backend is
    // currently active, so they are resolved the same way either way.
    // Safe w.r.t. the zero-launch-path-keychain-calls rule: every caller of
    // this function is a Settings tap (settings-open, the node preset /
    // address / custom-URL handlers, and the two credential callbacks) —
    // none runs before the first frame.
    if persist {
        match keychain::load_rpc_creds(st.network.as_str()) {
            Ok(Some((user, pass))) => {
                w.global::<Settings>().set_node_core_user(user.into());
                w.global::<Settings>().set_node_core_pass(pass.into());
            }
            Ok(None) => {
                w.global::<Settings>().set_node_core_user("".into());
                w.global::<Settings>().set_node_core_pass("".into());
            }
            Err(e) => {
                // Never expected — this item carries no ACL — but degrade to
                // blank fields rather than propagate a Keychain error into
                // Settings; the user can just retype credentials.
                println!("cb: rpc-creds load err={e}");
                w.global::<Settings>().set_node_core_user("".into());
                w.global::<Settings>().set_node_core_pass("".into());
            }
        }
    } else {
        // Switch OFF: the Keychain is never consulted — fields reflect
        // whatever this session's in-memory slot holds (empty if nothing
        // was typed yet since launch).
        match st.core_rpc_session_creds.get(st.network.as_str()) {
            Some((user, pass)) => {
                w.global::<Settings>().set_node_core_user(user.clone().into());
                w.global::<Settings>().set_node_core_pass(pass.to_string().into());
            }
            None => {
                w.global::<Settings>().set_node_core_user("".into());
                w.global::<Settings>().set_node_core_pass("".into());
            }
        }
    }
}

/// Preflight a configured Bitcoin Core node (plan §2.2/§2.3/U4,
/// `CoreRpcTransport::preflight`) and render it honestly in Settings — a
/// bonus courtesy, never a gate: the user is never blocked from proceeding
/// on a pruned/scanning/no-txindex node, only told about it. A no-op for an
/// Esplora base (`update_node_backend_ui` clears the health line and
/// returns before any network call). Runs on a worker thread exactly like
/// the account-picker's used/new probe (`show_notebook_picker`) — a
/// one-off user-facing check, not a scan-lane job. Also the U11 lazy point
/// for `flush_core_rpc_migration` — a config.json loaded with an inline
/// credential still on it (see `migrate_inline_node_creds`) gets that
/// credential routed to the Keychain/session slot here, never on the
/// launch path.
pub(crate) fn refresh_node_health(&mut self, w: &AppWindow) {
    let st = self;
    st.flush_core_rpc_migration();
    st.update_node_backend_ui(w);
    let Some(base) = st.base_url() else { return };
    if !base.starts_with("bitcoind+") {
        return;
    }
    let network = st.network;
    // Honest UI when credentials are missing (plan §2.4 / U10 design point
    // 5): with nothing to authenticate with, don't dial the node and let it
    // 401 into a generic "couldn't reach the node" line — say so directly.
    // Covers both the OFF-and-nothing-typed-this-session case and the
    // pre-existing ON-but-never-saved case identically.
    let creds = st.core_rpc_creds_for(&base, network);
    if creds.is_none() {
        w.global::<Settings>().set_node_health_text("enter RPC credentials to connect".into());
        w.global::<Ui>().set_node_health_warn(true);
        return;
    }
    w.global::<Settings>().set_node_health_text("checking node…".into());
    w.global::<Ui>().set_node_health_warn(false);
    let weak = w.as_weak();
    std::thread::spawn(move || {
        let _net_guard = NetOpGuard::new(weak.clone());
        let (text, warn) = match open_client(&base, network, creds) {
            Ok(client) => match &client.transport {
                AnyTransport::Core(t) => match t.preflight() {
                    Ok(status) => format_node_status(&status),
                    Err(e) => (format!("couldn't reach the node — {e}"), true),
                },
                // Unreachable: `base` was checked above to start with
                // "bitcoind+", which `AnyTransport::new` always maps to Core.
                AnyTransport::Esplora(_) => (String::new(), false),
            },
            Err(e) => (format!("couldn't reach the node — {e}"), true),
        };
        let r = NodeHealthResult { network, base: base.clone(), text: text.into(), warn };
        post(&weak, move |w, st| st.apply_node_health_result(w, r));
    });
}

pub(crate) fn update_settings_identity(&self, w: &AppWindow) {
    let st = self;
    let policy = st.lock_time_policy;
    w.global::<Settings>().set_locktime_mode(policy.as_str().into());
    w.global::<Settings>().set_locktime_text(st.lock_time().to_string().into());
    w.global::<Settings>().set_locktime_effective(
        locktime_caption(policy, st.store.as_ref().map(|s| s.tip_height)).into(),
    );
    w.global::<Settings>().set_settings_network(st.network.as_str().into());
    // Runs on every activate, including the import paths that never paint
    // home — see `update_identity_flags`.
    st.update_identity_flags(w);
    // Audit M2: surface a key-protection downgrade instead of letting it pass
    // silently. Recomputed here because this runs after every activate /
    // identity change, which is exactly when the answer can change.
    w.global::<Settings>().set_key_protection_degraded(st.ident.is_some() && keychain::protection_degraded());
    w.global::<Settings>().set_settings_hierarchical(
        st.material
            .as_deref()
            .map(|m| is_hierarchical(m, st.network))
            .unwrap_or(false),
    );
    if let Some(i) = &st.ident {
        let (active_n, archived_n) = st
            .notebooks
            .as_ref()
            .map(|ix| (ix.active(st.account).count(), ix.archived_count(st.account)))
            .unwrap_or((0, 0));
        let acct_part = if st
            .material
            .as_deref()
            .map(|m| is_hierarchical(m, st.network))
            .unwrap_or(false)
        {
            format!(" · account {}", st.account)
        } else {
            String::new()
        };
        w.global::<Settings>().set_settings_identity(
            format!(
                "{}{} · {}{acct_part} · {} notebook{}{}",
                i.kind,
                if i.is_watch() { " · watch-only" } else { "" },
                st.network.as_str(),
                active_n,
                if active_n == 1 { "" } else { "s" },
                if archived_n > 0 { format!(" ({archived_n} archived)") } else { String::new() }
            )
            .into(),
        );
    }
    if let Some(store) = &st.store {
        w.global::<Settings>().set_chunk_text(store.chunk_size.to_string().into());
    }
}

/// Identity-derived UI flags, refreshed on EVERY path that activates an
/// identity — not only the ones that paint home.
///
/// These lived in `update_home` alone, which meant they went stale after a
/// hierarchical seed import: `go_home_or_list` only calls `update_home` when
/// the notebook is already listed, and multi-notebook material deliberately
/// is not listed at import time, so the import landed on the notebook LIST
/// with both flags at their `false` defaults. Visible fallout: Settings hid
/// "Public keys" until the user opened a notebook once, and — worse — a
/// watch-only ranged xpub (also multi-notebook) left `watch-only` false, so
/// the UI offered "Private keys" and the compose surfaces for an identity
/// that has no private key. The Rust callbacks gate on `AppIdentity::full()`
/// so nothing could actually be signed, but the affordances should not have
/// been there. Boot was always fine — it calls `update_home` before landing.
pub(crate) fn update_identity_flags(&self, w: &AppWindow) {
    let st = self;
    let Some(ident) = &st.ident else { return };
    w.global::<Ui>().set_watch_only(ident.is_watch());
    // Single-key imports (wif/hex) have no account-level public material —
    // no xpub/descriptor to export — so hide the "Public keys" entry rather
    // than route to a dead-end hint (mirrors hiding Private for watch-only).
    w.global::<Settings>().set_reveal_can_public(!matches!(ident.kind, "wif" | "hex"));
}

/// Source Bitcoin Core RPC credentials for a `bitcoind+` base, honoring the
/// per-network "Save credentials" switch (`State::core_rpc_should_persist`,
/// plan §2.4 / U10). ON (the default — every pre-U10 install and every
/// network nobody has touched the switch for) reads the Keychain lazily,
/// exactly as before: this runs on every call, i.e. on every network
/// request against a Core backend, NOT once at boot or once at
/// Settings-open — deliberately, so caching the credential in `State`
/// itself never becomes tempting (the mistake that cost two shipped builds
/// on the identity item, builds 42/44). A plain, no-ACL keychain read has
/// no prompt to block on, so re-reading per request costs a little I/O and
/// nothing else. OFF reads the session-only slot on `State` instead and
/// the Keychain is never touched. Never called for an Esplora base (this
/// function's first check short-circuits before either source is
/// consulted). A Keychain error (never expected — this item carries no
/// ACL) degrades to no creds rather than failing the request outright; an
/// auth-required node then answers 401, which the caller already surfaces
/// as an ordinary network error — never a panic, never a credential in a
/// log line either way.
pub(crate) fn core_rpc_creds_for(&self, base: &str, network: Network) -> Option<(String, String)> {
    let st = self;
    if !base.starts_with("bitcoind+") {
        return None;
    }
    let persist = st.core_rpc_should_persist(network);
    let keychain_creds =
        if persist { keychain::load_rpc_creds(network.as_str()).ok().flatten() } else { None };
    let session_creds = if !persist {
        st.core_rpc_session_creds.get(network.as_str()).map(|(u, p)| (u.clone(), p.to_string()))
    } else {
        None
    };
    resolve_core_rpc_creds(base, persist, keychain_creds, session_creds)
}

/// The Keychain-touching follow-through to [`migrate_inline_node_creds`]:
/// route every network in `core_rpc_migrate_pending` to the Keychain (if
/// that network's "Save credentials" switch is on) or leave it in the
/// session-only slot (if it's off) — exactly like `on_set_node_custom`'s
/// inline-creds branch, reusing the same [`route_core_rpc_creds`]. Called
/// from `refresh_node_health`, which only ever runs from a Settings-screen
/// UI callback — NEVER the launch path, so a migrated credential's
/// Keychain write happens well after the first frame, never during boot
/// (the same "defer to a lazy point" rule U6/U10 already follow for their
/// own Keychain calls). A no-op (drains nothing) once the pending set is
/// empty, so repeat calls from every `refresh_node_health` invocation cost
/// nothing.
pub(crate) fn flush_core_rpc_migration(&mut self) {
    let s = self;
    if s.core_rpc_migrate_pending.is_empty() {
        return;
    }
    let pending: Vec<String> = s.core_rpc_migrate_pending.drain().collect();
    for net in pending {
        let Some((user, pass)) =
            s.core_rpc_session_creds.get(&net).map(|(u, p)| (u.clone(), p.to_string()))
        else {
            continue;
        };
        let persist = core_rpc_persist_default_true(&s.core_rpc_save_creds, &net);
        let net_for_store = net.clone();
        let result = route_core_rpc_creds(
            persist,
            &net,
            &user,
            &pass,
            &mut s.core_rpc_session_creds,
            |u, p| keychain::store_rpc_creds(&net_for_store, u, p),
            || Ok(()), // never reached: user/pass are non-empty by construction
        );
        match result {
            Ok(()) => {
                // route_core_rpc_creds only touches session_creds on the
                // persist==false branch — a successful persist==true store
                // leaves our load-time stash sitting in memory uselessly
                // (never read once persisted — see `core_rpc_creds_for`),
                // so drop it explicitly, same as `on_set_node_core_save_creds`
                // does on its own ON transition.
                if persist {
                    s.core_rpc_session_creds.remove(&net);
                }
                println!("cb: core-rpc-migrate net={net} persist={persist} ok");
            }
            Err(e) => println!("cb: core-rpc-migrate net={net} persist={persist} err={e}"),
        }
    }
}
}

impl State {
pub(crate) fn on_set_spending_enabled(&mut self, w: &AppWindow, on: bool) {
        println!("cb: set-spending enabled={on}");
        if let Some(store) = self.store.as_mut() {
            store.spending_set_enabled(on);
        }
        self.save_spending();
        self.update_spending_ui(w);
        if on && !self.spending_scanned {
            self.spending_refresh_async(w);
        }
    }

pub(crate) fn on_spending_refresh(&mut self, w: &AppWindow) {
        self.spending_refresh_async(w);
    }

pub(crate) fn on_open_coins(&mut self, w: &AppWindow) {
        println!("cb: open-coins");
        self.update_home(w);
        self.update_spending_ui(w);
        if w.global::<Ui>().get_coins_segment() == "spending" && self.spending_capable && !self.spending_scanned {
            self.spending_refresh_async(w);
        }
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::Coins);
    }

pub(crate) fn on_open_source(&mut self, _w: &AppWindow) {
        println!("cb: open-source");
        let _ = platform::open_url(SOURCE_URL);
    }

pub(crate) fn on_sweep_open(&mut self, w: &AppWindow) {
        println!("cb: sweep-open");
        // The send-to picker's sweep entry lands on screen 16 (fee tiers
        // shown) once a destination is picked — lazily (re)fetch here so
        // it's ready by then (network-efficiency, 2026-07-23).
        self.refresh_fees_price(w);
        self.pending_spending_sweep_index = None; // a fresh manual pick, not the spending-wallet shortcut
        // A wallet sweep's inputs include spending-wallet coins — ALWAYS kick
        // a fresh scan here (not just when never-scanned). A prior scan can be
        // stale: coins may have arrived since, or gap-discovery may not have
        // reached the funded index yet, which showed ONLY notebook coins in
        // the sweep preview until the user backed out and re-entered. The scan
        // runs while the user is on the picker; apply_spending_refresh_result
        // repaints screen 16 with the spending coins when it lands.
        if self.spending_capable
            && self.store.as_ref().map(|st| st.spending.enabled).unwrap_or(false)
        {
            self.spending_refresh_async(w);
        }
        w.global::<Ui>().set_sweep_kind("sweep".into());
        w.global::<Ui>().set_pick_mode("sweep".into());
        self.pull_icloud_contacts_on_open(w);
        w.global::<Ui>().set_contact_input("".into());
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_screen(Screen::Contacts);
    }

pub(crate) fn on_spending_sweep_here(&mut self, w: &AppWindow) {
        self.ensure_spending_source();
        let Some(src) = self.spending_source.clone() else {
            w.global::<Ui>().set_status("spending wallet unavailable for this identity".into());
            return;
        };
        let Some(idx) = self.store.as_ref().map(|st| st.spending.next_receive) else { return };
        let Ok(d) = src.derive(0, idx) else { return };
        self.pending_spending_sweep_index = Some(idx);
        w.global::<Ui>().set_sweep_kind("sweep".into());
        w.global::<Ui>().set_pick_mode("sweep".into());
        self.set_sweep_dest(w, d.address);
    }

pub(crate) fn on_open_info(&mut self, w: &AppWindow, kind: slint::SharedString) {
        let (title, body): (&str, String) = match kind.as_str() {
            "about" => ("About", about_body()),
            "privacy" => ("Privacy", PRIVACY.to_string()),
            "help" => ("Help", HELP.to_string()),
            "faq" => ("Q & A", FAQ.to_string()),
            // Terms & disclaimer re-views through the SAME info screen (25) as
            // the others, so Settings sub-screens share one scroll-top UX. The
            // centered screen 24 is now purely the first-run accept gate.
            "terms" => ("Terms & disclaimer", DISCLAIMER.to_string()),
            _ => return,
        };
        w.global::<Info>().set_info_title(title.into());
        w.global::<Info>().set_info_body(body.as_str().into());
        // The Slint attribution rides the About entry only. Section 2 of the
        // Slint Royalty-free license makes it a condition of the grant, so
        // this flag is load-bearing, not cosmetic — see THIRD-PARTY.md.
        w.global::<Info>().set_info_show_slint(kind.as_str() == "about");
        w.global::<Ui>().set_screen(Screen::Info);
        println!("cb: open-info {kind}");
    }

pub(crate) fn on_open_account_picker(&mut self, w: &AppWindow) {
        let Some(material) = self.material.as_ref().map(|z| String::from(z.as_str())) else { return };
        println!("cb: account-picker open");
        let page = self.account / 5;
        w.global::<AccountPicker>().set_account_pick_mode("switch".into());
        show_account_picker(w, &material, self.network, page, Some(self.account));
    }

pub(crate) fn on_set_network(&mut self, w: &AppWindow, net: SharedString) {
        let Some(n) = Network::from_str_opt(net.as_str()) else { return };
        if n == self.network {
            return;
        }
        self.network = n;
        println!("cb: set-network {}", self.network.as_str());
        self.save_config();
        // Notebooks are PER-NETWORK (`notebooks-<net>-<fp8>.json`), so a
        // network is a wallet context exactly like an account is — reset to
        // notebook 0 the same way the Settings account switch does, or the
        // active index would carry over to a chain that may not list it.
        self.nb_index = 0;
        // Same key material, new network: re-derive + reload store.
        let material = std::env::var("APP_KEY")
            .ok()
            .or_else(|| self.material.as_ref().map(|z| String::from(z.as_str())));
        if let Some(m) = material {
            match self.activate(&m, false) {
                Ok(()) => {
                    // A network this key has never touched starts with an
                    // EMPTY index, so the switch used to land on an empty
                    // notebook list (Sal 2026-08-01). Auto-create its first
                    // notebook, same guard and same wording as the account
                    // switch above. Safe w.r.t. gap discovery: activate()
                    // already decided `discovery_pending` from whether the
                    // index FILE existed, so writing an entry now cannot
                    // suppress the probe that recovers a used seed's other
                    // notebooks — it just means index 0 is listed first.
                    let empty = self
                        .notebooks
                        .as_ref()
                        .map(|ix| ix.active(self.account).count() == 0)
                        .unwrap_or(true);
                    if empty {
                        self.ensure_first_onboarded_notebook();
                    }
                    self.update_home(w);
                    self.update_notebook_list(w);
                    self.refresh_async(w);
                    self.spending_refresh_async(w); // CHANGE 5
                }
                Err(e) => w.global::<Ui>().set_status(format!("network switch: {e}").into()),
            }
        }
        w.global::<Settings>().set_settings_network(self.network.as_str().into());
    }

pub(crate) fn on_set_chunk(&mut self, w: &AppWindow, t: SharedString) {
        match t.trim().parse::<usize>() {
            Ok(n) if (20..=100_000).contains(&n) => {
                if let Some(store) = &mut self.store {
                    store.chunk_size = n;
                }
                self.save_store();
                self.chunk = Some(n); // device-level: every notebook, on activate
                self.save_config();
                println!("cb: set-chunk-size {n} ok");
                w.global::<Settings>().set_chunk_text(n.to_string().into());
                if n == 100_000 || n == 80 {
                    w.global::<Settings>().set_chunk_custom(false);
                }
                w.global::<Ui>().set_status("".into());
            }
            _ => {
                println!("cb: set-chunk-size err=range");
                w.global::<Ui>().set_status("chunk bytes must be 20..=100000".into());
            }
        }
    }

pub(crate) fn on_set_locktime(&mut self, w: &AppWindow, mode: SharedString, height: SharedString) {
        let policy = parse_locktime_mode(mode.as_str(), height.as_str());
        let Some(policy) = policy else {
            println!("cb: set-locktime err=range");
            w.global::<Ui>().set_status("locktime must be a block height below 500000000".into());
            return;
        };
        self.lock_time_policy = policy;
        if let Some(store) = &mut self.store {
            store.lock_time = policy; // device-level: every notebook, on activate
        }
        self.save_store();
        self.save_config();
        let effective = self.lock_time();
        println!("cb: set-locktime {} effective={effective} ok", policy.as_str());
        w.global::<Settings>().set_locktime_mode(policy.as_str().into());
        w.global::<Settings>().set_locktime_text(effective.to_string().into());
        w.global::<Settings>().set_locktime_effective(locktime_caption(policy, self.store.as_ref().map(|st| st.tip_height)).into());
        w.global::<Ui>().set_status("".into());
    }

pub(crate) fn on_set_node_preset(&mut self, w: &AppWindow, i: i32) {
        let net = self.network.as_str().to_string();
        let presets = node_presets(self.network);
        let i = i as usize;
        if i < presets.len() {
            match presets[i].1 {
                Some(url) => { self.node_urls.insert(net, url.to_string()); }
                None => { self.node_urls.remove(&net); }
            }
            self.save_config();
            println!("cb: set-node-preset {}", presets[i].0);
        } else if i == presets.len() {
            println!("cb: set-node-preset core");
        } else {
            println!("cb: set-node-preset custom");
        }
        w.global::<Ui>().set_status("".into());
        // Every preset is Esplora — this both clears a previously-active
        // Core node's credential fields/health line and is a no-op (no
        // network call) whenever the picker was already on Esplora.
        self.refresh_node_health(w);
    }

pub(crate) fn on_set_node_address(&mut self, w: &AppWindow, t: SharedString) {
        let net = self.network.as_str().to_string();
        match compose_core_url(t.trim(), self.network) {
            Ok((v, inline_creds)) => {
                self.node_urls.insert(net.clone(), v.clone());
                self.save_config();
                println!("cb: set-node-address {v}");
                if let Some((user, pass)) = &inline_creds {
                    let persist = self.core_rpc_should_persist(self.network);
                    let result = route_core_rpc_creds(
                        persist,
                        &net,
                        user,
                        pass,
                        &mut self.core_rpc_session_creds,
                        |u, p| keychain::store_rpc_creds(&net, u, p),
                        || keychain::delete_rpc_creds(&net),
                    );
                    match result {
                        Ok(()) => println!(
                            "cb: set-node-address inline-creds redacted stored=ok persist={persist}"
                        ),
                        Err(e) => {
                            println!("cb: set-node-address inline-creds redacted stored=err ({e})")
                        }
                    }
                }
                w.global::<Ui>().set_node_address_text(display_core_url(&v).into());
                w.global::<Ui>().set_status("".into());
            }
            Err(msg) => {
                println!("cb: set-node-address err={msg}");
                w.global::<Ui>().set_status(format!("Bitcoin node address: {msg}").into());
            }
        }
        self.refresh_node_health(w);
    }

pub(crate) fn on_set_node_custom(&mut self, w: &AppWindow, t: SharedString) {
        let net = self.network.as_str().to_string();
        // Strip any inline `user:pass@` userinfo BEFORE it ever reaches
        // config.json or this `cb:` log line (plan §2.4 — "the stored node
        // URL must contain NO credentials"). A pasted
        // `bitcoind+http://user:pass@host:8332` is routed exactly like the
        // credential fields below (`route_core_rpc_creds` — Keychain when
        // the "Save credentials" switch is on, the session-only slot when
        // it's off, so a pasted credential can't become a persisted one
        // behind the user's back); the value that gets
        // stored/logged/displayed is always the creds-free form.
        let (v, inline_creds) = split_url_userinfo(t.trim());
        if v.is_empty() {
            self.node_urls.remove(&net);
        } else {
            self.node_urls.insert(net.clone(), v.clone());
        }
        self.save_config();
        println!("cb: set-node-custom {}", if v.is_empty() { "default" } else { &v });
        if let Some((user, pass)) = &inline_creds {
            let persist = self.core_rpc_should_persist(self.network);
            let result = route_core_rpc_creds(
                persist,
                &net,
                user,
                pass,
                &mut self.core_rpc_session_creds,
                |u, p| keychain::store_rpc_creds(&net, u, p),
                || keychain::delete_rpc_creds(&net),
            );
            match result {
                Ok(()) => println!(
                    "cb: set-node-custom inline-creds redacted stored=ok persist={persist}"
                ),
                Err(e) => println!("cb: set-node-custom inline-creds redacted stored=err ({e})"),
            }
        }
        w.global::<Ui>().set_status("".into());
        self.refresh_node_health(w);
    }

pub(crate) fn on_set_node_core_creds(&mut self, w: &AppWindow, user: SharedString, pass: SharedString) {
        let net = self.network.as_str().to_string();
        let user = user.trim().to_string();
        let pass = pass.to_string();
        let persist = self.core_rpc_should_persist(self.network);
        let result = route_core_rpc_creds(
            persist,
            &net,
            &user,
            &pass,
            &mut self.core_rpc_session_creds,
            |u, p| keychain::store_rpc_creds(&net, u, p),
            || keychain::delete_rpc_creds(&net),
        );
        match &result {
            Ok(()) => println!(
                "cb: set-node-core-creds ok user_len={} pass_len={} persist={persist}",
                user.len(),
                pass.len()
            ),
            Err(e) => println!("cb: set-node-core-creds err={e}"),
        }
        w.global::<Ui>().set_status(if result.is_ok() { "".into() } else { "couldn't save RPC credentials".into() });
        self.refresh_node_health(w);
        if result.is_err() {
            // A FAILED save stored nothing, so the refresh above resolves
            // this network's credentials as absent and empties the fields —
            // destroying what the user typed on top of not saving it. Put
            // it back so they can fix the cause and press Save again
            // (reproducible on any unsigned dev build, where SecItemAdd
            // returns -34018).
            w.global::<Settings>().set_node_core_user(user.as_str().into());
            w.global::<Settings>().set_node_core_pass(pass.as_str().into());
        }
    }

pub(crate) fn on_set_node_core_save_creds(&mut self, w: &AppWindow, enabled: bool) {
        let net = self.network.as_str().to_string();
        let net_key = net.clone();
        let user = w.global::<Settings>().get_node_core_user().to_string();
        let pass = w.global::<Settings>().get_node_core_pass().to_string();
        let result = apply_core_rpc_persist_toggle(
            enabled,
            &user,
            &pass,
            || keychain::delete_rpc_creds(&net),
            |u, p| keychain::store_rpc_creds(&net, u, p),
        );
        match result {
            Ok(session) => {
                self.core_rpc_save_creds.insert(net_key.clone(), enabled);
                match session {
                    Some(entry) => {
                        self.core_rpc_session_creds.insert(net_key, entry);
                    }
                    None => {
                        self.core_rpc_session_creds.remove(&net_key);
                    }
                }
                self.save_config();
                println!("cb: set-node-core-save-creds {enabled} ok");
            }
            Err(e) => {
                w.global::<Settings>().set_node_core_save_creds(!enabled);
                println!("cb: set-node-core-save-creds {enabled} err={e}");
            }
        }
        self.update_node_backend_ui(w);
        self.refresh_node_health(w);
    }

pub(crate) fn on_set_explorer_preset(&mut self, w: &AppWindow, i: i32) {
        let net = self.network.as_str().to_string();
        let presets = explorer_presets(self.network);
        let i = i as usize;
        if i < presets.len() {
            match presets[i].1 {
                Some(url) => { self.explorers.insert(net, url.to_string()); }
                None => { self.explorers.remove(&net); }
            }
            self.save_config();
            self.update_activity(w); // refresh live Explorer links
            println!("cb: set-explorer-preset {}", presets[i].0);
        } else {
            println!("cb: set-explorer-preset custom");
        }
        w.global::<Ui>().set_status("".into());
    }

pub(crate) fn on_set_explorer_custom(&mut self, w: &AppWindow, t: SharedString) {
        let net = self.network.as_str().to_string();
        let v = t.trim().to_string();
        if v.is_empty() {
            self.explorers.remove(&net);
        } else {
            self.explorers.insert(net, v.clone());
        }
        self.save_config();
        self.update_activity(w); // refresh live Explorer links
        println!("cb: set-explorer-custom {}", if v.is_empty() { "default" } else { &v });
        w.global::<Ui>().set_status("".into());
    }

pub(crate) fn on_reveal_public(&mut self, w: &AppWindow) {
        let material = std::env::var("APP_KEY")
            .ok()
            .or_else(|| self.material.as_ref().map(|z| String::from(z.as_str())));
        let Some(material) = material else {
            w.global::<PublicKeys>().set_reveal_public_rows(VecModel::from_slice(&Vec::<RevealRow>::new()));
            w.global::<Ui>().set_reveal_fingerprint("".into());
            w.global::<Ui>().set_reveal_public_hint(
                "No key material cached this session — open Private keys once (it re-authenticates), or restart the app."
                    .into(),
            );
            w.global::<Ui>().set_screen(Screen::PublicKeys);
            println!("cb: reveal-public no-material");
            return;
        };
        match app_core::keyexport::export_formats(&material, self.network, self.account, self.nb_index) {
            Ok(f) => {
                let mut rows: Vec<RevealRow> = Vec::new();
                if let Some(v) = f.account_xpub.as_deref() {
                    rows.push(RevealRow {
                        label: "Account xpub".into(),
                        value: v.into(),
                        qr: qr::qr_image(v).unwrap_or_default(),
                        expanded: false,
                    });
                }
                if let Some(v) = f.descriptor.as_deref() {
                    rows.push(RevealRow {
                        label: "Descriptor (tr)".into(),
                        value: v.into(),
                        qr: qr::qr_image(v).unwrap_or_default(),
                        expanded: false,
                    });
                }
                let fp_line = match f.fingerprint.as_deref() {
                    Some(fp) => format!("{fp} · account {}", self.account),
                    None => format!("account {}", self.account),
                };
                println!("cb: reveal-public ok rows={}", rows.len());
                w.global::<Ui>().set_reveal_fingerprint(fp_line.into());
                w.global::<PublicKeys>().set_reveal_public_rows(VecModel::from_slice(&rows));
                // A single hex/WIF key import has a leaf key but no account
                // node — legitimately nothing public to export. Explain the
                // empty screen instead of leaving it blank.
                w.global::<Ui>().set_reveal_public_hint(if rows.is_empty() {
                    "This key has no account-level public material — a single hex/WIF import can't yield a watch-only xpub or descriptor.".into()
                } else {
                    "".into()
                });
            }
            Err(e) => {
                w.global::<PublicKeys>().set_reveal_public_rows(VecModel::from_slice(&Vec::<RevealRow>::new()));
                w.global::<Ui>().set_reveal_public_hint(format!("Couldn't derive public keys: {e}").into());
                println!("cb: reveal-public err");
            }
        }
        w.global::<Ui>().set_screen(Screen::PublicKeys);
    }

pub(crate) fn on_reveal_private(&mut self, w: &AppWindow) {
        match keychain::reveal_secret(KEYCHAIN_ACCOUNT, "reveal your keys") {
            Ok(Some(secret)) => {
                match app_core::keyexport::export_formats(&secret, self.network, self.account, self.nb_index)
                {
                    Ok(f) => {
                        let fp_line = match f.fingerprint.as_deref() {
                            Some(fp) => format!("{fp} · account {}", self.account),
                            None => format!("account {}", self.account),
                        };
                        w.global::<Ui>().set_reveal_fingerprint(fp_line.into());
                        w.global::<PrivateKeys>().set_reveal_has_recovery(f.mnemonic.is_some());
                        w.global::<PrivateKeys>().set_reveal_has_xprv(f.account_xprv.is_some());
                        w.global::<PrivateKeys>().set_reveal_has_hex(f.leaf_hex.is_some());
                        w.global::<PrivateKeys>().set_reveal_has_wif(f.leaf_wif.is_some());
                        // Nothing selected yet — the screen shows only the
                        // pills until one is tapped.
                        w.global::<Ui>().set_reveal_private_format("".into());
                        w.global::<PrivateKeys>().set_reveal_private_value("".into());
                        w.global::<PrivateKeys>().set_reveal_private_qr(slint::Image::default());
                        w.global::<PrivateKeys>().set_reveal_words_col1("".into());
                        w.global::<PrivateKeys>().set_reveal_words_col2("".into());
                        w.global::<PrivateKeys>().set_reveal_show_seedqr(false);
                        w.global::<PrivateKeys>().set_reveal_seedqr_image(slint::Image::default());
                        // Hex/WIF picker: the active account's notebooks,
                        // defaulting to the active notebook. Hidden in the UI
                        // for recovery/xprv, but harmless to populate always.
                        w.global::<PrivateKeys>().set_reveal_nb_rows(VecModel::from_slice(&self.private_nb_rows()));
                        w.global::<PrivateKeys>().set_reveal_nb_index(self.nb_index as i32);
                        println!("cb: reveal-private ok");
                        self.reveal_formats = Some(f);
                        w.global::<Ui>().set_status("".into());
                        w.global::<Ui>().set_screen(Screen::PrivateKeys);
                    }
                    Err(e) => {
                        println!("cb: reveal-private err");
                        w.global::<Ui>().set_status(format!("export: {e}").into());
                    }
                }
            }
            Ok(None) => {
                println!("cb: reveal-private no-key");
                w.global::<Ui>().set_status("(no key in keychain — APP_KEY env session?)".into());
            }
            Err(e) if e == "cancelled" => {
                println!("cb: reveal-private cancelled");
                w.global::<Ui>().set_status("authentication cancelled".into());
            }
            Err(e) => {
                println!("cb: reveal-private err");
                w.global::<Ui>().set_status(format!("keychain: {e}").into());
            }
        }
    }

pub(crate) fn on_open_pq_keys(&mut self, w: &AppWindow) {
        // User-initiated — the LAUNCH-PATH rule's other sanctioned door for
        // loading an imported ML-KEM secret from the Keychain this session
        // (a no-op once already cached).
        self.ensure_pq_imported_loaded();
        w.global::<QuantumKeys>().set_pq_import_text("".into());
        w.global::<QuantumKeys>().set_pq_import_error("".into());
        w.global::<Ui>().set_pq_import_source("".into());
        w.global::<Ui>().set_pq_show_backup_confirm(false);
        w.global::<QuantumKeys>().set_pq_gen_level("768".into());
        w.global::<QuantumKeys>().set_pq_gen_extra("".into());
        w.global::<Ui>().set_pq_show_replace_confirm(false);
        w.global::<Ui>().set_pq_show_export_private_confirm(false);
        w.global::<Modals>().set_pq_imported_private_value("".into());
        w.global::<Modals>().set_pq_imported_private_qr(slint::Image::default());
        self.pq_pending_replace = None;
        self.update_pq_keys_screen(w);
        w.global::<Ui>().set_screen(Screen::QuantumKeys);
        // Log-contract landing signal (graffito-app-selfpq.sh) — emitted
        // LAST, after ensure_pq_imported_loaded (which blocks on a
        // SecurityAgent keychain prompt on a freshly-resigned debug build)
        // and set_screen, so it fires only once the screen is truly shown.
        println!("cb: pq-keys open");
    }
}
