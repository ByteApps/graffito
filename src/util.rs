//! Small pure helpers shared across screens — moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

/// The ONE way a store reaches disk (audit M1). `Store::save` writes a temp
/// file and renames it over the target, so the backup-exclusion flag — which
/// lives on the file, not the path — is destroyed on every save and has to be
/// re-applied here. Routing every write through this is what keeps decrypted
/// note text out of unencrypted device backups; a `store.save(...)` called
/// directly would silently re-enrol that notebook.
///
/// Save failures stay swallowed, exactly as every call site already did:
/// the store is a chain-derived cache, and a failed write leaves the previous
/// file intact (temp-then-rename).
pub(crate) fn save_store_file(store: &app_core::store::Store, path: &std::path::Path) {
    if store.save(path).is_ok() {
        platform::exclude_from_backup(path);
    }
}

/// "tb1p2ylq…q7ax" — the row/label short form of an address.
pub(crate) fn addr_short(a: &str) -> String {
    if a.len() > 14 {
        format!("{}…{}", &a[..9], &a[a.len() - 4..])
    } else {
        a.to_string()
    }
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix MILLISECONDS — the clock for contacts-tombstones' `updated_at`/
/// `deleted_at` timestamps (`app_core::contacts` needs finer resolution
/// than `now()`'s seconds so two touches in the same second still order
/// correctly). The only place this crate calls `SystemTime::now()` for
/// that feature — every `app_core::contacts` function stays clock-free
/// and takes timestamps as parameters (see that module's doc for the
/// cross-device wall-clock assumption this relies on).
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn spendable_inputs(store: &Store) -> Vec<app_core::store::TxInput> {
    store
        .utxos
        .iter()
        .filter(|u| !u.pending_spend)
        .map(|u| app_core::store::TxInput { txid: u.txid.clone(), vout: u.vout, value: u.value })
        .collect()
}

/// "R.R sat/vB · F sats" (or just "F sats" without a known vsize).
pub(crate) fn fee_line_str(fee: Option<u64>, vsize: Option<u64>) -> String {
    match (fee, vsize) {
        (Some(f), Some(v)) if v > 0 => format!("{:.1} sat/vB · {f} sats", f as f64 / v as f64),
        (Some(f), _) => format!("{f} sats"),
        _ => "—".into(),
    }
}

/// "replaced N×" when a tx was RBF-bumped (>1 txids), else empty.
pub(crate) fn replaced_label(txid_count: usize) -> String {
    if txid_count > 1 {
        format!("replaced {}×", txid_count - 1)
    } else {
        String::new()
    }
}

/// Activity's funding-source pill (funding-unification M3): `NoteRecord.
/// funded_by` is `Some("spending")` for the internal BIP-84 spending
/// wallet or `Some("wallet:<label>")` for an external funding wallet;
/// `None` (every pre-M3 record, and every notebook-funded note) shows no
/// pill at all — byte-identical to today's Activity row.
pub(crate) fn funded_pill(funded_by: Option<&str>) -> String {
    match funded_by {
        Some("spending") => "spending wallet".to_string(),
        Some(s) => s.strip_prefix("wallet:").map(str::to_string).unwrap_or_default(),
        None => String::new(),
    }
}

/// "New fee ~N sats (+D)" for a proposed rate over a tx of `vsize`.
pub(crate) fn new_fee_line(rate: f64, vsize: u64, old_fee: u64) -> String {
    let new_fee = (rate * vsize as f64).ceil() as u64;
    let delta = new_fee.saturating_sub(old_fee);
    format!("New fee ~{new_fee} sats  (+{delta} over current)")
}

/// Current rate (sat/vB), fee, vsize for a pending tx referenced by the
/// activity list (note_id if is_note, else txid).
pub(crate) fn tx_rate(store: &Store, ref_id: &str, is_note: bool) -> Option<(f64, u64, u64)> {
    if is_note {
        let n = store.notes.iter().find(|n| n.note_id == ref_id)?;
        let (f, v) = (n.fee?, n.vsize?);
        (v > 0).then(|| (f as f64 / v as f64, f, v))
    } else {
        let t = store.txs.iter().find(|t| t.txids.iter().any(|x| x == ref_id))?;
        (t.vsize > 0).then(|| (t.fee as f64 / t.vsize as f64, t.fee, t.vsize))
    }
}

/// Graffito companion note.html permalink, or empty on regtest.
pub(crate) fn note_web_url(network: Network, address: &str, note_id: &str) -> String {
    match network {
        Network::Regtest => String::new(),
        net => format!(
            "https://byteapps.com/graffito/companion/note.html?address={address}&network={}&note={note_id}",
            net.as_str()
        ),
    }
}

pub(crate) fn normalize_addr(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    if let Some(rest) = s.strip_prefix("bitcoin:").or_else(|| s.strip_prefix("BITCOIN:")) {
        s = rest.to_string();
    }
    if let Some(q) = s.find('?') {
        s.truncate(q);
    }
    s
}

/// Group digits with thousands separators: 143473 → "143,473".
pub(crate) fn commas(n: u64) -> String {
    let s = n.to_string();
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in b.iter().enumerate() {
        if i > 0 && (b.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*c as char);
    }
    out
}

/// The structured cost card's "To recipient" row value (Sal, 2026-07-19):
/// "+G sats" for exactly one recipient (unchanged copy), "N × G = T sats"
/// for 2+ (uniform gift × N) — shared by every compose preview that shows a
/// gift row (notebook, mixed, spending) so the wording never drifts between
/// paths. `total` is the byte-true sum the builder actually paid, not
/// `gift * n_recipients` recomputed here (they're equal for a uniform gift,
/// but passing it through keeps this a pure formatter).
pub(crate) fn gift_row(n_recipients: usize, gift: u64, total: u64) -> String {
    match n_recipients {
        0 => String::new(),
        1 => format!("+{} sats", commas(total)),
        n => format!("{n} × {} = {} sats", commas(gift), commas(total)),
    }
}

/// " · G sats to recipient" (single) or " · N × G = T sats to N recipients"
/// (multi) — the ×N fee-copy rule (Sal, 2026-07-19) for the plain "sign
/// with your external wallet" cost strings on the PSBT-sign screen (mixed/
/// watch-note build paths, which don't use the structured cost card).
/// Empty for a self-note (`n_recipients == 0`).
pub(crate) fn gift_cost_suffix(n_recipients: usize, gift: u64) -> String {
    match n_recipients {
        0 => String::new(),
        1 => format!(" · {gift} sats to recipient"),
        n => format!(" · {n} × {gift} = {} sats to {n} recipients", gift * n as u64),
    }
}

/// The bare host from a Bitcoin-node base URL, e.g.
/// `https://mempool.space/testnet4/api` → `mempool.space`. Falls back to
/// "your node" when `base_url` is empty/unparseable (no node configured, or
/// the setting changed between the broadcast attempt and this being shown).
pub(crate) fn host_of(base_url: &str) -> String {
    let rest = base_url.split_once("://").map_or(base_url, |(_, r)| r);
    match rest.split('/').next().filter(|h| !h.is_empty()) {
        Some(h) => h.to_string(),
        None => "your node".to_string(),
    }
}

/// Turn a raw HTTP-error-class message into a short, calm, user-safe status
/// line. A rate-limited esplora/mempool.space answers `429 Too Many
/// Requests` with an HTML body — before this helper, that landed verbatim
/// on screen ("spending wallet scan failed: http: 429 Too Many Requests:
/// <html>..."). Two rules: a 429 anywhere in the raw text becomes a calm
/// retry message (no status-code jargon); anything else has everything
/// from the first `<` onward stripped (so no future HTML error page can
/// ever reach the screen), its whitespace collapsed, and is capped at
/// ~120 chars — a defensive fallback, not just for HTML, in case a server
/// ever answers with an unexpectedly large body.
///
/// Pure and UI-independent (host-tested below); every call site keeps the
/// FULL raw error in its `cb:`/println! debug log and only feeds the
/// user-visible `set_status` text through this.
/// Byte offset of the first `<` that opens an HTML tag (`<html`, `</body`,
/// `<!DOCTYPE`) — `None` when every `<` is plain text (a comparison in a
/// rejection body). Shared rule with app-core's `trim_error_body`.
pub(crate) fn html_tag_start(s: &str) -> Option<usize> {
    s.match_indices('<').find_map(|(i, _)| {
        let next = s[i + 1..].chars().next()?;
        (next.is_ascii_alphabetic() || next == '/' || next == '!').then_some(i)
    })
}

pub(crate) fn friendly_net_err(raw: &str) -> String {
    // Anchored to the Error formats, NOT a bare `contains("429")` — server
    // rejection bodies embed literal sat amounts ("min relay fee not met,
    // 429 < 1000") that must never masquerade as a rate limit. app-core's
    // `trim_error_body` guarantees an HTTP-status message starts with the
    // numeric code (`429: …`), and `Error::Http`'s Display prefixes
    // `http: ` — so a real rate limit is only ever `429…` or `http: 429…`.
    if raw.starts_with("429") || raw.starts_with("http: 429") {
        return "server is busy — retrying shortly".to_string();
    }
    // Strip from the first '<' that actually opens a tag (`<html`, `</`,
    // `<!DOCTYPE`) — a bare comparison in a rejection body ("min relay fee
    // not met, 429 < 1000") must survive intact.
    let stripped = match html_tag_start(raw) {
        Some(i) => &raw[..i],
        None => raw,
    };
    let collapsed = stripped.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return "server error — try again shortly".to_string();
    }
    if collapsed.chars().count() > 120 {
        collapsed.chars().take(120).collect::<String>() + "..."
    } else {
        collapsed
    }
}

/// U5 (`../PLAN-chain-notes-app-core-rpc.md` §2.1/§2.4): Bitcoin Core's
/// rejection vocabulary — `testmempoolaccept` reject-reason tokens
/// (`"txn-already-known"`, `"min relay fee not met, ..."`,
/// `"bad-txns-inputs-missingorspent"`, `"non-final"`) and
/// `sendrawtransaction` RPC-error messages (codes -25/-26/-27, forwarded
/// verbatim by [`app_core::chain::CoreRpcTransport`]'s generic `rpc()`
/// path) — reads nothing like mempool.space's own rejection bodies. Left
/// alone, the exact same underlying condition (already broadcast, fee too
/// low, a missing input, a non-final locktime) would show the user two
/// completely different raw strings depending purely on which backend
/// they picked. This recognizes both vocabularies — real Esplora/
/// mempool.space bodies already tend to embed plain English for these
/// cases; Core's are short machine tokens or terse RPC messages — and
/// collapses the common ones to ONE calm, backend-agnostic phrase, so the
/// UI reads identically either way. Matched case-insensitively against the
/// FULL error text (whatever prefix `Error`'s `Display`/`trim_error_body`
/// put in front of it) rather than anchored to a position, since Core and
/// Esplora don't even agree on where in the string the reason token sits.
/// `None` for anything not recognized — the existing pass-through/
/// [`friendly_net_err`] path handles those exactly as before.
pub(crate) fn map_broadcast_rejection(e: &str) -> Option<&'static str> {
    let lower = e.to_ascii_lowercase();
    const ALREADY: &[&str] = &[
        "txn-already-known",
        "already-known",
        "already in block chain",
        "already have transaction",
        "already in the mempool",
        "already in mempool",
    ];
    const LOW_FEE: &[&str] = &[
        "min relay fee not met",
        "insufficient fee",
        "min-relay-fee-not-met",
        "mempool min fee not met",
    ];
    const MISSING_INPUTS: &[&str] =
        &["missing inputs", "missingorspent", "bad-txns-inputs-missingorspent"];
    const NON_FINAL: &[&str] =
        &["non-final", "non-bip68-final", "bad-txns-nonfinal", "transaction is not final"];

    if ALREADY.iter().any(|s| lower.contains(s)) {
        Some("already broadcast — this transaction is already on the network")
    } else if LOW_FEE.iter().any(|s| lower.contains(s)) {
        Some("fee too low — increase the fee and try again")
    } else if MISSING_INPUTS.iter().any(|s| lower.contains(s)) {
        Some("inputs missing or already spent — this transaction can't be sent")
    } else if NON_FINAL.iter().any(|s| lower.contains(s)) {
        Some("not final yet — try again once its timelock has passed")
    } else {
        None
    }
}

/// Broadcast-failure sites see a stringified `app_core::Error` (workers
/// already `.map_err(|e| format!("{e}"))` before crossing the thread
/// boundary — see the `client.broadcast()` call sites). A TRANSPORT-class
/// failure (`app_core::Error::Transport`, tagged by its Display impl with a
/// "transport: " prefix — chain.rs already retried it once and it still
/// didn't reach a server) reads as raw reqwest text like `error sending
/// request for url (...)`, which is Greek to a user on a weak connection;
/// swap it for a plain-language message naming the node host instead.
/// A recognized rejection condition (U5: already-broadcast, fee too low, a
/// missing input, a non-final locktime — [`map_broadcast_rejection`]) gets
/// ONE calm phrase regardless of which backend produced it. Anything else
/// — an unrecognized server rejection (`Error::Http`, e.g. "400 Bad
/// Request: bad-txns-in-belowout"), a local build/sign error, ... — goes
/// through [`friendly_net_err`] (a plain rejection like "400 Bad Request:
/// foo" passes through that untouched too; it only bites on a 429 or a
/// stray HTML body).
///
/// Applied ONLY at user-facing `set_status`/toast broadcast-failure sites;
/// every `cb:`/println! log line keeps the raw error verbatim (the
/// debugging contract — see the workspace CLAUDE.md's log-contract note).
pub(crate) fn friendly_broadcast_err(e: &str, base_url: &str) -> String {
    match e.strip_prefix("transport: ") {
        Some(_raw) => format!("network error reaching {} — check your connection", host_of(base_url)),
        None => match map_broadcast_rejection(e) {
            Some(msg) => msg.to_string(),
            None => friendly_net_err(e),
        },
    }
}

pub(crate) fn is_hierarchical(material_str: &str, network: Network) -> bool {
    parse_key_material(material_str, network).map(|m| m.is_hierarchical()).unwrap_or(false)
}

/// Whether the material can hold more than one notebook (receive indexes
/// of one account) — everything but raw WIF/hex keys, including ranged
/// watch-only descriptors.
pub(crate) fn is_multi_notebook(material_str: &str, network: Network) -> bool {
    parse_key_material(material_str, network).map(|m| m.is_multi_notebook()).unwrap_or(false)
}

/// Populate the Settings screen's identity/network/note-size fields from
/// current state. Called by `update_home` (fresh whenever a notebook home
/// renders) AND by `on_settings_open` — so Settings is correct even when the
/// user reaches it WITHOUT first visiting a notebook's home. Onboarding now
/// lands on the notebook LIST (Sal 2026-07-21), not a home; before this,
/// `settings-hierarchical` (which gates the "Change account…" row) and the
/// note-size field were only ever set by `update_home`, so a fresh
/// hierarchical import that never opened a home showed no "Change account…"
/// row and a stale chunk value.
/// One line under the locktime pills spelling out what the current policy
/// would actually put on the wire — "chain height" is only meaningful if
/// the user knows which height we last scanned to.
pub(crate) fn locktime_caption(
    policy: app_core::notes_core::tx::LockTimePolicy,
    tip: Option<u64>,
) -> String {
    use app_core::notes_core::tx::LockTimePolicy;
    match policy {
        LockTimePolicy::Tip => match tip.filter(|h| *h > 0) {
            Some(h) => format!(
                "New transactions get locktime {h}, the height of your last scan."
            ),
            None => "Nothing scanned yet, so locktime stays 0 until the first sync.".to_string(),
        },
        LockTimePolicy::Zero => {
            "New transactions get locktime 0 — simplest, but stands out from most wallets."
                .to_string()
        }
        LockTimePolicy::Custom { height } => format!("New transactions get locktime {height}."),
    }
}

/// Parse a locktime mode pill + custom-height text into a `LockTimePolicy`,
/// the same validation `on_set_locktime` (device Settings) always used —
/// factored out so the compose (screen 6) and sweep/consolidate (screen
/// 16) override panels share IDENTICAL parsing/validation, not a second
/// hand-copied version. `None` = invalid (a custom height that doesn't
/// parse, or is `>= 500_000_000` — read by consensus as a UNIX timestamp,
/// never what someone typing a block height means).
pub(crate) fn parse_locktime_mode(mode: &str, height: &str) -> Option<app_core::notes_core::tx::LockTimePolicy> {
    use app_core::notes_core::tx::LockTimePolicy;
    match mode {
        "zero" => Some(LockTimePolicy::Zero),
        "custom" => match height.trim().parse::<u32>() {
            Ok(h) if h < 500_000_000 => Some(LockTimePolicy::Custom { height: h }),
            _ => None,
        },
        _ => Some(LockTimePolicy::Tip),
    }
}

/// The compose (screen 6) and sweep/consolidate (screen 16) locktime
/// panels' four display values for a given policy: the mode pill, the
/// custom-height field text (ALWAYS the currently-effective resolved
/// height, even outside Custom mode — mirrors `on_set_locktime`'s own
/// `locktime_text` convention, so tapping Custom starts from a sensible
/// seed instead of a blank field), the effective caption
/// (`locktime_caption` — the ONE wording source, shared with Settings),
/// and the future-tip warning (empty = none). This is the safety content
/// of the whole feature: our inputs signal RBF (nSequence 0xfffffffd), so
/// nLockTime is ENFORCED — a height above the tip makes the tx non-final
/// and the node rejects it outright.
pub(crate) fn locktime_panel_values(
    policy: app_core::notes_core::tx::LockTimePolicy,
    tip: Option<u64>,
) -> (String, String, String, String) {
    use app_core::notes_core::tx::LockTimePolicy;
    let tip32 = tip.and_then(|t| u32::try_from(t).ok());
    let resolved = policy.resolve(tip32);
    let mode = policy.as_str().to_string();
    let height_text = resolved.to_string();
    let effective = locktime_caption(policy, tip);
    let warn = match policy {
        LockTimePolicy::Custom { height } if tip32.is_some_and(|t| height > t) => format!(
            "Height {height} is above the current chain tip ({}) — this transaction won't be final, and the node will reject it until block {height}.",
            tip32.unwrap()
        ),
        _ => String::new(),
    };
    (mode, height_text, effective, warn)
}

/// Compute [`PayfromState`] for the CURRENT cross-wallet selection, using
/// whichever of the three real compose branches' math matches this
/// selection's shape (notebook-only / spending-only / external-only /
/// mixed) — the branches already compute the exact fee for their own shape;
/// this never invents a new estimator, it just stops letting the ANSWER
/// depend on which panel happens to be `payfrom_active_source`. The two
/// "funded" shapes (spending, mixed) reuse [`app_core::mixed::estimate_funded_fee`]
/// — the same weight/output math [`app_core::mixed::assemble_mixed_note_psbt`]
/// and `build_funding_psbt_amount` use internally, minus their insufficiency
/// gate (which would otherwise swallow the very fee figure a "you're short"
/// UI needs to show).
/// The Pay-from summary card's "Required" line, honest about a predicted
/// sub-dust fold (2026-07-18): `required` is always the NOMINAL figure
/// (what the shape actually needs at the chosen rate — never the eventual
/// byte-true fee, which includes the folded leftover on top), and a
/// `fold` prediction appends the leftover so the line never reads as an
/// inflated/expensive requirement. `"~0 sats"` when nothing is known yet
/// (unchanged from every branch's previous fallback).
pub(crate) fn fold_required_line(required: Option<u64>, fold: Option<(u64, u64)>) -> String {
    match (required, fold) {
        (Some(r), Some((_, folded))) => format!("~{} sats (+{} leftover, dust rule)", commas(r), commas(folded)),
        (Some(r), None) => format!("~{} sats", commas(r)),
        (None, _) => "~0 sats".to_string(),
    }
}

/// A per-frame preview closure for [`camera::capture_frames`] — pushes each
/// downscaled frame to the shared `camera-frame` image so the scan overlay
/// shows a live view (QR detection, not the preview, is what's throttled).
pub(crate) fn scan_preview(weak: slint::Weak<AppWindow>) -> impl FnMut(&[u8], u32, u32) {
    move |rgba: &[u8], pw: u32, ph: u32| {
        let mut buf = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(pw, ph);
        buf.make_mut_bytes().copy_from_slice(rgba);
        let _ = weak.upgrade_in_event_loop(move |w| w.global::<Modals>().set_camera_frame(slint::Image::from_rgba8(buf)));
    }
}

/// Show the shared scan overlay and clear the cancel flag (call on the UI thread
/// before spawning the capture thread).
pub(crate) fn begin_scan(weak: &slint::Weak<AppWindow>, cancel: &Arc<AtomicBool>, hint: &str) {
    cancel.store(false, Ordering::Relaxed);
    if let Some(w) = weak.upgrade() {
        w.global::<Modals>().set_scan_hint(hint.into());
        w.global::<Modals>().set_scan_progress(0.0);
        w.global::<Ui>().set_scanning(true);
    }
}

/// Shorten a bech32 address for display: `bcrt1p2caqg…6hrewe`.
pub(crate) fn short_addr(a: &str) -> String {
    if a.len() > 20 {
        format!("{}…{}", &a[..10], &a[a.len() - 6..])
    } else {
        a.to_string()
    }
}

/// Pull an output descriptor out of pasted text or a wallet-export file:
/// a bare descriptor/xpub passes through; otherwise find an embedded
/// `tr(...)`/`wpkh(...)` token (handles Sparrow-style JSON + text exports).
pub(crate) fn extract_descriptor(text: &str) -> String {
    let t = text.trim();
    for pat in ["tr(", "wpkh("] {
        if let Some(i) = t.find(pat) {
            let rest = &t[i..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '}')
                .unwrap_or(rest.len());
            return rest[..end].to_string();
        }
    }
    t.to_string()
}

/// Pull EVERY `tr()`/`wpkh()` descriptor out of pasted text or a wallet-export
/// file — a single export can list several script types. Falls back to the
/// whole trimmed input as one candidate when no `tr(`/`wpkh(` token is present.
pub(crate) fn extract_all_descriptors(text: &str) -> Vec<String> {
    let t = text.trim();
    let mut found: Vec<String> = Vec::new();
    for pat in ["tr(", "wpkh("] {
        let mut from = 0;
        while let Some(rel) = t[from..].find(pat) {
            let start = from + rel;
            let rest = &t[start..];
            let end = rest
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == '}')
                .unwrap_or(rest.len());
            let desc = rest[..end].to_string();
            if !found.contains(&desc) {
                found.push(desc);
            }
            from = start + end.max(1);
        }
    }
    if found.is_empty() {
        vec![t.to_string()]
    } else {
        found
    }
}

/// The confirm screen's one-liner caption for any note-composing tx:
/// "Public note · testnet4" / "Private note · testnet4" / "Directed note ·
/// testnet4". Directed takes priority in the label — a directed note's own
/// privacy is already visible on its NOTE card and recipient row.
pub(crate) fn note_context(directed: bool, private: bool, network: Network) -> String {
    let kind = if directed { "Directed note" } else if private { "Private note" } else { "Public note" };
    format!("{kind} · {}", network.as_str())
}

/// Decode a raw signed tx's txid + vsize directly (no `ConfirmCtx` needed)
/// — used by the rebroadcast path, which has the raw hex in hand (cached
/// or freshly fetched) but no build-time `NoteTx`/`finalize_extract`
/// result to read them from. `None` on malformed hex; the caller falls
/// back to empty/zero, and `show_confirm`'s own decode will independently
/// (and honestly) fail too.
pub(crate) fn decode_txid_vsize(raw_hex: &str) -> Option<(String, usize)> {
    let bytes = hex::decode(raw_hex.trim()).ok()?;
    let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&bytes).ok()?;
    Some((tx.compute_txid().to_string(), tx.vsize()))
}

/// Push the platform type scale into the UI when it CHANGES — at boot, and
/// from the slow poll after a font-size change: the Android manifest keeps
/// `fontScale` in `configChanges` so the activity is NOT recreated (a
/// recreation re-runs `android_main` inside the same process, which is how
/// the safe-area insets were lost on 2026-09-05), so the new value has to be
/// noticed here instead. Desktop is a no-op (always 1.0).
pub(crate) fn apply_type_scale(win: &AppWindow) {
    let scale = platform::type_scale();
    let m = win.global::<Metrics>();
    if (m.get_type_scale() - scale).abs() > 0.001 {
        println!("cb: type-scale os={:.3} applied={scale:.3}", platform::os_font_scale());
        m.set_type_scale(scale);
        m.set_word_columns(platform::word_columns());
    }
}

/// Read the platform safe-area insets (converting with the window's scale
/// factor) and push them into the UI. Cheap; called on a few startup ticks
/// and a slow rotation poll. No-op on desktop (insets are 0).
pub(crate) fn apply_safe_area(win: &AppWindow) {
    apply_type_scale(win);
    let scale = win.window().scale_factor();
    let (top, bottom) = platform::safe_area_insets(scale);
    // A phone in portrait always has a status bar, so a (0, 0) reading after
    // a real inset was known is the platform not knowing YET (window detached
    // across a background/foreground or activity recreation), never a real
    // layout — keep the last good value rather than sliding the header under
    // the status bar until the next poll succeeds.
    if platform::has_insets() && top <= 0.0 && win.global::<Ui>().get_safe_top() > 0.0 {
        return;
    }
    if (win.global::<Ui>().get_safe_top() - top).abs() > 0.5 || (win.global::<Ui>().get_safe_bottom() - bottom).abs() > 0.5 {
        println!("cb: safe-area top={top:.1} bottom={bottom:.1} scale={scale:.2}");
    }
    win.global::<Ui>().set_safe_top(top);
    win.global::<Ui>().set_safe_bottom(bottom);
    // Reveal the UI once the inset is known — immediately on desktop (no
    // insets), or as soon as a mobile window reports a real top inset. Until
    // then a splash cover hides the content so it never visibly slides down
    // from under the status bar on cold start.
    if !platform::has_insets() || top > 0.0 {
        win.global::<Modals>().set_ready(true);
    }
}
