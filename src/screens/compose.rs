//! Screen.compose — handlers moved out of `lib.rs` verbatim (U4,
//! PLAN-graffito-app-arch.md).

use crate::*;

pub(crate) fn note_est(
    store: &Store,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_len: Option<usize>,
    change_spk_len: Option<usize>,
) -> Result<(usize, usize), app_core::notes_core::Error> {
    note_est_at(store.chunk_size, text_len, private, n_inputs, recipient_spk_len, change_spk_len)
}

/// `note_est` at an arbitrary chunk size — used to test whether a note that
/// doesn't fit at the current setting would fit at Standard.
pub(crate) fn note_est_at(
    chunk_size: usize,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_len: Option<usize>,
    change_spk_len: Option<usize>,
) -> Result<(usize, usize), app_core::notes_core::Error> {
    let (chunks, vsize) =
        estimate_note_cost(text_len, private, chunk_size, n_inputs, recipient_spk_len)?;
    let vsize = change_spk_len.map_or(vsize, |l| (vsize as i64 + l as i64 - 34).max(0) as usize);
    Ok((chunks, vsize))
}

/// Multi-recipient (2+ chips) analog of `note_est`: notes-core's
/// `estimate_note_cost` only takes a single optional recipient spk length
/// (and is hardwired to `multi_count: None`) — so this computes the body
/// length matching `multi_body`'s framing (PLAN-pnte-redesign.md: the
/// recipient count lives in the envelope HEADER now, not a body-leading
/// byte — `text` verbatim public, `count×WRAP_LEN || SEAL_OVERHEAD+text`
/// private) and calls notes-core's own public `envelope::payload_lens_for`
/// for the chunking arithmetic (never reimplemented here — that's exactly
/// the drift `estimate_note_cost` itself avoids by doing the same), then
/// feeds the result to `tx::estimate_vsize_multi`. This is a PREVIEW
/// convenience only — the universal confirm screen prices the ACTUAL
/// signed tx regardless, so an approximation here can never desync what
/// gets broadcast from what the user confirmed.
pub(crate) fn multi_note_est(
    text_len: usize,
    private: bool,
    chunk_size: usize,
    n_inputs: usize,
    recipient_spk_lens: &[usize],
    change_spk_len: Option<usize>,
) -> Result<(usize, usize), app_core::notes_core::Error> {
    use app_core::notes_core::{crypt, dm, envelope, tx};
    let n = recipient_spk_lens.len();
    let body_len = if private { n * dm::WRAP_LEN + crypt::SEAL_OVERHEAD + text_len } else { text_len };
    let flags = envelope::FLAG_DIRECTED
        | envelope::FLAG_MULTI
        | if private { envelope::FLAG_PRIVATE } else { 0 };
    let payload_lens = envelope::payload_lens_for(flags, Some(n as u8), body_len, chunk_size)?;
    let vsize = tx::estimate_vsize_multi(n_inputs.max(1), &payload_lens, recipient_spk_lens, true);
    let vsize = change_spk_len.map_or(vsize, |l| (vsize as i64 + l as i64 - 34).max(0) as usize);
    Ok((payload_lens.len(), vsize))
}

/// Single call site for the compose preview's cost estimate: delegates to
/// the ordinary single-recipient `note_est` for 0 or 1 recipients (today's
/// exact byte-identical estimator) and to `multi_note_est` for 2+ — so
/// every existing caller (self-notes, ordinary directed notes) is
/// unaffected.
pub(crate) fn compose_est(
    store: &Store,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_lens: &[usize],
    change_spk_len: Option<usize>,
) -> Result<(usize, usize), app_core::notes_core::Error> {
    if recipient_spk_lens.len() >= 2 {
        multi_note_est(text_len, private, store.chunk_size, n_inputs, recipient_spk_lens, change_spk_len)
    } else {
        note_est(store, text_len, private, n_inputs, recipient_spk_lens.first().copied(), change_spk_len)
    }
}

/// `compose_est`, pq-aware: when `pq` carries nonzero flags, prices the
/// note through notes-core's `estimate_note_cost_pq` (which bakes in
/// `pq::pq_overhead`) instead of the ordinary `estimate_note_cost` — so
/// the compose screen's live cost card shows the extra prefix bytes a pq
/// layer adds seamlessly, without a separate line. pq notes are always
/// single-recipient directed-private by construction (mirrors
/// `compose::compose_note`'s own structural requirement), so this only
/// ever takes the single-recipient path; `pq = (0, _)` (nothing on, or the
/// section doesn't apply) delegates to `compose_est` unchanged — every
/// non-pq compose stays byte-identical to before this function existed.
pub(crate) fn compose_est_pq(
    store: &Store,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_lens: &[usize],
    change_spk_len: Option<usize>,
    pq: (u8, Option<app_core::notes_core::pq::MlKemAlg>),
) -> Result<(usize, usize), app_core::notes_core::Error> {
    let (pq_flags, alg) = pq;
    if pq_flags == 0 {
        return compose_est(store, text_len, private, n_inputs, recipient_spk_lens, change_spk_len);
    }
    let (chunks, vsize) = app_core::notes_core::bundle::estimate_note_cost_pq(
        text_len,
        store.chunk_size,
        n_inputs,
        recipient_spk_lens.first().copied(),
        pq_flags,
        alg,
    )?;
    let vsize = change_spk_len.map_or(vsize, |l| (vsize as i64 + l as i64 - 34).max(0) as usize);
    Ok((chunks, vsize))
}

/// Whether the composed note can go out as one standard tx, and if not, whether
/// bumping the chunk size to Standard would rescue it.
pub(crate) enum FitCheck {
    /// Broadcastable at the current chunk-size setting.
    Ok,
    /// Over the limit now, but would fit at Standard (the user is on a smaller
    /// setting whose 255-chunk cap binds first) — offer to switch.
    FitsAtStandard,
    /// Over even at Standard: the ~100 kB per-tx network wall. No setting helps.
    HardWall,
}

pub(crate) fn fit_check(
    store: &Store,
    text_len: usize,
    private: bool,
    n_inputs: usize,
    recipient_spk_len: Option<usize>,
    change_spk_len: Option<usize>,
) -> FitCheck {
    let fits = |chunk: usize| {
        note_est_at(chunk, text_len, private, n_inputs, recipient_spk_len, change_spk_len)
            .map(|(_, vsize)| vsize <= MAX_STANDARD_TX_VSIZE)
            .unwrap_or(false) // Err = >255 chunks → treat as over-limit
    };
    if fits(store.chunk_size) {
        FitCheck::Ok
    } else if store.chunk_size < DEFAULT_CHUNK && fits(DEFAULT_CHUNK) {
        FitCheck::FitsAtStandard
    } else {
        FitCheck::HardWall
    }
}

/// Suggested coin selection over every SPENDABLE coin — unconfirmed
/// included (Sal 2026-07-25). The old rule auto-selected CONFIRMED coins
/// only, which left a freshly funded notebook (and, right after a note, its
/// own unconfirmed change) with an empty selection and a red
/// Required/Selected line, forcing a manual tap every time on a slow
/// network. Only `pending_spend` (locked by one of our own pending spends)
/// still excludes a coin — the same set the panel lists as spendable, so
/// the suggestion can now always cover what the panel shows. Every row
/// carries a confirmed/unconfirmed badge (`CoinPickRow`), so a chained-on
/// unconfirmed parent is visible, not silent. The spending-wallet panel has
/// always auto-selected regardless of confirmation
/// (`spending_compose_ui`) — this aligns the notebook path with it.
/// `consolidate` = pick
/// SMALLEST coins first (sweeps dust up into the change); otherwise LARGEST
/// first (fewest inputs, lowest fee). Stops once the note + fee is covered.
/// `recipient_spk_lens` replaces the old singular `spk_len` (additive,
/// 2026-07 multi-recipient): 0 entries = self-note, 1 = an ordinary
/// directed note (byte-identical to before via `compose_est`'s
/// delegation), 2+ = a multi-recipient note priced through
/// `multi_note_est`. `sent` is the TOTAL sats sent to every recipient
/// (gift × recipient count), not a single recipient's gift.
#[allow(clippy::too_many_arguments)]
pub(crate) fn suggested_coins(
    store: &Store,
    text_len: usize,
    private: bool,
    rate: f64,
    recipient_spk_lens: &[usize],
    change_spk_len: Option<usize>,
    sent: u64,
    consolidate: bool,
) -> Vec<(String, u32)> {
    let mut coins: Vec<&app_core::store::LedgerUtxo> = store
        .utxos
        .iter()
        .filter(|u| !u.pending_spend)
        .collect();
    if consolidate {
        coins.sort_by_key(|a| a.value); // smallest first
    } else {
        coins.sort_by_key(|b| std::cmp::Reverse(b.value)); // largest first
    }
    let mut chosen = Vec::new();
    let mut total = 0u64;
    for u in coins {
        chosen.push((u.txid.clone(), u.vout));
        total += u.value;
        if let Ok((_, vsize)) =
            compose_est(store, text_len.max(1), private, chosen.len(), recipient_spk_lens, change_spk_len)
        {
            let fee = (vsize as f64 * rate).ceil() as u64;
            if total >= fee + sent {
                break;
            }
        }
    }
    chosen
}

/// Everything [`app_core::mixed::assemble_mixed_note_psbt`] needs that comes
/// from the CURRENT cross-wallet selection + change choice — built by the
/// ONE args-builder ([`mixed_compose_args`]) shared by the compose preview
/// (`mixed_compose_ui`) and the send path (`on_compose_send_mixed` stage A),
/// so the two can structurally never disagree about what would be built
/// (Sal's TestFlight build-20 bug, 2026-07-18: the preview dry-ran the
/// spending-only builder — unconditional dust, spending-only weights —
/// while Sign built the anchored mixed shape).
pub(crate) struct MixedComposeArgs {
    pub(crate) coins: Vec<app_core::mixed::MixedCoin>,
    pub(crate) wallets_map: HashMap<String, FundingSource>,
    /// Chain-1 index → that leaf's own P2TR scriptPubKey, for every UNIQUE
    /// index among the selected `CoinSource::Change` coins (taproot-change
    /// unit 5) — the map `assemble_mixed_note_psbt_multi_ext` needs since
    /// the builder itself has no key material. Empty when no change coin
    /// is selected (every existing caller's shape, unaffected).
    pub(crate) change_spks: HashMap<u32, Vec<u8>>,
    pub(crate) change_default: app_core::mixed::ChangeDefault,
    pub(crate) change_override: Option<Vec<u8>>,
    pub(crate) change_index: u32,
}

/// The ONE authoritative Pay-from verdict (Sal's iPhone bug cluster,
/// 2026-07-18: sufficiency was being evaluated per-wallet-PANEL — whichever
/// of `refresh_compose`'s three branches happened to be `payfrom_active_source`
/// at the time — instead of on the TRUE cross-wallet selection, so a
/// well-funded selection could render red, or the "Required" figure could go
/// blank, depending purely on which section was last tapped). Computed fresh
/// from `mixed_selected` (the cross-wallet memory — what actually gets
/// spent), NEVER from `payfrom_active_source` (a last-touched/visibility
/// concern, orthogonal to what's selected). Every consumer renders from
/// this: the summary card, the single insufficiency message, the compose
/// "Pay from" row (label + amount + tint), and the Sign gate
/// (`spend_enough`). Panel captions stay neutral always — see
/// `payfrom_panel_coins`, unchanged.
pub(crate) struct PayfromState {
    /// The exact fee-plus-outputs figure this selection's SHAPE needs, when
    /// one can be estimated numerically. `None` only for a lone external
    /// wallet, whose real cost is "whatever the wallet pays" — never an
    /// invented sats figure (unchanged design intent).
    pub(crate) required: Option<u64>,
    /// Always non-empty — "~N sats" for numeric shapes, a descriptive line
    /// ("funded by <wallet>") for the external-only shape.
    pub(crate) required_line: String,
    /// True cross-wallet total, regardless of which source is active/expanded.
    pub(crate) selected: u64,
    /// The single sufficiency verdict every consumer renders from.
    pub(crate) enough: bool,
    /// "Notebook" | "Spending wallet" | the external wallet's label | "N wallets".
    pub(crate) source_label: String,
    /// Machine-readable selection shape — drives the Sign-button DISPATCH
    /// inputs too (Sal's TestFlight-build-13 follow-up, 2026-07-18): see
    /// `sync_and_finalize_payfrom`'s alignment step.
    pub(crate) shape: PayfromShape,
}

/// Which single compose path (or the mixed one) the CURRENT cross-wallet
/// selection actually needs. `External` carries the full source key
/// ("wallet:<id>").
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum PayfromShape {
    Empty,
    Notebook,
    Spending,
    External(String),
    Mixed,
}

/// Fill the compose screen's structured cost-breakdown card (Sal's
/// build-17 follow-up, 2026-07-18: replace the single wrapped cost-line
/// string with key:value sections). Empty strings hide their row;
/// `fold_total` is `(folded_leftover, byte-true_total_fee)` when the
/// dust-rule fold prediction fired — it populates the "Leftover (dust
/// rule)" and "Total" rows (Total == Fee otherwise, so both stay hidden).
/// Clears `cost_line`: the plain accent text only renders while the card
/// is empty (error/status messaging goes through [`set_cost_status`]).
pub(crate) fn set_cost_card(
    w: &AppWindow,
    size: String,
    fee: String,
    gift: String,
    dust: String,
    fold_total: Option<(u64, u64)>,
) {
    w.global::<Compose>().set_cost_line("".into());
    w.global::<Compose>().set_cost_size(size.into());
    w.global::<Compose>().set_cost_fee(fee.into());
    w.global::<Compose>().set_cost_gift(gift.into());
    w.global::<Compose>().set_cost_dust(dust.into());
    match fold_total {
        Some((folded, total)) => {
            w.global::<Ui>().set_cost_fold(format!("+{} sats", commas(folded)).into());
            w.global::<Ui>().set_cost_total(format!("~{} sats", commas(total)).into());
        }
        None => {
            w.global::<Ui>().set_cost_fold("".into());
            w.global::<Ui>().set_cost_total("".into());
        }
    }
}

/// ERROR/status text under the rate box ("Too large to broadcast…",
/// "~N sats fee minimum", "funded from the external wallet"): plain
/// accent `cost_line` text, structured card hidden — these render exactly
/// as they did before the card existed.
pub(crate) fn set_cost_status(w: &AppWindow, text: String) {
    w.global::<Compose>().set_cost_size("".into());
    w.global::<Compose>().set_cost_fee("".into());
    w.global::<Compose>().set_cost_gift("".into());
    w.global::<Compose>().set_cost_dust("".into());
    w.global::<Ui>().set_cost_fold("".into());
    w.global::<Ui>().set_cost_total("".into());
    w.global::<Compose>().set_cost_line(text.into());
}

/// The tx builders fold sub-dust change into the fee (notes-core rule: a
/// leftover below the 330-sat dust minimum can't be an output, and the
/// builder never burns MORE than dust — larger leftovers force a change
/// output). Without this note the confirm screen shows a fee visibly above
/// rate×vsize with no explanation — Sal hit exactly that on testnet4
/// (single 330-sat coin → whole coin to fee) and asked if dust was
/// forgotten. The byte-truth fee row (e.g. "330 sats · 3.2 sat/vB") stays
/// untouched elsewhere on the screen — this banner is what keeps that
/// figure from reading as an inflated/expensive fee: it splits it into the
/// real network fee at the user's chosen rate (`nominal = ceil(vsize×rate)`)
/// and the sub-dust leftover riding along on top (Sal 2026-07-18: "every
/// fee label must split honestly ... so it's not misleading as being
/// expensive to use this app"). Appends to the warn banner AFTER
/// show_confirm populated it; only when the confirm screen actually
/// navigated.
pub(crate) fn note_subdust_fold_warn(w: &AppWindow, change: u64, fee: u64, vsize: u64, rate: f64) {
    if change != 0 || w.global::<Ui>().get_screen() != Screen::Confirm {
        return;
    }
    let nominal = (vsize as f64 * rate).ceil() as u64;
    let folded = fee.saturating_sub(nominal);
    if folded == 0 {
        return;
    }
    println!("cb: confirm subdust-fold folded={folded}");
    let msg = format!(
        "network fee ~{} sats at your rate · +{} sats leftover below the {} sat dust minimum (too small to form a change output)",
        commas(nominal),
        commas(folded),
        DUST_SATS
    );
    let existing = w.global::<Ui>().get_confirm_warn().to_string();
    w.global::<Ui>().set_confirm_warn(if existing.is_empty() { msg.into() } else { format!("{existing}; {msg}").into() });
}

impl State {
/// The active external funding wallet's Activity pill value
/// (`"wallet:<label>"`), or `None` if no funding wallet is active — used
/// when recording a note an external wallet paid for.
pub(crate) fn active_funding_pill(&self) -> Option<String> {
    let st = self;
    let id = st.active_funding_id.as_ref()?;
    let fw = st.funding_wallets.iter().find(|f| &f.id == id)?;
    Some(format!("wallet:{}", fw.label))
}

/// Refresh the compose screen's removable To-chips (`AppWindow.to-chips`)
/// from `st.to_addresses_extra`, resolving each address to its contact
/// name (if any) the same way the confirm screen's `recipient_name`
/// lookup does. Called whenever the extra-recipient list changes: a fresh
/// primary pick (cleared), `on_add_chip` (appended), `on_remove_chip`
/// (removed).
pub(crate) fn refresh_to_chips(&self, w: &AppWindow) {
    let st = self;
    let rows: Vec<ContactItem> = st
        .to_addresses_extra
        .iter()
        .map(|a| {
            let name = st
                .contacts
                .iter()
                .find(|c| &c.address == a && !c.name.is_empty())
                .map(|c| c.name.clone())
                .unwrap_or_default();
            ContactItem { address: a.clone().into(), name: name.into(), synced: false, sync_status: 0, pq: false }
        })
        .collect();
    w.global::<Compose>().set_to_chips(VecModel::from_slice(&rows));
}

/// Multi-select: append `addr` to `st.to_addresses_extra` (validated,
/// normalized/lowercased the same way `pick_contact_core` handles a typo'd
/// address case, deduped against BOTH the primary `to_address` and the
/// existing extras, capped at 255 total recipients — the UI selection cap;
/// notes-core's own compose-time 1..=255 dedupe is the wire-level
/// backstop). Touches the contact (recency) and returns to compose
/// (screen 6), reusing the SAME `refresh_compose` the primary picker uses
/// so the cost line/preview updates immediately.
pub(crate) fn add_recipient_chip(&mut self, w: &AppWindow, addr: &str) {
    let st = self;
    let mut a = normalize_addr(addr);
    if a == "self" || a.is_empty() {
        w.global::<Ui>().set_status("pick an address".into());
        return;
    }
    let parsed = match Recipient::parse(st.network, &a) {
        Ok(r) => r,
        Err(_) => {
            let lower = a.to_lowercase();
            match Recipient::parse(st.network, &lower) {
                Ok(r) => {
                    a = lower;
                    r
                }
                Err(_) => {
                    println!("cb: add-chip err=bad-address");
                    w.global::<Ui>().set_status(format!("not a valid {} address", st.network.as_str()).into());
                    return;
                }
            }
        }
    };
    // Same inline error pattern as the single-recipient compose path
    // (notes-core's `Error::RecipientNotTaproot`, surfaced when Sign is
    // tapped) — checked proactively here too, before it's even added as a
    // chip, since private+non-taproot is knowable immediately.
    if w.global::<Compose>().get_compose_private() && parsed.p2tr_x.is_none() {
        println!("cb: add-chip err=not-taproot");
        w.global::<Ui>().set_status("private directed notes need a taproot (bc1p…) recipient".into());
        return;
    }
    let already = st.to_address.as_deref() == Some(a.as_str()) || st.to_addresses_extra.iter().any(|x| x == &a);
    st.picking_extra = false;
    w.global::<Ui>().set_picking_extra(false);
    if already {
        println!("cb: add-chip dup");
        w.global::<Ui>().set_status("already added".into());
        w.global::<Ui>().set_screen(Screen::Compose);
        return;
    }
    let total = 1 + st.to_addresses_extra.len();
    if total >= 255 {
        println!("cb: add-chip err=limit");
        w.global::<Ui>().set_status("recipient limit reached (255)".into());
        w.global::<Ui>().set_screen(Screen::Compose);
        return;
    }
    st.touch_contact(&a);
    st.save_contacts();
    st.refresh_contacts(w);
    st.to_addresses_extra.push(a.clone());
    println!("cb: add-chip n={}", st.to_addresses_extra.len() + 1);
    st.refresh_to_chips(w);
    w.global::<Ui>().set_screen(Screen::Compose);
    st.refresh_compose(w);
}

/// Funding-unification: default "Pay from" to the spending wallet ONLY when
/// the setting is on AND it actually has spendable balance (Sal
/// 2026-07-16) — an enabled-but-empty spending wallet still defaults to
/// Notebook. Balance is whatever's cached this session; an unscanned wallet
/// reads as 0 and falls through to Notebook too (never guess a positive
/// balance we haven't confirmed). A watch identity has no spending wallet
/// at all. Shared by `pick_contact_core` (fresh compose session) and
/// `apply_spending_refresh_result` (CHANGE 5: a landed scan re-resolves
/// the default for a user already sitting on compose, as long as they
/// haven't made an explicit pick yet this session — `payfrom_manual`).
pub(crate) fn resolve_payfrom_default(&mut self, w: &AppWindow) {
    let st = self;
    let spending_balance: u64 = st.spending_coins.iter().map(|c| c.value).sum();
    let spending_default = st.spending_capable
        && !st.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false)
        && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false)
        && spending_balance > 0;
    let default_source = if spending_default { "spending" } else { "notebook" };
    st.payfrom_active_source = default_source.to_string();
    st.apply_pay_from(w, default_source);
}

/// Repaint the compose screen's locktime panel from `st`'s current
/// effective policy (override if the panel set one this session, else the
/// device default) — called on every fresh compose session AND after
/// every `on_set_compose_locktime` tap, so the panel always reflects
/// exactly what the next Sign would build with.
pub(crate) fn refresh_compose_locktime_panel(&self, w: &AppWindow) {
    let st = self;
    let policy = st.tx_lock_time_override.unwrap_or(st.lock_time_policy);
    let tip = st.store.as_ref().map(|s| s.tip_height);
    let (mode, height, effective, warn) = locktime_panel_values(policy, tip);
    w.global::<Compose>().set_compose_locktime_mode(mode.into());
    w.global::<Compose>().set_compose_locktime_height(height.into());
    w.global::<Compose>().set_compose_locktime_effective(effective.into());
    w.global::<Compose>().set_compose_locktime_warn(warn.into());
}

/// Whether the compose screen's post-quantum "Security" section applies at
/// all — private + single-recipient (no removable To-chips, no multi-
/// recipient) + a KEYED identity (watch-only can't seal anything) +
/// NOTEBOOK-funded (mixed/spending-funded compose calls a different
/// builder that never carries pq layers — see `ComposeRequest::
/// pq_password`'s doc). Covers BOTH a directed note (`st.to_address` set)
/// and a self-note (`st.to_address` empty) since PLAN-graffito-self-pw.md —
/// before that, self-notes were excluded entirely. Shared by the panel
/// visibility condition (app.slint mirrors this exact logic) and every
/// Rust caller that needs to know whether pq layers are even reachable
/// right now.
pub(crate) fn pq_compose_eligible(&self, w: &AppWindow) -> bool {
    let st = self;
    w.global::<Compose>().get_compose_private()
        && st.to_addresses_extra.is_empty()
        && st.ident.as_ref().map(|i| !i.is_watch()).unwrap_or(false)
        && st.payfrom_active_source == "notebook"
}

/// Repaint the compose screen's "Security" section from current UI toggle
/// state + the resolved recipient's contact key, and return the pq flags/
/// alg the cost estimate and (at Sign time) `ComposeRequest` should use —
/// `(0, None)` when the section doesn't apply or neither layer is on, so
/// every non-pq compose stays byte-identical to before this feature.
/// Called from `refresh_compose` on every relevant compose change (mirrors
/// `refresh_compose_locktime_panel`'s pattern).
pub(crate) fn refresh_compose_pq(&mut self, w: &AppWindow) -> (u8, Option<app_core::notes_core::pq::MlKemAlg>) {
    let st = self;
    use app_core::notes_core::envelope::{FLAG_MLKEM, FLAG_PW};
    use app_core::passphrase::{self, SecurityChoice};

    if !st.pq_compose_eligible(w) {
        // Hidden on screen 6 (same condition, mirrored in app.slint) — keep
        // the outward-facing props at their inert defaults so nothing
        // stale lingers if the section becomes reachable again mid-session
        // (e.g. the user removes an extra recipient chip).
        w.global::<Ui>().set_pq_quantum_resistant(false);
        w.global::<Compose>().set_pq_security_label("".into());
        w.global::<Compose>().set_pq_mlkem_available(false);
        w.global::<Compose>().set_pq_mlkem_caption("".into());
        return (0, None);
    }

    let private = true; // pq_compose_eligible already required this
    let directed = st.to_address.is_some();

    // ---- ML-KEM availability ----
    let (mlkem_available, mlkem_level, mlkem_caption) = if directed {
        // Directed note: cached per resolved recipient address (unchanged).
        let addr = st.to_address.clone().unwrap_or_default();
        let recompute = st.pq_recipient_cache.as_ref().map(|(a, _)| a.as_str()) != Some(addr.as_str());
        if recompute {
            let net = st.network.as_str();
            let display = st
                .contacts
                .iter()
                .find(|c| c.address == addr && (c.network == net || c.network.is_empty()))
                .and_then(|c| c.mlkem_ek.as_deref())
                .map(app_core::pqkeys::contact_pq_display);
            st.pq_recipient_cache = Some((addr.clone(), display));
        }
        let resolved = st.pq_recipient_cache.as_ref().and_then(|(_, d)| d.as_ref());
        match resolved {
            Some(Ok((level, line))) => (true, Some(*level), line.clone()),
            Some(Err(e)) => (false, None, format!("couldn't read this contact's quantum key: {e}")),
            None => (false, None, "recipient has no quantum key — add one in Contacts".to_string()),
        }
    } else {
        // Self-note (PLAN-graffito-self-pw.md): the ONLY eligible key is an
        // imported/randomly-generated quantum key living outside the seed
        // tree (`State.pq_imported`) — NEVER the notebook's seed-derived
        // receive key, which shares the same leaf secret as the enc key it
        // would be layered over and so buys nothing (notes-core's `pq.rs`
        // "Self-note pq layers" doc calls this out explicitly). No
        // recipient-keyed cache applies here.
        st.pq_recipient_cache = None;
        match st.pq_imported.as_ref() {
            Some(kp) => (
                true,
                Some(app_core::pqkeys::from_pq_alg(kp.alg())),
                // "your quantum key", not "this imported key": the slot has
                // held generated keys too since PLAN-graffito-quantum-key.md.
                "readable only where your quantum key is present — losing the key loses \
                 this note forever, even with your seed."
                    .to_string(),
            ),
            None => (
                false,
                None,
                "add a quantum key first (Settings → Quantum keys) to add this layer".to_string(),
            ),
        }
    };
    w.global::<Compose>().set_pq_mlkem_available(mlkem_available);
    w.global::<Compose>().set_pq_mlkem_caption(mlkem_caption.into());
    // The recipient changed out from under an enabled toggle (picked a
    // different contact without one) — don't leave it silently on for a
    // layer that can no longer apply.
    if !mlkem_available && w.global::<Compose>().get_pq_mlkem_enabled() {
        w.global::<Compose>().set_pq_mlkem_enabled(false);
    }
    // Hybrid by DEFAULT (2026-09-05): whenever a quantum key is available
    // for this note — the recipient published one, or this is a self-note
    // and the notebook has one — the ML-KEM layer starts ON. The classical
    // ECDH/seed key is the only quantum-weak primitive in a private note,
    // and having the key but not using it was the worst of both. A manual
    // switch-off sticks for the session (`pq_mlkem_user_off`).
    if mlkem_available && !st.pq_mlkem_user_off && !w.global::<Compose>().get_pq_mlkem_enabled() {
        w.global::<Compose>().set_pq_mlkem_enabled(true);
    }
    let mlkem_on = mlkem_available && w.global::<Compose>().get_pq_mlkem_enabled();

    // ---- passphrase layer ----
    let passphrase_on = w.global::<Compose>().get_pq_passphrase_enabled();
    let passphrase_text = w.global::<Compose>().get_pq_passphrase_text().to_string();
    let (passphrase_bits, strength_line) = if passphrase_on {
        let strength = if st.pq_passphrase_verified {
            passphrase::check_generated()
        } else {
            passphrase::check(&passphrase_text)
        };
        // A typed phrase under ~45 estimated bits is called out as WEAK
        // outright (red, not amber): zxcvbn's ceiling for typed input is
        // ~64 bits, so 45 separates "thin but deliberate" multi-word
        // phrases from single words + trivial suffixes that any cracker
        // enumerates. The device app applies the same idea through its
        // simpler passphrase::typed_is_weak gate.
        let weak = !st.pq_passphrase_verified
            && !passphrase_text.is_empty()
            && strength.bits < 45.0;
        w.global::<Compose>().set_pq_passphrase_weak(weak);
        let line = if st.pq_passphrase_verified {
            format!("{:.0}-bit generated phrase", strength.bits)
        } else if weak {
            format!(
                "weak (~{:.0} bits) — easily brute-forced; use Generate or add more words",
                strength.bits
            )
        } else {
            format!(
                "~{:.0} bits — strength can't be verified; use Generate for a certified phrase",
                strength.bits
            )
        };
        (Some(strength.bits), line)
    } else {
        (None, String::new())
    };
    w.global::<Compose>().set_pq_passphrase_verified(passphrase_on && st.pq_passphrase_verified);
    w.global::<Compose>().set_pq_passphrase_strength_line(strength_line.into());
    w.global::<Compose>().set_pq_pw_cost(st.pq_pw_cost.as_str().into());
    w.global::<Compose>().set_pq_pw_cost_caption(pw_cost_caption(st.pq_pw_cost).into());

    // ---- combined label (Rust-computed, never reimplemented in slint) --
    let choice = SecurityChoice {
        private,
        directed,
        passphrase_bits,
        passphrase_verified: st.pq_passphrase_verified,
        mlkem: if mlkem_on { mlkem_level } else { None },
    };
    // `security_label` is total over `SecurityChoice` — the self-note
    // layered cases included (they used to be patched over the label right
    // here, and the patch went stale; the whole table is pinned in
    // app-core/tests/security_label_contract.rs). Nothing to override.
    let (quantum_resistant, label) = passphrase::describe(&choice);
    w.global::<Ui>().set_pq_quantum_resistant(quantum_resistant);
    w.global::<Compose>().set_pq_security_label(label.into());

    let flags = (if passphrase_on { FLAG_PW } else { 0 }) | (if mlkem_on { FLAG_MLKEM } else { 0 });
    let alg = if mlkem_on { mlkem_level.map(app_core::pqkeys::pq_alg) } else { None };
    (flags, alg)
}

/// Recompute the whole compose screen from state: coin list + selection,
/// spend total, live cost, change preview, change-address validation, and
/// the feasibility gate on the Sign button.
/// Apply a "Pay from" picker selection on compose (funding-unification
/// M3): "notebook" (today's path, default) or "spending" (the identity's
/// own BIP-84 wallet). External wallets go through [`activate_funding_wallet`]
/// instead (it sets `pay-from` to `"wallet:<id>"` itself, since picking one
/// also has to scan it). Kicks a background scan the first time "spending"
/// is chosen this session.
pub(crate) fn apply_pay_from(&mut self, w: &AppWindow, kind: &str) {
    let st = self;
    match kind {
        "spending" => {
            w.global::<Ui>().set_pay_from("spending".into());
            w.global::<Compose>().set_pay_from_label("Spending wallet".into());
            w.global::<Ui>().set_fund_external(false);
            w.global::<Ui>().set_spend_from_wallet(true);
            if !st.spending_scanned {
                st.spending_refresh_async(w);
            }
        }
        _ => {
            w.global::<Ui>().set_pay_from("notebook".into());
            w.global::<Compose>().set_pay_from_label("Notebook".into());
            w.global::<Ui>().set_fund_external(false);
            w.global::<Ui>().set_spend_from_wallet(false);
        }
    }
    w.global::<Ui>().set_pay_from_balance(st.balance_text_for(kind).into());
}

/// Coins remembered under `source` in the cross-wallet selection memory
/// (funding-unification UI rework) — source key convention: "notebook" |
/// "spending" | "wallet:<id>".
pub(crate) fn mixed_coins_for(&self, source: &str) -> Vec<(String, u32)> {
    let st = self;
    st.mixed_selected
        .iter()
        .filter(|(s, _, _)| s == source)
        .map(|(_, t, v)| (t.clone(), *v))
        .collect()
}

/// Replace `source`'s entries in the cross-wallet selection memory with
/// `coins` — keeps it in sync with the legacy single-source scratch state
/// (`selected_coins`) whenever the active source's selection changes.
pub(crate) fn mixed_sync_source(&mut self, source: &str, coins: &[(String, u32)]) {
    let st = self;
    st.mixed_selected.retain(|(s, _, _)| s != source);
    for (t, v) in coins {
        st.mixed_selected.push((source.to_string(), t.clone(), *v));
    }
}

/// Resolve the mixed-compose builder arguments from the live selection.
/// `Err` only for a "custom" change choice whose typed address doesn't
/// parse — the same (and only) validation failure `on_compose_send_mixed`'s
/// inline version had.
pub(crate) fn mixed_compose_args(&self, w: &AppWindow) -> Result<MixedComposeArgs, String> {
    let st = self;
    let net = st.network;

    // Partition the cross-wallet selection into per-source coins.
    let notebook_sel = st.mixed_coins_for("notebook");
    let spending_sel = st.mixed_coins_for("spending");
    let wallet_key = st
        .mixed_selected
        .iter()
        .find_map(|(src, _, _)| src.strip_prefix("wallet:").map(|_| src.clone()));
    let wallet_sel = wallet_key.as_deref().map(|k| st.mixed_coins_for(k)).unwrap_or_default();

    let mut coins: Vec<app_core::mixed::MixedCoin> = Vec::new();
    if let Some(store) = st.store.as_ref() {
        for (txid, vout) in &notebook_sel {
            if let Some(u) =
                store.utxos.iter().find(|u| &u.txid == txid && u.vout == *vout && !u.pending_spend)
            {
                coins.push(app_core::mixed::MixedCoin {
                    source: app_core::mixed::CoinSource::Notebook,
                    txid: u.txid.clone(),
                    vout: u.vout,
                    value: u.value,
                    chain: 0,
                    index: 0,
                });
            }
        }
    }
    for (txid, vout) in &spending_sel {
        if let Some(c) = st.spending_coins.iter().find(|c| &c.txid == txid && c.vout == *vout) {
            coins.push(app_core::mixed::MixedCoin {
                source: app_core::mixed::CoinSource::Spending,
                txid: c.txid.clone(),
                vout: c.vout,
                value: c.value,
                chain: c.chain,
                index: c.index,
            });
        }
    }
    let mut wallets_map: HashMap<String, FundingSource> = HashMap::new();
    if let Some(wk) = wallet_key.as_deref() {
        if let (Some(id), Some(src)) = (wk.strip_prefix("wallet:"), st.funding.clone()) {
            for (txid, vout) in &wallet_sel {
                if let Some(c) = st.funding_coins.iter().find(|c| &c.txid == txid && c.vout == *vout) {
                    coins.push(app_core::mixed::MixedCoin {
                        source: app_core::mixed::CoinSource::Wallet(id.to_string()),
                        txid: c.txid.clone(),
                        vout: c.vout,
                        value: c.value,
                        chain: c.chain,
                        index: c.index,
                    });
                }
            }
            wallets_map.insert(id.to_string(), src);
        }
    }

    // Taproot CHANGE-chain coins (unit 5, see
    // `../PLAN-chain-notes-app-taproot-change.md`): same account, chain 1
    // instead of the notebooks' chain 0 — `CoinSource::Change` carries the
    // chain-1 index (needed to derive the signing owner later); the
    // builder-side `change_spks` map is built here from the UNIQUE indexes
    // actually selected, via `realize_change` (the chain-1 sibling of
    // `realize`), mirroring `build_sweep_confirm`'s change-idents loop.
    let change_sel = st.mixed_coins_for("change");
    let mut change_spks: HashMap<u32, Vec<u8>> = HashMap::new();
    if !change_sel.is_empty() {
        if let Some(material_str) = st.material.as_ref().map(|z| String::from(z.as_str())) {
            if let Ok(material) = parse_key_material(&material_str, net) {
                for (txid, vout) in &change_sel {
                    if let Some(c) = st.change_coins.iter().find(|c| &c.txid == txid && c.vout == *vout) {
                        coins.push(app_core::mixed::MixedCoin {
                            source: app_core::mixed::CoinSource::Change,
                            txid: c.txid.clone(),
                            vout: c.vout,
                            value: c.value,
                            chain: 1,
                            index: c.index,
                        });
                        if let std::collections::hash_map::Entry::Vacant(e) = change_spks.entry(c.index) {
                            if let Ok(owner) = realize_change(&material, net, st.account, c.index) {
                                e.insert(p2tr_script_pubkey(&owner.output_x()));
                            }
                        }
                    }
                }
            }
        }
    }

    // Change: an explicit "custom" pick overrides; otherwise the resolved
    // default already reflected in `change-choice`.
    let choice = w.global::<Ui>().get_change_choice().to_string();
    let change_override = if choice == "custom" {
        let addr = normalize_addr(w.global::<Ui>().get_change_address().as_str());
        if addr.is_empty() {
            None
        } else {
            match Recipient::parse(net, &addr) {
                Ok(r) => Some(r.spk),
                Err(_) => {
                    return Err(format!("change address isn't a valid {} address", net.as_str()))
                }
            }
        }
    } else {
        None
    };
    let change_default = match choice.as_str() {
        "spending" => app_core::mixed::ChangeDefault::Spending,
        c if c.starts_with("wallet:") => {
            app_core::mixed::ChangeDefault::Wallet(c.trim_start_matches("wallet:").to_string())
        }
        _ => app_core::mixed::ChangeDefault::Notebook,
    };
    let change_index = st.store.as_ref().map(|s| s.spending.next_change).unwrap_or(0);

    Ok(MixedComposeArgs { coins, wallets_map, change_spks, change_default, change_override, change_index })
}

/// Build a source's OWN coin list + "N coins selected · X sats" caption for
/// the Pay-from screen's independently-expandable sections (2026-07-18
/// rework: every expanded section now renders its own data, so opening one
/// wallet never hides another's — see `nb_expanded`/`sp_expanded`/
/// `payfrom_expanded_source`). Deliberately separate from the legacy
/// singular `spend-coins`/`spend-title` (untouched — still driven by
/// whichever source is `payfrom_active_source` and feeds the live fee/
/// change preview via `refresh_compose`'s three branches). Selection
/// membership is read from the cross-wallet memory (`mixed_selected`) —
/// read-only, never mutates it. An external wallet's coins come from
/// `funding_coins` when it's the currently-active one, else the display-
/// only peek cache (`payfrom_wallet_coins`) populated by
/// `payfrom_scan_wallet_for_display` — empty (not yet scanned) shows as a
/// zero-coin panel, never a stale/wrong wallet's coins.
///
/// Taproot CHANGE-chain coins (unit 5, see
/// `../PLAN-chain-notes-app-taproot-change.md`): folded into the
/// `"notebook"` panel's row list — Sal's "one unified balance" rule, same
/// philosophy as the Coins screen (`update_wallet_coins`'s `notebook:
/// "change"` tag) — but their SELECTION membership is tracked under a
/// DISTINCT `"change"` key in `mixed_selected` (a change coin's signing
/// owner is per chain-1 INDEX, unlike the notebook's one fixed leaf, so
/// `mixed_compose_args` must be able to tell them apart), and each row
/// carries `tag: "change"` so `CoinListPanel` badges it.
pub(crate) fn payfrom_panel_coins(&self, source: &str) -> (Vec<SpendCoin>, String) {
    let st = self;
    let net = st.network;
    let exb = st.explorer_base();
    let sel: std::collections::HashSet<(String, u32)> = st.mixed_coins_for(source).into_iter().collect();
    let row = |txid: &str, vout: u32, value: u64, confirmed: bool, selected: bool, tag: &str| SpendCoin {
        outpoint: format!("{txid}:{vout}").into(),
        value: value.to_string().into(),
        confirmed,
        selected,
        txid_short: txid[..8.min(txid.len())].to_string().into(),
        explorer: explorer_tx_url(exb.as_deref(), net, txid).into(),
        tag: tag.into(),
    };
    let mut coins: Vec<SpendCoin> = Vec::new();
    match source {
        "notebook" => {
            if let Some(store) = st.store.as_ref() {
                let mut spendable: Vec<&app_core::store::LedgerUtxo> =
                    store.utxos.iter().filter(|u| !u.pending_spend).collect();
                spendable.sort_by_key(|a| a.value);
                for u in spendable {
                    let selected = sel.contains(&(u.txid.clone(), u.vout));
                    coins.push(row(&u.txid, u.vout, u.value, u.height.is_some(), selected, ""));
                }
            }
            // Fold in taproot CHANGE-chain coins (unit 5): SAME account,
            // chain 1 — tagged into the SAME panel per Sal's "one unified
            // balance" rule, but their selection lives under the DISTINCT
            // "change" key (see this function's doc comment above).
            let chg_sel: std::collections::HashSet<(String, u32)> =
                st.mixed_coins_for("change").into_iter().collect();
            let mut change_sorted: Vec<&ChangeCoin> = st.change_coins.iter().collect();
            change_sorted.sort_by_key(|a| a.value);
            for c in change_sorted {
                let selected = chg_sel.contains(&(c.txid.clone(), c.vout));
                coins.push(row(&c.txid, c.vout, c.value, c.confirmed, selected, "change"));
            }
        }
        "spending" => {
            for c in &st.spending_coins {
                let selected = sel.contains(&(c.txid.clone(), c.vout));
                coins.push(row(&c.txid, c.vout, c.value, c.confirmed, selected, ""));
            }
        }
        _ => {
            if let Some(id) = source.strip_prefix("wallet:") {
                let cached: Vec<FundingUtxo> = if st.active_funding_id.as_deref() == Some(id) {
                    st.funding_coins.clone()
                } else {
                    st.payfrom_wallet_coins.get(id).cloned().unwrap_or_default()
                };
                for c in &cached {
                    let selected = sel.contains(&(c.txid.clone(), c.vout));
                    coins.push(row(&c.txid, c.vout, c.value, c.confirmed, selected, ""));
                }
            }
        }
    }
    let sel_count = coins.iter().filter(|c| c.selected).count();
    let sel_total: u64 =
        coins.iter().filter(|c| c.selected).filter_map(|c| c.value.parse::<u64>().ok()).sum();
    let plural = if sel_count == 1 { "" } else { "s" };
    let title = format!("{sel_count} coin{plural} selected · {} sats", commas(sel_total));
    (coins, title)
}

/// Refresh the Pay-from screen's per-section coin lists — Notebook and
/// Spending only (external wallets are handled per-row inside
/// `refresh_funding_list`, since they're a dynamic list). Pure read +
/// render, called after every state change that could affect what an
/// expanded section shows (open, header-tap expand, a coin toggle, a
/// landed scan) — cheap (bounded by UTXO count), never touches selection.
pub(crate) fn update_payfrom_panels(&mut self, w: &AppWindow) {
    let st = self;
    let (nb_coins, nb_title) = st.payfrom_panel_coins("notebook");
    w.global::<PayFrom>().set_nb_panel_coins(VecModel::from_slice(&nb_coins));
    w.global::<PayFrom>().set_nb_panel_title(nb_title.into());
    let (sp_coins, sp_title) = st.payfrom_panel_coins("spending");
    w.global::<PayFrom>().set_sp_panel_coins(VecModel::from_slice(&sp_coins));
    w.global::<PayFrom>().set_sp_panel_title(sp_title.into());
}

/// Scan a saved wallet PURELY to populate its Pay-from screen coin list
/// (independent-expand rework, 2026-07-18) — the header-tap counterpart to
/// `activate_funding_wallet` that never makes the wallet the active/primary
/// funding source and never defaults its selection to "every coin" (that
/// default-to-all-on-expand was Sal's iPhone complaint #3). Only an actual
/// coin tap (`on_toggle_coin`, via `promote_wallet_active`) or a remembered
/// selection from earlier this session puts anything in `mixed_selected`.
/// A no-op once this wallet is either the live active one or already
/// peek-cached — re-expanding just shows what's already there.
pub(crate) fn payfrom_scan_wallet_for_display(&mut self, w: &AppWindow, id: &str) {
    let st = self;
    if st.active_funding_id.as_deref() == Some(id) || st.payfrom_wallet_coins.contains_key(id) {
        return;
    }
    let net = st.network;
    let Some(idx) = st.funding_wallets.iter().position(|fw| fw.id == id) else { return };
    let descriptor = st.funding_wallets[idx].descriptor.clone();
    let src = match FundingSource::parse(&descriptor, net) {
        Ok(src) => src,
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
    };
    let Some(base) = st.base_url() else {
        w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
        return;
    };
    w.global::<Ui>().set_status("scanning funding wallet…".into());
    let creds = st.core_rpc_creds_for(&base, net);
    let client = match open_client(&base, net, creds) {
        Ok(c) => c,
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
    };
    match client.scan_funding(&src, 20) {
        Ok(scan) => {
            st.funding_wallets[idx].balance = scan.utxos.iter().map(|c| c.value).sum();
            st.funding_wallets[idx].coins = scan.utxos.len();
            st.funding_wallets[idx].scanned = true;
            st.funding_wallets[idx].next_change_index = scan.next_change_index;
            st.save_funding_wallets();
            let empty = scan.utxos.is_empty();
            st.payfrom_wallet_coins.insert(id.to_string(), scan.utxos);
            w.global::<Ui>().set_status(if empty { "wallet has no spendable coins yet".to_string() } else { String::new() }.into());
        }
        Err(e) => {
            w.global::<Ui>().set_status(format!("{e}").into());
        }
    }
}

/// Make a wallet the compose engine's active/primary pay-from source —
/// counterpart to `apply_pay_from`'s notebook/spending cases, called from
/// `on_toggle_coin` right after a coin tap (never from a mere expand).
/// Promotes the display-only peek cache (`payfrom_wallet_coins`) into the
/// SINGLE live `funding_coins`/`funding`/`active_funding_id` the rest of
/// the external-funding plumbing reads, unless this wallet is already the
/// live one (then its current scan is left untouched — never reverted to a
/// possibly-stale peek snapshot). Never auto-selects coins: by the time
/// this runs, the caller has already synced the just-toggled selection into
/// `mixed_selected`.
pub(crate) fn promote_wallet_active(&mut self, w: &AppWindow, id: &str) {
    let st = self;
    let net = st.network;
    let Some(idx) = st.funding_wallets.iter().position(|fw| fw.id == id) else { return };
    if st.active_funding_id.as_deref() != Some(id) {
        let descriptor = st.funding_wallets[idx].descriptor.clone();
        let src = match FundingSource::parse(&descriptor, net) {
            Ok(src) => src,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        st.funding_coins = st.payfrom_wallet_coins.get(id).cloned().unwrap_or_default();
        st.funding_change_index = st.funding_wallets[idx].next_change_index;
        st.funding = Some(src);
        st.active_funding_id = Some(id.to_string());
    }
    let label = st.funding_wallets[idx].label.clone();
    let balance = st.funding_wallets[idx].balance;
    w.global::<Ui>().set_fund_external(true);
    w.global::<Ui>().set_spend_from_wallet(false);
    w.global::<Ui>().set_pay_from(format!("wallet:{id}").into());
    w.global::<Compose>().set_pay_from_label(label.clone().into());
    w.global::<Ui>().set_pay_from_balance(format!("{} sats", commas(balance)).into());
    println!("cb: pay-from wallet:{label}");
}

pub(crate) fn payfrom_state(&self, w: &AppWindow) -> PayfromState {
    let st = self;
    let net = st.network;

    // ---- partition the TRUE cross-wallet selection — never the legacy
    // single-source `selected_coins` scratch, which only ever mirrors
    // whichever source is `payfrom_active_source`. ----
    let nb_sel = st.mixed_coins_for("notebook");
    let nb_total: u64 = st
        .store
        .as_ref()
        .map(|store| {
            nb_sel
                .iter()
                .filter_map(|(t, v)| store.utxos.iter().find(|u| &u.txid == t && u.vout == *v).map(|u| u.value))
                .sum()
        })
        .unwrap_or(0);
    let sp_sel = st.mixed_coins_for("spending");
    let sp_total: u64 = sp_sel
        .iter()
        .filter_map(|(t, v)| st.spending_coins.iter().find(|c| &c.txid == t && c.vout == *v).map(|c| c.value))
        .sum();
    // Taproot CHANGE-chain coins (unit 5, see
    // `../PLAN-chain-notes-app-taproot-change.md`): tracked under their own
    // "change" key in `mixed_selected` (see `payfrom_panel_coins`'s doc),
    // even though their rows render inside the "Notebook" panel.
    let chg_sel = st.mixed_coins_for("change");
    let chg_total: u64 = chg_sel
        .iter()
        .filter_map(|(t, v)| st.change_coins.iter().find(|c| &c.txid == t && c.vout == *v).map(|c| c.value))
        .sum();
    let mut wallet_sources: Vec<String> = st
        .mixed_selected
        .iter()
        .filter(|(s, _, _)| s.starts_with("wallet:"))
        .map(|(s, _, _)| s.clone())
        .collect();
    wallet_sources.sort();
    wallet_sources.dedup();
    let ext_total: u64 = wallet_sources
        .iter()
        .map(|src| {
            let coins = st.mixed_coins_for(src);
            let id = src.strip_prefix("wallet:").unwrap_or("");
            let pool: Vec<FundingUtxo> = if st.active_funding_id.as_deref() == Some(id) {
                st.funding_coins.clone()
            } else {
                st.payfrom_wallet_coins.get(id).cloned().unwrap_or_default()
            };
            coins.iter().filter_map(|(t, v)| pool.iter().find(|c| &c.txid == t && c.vout == *v).map(|c| c.value)).sum::<u64>()
        })
        .sum();

    let selected = nb_total + sp_total + ext_total + chg_total;
    // A change coin is always this identity's OWN coin — never a distinct
    // "group" the way an external wallet is — but it DOES need the mixed
    // builder (no single-source Sign button covers it), so it still counts
    // toward the group tally that decides whether a single-source branch
    // below applies (taproot-change unit 5).
    let groups =
        [nb_total > 0, sp_total > 0, ext_total > 0, chg_total > 0].into_iter().filter(|b| *b).count();

    // ---- shared compose context ----
    let text = w.global::<Compose>().get_compose_text().to_string();
    let text_for_est: String = if text.is_empty() { "x".to_string() } else { text.clone() };
    let private = w.global::<Compose>().get_compose_private();
    let rate: f64 = w.global::<Compose>().get_rate_text().trim().parse().unwrap_or(1.0);
    let recipient = st.to_address.as_deref().and_then(|a| Recipient::parse(net, a).ok());
    let gift = if recipient.is_some() {
        w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
    } else {
        0
    };
    // Multi-recipient: every chip's spk length (uniform gift each) — empty
    // when self-note, one entry for an ordinary directed note (unchanged
    // estimate via `compose_est`'s delegation), 2+ for a real multi note.
    let recipient_spk_lens: Vec<usize> = match recipient.as_ref() {
        Some(r) => {
            let mut v = vec![r.spk.len()];
            v.extend(st.to_addresses_extra.iter().filter_map(|a| Recipient::parse(net, a).ok()).map(|x| x.spk.len()));
            v
        }
        None => Vec::new(),
    };
    // `gift` is already 0 for a self-note, so this is 0 there regardless
    // of the `.max(1)` below (empty `recipient_spk_lens`).
    let total_sent = gift * recipient_spk_lens.len().max(1) as u64;
    let change_raw = w.global::<Ui>().get_change_address().to_string();
    let change_trim = change_raw.trim();
    let custom_change = if change_trim.is_empty() { None } else { Recipient::parse(net, change_trim).ok() };
    // An explicitly-typed change address that DOESN'T parse is invalid —
    // gate Sign on it same as before (each branch used to bail out on this
    // independently; now it's one check).
    let change_valid = change_trim.is_empty() || custom_change.is_some();
    let custom_change_spk_len = custom_change.map(|r| r.spk.len());

    // Fee estimate for a "funded" shape (spending / mixed): reuses the real
    // sealer (`sealed_note_payloads`, the same primitive `build_funding_psbt_amount`/
    // `assemble_mixed_note_psbt` call internally) for accurate payload sizes,
    // then `estimate_funded_fee`/`estimate_funded_fee_no_change` for the
    // weight/fee math — WITHOUT their insufficiency gate, so a number
    // always comes back. Returns (fee_with_change, fee_no_change): the pair
    // `app_core::mixed::predict_fold` needs to tell whether THIS selection
    // would fold a sub-dust leftover into the fee (honest-fee-label,
    // 2026-07-18). `dust_to_self` mirrors `assemble_mixed_note_psbt`'s own
    // input-anchored skip (2026-07-18 dust-skip rework): callers pass
    // `false` when the selection includes a notebook coin, so the preview
    // stays byte-exact with the real build either way.
    let funded_fee_pair = |input_weights: &[bitcoin::transaction::InputWeightPrediction], change_spk_len: usize, dust_to_self: bool| -> Option<(u64, u64)> {
        let identity = st.ident.as_ref().and_then(|i| i.full())?.clone_fields();
        let chunk = st.store.as_ref().map(|s| s.chunk_size).unwrap_or(DEFAULT_CHUNK);
        // Multi-recipient: `recipient_spk_lens` (computed above) already
        // carries every chip's spk length — go through the multi sealer
        // when there are 2+ distinct recipients so the payload/chunk count
        // this estimate uses matches what the real multi build would emit
        // (a FLAG_MULTI body is a different size than a single-recipient
        // one for the same text).
        let payloads = if recipient_spk_lens.len() >= 2 {
            let extra_recipients: Vec<&str> = st.to_addresses_extra.iter().map(String::as_str).collect();
            let recipients =
                app_core::compose::parse_dedupe_recipients(net, st.to_address.as_deref(), &extra_recipients).ok()?;
            let content_key = [0u8; 32]; // preview only — lengths don't depend on the seal
            app_core::notes_core::bundle::sealed_note_payloads_multi(
                &identity, &text_for_est, private, &recipients, [0u8; 36], content_key, chunk,
            )
            .ok()?
            .0
        } else {
            app_core::notes_core::bundle::sealed_note_payloads(
                &identity, &text_for_est, private, recipient.as_ref(), [0u8; 36], chunk,
            )
            .ok()?
            .0
        };
        let fee_wc = app_core::mixed::estimate_funded_fee_multi(input_weights, &payloads, &recipient_spk_lens, change_spk_len, dust_to_self, rate);
        let fee_nc = app_core::mixed::estimate_funded_fee_no_change_multi(input_weights, &payloads, &recipient_spk_lens, dust_to_self, rate);
        Some((fee_wc, fee_nc))
    };

    let (required, required_line, source_label): (Option<u64>, String, String);
    let shape: PayfromShape;
    if groups == 0 {
        // Nothing selected in ANY source — estimate the minimal 1-input
        // self-funded shape (what auto-suggest will land on): never leave
        // the line blank just because the user hasn't picked a coin yet.
        // No fold prediction here — there's no real selection yet to fold
        // FROM (`in_value` would be 0), so this stays the plain estimate.
        let change_len = custom_change_spk_len.or(Some(34));
        let fee = st
            .store
            .as_ref()
            .and_then(|store| compose_est(store, text_for_est.len(), private, 1, &recipient_spk_lens, change_len).ok())
            .map(|(_, vsize)| (vsize as f64 * rate).ceil().max(0.0) as u64);
        required = fee.map(|f| f + total_sent);
        source_label = if st.payfrom_active_source == "spending" { "Spending wallet".to_string() } else { "Notebook".to_string() };
        required_line = required.map(|r| format!("~{} sats", commas(r))).unwrap_or_else(|| "~0 sats".to_string());
        shape = PayfromShape::Empty;
    } else if nb_total > 0 && groups == 1 {
        // Notebook-only — same self-funded estimator the plain compose path
        // already uses (no dust-to-self: change naturally returns to the
        // notebook, which already keeps the note discoverable). Sub-dust
        // fold prediction (honest-fee-label, 2026-07-18): `required` stays
        // the NOMINAL fee (what the no-change shape actually needs), and
        // the line notes the folded leftover separately so it never reads
        // as an inflated/expensive fee.
        let change_len = custom_change_spk_len.unwrap_or(34);
        let vsize = st
            .store
            .as_ref()
            .and_then(|store| {
                compose_est(store, text_for_est.len(), private, nb_sel.len().max(1), &recipient_spk_lens, Some(change_len)).ok()
            })
            .map(|(_, vsize)| vsize);
        let fee_wc = vsize.map(|v| (v as f64 * rate).ceil().max(0.0) as u64);
        let fold = vsize.and_then(|v| app_core::mixed::predict_notebook_fold(nb_total, total_sent, v, change_len, rate));
        let nominal = fold.map(|(n, _)| n).or(fee_wc);
        required = nominal.map(|f| f + total_sent);
        source_label = "Notebook".to_string();
        required_line = fold_required_line(required, fold);
        shape = PayfromShape::Notebook;
    } else if sp_total > 0 && groups == 1 {
        // Spending-only — same funded shape `spending_compose_ui` builds for
        // real (dust-to-self ALWAYS), just never gated on affordability.
        // Same fold treatment as the notebook branch above, via the funded
        // (with-change/no-change) estimator pair.
        let weights: Vec<_> = std::iter::repeat_n(
            bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX,
            sp_sel.len().max(1),
        )
        .collect();
        let change_len = custom_change_spk_len.unwrap_or(22); // BIP84 p2wpkh spk is always 22 bytes
        // Spending-only can never include a notebook coin (groups == 1,
        // nb_total == 0 by this branch's own guard) — dust-to-self always
        // rides, same as `assemble_funded_note_psbt`'s unconditional rule.
        let fees = funded_fee_pair(&weights, change_len, true);
        // `total_sent` (not `gift`) is the fixed non-fee output total when
        // 2+ recipients are chipped in — uniform gift × N (Sal, 2026-07-19).
        let fixed_out = total_sent + DUST_SATS; // recipients + the ALWAYS dust-to-self output
        let fold = fees.and_then(|(fee_wc, fee_nc)| app_core::mixed::predict_fold(sp_total, fixed_out, fee_wc, fee_nc, false));
        let nominal = fold.map(|(n, _)| n).or_else(|| fees.map(|(wc, _)| wc));
        required = nominal.map(|f| f + total_sent + DUST_SATS);
        source_label = "Spending wallet".to_string();
        required_line = fold_required_line(required, fold);
        shape = PayfromShape::Spending;
    } else if ext_total > 0 && groups == 1 {
        // External-only — cost is "whatever the wallet pays"; never invent a
        // numeric fee for it (unchanged design intent). Guarded on
        // `ext_total > 0` (taproot-change unit 5): a change-ONLY selection
        // is ALSO `groups == 1` (its own single group) but has no wallet
        // source at all — it must fall through to the Mixed branch below,
        // the only builder that knows `CoinSource::Change`.
        let id = wallet_sources.first().and_then(|s| s.strip_prefix("wallet:"));
        let label = id
            .and_then(|id| st.funding_wallets.iter().find(|fw| fw.id == id))
            .map(|fw| fw.label.clone())
            .unwrap_or_else(|| "External wallet".to_string());
        required = None;
        // Always non-empty (never blank just because no note text is typed
        // yet) — a funding wallet's role doesn't depend on that; "enough"
        // below still gates Sign on text being present.
        required_line = format!("funded by {label}");
        source_label = label;
        shape = PayfromShape::External(wallet_sources.first().cloned().unwrap_or_default());
    } else {
        // Mixed: 2+ source groups in ONE tx — the real mixed builder
        // (`assemble_mixed_note_psbt`) is the only correct sizer for this
        // shape (per-source input weights + the funded output shape), reused
        // here via `estimate_funded_fee` (same weights/outputs, no
        // insufficiency gate).
        let mut weights: Vec<bitcoin::transaction::InputWeightPrediction> = Vec::new();
        weights.extend(std::iter::repeat_n(bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH, nb_sel.len()));
        weights.extend(std::iter::repeat_n(bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX, sp_sel.len()));
        // Taproot CHANGE-chain coins (unit 5) are P2TR key-path, same
        // weight as a notebook coin.
        weights.extend(std::iter::repeat_n(bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH, chg_sel.len()));
        for src in &wallet_sources {
            let id = src.strip_prefix("wallet:").unwrap_or("");
            let taproot = st.funding_wallets.iter().find(|fw| fw.id == id).map(|fw| fw.kind == "taproot").unwrap_or(true);
            let iw = if taproot {
                bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH
            } else {
                bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX
            };
            weights.extend(std::iter::repeat_n(iw, st.mixed_coins_for(src).len()));
        }
        let spending_enabled = st.spending_capable && st.store.as_ref().map(|s| s.spending.enabled).unwrap_or(false);
        // `chg_total == 0` (taproot-change unit 5): a change coin is this
        // identity's OWN coin, so its presence disqualifies the "only an
        // external wallet participates" default just like a notebook coin
        // would — `resolve_change_default` then falls back to Notebook.
        let single_external = if wallet_sources.len() == 1 && nb_total == 0 && sp_total == 0 && chg_total == 0 {
            wallet_sources.first().and_then(|s| s.strip_prefix("wallet:"))
        } else {
            None
        };
        let default_change =
            app_core::mixed::resolve_change_default(spending_enabled, sp_total > 0, single_external);
        let change_len = custom_change_spk_len.unwrap_or(match &default_change {
            app_core::mixed::ChangeDefault::Spending => 22,
            app_core::mixed::ChangeDefault::Notebook => 34,
            app_core::mixed::ChangeDefault::Wallet(id) => st
                .funding_wallets
                .iter()
                .find(|fw| &fw.id == id)
                .map(|fw| if fw.kind == "taproot" { 34 } else { 22 })
                .unwrap_or(34),
        });
        // Input-anchored skip (2026-07-18 dust-skip rework; extended to
        // Change by taproot-change unit 5): a notebook OR change-chain coin
        // in this mixed selection means the tx is already input-anchored —
        // both are this identity's own coin — `assemble_mixed_note_psbt`
        // omits dust-to-self, so the preview must too, or the
        // Required/Leftover figures drift from the real build's fee.
        let has_self_input = nb_total > 0 || chg_total > 0;
        let dust_sats = if has_self_input { 0 } else { DUST_SATS };
        let fees = funded_fee_pair(&weights, change_len, !has_self_input);
        // `total_sent` (not `gift`) is the fixed non-fee output total when
        // 2+ recipients are chipped in — uniform gift × N (Sal, 2026-07-19).
        let fixed_out = total_sent + dust_sats; // recipients (if any) + dust-to-self, when present
        let fold = fees.and_then(|(fee_wc, fee_nc)| app_core::mixed::predict_fold(selected, fixed_out, fee_wc, fee_nc, false));
        let nominal = fold.map(|(n, _)| n).or_else(|| fees.map(|(wc, _)| wc));
        required = nominal.map(|f| f + total_sent + dust_sats);
        // A notebook and/or change-chain-only mix is still ONE wallet (two
        // chains of the same account, taproot-change unit 5) — "N wallets"
        // only describes a genuine cross-wallet mix (spending and/or an
        // external wallet participating).
        source_label =
            if sp_total == 0 && ext_total == 0 { "Notebook".to_string() } else { format!("{groups} wallets") };
        required_line = fold_required_line(required, fold);
        shape = PayfromShape::Mixed;
    }

    let enough = match required {
        Some(r) => change_valid && selected >= r,
        None => {
            // External-only: readiness, not a sats comparison — a watch
            // wallet's real cost isn't knowable up front (unchanged rule).
            let ready = st.funding.is_some() && !st.funding_coins.is_empty();
            change_valid && ready && ext_total > 0 && !text.is_empty()
        }
    };

    PayfromState { required, required_line, selected, enough, source_label, shape }
}

/// Recompute the mixed-source bookkeeping after `refresh_compose`'s active-
/// source branch runs: mirror its (possibly just auto-suggested) selection
/// into the cross-wallet memory, flag the linkage hint when the total
/// selection spans more than one wallet, and resolve the Change screen's
/// current destination label. Also the ONE place [`payfrom_state`] is
/// computed and fanned out to every consumer (summary card, insufficiency
/// message, compose row, Sign gate) — see its doc comment for why this
/// replaced each branch setting `spend_enough`/`payfrom_required_line`
/// independently (Sal's iPhone bug cluster, 2026-07-18).
pub(crate) fn sync_and_finalize_payfrom(&mut self, w: &AppWindow) {
    let st = self;
    // Mirror the active source's scratch selection into the cross-wallet
    // memory — ONLY for notebook/spending, the two sources whose compose
    // branches actually maintain `selected_coins`. External wallets keep
    // their entries via `on_toggle_coin` + `funding_compose_ui`'s
    // default-all seeding; mirroring the (necessarily stale) scratch under
    // a "wallet:<id>" key would clobber the wallet's real selection with
    // another source's coin list (a latent 3f29024 hazard, closed in the
    // TestFlight-13 dispatch fix, 2026-07-18).
    let active = st.payfrom_active_source.clone();
    if active == "notebook" || active == "spending" {
        let coins = st.selected_coins.clone();
        st.mixed_sync_source(&active, &coins);
    }

    let pf = st.payfrom_state(w);
    // The note-size ceiling (`compose_oversize`, set by the notebook
    // branch's `fit_check`) is a hard broadcast-legality gate independent of
    // fund sufficiency — AND it in here rather than duplicating it into
    // every branch's own `enough` computation.
    let enough = pf.enough && !st.compose_oversize;
    w.global::<Ui>().set_spend_enough(enough);
    w.global::<PayFrom>().set_payfrom_required_line(pf.required_line.into());
    w.global::<Ui>().set_payfrom_selected_line(format!("{} sats", commas(pf.selected)).into());
    w.global::<Compose>().set_payfrom_source_label(pf.source_label.clone().into());
    // The linkage hint doubles as the Sign-button dispatch selector for the
    // mixed path — derived from the verdict's shape, same source of truth
    // as everything else here.
    w.global::<Ui>().set_mixed_linkage_hint(pf.shape == PayfromShape::Mixed);
    println!(
        "cb: payfrom state src={} required={} selected={} enough={}",
        pf.source_label,
        pf.required.map(|r| r.to_string()).unwrap_or_else(|| "?".to_string()),
        pf.selected,
        if enough { 1 } else { 0 },
    );

    // ---- Dispatch alignment (Sal's TestFlight-build-13 follow-up,
    // 2026-07-18): the Sign button in app.slint picks its send callback
    // from `mixed-linkage-hint` + `pay-from`/`fund-external`/
    // `spend-from-wallet`, which until now were LAST-TAPPED state — e.g.
    // deselecting the spending wallet's final coin (a tap ON the spending
    // source) left `pay-from` = "spending" while the actual selection was
    // notebook-only, so Sign invoked the spending branch, which bailed red
    // "no coins selected" despite a green globally-sufficient verdict.
    // Whenever the verdict's shape names ONE source, force the dispatch
    // inputs (and the active-source scratch the compose branches read) to
    // that source — payfrom_state is the single source of truth for which
    // send path runs, structurally. Empty/Mixed leave the flags alone
    // (Empty can't Sign — enough=0; Mixed dispatches via the hint,
    // ignoring `pay-from`). Re-runs `refresh_compose` once after a switch
    // so the preview lines come from the branch that will actually send;
    // `payfrom_aligning` guards the recursion (the inner pass finds the
    // flags agreeing and falls through).
    let desired: Option<String> = match &pf.shape {
        PayfromShape::Notebook => Some("notebook".to_string()),
        PayfromShape::Spending => Some("spending".to_string()),
        PayfromShape::External(key) => Some(key.clone()),
        PayfromShape::Empty | PayfromShape::Mixed => None,
    };
    if let Some(src) = desired {
        let flags_agree = w.global::<Ui>().get_pay_from().as_str() == src
            && st.payfrom_active_source == src
            && w.global::<Ui>().get_fund_external() == src.starts_with("wallet:")
            && w.global::<Ui>().get_spend_from_wallet() == (src == "spending");
        if !flags_agree && !st.payfrom_aligning {
            st.payfrom_aligning = true;
            println!("cb: payfrom align src={src}");
            st.payfrom_active_source = src.clone();
            if let Some(id) = src.strip_prefix("wallet:") {
                let id = id.to_string();
                st.promote_wallet_active(w, &id);
            } else {
                // Seed the scratch from the source's remembered selection so
                // the branch (and the send path) spends exactly what the
                // verdict counted — never a re-auto-suggest.
                st.selected_coins = st.mixed_coins_for(&src);
                st.coins_overridden = true;
                st.apply_pay_from(w, &src);
            }
            st.refresh_compose(w);
            st.payfrom_aligning = false;
            return;
        }
    }
    st.update_change_label(w);
}

/// Short "<n> sats" figure for the compose compact "Pay from" row and the
/// funding screen's Notebook row — deliberately terse (no coin count) so it
/// always elides cleanly at iPhone width. `kind` is a `pay-from` value:
/// "notebook" | "spending" | "wallet:<id>".
pub(crate) fn balance_text_for(&self, kind: &str) -> String {
    let st = self;
    if let Some(id) = kind.strip_prefix("wallet:") {
        return st
            .funding_wallets
            .iter()
            .find(|fw| fw.id == id)
            .map(|fw| format!("{} sats", commas(fw.balance)))
            .unwrap_or_else(|| "watch-only".to_string());
    }
    if kind == "spending" {
        return if !st.spending_scanned {
            "scanning…".to_string()
        } else {
            let total: u64 = st.spending_coins.iter().map(|c| c.value).sum();
            format!("{} sats", commas(total))
        };
    }
    st.store.as_ref().map(|s| format!("{} sats", commas(s.balance()))).unwrap_or_default()
}

pub(crate) fn refresh_compose(&mut self, w: &AppWindow) {
    let st = self;
    // Keep the locktime panel's caption/warning fresh against the current
    // tip even if the store's scan advances while compose stays open (the
    // panel's mode/height reflect `st`, not the other way around, so
    // recomputing here is always idempotent with whatever the user picked).
    st.refresh_compose_locktime_panel(w);
    // Post-quantum layers: repaint the Security section from current
    // toggle state + the resolved recipient's key, and thread the
    // resulting flags/alg into the cost preview below (`pq_est` is `(0,
    // None)`, a strict no-op, whenever the section doesn't apply or
    // neither layer is on).
    let pq_est = st.refresh_compose_pq(w);
    let net = st.network;
    let text = w.global::<Compose>().get_compose_text().to_string();
    let private = w.global::<Compose>().get_compose_private();
    let rate: f64 = w.global::<Compose>().get_rate_text().trim().parse().unwrap_or(1.0);
    // Keep the compact "Pay from" row's balance current regardless of which
    // branch below runs (notebook / spending / external).
    w.global::<Ui>().set_pay_from_balance(st.balance_text_for(w.global::<Ui>().get_pay_from().as_str()).into());
    // MIXED selection (TestFlight build-20 fix, 2026-07-18): a selection
    // spanning 2+ wallets dispatches Sign to `on_compose_send_mixed`
    // (`assemble_mixed_note_psbt`), so its preview must dry-run THAT
    // builder — routing by the last-active single-source flags rendered a
    // different builder's card (spending's unconditional dust-to-self +
    // spending-only input weights vs the anchored mixed build the confirm
    // screen then truthfully decoded). Mirror the active source's scratch
    // selection first (the same idempotent first step
    // `sync_and_finalize_payfrom` performs) so the shape check sees the
    // current selection, and refresh the resolved change default so the
    // dry-run prices the same change destination Sign will use. Watch
    // identities can't mix (no full key) — they fall through unchanged.
    {
        let active = st.payfrom_active_source.clone();
        if active == "notebook" || active == "spending" {
            let coins = st.selected_coins.clone();
            st.mixed_sync_source(&active, &coins);
        }
    }
    if st.ident.as_ref().and_then(|i| i.full()).is_some()
        && st.payfrom_state(w).shape == PayfromShape::Mixed
    {
        st.update_change_label(w);
        st.mixed_compose_ui(w, &text);
        st.sync_and_finalize_payfrom(w);
        return;
    }
    // External-funding mode: the coin panel shows the funding wallet's coins,
    // not the self-funded store coins. Handled on its own isolated path.
    if w.global::<Ui>().get_fund_external() {
        st.funding_compose_ui(w, &text);
        st.sync_and_finalize_payfrom(w);
        return;
    }
    // Internal spending-wallet mode (funding-unification M3): same idea,
    // but the source is the identity's OWN BIP-84 wallet, signed in-app.
    if w.global::<Ui>().get_spend_from_wallet() {
        st.spending_compose_ui(w, &text);
        st.sync_and_finalize_payfrom(w);
        return;
    }
    let spk_len = st
        .to_address
        .as_deref()
        .and_then(|a| Recipient::parse(net, a).ok())
        .map(|r| r.spk.len());
    // Multi-recipient: every chip's spk length (uniform gift each) — empty
    // for a self-note, one entry for an ordinary directed note (byte-
    // identical estimate via `compose_est`'s <=1 delegation), 2+ for a
    // real multi-recipient note.
    let recipient_spk_lens: Vec<usize> = match spk_len {
        Some(l) => {
            let mut v = vec![l];
            v.extend(st.to_addresses_extra.iter().filter_map(|a| Recipient::parse(net, a).ok()).map(|r| r.spk.len()));
            v
        }
        None => Vec::new(),
    };
    let n_recipients = recipient_spk_lens.len();
    // Directed notes send a "gift" to EACH recipient (>= dust); self-notes send 0.
    let gift = w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS);
    let sent = if spk_len.is_some() { gift * n_recipients.max(1) as u64 } else { 0 };

    // Change-address destination label + validation. A valid custom change
    // address also yields its scriptPubKey length so the fee/change preview
    // sizes the real change output (not the assumed taproot one).
    let change_raw = w.global::<Ui>().get_change_address().to_string();
    let change_trim = change_raw.trim();
    let (change_dest, change_err, change_spk_len) = if change_trim.is_empty() {
        ("your address".to_string(), String::new(), None)
    } else {
        match Recipient::parse(net, change_trim) {
            Ok(r) => (
                format!("{}…", &change_trim[..14.min(change_trim.len())]),
                String::new(),
                Some(r.spk.len()),
            ),
            Err(_) => (
                "⚠ invalid".to_string(),
                format!("Not a valid {} address.", net.as_str()),
                None,
            ),
        }
    };
    w.global::<Change>().set_change_error(change_err.clone().into());

    // Pay-from screen summary card / Sign gate: computed ONCE, centrally, by
    // `payfrom_state` inside `sync_and_finalize_payfrom` below — from the
    // TRUE cross-wallet selection, not from whichever branch happens to run
    // here. This function still computes its own `cost_line`/`change_amount`
    // preview text (compose-screen display, unrelated to the Pay-from
    // cluster) but no longer sets `spend_enough`/`payfrom_required_line`
    // itself (Sal's iPhone bug cluster, 2026-07-18).
    let consolidate = st.consolidate_coins;
    let Some(store) = &st.store else { return };
    // Auto-suggest a selection until the user overrides it.
    if !st.coins_overridden {
        st.selected_coins = suggested_coins(
            store,
            text.len(),
            private,
            rate,
            &recipient_spk_lens,
            change_spk_len,
            sent,
            consolidate,
        );
    }
    let store = st.store.as_ref().unwrap();
    let exb = st.explorer_base();
    let sel: std::collections::HashSet<(String, u32)> = st.selected_coins.iter().cloned().collect();

    let mut coins: Vec<SpendCoin> = Vec::new();
    let (mut sel_total, mut sel_count) = (0u64, 0usize);
    // Spendable coins, sorted by amount low → high.
    let mut spendable: Vec<&app_core::store::LedgerUtxo> =
        store.utxos.iter().filter(|u| !u.pending_spend).collect();
    spendable.sort_by_key(|a| a.value);
    for u in spendable {
        let selected = sel.contains(&(u.txid.clone(), u.vout));
        if selected {
            sel_total += u.value;
            sel_count += 1;
        }
        coins.push(SpendCoin {
            outpoint: format!("{}:{}", u.txid, u.vout).into(),
            value: u.value.to_string().into(),
            confirmed: u.height.is_some(),
            selected,
            txid_short: u.txid[..8.min(u.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &u.txid).into(),
            tag: "".into(),
        });
    }
    w.global::<Ui>().set_spend_coins(VecModel::from_slice(&coins));
    let plural = if sel_count == 1 { "" } else { "s" };
    w.global::<Ui>().set_spend_title(format!("Spending {sel_count} coin{plural} · {sel_total} sats").into());

    if text.is_empty() {
        // The rate box + cost line are always visible now (fee-tier
        // redesign, 2026-07-16) — with no text yet, show the minimum
        // one-chunk estimate (text_len=1, the shortest possible note) so
        // the line still reads as a real (labeled) estimate instead of
        // going blank.
        let n = sel_count.max(1);
        let est_fee = compose_est_pq(store, 1, private, n, &recipient_spk_lens, change_spk_len, pq_est)
            .ok()
            .map(|(_, vsize)| (vsize as f64 * rate).ceil().max(0.0) as u64);
        let min_line = est_fee
            .map(|fee| format!("~{} sats fee minimum", commas(fee)))
            .unwrap_or_default();
        set_cost_status(w, min_line);
        w.global::<Ui>().set_change_amount(format!("Change to {change_dest}").into());
        st.compose_oversize = false;
        st.sync_and_finalize_payfrom(w);
        return;
    }
    let n = sel_count.max(1);
    let est = compose_est_pq(store, text.len(), private, n, &recipient_spk_lens, change_spk_len, pq_est);
    // fit_check stays the single-recipient shape on purpose: the >255-
    // chunk/100kB-vsize ceiling it guards is dominated by the TEXT/chunk
    // count, which multi-recipient outputs don't change (recipients add a
    // fixed handful of vB each — `est` above already prices them exactly;
    // this only decides whether the oversize dialog shows, so an N-
    // recipient note stays governed by the same body-size wall as N=1).
    let fit = fit_check(store, text.len(), private, n, spk_len, change_spk_len);
    let over = !matches!(fit, FitCheck::Ok);
    match est {
        Ok((chunks, vsize)) if !over => {
            let change_len = change_spk_len.unwrap_or(34);
            // Sub-dust fold prediction (honest-fee-label, 2026-07-18): when
            // the leftover after this selection's fee can't clear the dust
            // minimum, the real builder folds it into the fee instead of a
            // change output — mirror that HERE so the preview shows the
            // vsize/fee the tx will ACTUALLY have (the no-change shape), not
            // the with-change one that won't be built.
            let fold = app_core::mixed::predict_notebook_fold(sel_total, sent, vsize, change_len, rate);
            let (vsize, fee, change) = match fold {
                Some((nominal, _)) => {
                    (app_core::mixed::notebook_vsize_no_change(vsize, change_len), nominal, 0)
                }
                None => {
                    let fee = (vsize as f64 * rate).ceil() as u64;
                    (vsize, fee, sel_total.saturating_sub(fee + sent))
                }
            };
            let usd = st
                .usd
                .map(|p| format!(" (~${:.2})", fee as f64 * p / 1e8))
                .unwrap_or_default();
            let fold_amount = fold.map(|(_, folded)| folded).unwrap_or(0);
            if fold_amount != st.compose_fold_shown {
                if fold_amount > 0 {
                    println!("cb: compose-est fold={fold_amount}");
                }
                st.compose_fold_shown = fold_amount;
            }
            // "+330 sats" for one recipient (unchanged copy); "N × G = T
            // sats" for a multi-recipient note (uniform gift × N — Sal,
            // 2026-07-19) — shared formatter, see `gift_row`.
            let gift_line = gift_row(n_recipients, gift, sent);
            set_cost_card(
                w,
                format!("{chunks} chunk{} · ~{vsize} vB", if chunks == 1 { "" } else { "s" }),
                format!("~{} sats{usd}", commas(fee)),
                gift_line,
                String::new(), // no dust-to-self on the self-funded notebook shape
                fold.map(|(nominal, folded)| (folded, nominal + folded)),
            );
            w.global::<Ui>().set_change_amount(format!("Change to {change_dest} · ~{change} sats").into());
        }
        // Over the per-tx broadcast ceiling: vsize > 100 kB (Ok arm) or the
        // body needs > 255 chunks (Err arm). Sign is gated off via
        // `compose_oversize` (ANDed into `spend_enough` centrally below) —
        // the dialog below offers the fix.
        Ok((chunks, vsize)) => {
            set_cost_status(
                w,
                format!("{chunks} chunk(s) · ~{vsize} vB — too large to broadcast"),
            );
        }
        Err(_) => {
            set_cost_status(w, "Too large to broadcast (> 255 chunks)".to_string());
        }
    }

    // Edge-trigger the "too large" dialog: pop once when the draft first
    // crosses the ceiling, not on every keystroke while it stays over.
    if over && !st.compose_oversize {
        match fit {
            FitCheck::FitsAtStandard => {
                w.global::<Modals>().set_oversize_offer_bump(true);
                w.global::<Modals>().set_oversize_message(
                    "This note doesn't fit at your current chunk size. \
                     Switch to Standard (a single large chunk) to fit it in one transaction?"
                        .into(),
                );
                w.global::<Ui>().set_show_oversize_modal(true);
            }
            FitCheck::HardWall => {
                w.global::<Modals>().set_oversize_offer_bump(false);
                w.global::<Modals>().set_oversize_message(
                    "This note is too large to broadcast. A single Bitcoin transaction \
                     can't exceed ~100 kB (the network relay limit), whatever the chunk \
                     size. Shorten the note, or split it across several notes. \
                     Multi-transaction notes are planned for a future release."
                        .into(),
                );
                w.global::<Ui>().set_show_oversize_modal(true);
            }
            FitCheck::Ok => {}
        }
    }
    st.compose_oversize = over;
    st.sync_and_finalize_payfrom(w);
}

/// External-funding variant of the compose coin panel: show the funding
/// wallet's scanned coins and a source summary, instead of the self-funded
/// store coins. Coin selection (funding-unification UI rework) defaults to
/// every scanned coin until the user overrides it — same tap-to-toggle
/// pattern the notebook/spending panels use, tracked in the cross-wallet
/// selection memory keyed "wallet:<id>" so a mixed compose can spend only
/// SOME of an external wallet's coins.
pub(crate) fn funding_compose_ui(&mut self, w: &AppWindow, text: &str) {
    let st = self;
    let net = st.network;
    let total: u64 = st.funding_coins.iter().map(|c| c.value).sum();
    let n = st.funding_coins.len();
    let ready = st.funding.is_some() && n > 0;
    w.global::<Ui>().set_funding_ready(ready);

    // Summary card = which wallet + how much (its first receive address is a
    // recognisable handle for a multi-address wallet).
    match &st.funding {
        Some(src) => {
            let addr0 = src.derive(0, 0).map(|d| d.address).unwrap_or_default();
            w.global::<Sweep>().set_funding_summary(
                format!("{} · {} · {n} coin{} · {total} sats", src.kind.label(), short_addr(&addr0), if n == 1 { "" } else { "s" }).into(),
            );
        }
        None => w.global::<Sweep>().set_funding_summary("Set a funding wallet".into()),
    }

    let source_key = st
        .active_funding_id
        .as_deref()
        .map(|id| format!("wallet:{id}"))
        .unwrap_or_default();
    let remembered = st.mixed_coins_for(&source_key);
    let sel: std::collections::HashSet<(String, u32)> = if remembered.is_empty() {
        // First time this wallet is shown this session: default to every
        // scanned coin (matches the pre-rework behavior byte-for-byte) and
        // remember that as the baseline.
        let all: Vec<(String, u32)> = st.funding_coins.iter().map(|c| (c.txid.clone(), c.vout)).collect();
        if !all.is_empty() && !source_key.is_empty() {
            st.mixed_sync_source(&source_key, &all);
        }
        all.into_iter().collect()
    } else {
        remembered.into_iter().collect()
    };

    let exb = st.explorer_base();
    let coins: Vec<SpendCoin> = st
        .funding_coins
        .iter()
        .map(|c| SpendCoin {
            outpoint: format!("{}:{}", c.txid, c.vout).into(),
            value: c.value.to_string().into(),
            confirmed: c.confirmed,
            selected: sel.contains(&(c.txid.clone(), c.vout)),
            txid_short: c.txid[..8.min(c.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &c.txid).into(),
            tag: "".into(),
        })
        .collect();
    let sel_count = coins.iter().filter(|c| c.selected).count();
    let sel_total: u64 = st
        .funding_coins
        .iter()
        .filter(|c| sel.contains(&(c.txid.clone(), c.vout)))
        .map(|c| c.value)
        .sum();
    w.global::<Ui>().set_spend_coins(VecModel::from_slice(&coins));
    w.global::<Ui>().set_spend_title(
        format!("Funding {sel_count}/{n} coin{} · {} sats", if n == 1 { "" } else { "s" }, commas(sel_total)).into(),
    );
    set_cost_status(w, if text.is_empty() { String::new() } else { "funded from the external wallet".to_string() });
    // `spend_enough`/`payfrom_required_line` are no longer set here — see
    // `payfrom_state`'s external-only branch (same readiness rule: a funding
    // wallet's real cost isn't knowable up front, so no numeric fee).

    // Change: blank = the funding wallet's own change; a valid custom address
    // overrides it. Same validation/label pattern as the self-funded path.
    let change_trim = w.global::<Ui>().get_change_address().trim().to_string();
    if change_trim.is_empty() {
        w.global::<Ui>().set_change_amount("Change to funding wallet".into());
        w.global::<Change>().set_change_error("".into());
    } else if Recipient::parse(net, &normalize_addr(&change_trim)).is_ok() {
        w.global::<Ui>().set_change_amount(format!("Change to {}…", &change_trim[..14.min(change_trim.len())]).into());
        w.global::<Change>().set_change_error("".into());
    } else {
        w.global::<Ui>().set_change_amount("Change: ⚠ invalid".into());
        w.global::<Change>().set_change_error(format!("Not a valid {} address.", net.as_str()).into());
    }
}

/// Internal-spending-wallet variant of the compose coin panel (funding-
/// unification M3, coin control added funding-unification/M4): shows the
/// identity's OWN BIP-84 spending-wallet coins with the SAME tap-to-toggle
/// coin control as the notebook path (`selected_coins`/`coins_overridden`,
/// shared with [`refresh_compose`]'s notebook branch — default is every
/// scanned coin until the user overrides it) and a LIVE cost/change preview
/// from a dry-run of the exact same funded-note assembly the broadcast path
/// uses (`psbt_build::build_funding_psbt_amount`), spending only the
/// SELECTED coins, so the preview and the real build can never disagree.
pub(crate) fn spending_compose_ui(&mut self, w: &AppWindow, text: &str) {
    let st = self;
    let net = st.network;
    // `spend_enough`/`payfrom_required_line` are no longer set anywhere in
    // this function — `payfrom_state` (called centrally in
    // `sync_and_finalize_payfrom` right after this returns) now computes
    // both from the TRUE cross-wallet selection, using the same funded-shape
    // math this function's `build_funding_psbt_amount` dry-run uses, minus
    // its insufficiency gate (Sal's iPhone bug cluster, 2026-07-18).
    let n = st.spending_coins.len();
    if !st.coins_overridden {
        st.selected_coins = st.spending_coins.iter().map(|c| (c.txid.clone(), c.vout)).collect();
    }
    let sel: std::collections::HashSet<(String, u32)> = st.selected_coins.iter().cloned().collect();
    let exb = st.explorer_base();
    let coins: Vec<SpendCoin> = st
        .spending_coins
        .iter()
        .map(|c| SpendCoin {
            outpoint: format!("{}:{}", c.txid, c.vout).into(),
            value: c.value.to_string().into(),
            confirmed: c.confirmed,
            selected: sel.contains(&(c.txid.clone(), c.vout)),
            txid_short: c.txid[..8.min(c.txid.len())].to_string().into(),
            explorer: explorer_tx_url(exb.as_deref(), net, &c.txid).into(),
            tag: "".into(),
        })
        .collect();
    let sel_count = coins.iter().filter(|c| c.selected).count();
    let sel_total: u64 = st
        .spending_coins
        .iter()
        .filter(|c| sel.contains(&(c.txid.clone(), c.vout)))
        .map(|c| c.value)
        .sum();
    w.global::<Ui>().set_spend_coins(VecModel::from_slice(&coins));
    w.global::<Ui>().set_spend_title(
        format!(
            "Spending wallet · {sel_count}/{n} coin{} · {} sats",
            if n == 1 { "" } else { "s" },
            commas(sel_total)
        )
        .into(),
    );

    // Change destination: blank = a fresh spending-wallet address; a valid
    // custom address overrides it — same pattern as the other two panels.
    let change_trim = w.global::<Ui>().get_change_address().trim().to_string();
    let change_override_spk = if change_trim.is_empty() {
        w.global::<Change>().set_change_error("".into());
        None
    } else {
        match Recipient::parse(net, &normalize_addr(&change_trim)) {
            Ok(r) => {
                w.global::<Change>().set_change_error("".into());
                Some(r.spk)
            }
            Err(_) => {
                w.global::<Ui>().set_change_amount("Change: ⚠ invalid".into());
                w.global::<Change>().set_change_error(format!("Not a valid {} address.", net.as_str()).into());
                return;
            }
        }
    };

    if n == 0 {
        set_cost_status(w, String::new());
        w.global::<Ui>().set_change_amount("Spending wallet has no coins yet — fund its receive address in Settings.".into());
        return;
    }
    if sel_count == 0 {
        set_cost_status(w, String::new());
        w.global::<Ui>().set_change_amount("No coins selected — select at least one below.".into());
        return;
    }
    if text.is_empty() {
        set_cost_status(w, String::new());
        w.global::<Ui>().set_change_amount(
            if change_override_spk.is_some() {
                format!("Change to {}…", &change_trim[..14.min(change_trim.len())])
            } else {
                "Change to a fresh spending-wallet address".to_string()
            }
            .into(),
        );
        return;
    }
    let (Some(source), Some(store), Some(identity)) = (
        st.spending_source.as_ref(),
        st.store.as_ref(),
        st.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()),
    ) else {
        set_cost_status(w, String::new());
        return;
    };
    let recipient = st.to_address.as_deref().and_then(|a| Recipient::parse(net, a).ok());
    let gift = if recipient.is_some() {
        w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
    } else {
        0
    };
    // Multi-recipient: every chip's spk (uniform gift each) — mirrors the
    // notebook path's preview (`refresh_compose`'s `recipient_spk_lens`).
    let extra_recipients: Vec<&str> = st.to_addresses_extra.iter().map(String::as_str).collect();
    let recipients = app_core::compose::parse_dedupe_recipients(net, st.to_address.as_deref(), &extra_recipients)
        .unwrap_or_default();
    let n_recipients = recipients.len();
    let rate: f64 = w.global::<Compose>().get_rate_text().trim().parse().unwrap_or(1.0);
    let change_index = store.spending.next_change;
    let has_custom_change = change_override_spk.is_some();
    // Spend exactly the coins selected in the coin-control list below —
    // mirrors the notebook path's `compose_*_exact`.
    let selected_coins: Vec<app_core::funding::FundingUtxo> = st
        .spending_coins
        .iter()
        .filter(|c| sel.contains(&(c.txid.clone(), c.vout)))
        .cloned()
        .collect();
    let plan = FundingPlan {
        source,
        coins: &selected_coins,
        change_index,
        fee_rate: rate,
        change_override: change_override_spk,
    };
    let np = NoteParams {
        identity: &identity,
        text,
        private: w.global::<Compose>().get_compose_private(),
        recipient: recipient.as_ref(),
        max_op_return_bytes: store.chunk_size,
        network: net,
    };
    let build_result = if n_recipients >= 2 {
        app_core::psbt_build::build_funding_psbt_multi(&plan, &np, &recipients, gift, st.effective_lock_time())
    } else {
        app_core::psbt_build::build_funding_psbt_amount(&plan, &np, gift, st.effective_lock_time())
    };
    match build_result {
        Ok(built) => {
            // Sub-dust fold prediction (honest-fee-label, 2026-07-18):
            // `built.change == 0` means the REAL build already chose the
            // no-change shape — split its fee into the nominal figure
            // (what that shape actually costs at the chosen rate) and the
            // sub-dust leftover folded in on top, so the line never reads
            // as an inflated/expensive fee.
            let fold = if built.change == 0 {
                let weights: Vec<_> = std::iter::repeat_n(
                    bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX,
                    selected_coins.len().max(1),
                )
                .collect();
                let payload_and_lens = if n_recipients >= 2 {
                    let mut content_key = [0u8; 32]; // preview only — lengths don't depend on the seal
                    app_core::notes_core::bundle::sealed_note_payloads_multi(
                        &identity, text, w.global::<Compose>().get_compose_private(), &recipients, [0u8; 36], content_key,
                        store.chunk_size,
                    )
                    .ok()
                    .map(|(p, spks)| (p, spks.iter().map(|s| s.len()).collect::<Vec<usize>>()))
                    .inspect(|_| content_key.zeroize())
                } else {
                    app_core::notes_core::bundle::sealed_note_payloads(
                        &identity, text, w.global::<Compose>().get_compose_private(), recipient.as_ref(), [0u8; 36],
                        store.chunk_size,
                    )
                    .ok()
                    .map(|(p, spk)| {
                        let lens = spk.map(|s| vec![s.len()]).unwrap_or_default();
                        (p, lens)
                    })
                };
                payload_and_lens.map(|(payloads, recipient_spk_lens)| {
                    // Spending-only path: never a notebook coin, so
                    // dust-to-self is always present (matches
                    // `build_funding_psbt_amount`'s unconditional rule).
                    let nominal = app_core::mixed::estimate_funded_fee_no_change_multi(
                        &weights,
                        &payloads,
                        &recipient_spk_lens,
                        true,
                        rate,
                    );
                    (nominal, built.fee.saturating_sub(nominal))
                })
                .filter(|(_, folded)| *folded > 0)
            } else {
                None
            };
            let fold_amount = fold.map(|(_, f)| f).unwrap_or(0);
            if fold_amount != st.compose_fold_shown {
                if fold_amount > 0 {
                    println!("cb: compose-est fold={fold_amount}");
                }
                st.compose_fold_shown = fold_amount;
            }
            let fee_shown = fold.map(|(nominal, _)| nominal).unwrap_or(built.fee);
            let usd = st.usd.map(|p| format!(" (~${:.2})", fee_shown as f64 * p / 1e8)).unwrap_or_default();
            set_cost_card(
                w,
                String::new(), // funded shape: no chunk/vsize estimate on this path
                format!("~{} sats{usd}", commas(fee_shown)),
                gift_row(n_recipients, gift, built.sent_to_recipient),
                // Row hidden when the built tx carries no dust-to-self —
                // always present on THIS (spending-only) shape today, but
                // conditional so the card can never claim an output the
                // build doesn't contain (TestFlight build-20 audit).
                if built.dust_to_self > 0 { format!("+{} sats", commas(built.dust_to_self)) } else { String::new() },
                // Total = the byte-true fee the tx pays (nominal + leftover).
                fold.map(|(_, folded)| (folded, built.fee)),
            );
            w.global::<Ui>().set_change_amount(
                if has_custom_change {
                    format!(
                        "Change to {}… · ~{} sats",
                        &change_trim[..14.min(change_trim.len())],
                        commas(built.change)
                    )
                } else {
                    format!("Change to a fresh spending-wallet address · ~{} sats", commas(built.change))
                }
                .into(),
            );
        }
        Err(e) => {
            set_cost_status(w, String::new());
            w.global::<Ui>().set_change_amount(format!("{e}").into());
        }
    }
}

/// MIXED-selection compose preview (TestFlight build-20 fix, 2026-07-18):
/// when the cross-wallet selection spans 2+ sources, Sign dispatches to
/// `on_compose_send_mixed` (`assemble_mixed_note_psbt`) — so the cost card
/// must dry-run THAT builder with THE SAME arguments ([`mixed_compose_args`],
/// the shared seam) instead of whichever single-source branch happened to be
/// `payfrom_active_source` (Sal's report: a spending-active mixed selection
/// rendered spending_compose_ui's card — unconditional dust-to-self,
/// spending-only inputs — while the confirm screen showed the anchored mixed
/// build with no dust output and a different fee). Rendering mirrors
/// `spending_compose_ui`'s Ok arm: fee/fold via the anchored-aware
/// estimators, dust row from `built.dust_to_self` (hidden when 0), Total =
/// byte-true fee. Logs `cb: compose-est shape=mixed dust=<n> fee=<n>` per
/// distinct value (same guard style as the fold line) — the e2e pins that
/// fee to the confirm screen's `fee=` for the same compose.
pub(crate) fn mixed_compose_ui(&mut self, w: &AppWindow, text: &str) {
    let st = self;
    let net = st.network;
    let args = match st.mixed_compose_args(w) {
        Ok(a) => a,
        Err(_) => {
            // Same invalid-custom-change rendering the other branches use.
            set_cost_status(w, String::new());
            w.global::<Ui>().set_change_amount("Change: ⚠ invalid".into());
            w.global::<Change>().set_change_error(format!("Not a valid {} address.", net.as_str()).into());
            return;
        }
    };
    w.global::<Change>().set_change_error("".into());
    let change_dest = if args.change_override.is_some() {
        let t = w.global::<Ui>().get_change_address().trim().to_string();
        format!("{}…", &t[..14.min(t.len())])
    } else {
        match &args.change_default {
            app_core::mixed::ChangeDefault::Spending => "a fresh spending-wallet address".to_string(),
            app_core::mixed::ChangeDefault::Notebook => "your notebook address".to_string(),
            app_core::mixed::ChangeDefault::Wallet(_) => "the funding wallet".to_string(),
        }
    };
    if text.is_empty() {
        set_cost_status(w, String::new());
        w.global::<Ui>().set_change_amount(format!("Change to {change_dest}").into());
        return;
    }
    let Some(identity) = st.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
        set_cost_status(w, String::new());
        return;
    };
    let recipient = st.to_address.as_deref().and_then(|a| Recipient::parse(net, a).ok());
    let gift = if recipient.is_some() {
        w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
    } else {
        0
    };
    // Multi-recipient: every chip's spk (uniform gift each) — mirrors
    // `on_compose_send_mixed`'s send path.
    let extra_recipients: Vec<&str> = st.to_addresses_extra.iter().map(String::as_str).collect();
    let recipients = app_core::compose::parse_dedupe_recipients(net, st.to_address.as_deref(), &extra_recipients)
        .unwrap_or_default();
    let n_recipients = recipients.len();
    let rate: f64 = w.global::<Compose>().get_rate_text().trim().parse().unwrap_or(1.0);
    let chunk = st.store.as_ref().map(|s| s.chunk_size).unwrap_or(DEFAULT_CHUNK);
    // Preview outpoint is all-zero, like every other preview dry-run —
    // payload LENGTHS (all the fee math consumes) don't depend on the AAD.
    let sealed = if n_recipients >= 2 {
        let content_key = [0u8; 32]; // preview only — lengths don't depend on the seal
        app_core::notes_core::bundle::sealed_note_payloads_multi(
            &identity, text, w.global::<Compose>().get_compose_private(), &recipients, [0u8; 36], content_key, chunk,
        )
    } else {
        app_core::notes_core::bundle::sealed_note_payloads(
            &identity, text, w.global::<Compose>().get_compose_private(), recipient.as_ref(), [0u8; 36], chunk,
        )
        .map(|(p, spk)| (p, spk.into_iter().collect::<Vec<Vec<u8>>>()))
    };
    let Ok((payloads, recipient_spks)) = sealed else {
        set_cost_status(w, String::new());
        return;
    };
    let recipient_spk_lens: Vec<usize> = recipient_spks.iter().map(|s| s.len()).collect();
    let recipients_out: Vec<(Vec<u8>, u64)> = recipient_spks.into_iter().map(|spk| (spk, gift)).collect();
    match app_core::mixed::assemble_mixed_note_psbt_multi_ext(
        &args.coins,
        p2tr_script_pubkey(&identity.output_x),
        st.spending_source.as_ref(),
        &args.wallets_map,
        &args.change_spks,
        &payloads,
        &recipients_out,
        &args.change_default,
        args.change_override.clone(),
        args.change_index,
        rate,
        st.effective_lock_time(),
    ) {
        Ok(built) => {
            // Sub-dust fold prediction — `built.change == 0` means the REAL
            // build already chose the no-change shape; split its fee into
            // the nominal figure and the folded leftover, exactly like the
            // spending branch, but with per-coin input weights and the
            // anchored-aware dust flag (`built.dust_to_self > 0`).
            let fold = if built.change == 0 {
                let weights: Vec<bitcoin::transaction::InputWeightPrediction> = args
                    .coins
                    .iter()
                    .map(|c| match &c.source {
                        app_core::mixed::CoinSource::Notebook => {
                            bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH
                        }
                        app_core::mixed::CoinSource::Spending => {
                            bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX
                        }
                        app_core::mixed::CoinSource::Wallet(id) => match args.wallets_map.get(id).map(|s| s.kind) {
                            Some(app_core::funding::FundingKind::Wpkh) => {
                                bitcoin::transaction::InputWeightPrediction::P2WPKH_MAX
                            }
                            _ => bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
                        },
                        app_core::mixed::CoinSource::Change => {
                            bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH
                        }
                    })
                    .collect();
                let nominal = app_core::mixed::estimate_funded_fee_no_change_multi(
                    &weights,
                    &payloads,
                    &recipient_spk_lens,
                    built.dust_to_self > 0,
                    rate,
                );
                Some((nominal, built.fee.saturating_sub(nominal))).filter(|(_, folded)| *folded > 0)
            } else {
                None
            };
            let fold_amount = fold.map(|(_, f)| f).unwrap_or(0);
            if fold_amount != st.compose_fold_shown {
                if fold_amount > 0 {
                    println!("cb: compose-est fold={fold_amount}");
                }
                st.compose_fold_shown = fold_amount;
            }
            // The preview==confirm pin: `fee` here is the byte-true total
            // fee the built tx pays — the confirm screen's `fee=` decodes
            // the same figure from the raw tx, and the e2e asserts equality.
            if st.mixed_est_shown != Some((built.dust_to_self, built.fee)) {
                println!("cb: compose-est shape=mixed dust={} fee={}", built.dust_to_self, built.fee);
                st.mixed_est_shown = Some((built.dust_to_self, built.fee));
            }
            let fee_shown = fold.map(|(nominal, _)| nominal).unwrap_or(built.fee);
            let usd = st.usd.map(|p| format!(" (~${:.2})", fee_shown as f64 * p / 1e8)).unwrap_or_default();
            set_cost_card(
                w,
                String::new(), // funded shape: no chunk/vsize estimate on this path
                format!("~{} sats{usd}", commas(fee_shown)),
                gift_row(n_recipients, gift, built.sent_to_recipient),
                // Anchored (a notebook coin spends) → no dust output → row hidden.
                if built.dust_to_self > 0 { format!("+{} sats", commas(built.dust_to_self)) } else { String::new() },
                fold.map(|(_, folded)| (folded, built.fee)),
            );
            w.global::<Ui>().set_change_amount(format!("Change to {change_dest} · ~{} sats", commas(built.change)).into());
        }
        Err(e) => {
            set_cost_status(w, String::new());
            w.global::<Ui>().set_change_amount(format!("{e}").into());
        }
    }
}
}

impl State {
pub(crate) fn on_set_fee_tier(&mut self, w: &AppWindow, tier: i32) {
        let f = self.fees.clone().unwrap_or_default();
        let rate = match tier {
            0 => f.economy,
            2 => f.fastest,
            _ => f.hour,
        }
        .max(1.0);
        w.global::<Compose>().set_fee_tier(tier);
        // Custom (tier 3, also reached by editing the always-visible rate
        // box) keeps whatever the field already holds — Rust never
        // overwrites it while tier == 3 (same rule as sweep's
        // on_set_sweep_tier), so auto-selecting custom on edit can't fight
        // the user's typing.
        if tier != 3 {
            w.global::<Compose>().set_rate_text(format!("{rate}").into());
        }
        println!("cb: fee-tier {tier} rate={rate}");
        self.refresh_compose(w);
    }

pub(crate) fn on_add_recipient_open(&mut self, w: &AppWindow) {
        // Multi-select stays notebook-funded-compose only (watch-only has
        // no multi-recipient PSBT builder yet — a later unit).
        if self.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            return;
        }
        let total = 1 + self.to_addresses_extra.len();
        if total >= 255 {
            w.global::<Ui>().set_status("recipient limit reached (255)".into());
            return;
        }
        println!("cb: add-recipient-open");
        self.picking_extra = true;
        w.global::<Ui>().set_picking_extra(true);
        w.global::<Ui>().set_contact_input("".into());
        w.global::<Ui>().set_status("".into());
        w.global::<Ui>().set_pick_mode("compose".into());
        self.pull_icloud_contacts_on_open(w);
        w.global::<Ui>().set_screen(Screen::Contacts);
    }

pub(crate) fn on_remove_chip(&mut self, w: &AppWindow, addr: SharedString) {
        let a = addr.to_string();
        self.to_addresses_extra.retain(|x| x != &a);
        println!("cb: remove-chip n={}", self.to_addresses_extra.len() + 1);
        self.refresh_to_chips(w);
        self.refresh_compose(w);
    }

pub(crate) fn on_pq_generate_passphrase(&mut self, w: &AppWindow) {
        match app_core::passphrase::generate() {
            Ok((phrase, bits)) => {
                w.global::<Compose>().set_pq_passphrase_text(phrase.clone().into());
                self.pq_passphrase_generated = Some(phrase);
                self.pq_passphrase_verified = true;
                println!("cb: pq-generate bits={}", bits as u64);
                self.refresh_compose(w);
            }
            Err(e) => {
                w.global::<Ui>().set_status(format!("couldn't generate a passphrase: {e}").into());
            }
        }
    }

pub(crate) fn on_pq_passphrase_changed(&mut self, w: &AppWindow, text: SharedString) {
        let text = text.to_string();
        self.pq_passphrase_verified = self.pq_passphrase_generated.as_deref() == Some(text.as_str());
        self.refresh_compose(w);
    }

pub(crate) fn on_pq_mlkem_toggled(&mut self, w: &AppWindow, on: bool) {
        self.pq_mlkem_user_off = !on;
        self.save_config();
        self.refresh_compose(w);
    }

    /// "Unlock cost" pills: which Argon2id preset seals the passphrase layer
    /// of the note being composed. The caption spells out what the reader
    /// (and an attacker, per guess) pays.
    pub(crate) fn on_pq_pw_cost_changed(&mut self, w: &AppWindow, cost: SharedString) {
        use app_core::notes_core::pq::PwCost;
        if let Some(c) = PwCost::parse(&cost) {
            self.pq_pw_cost = c;
            self.save_config();
            println!("cb: pq-pw-cost {}", c.as_str());
        }
        w.global::<Compose>().set_pq_pw_cost(self.pq_pw_cost.as_str().into());
        w.global::<Compose>().set_pq_pw_cost_caption(pw_cost_caption(self.pq_pw_cost).into());
        self.refresh_compose(w);
    }

pub(crate) fn on_pq_panel_toggled(&mut self, w: &AppWindow, opened: bool) {
        if opened {
            self.ensure_pq_imported_loaded();
            self.refresh_compose(w);
        }
    }

pub(crate) fn on_open_funding_screen(&mut self, w: &AppWindow) {
        println!("cb: funding-open");
        // Screen 20 (pay-from) shows fee tiers via the compose cost line —
        // lazily (re)fetch (network-efficiency, 2026-07-23).
        self.refresh_fees_price(w);
        w.global::<Ui>().set_status("".into());
        self.nb_expanded = !self.mixed_coins_for("notebook").is_empty();
        self.sp_expanded = !self.mixed_coins_for("spending").is_empty();
        w.global::<PayFrom>().set_nb_expanded(self.nb_expanded);
        w.global::<PayFrom>().set_sp_expanded(self.sp_expanded);
        println!("cb: payfrom expand wallet=notebook expanded={}", self.nb_expanded);
        println!("cb: payfrom expand wallet=spending expanded={}", self.sp_expanded);
        let wallet_open = self
            .funding_wallets
            .iter()
            .find(|fw| !self.mixed_coins_for(&format!("wallet:{}", fw.id)).is_empty())
            .map(|fw| format!("wallet:{}", fw.id))
            .unwrap_or_default();
        self.payfrom_expanded_source = wallet_open;
        w.global::<Ui>().set_payfrom_expanded_source(self.payfrom_expanded_source.clone().into());
        if !self.payfrom_expanded_source.is_empty() {
            println!("cb: payfrom expand wallet={} expanded=true", self.payfrom_expanded_source);
        }
        self.update_funding_screen_ui(w);
        self.update_payfrom_panels(w);
        self.refresh_funding_list(w);
        w.global::<Ui>().set_screen(Screen::PayFrom);
    }

pub(crate) fn on_change_open(&mut self, w: &AppWindow) {
        w.global::<Ui>().set_status("".into());
        self.refresh_funding_list(w);
        self.update_change_label(w);
        // Logged AFTER resolution so `default=<choice>` reflects the
        // effective destination (an explicit pick if one was made this
        // session, else app-core's resolved default) — a screenshot-
        // independent way to assert change-default behavior in e2e.
        println!("cb: change-open default={}", w.global::<Ui>().get_change_choice());
        w.global::<Ui>().set_screen(Screen::Change);
    }

pub(crate) fn on_fund_build(&mut self, w: &AppWindow) {
        let text = w.global::<Compose>().get_compose_text().to_string();
        let private = w.global::<Compose>().get_compose_private();
        let rate: f64 = w.global::<Compose>().get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.global::<Ui>().set_status("empty note or bad fee rate".into());
            return;
        }
        if self.funding.is_none() || self.funding_coins.is_empty() {
            w.global::<Ui>().set_status("set a funding wallet first".into());
            return;
        }
        let net = self.network;
        let to = self.to_address.clone();
        let recipient = match to.as_deref() {
            Some(a) => match Recipient::parse(net, a) {
                Ok(r) => Some(r),
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            },
            None => None,
        };
        // Change destination: blank field = the funding wallet's own change
        // address; a valid custom address overrides it.
        let change_raw = normalize_addr(w.global::<Ui>().get_change_address().as_str());
        let change_override = if change_raw.is_empty() {
            None
        } else {
            match Recipient::parse(net, &change_raw) {
                Ok(r) => Some(r.spk),
                Err(_) => {
                    w.global::<Ui>().set_status(format!("change address isn't a valid {} address", net.as_str()).into());
                    return;
                }
            }
        };
        let src = self.funding.clone().unwrap();
        let coins = self.funding_coins.clone();
        let change_index = self.funding_change_index;
        let plan =
            FundingPlan { source: &src, coins: &coins, change_index, fee_rate: rate, change_override };
        if self.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            // Watch identity + funding wallet: PUBLIC note paid entirely by
            // the funding coins; both signatures happen externally. Frozen-
            // scan caveat: a rescan attributes an externally funded PUBLIC
            // note as received-from-funder — the local record keeps it own.
            if private {
                w.global::<Ui>().set_status("watch-only identities can only compose public notes".into());
                return;
            }
            let output_x = self.ident.as_ref().map(|i| i.output_x()).unwrap_or_default();
            let gift = if recipient.is_some() {
                w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
            } else {
                0
            };
            // Multi-recipient: the compose screen's extra To-chips — same
            // treatment as `on_compose_send`'s watch branch.
            let extra_recipients: Vec<&str> = self.to_addresses_extra.iter().map(String::as_str).collect();
            let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
                Ok(rc) => rc,
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            };
            let recipients_out: Vec<(Vec<u8>, u64)> = recipients.iter().map(|rc| (rc.spk.clone(), gift)).collect();
            let recipient_addrs: Vec<String> =
                if recipients.len() >= 2 { recipients.iter().map(|rc| rc.address.clone()).collect() } else { Vec::new() };
            let chunk = self.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);
            match app_core::psbt_build::build_watch_funded_note_psbt_multi(
                &output_x, &plan, &text, &recipients_out, chunk, self.effective_lock_time(),
            ) {
                Ok(built) => {
                    let payload_outputs = built
                        .psbt
                        .unsigned_tx
                        .output
                        .iter()
                        .filter(|o| o.script_pubkey.is_op_return())
                        .count();
                    self.watch_spend = None;
                    self.watch_note = Some(WatchNote {
                        text: text.clone(),
                        recipient: to.clone(),
                        recipients: recipient_addrs,
                        gift,
                        chunks: payload_outputs,
                        fee: built.fee,
                        change: 0, // funding change isn't an own coin
                        spent: Vec::new(),
                        funded: self.active_funding_pill(),
                        is_watch: true,
                        private: false,
                        dust_to_self: false,
                        change_spent: Vec::new(), // watch compose never spends change coins
                    });
                    let n = coins.len();
                    let nr = recipients.len();
                    let cost = format!(
                        "public note · fee {} sats · {n} funding input{} · sign with your external wallet{}",
                        built.fee,
                        if n == 1 { "" } else { "self" },
                        gift_cost_suffix(nr, gift),
                    );
                    // PLAN-pnte-redesign.md: the note id IS the txid.
                    println!(
                        "cb: watch-note-build id={} txid={} fee={} chunks={payload_outputs} funded=1{}",
                        built.txid,
                        built.txid,
                        built.fee,
                        if nr >= 2 { format!(" recipients={nr}") } else { String::new() }
                    );
                    self.show_psbt_sign_screen(w, built, cost);
                }
                Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
            }
            return;
        }
        let Some(identity) = self.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        let np = NoteParams {
            identity: &identity,
            text: &text,
            private,
            recipient: recipient.as_ref(),
            max_op_return_bytes: DEFAULT_CHUNK,
            network: net,
        };
        match build_funding_psbt(&plan, &np, self.effective_lock_time()) {
            Ok(built) => {
                let n = coins.len();
                let cost =
                    format!("fee {} sats · {n} input{}", built.fee, if n == 1 { "" } else { "self" });
                self.watch_spend = None; // this sign screen serves external funding
                self.watch_note = None;
                self.show_psbt_sign_screen(w, built, cost);
                println!("cb: fund-build ok");
            }
            Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
        }
    }

pub(crate) fn on_compose_send(&mut self, w: &AppWindow) {
        // Async sign+broadcast (2026-07-16): re-entrancy guard so a
        // double-tap on Sign can't double-broadcast.
        if self.compose_busy {
            return;
        }
        // Scan-freshness gate — see on_sweep_send.
        if w.global::<Ui>().get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=compose");
            w.global::<Ui>().set_status("still syncing — one moment".into());
            return;
        }
        let text = w.global::<Compose>().get_compose_text().to_string();
        let private = w.global::<Compose>().get_compose_private();
        let rate: f64 = w.global::<Compose>().get_rate_text().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.global::<Ui>().set_status("empty note or bad fee rate".into());
            return;
        }
        // Optional custom change address (empty = back to self).
        let change_addr = normalize_addr(w.global::<Ui>().get_change_address().as_str());
        if !change_addr.is_empty() && Recipient::parse(self.network, &change_addr).is_err() {
            w.global::<Ui>().set_status(format!("change address isn't a valid {} address", self.network.as_str()).into());
            return;
        }
        let net = self.network;
        let to = self.to_address.clone();
        if self.base_url().is_none() {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        }
        if !w.global::<Ui>().get_spend_enough() {
            w.global::<Ui>().set_status("selected coins don't cover the note + fee".into());
            return;
        }
        if self.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            // Watch compose: PUBLIC note as an external-sign PSBT over the
            // selected coins; recorded on broadcast like a keyed compose.
            if private {
                w.global::<Ui>().set_status("watch-only identities can only compose public notes".into());
                return;
            }
            let Some(src) = self.ident.as_ref().and_then(|i| i.watch_source()).cloned() else { return };
            let recipient = match to.as_deref() {
                Some(a) => match Recipient::parse(net, a) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        w.global::<Ui>().set_status(format!("{e}").into());
                        return;
                    }
                },
                None => None,
            };
            let gift = if recipient.is_some() {
                w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
            } else {
                0
            };
            // Multi-recipient: the compose screen's extra To-chips, exactly
            // like the notebook path — a watch identity can't compose
            // PRIVATE notes at all (checked above), so no content-key/ECDH
            // concerns here; `public_multi_payloads`/`build_watch_note_psbt_
            // multi` hand-frame the same FLAG_MULTI body a keyed identity's
            // sealer would produce.
            let extra_recipients: Vec<&str> = self.to_addresses_extra.iter().map(String::as_str).collect();
            let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
                Ok(r) => r,
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            };
            let recipients_out: Vec<(Vec<u8>, u64)> = recipients.iter().map(|r| (r.spk.clone(), gift)).collect();
            let recipient_addrs: Vec<String> =
                if recipients.len() >= 2 { recipients.iter().map(|r| r.address.clone()).collect() } else { Vec::new() };
            let Some(store) = self.store.as_ref() else { return };
            let sel: std::collections::HashSet<(String, u32)> =
                self.selected_coins.iter().cloned().collect();
            let nb = self.ident.as_ref().map(|i| i.index).unwrap_or(0);
            let coins: Vec<WatchCoin> = store
                .utxos
                .iter()
                .filter(|u| !u.pending_spend && sel.contains(&(u.txid.clone(), u.vout)))
                .map(|u| WatchCoin { txid: u.txid.clone(), vout: u.vout, value: u.value, chain: 0, index: nb })
                .collect();
            if coins.is_empty() {
                println!("cb: compose-send bail=no-coins src=watch");
                w.global::<Ui>().set_status("no coins selected".into());
                return;
            }
            let chunk = store.chunk_size;
            match build_watch_note_psbt_multi(
                &src, &coins, &text, &recipients_out, chunk, rate, self.effective_lock_time(),
            ) {
                Ok(built) => {
                    let payload_outputs = built
                        .psbt
                        .unsigned_tx
                        .output
                        .iter()
                        .filter(|o| o.script_pubkey.is_op_return())
                        .count();
                    self.watch_spend = None;
                    self.watch_note = Some(WatchNote {
                        text: text.clone(),
                        recipient: to.clone(),
                        recipients: recipient_addrs,
                        gift,
                        chunks: payload_outputs,
                        fee: built.fee,
                        change: built.change,
                        spent: coins
                            .iter()
                            .map(|c| app_core::store::OutPointRef { txid: c.txid.clone(), vout: c.vout })
                            .collect(),
                        funded: None, // spends the notebook's own coins
                        is_watch: true,
                        private: false,
                        dust_to_self: false,
                        change_spent: Vec::new(), // watch compose never spends change coins
                    });
                    let n = recipients.len();
                    let cost = format!(
                        "public note · fee {} sats{} · sign with your external wallet",
                        built.fee,
                        gift_cost_suffix(n, gift)
                    );
                    // PLAN-pnte-redesign.md: the note id IS the txid.
                    println!(
                        "cb: watch-note-build id={} txid={} fee={} chunks={payload_outputs}{}",
                        built.txid,
                        built.txid,
                        built.fee,
                        if n >= 2 { format!(" recipients={n}") } else { String::new() }
                    );
                    self.show_psbt_sign_screen(w, built, cost);
                }
                Err(e) => w.global::<Ui>().set_status(format!("{e}").into()),
            }
            return;
        }
        let Some(identity) = self.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        // Universal confirm screen (2026-07-17): stage A builds + signs
        // via the PURE `compose_note` (split out of `compose_and_record` —
        // see app-core/src/compose.rs) — no store mutation, so a Cancel on
        // screen 26 leaves zero trace. Stage B (`on_confirm_broadcast`)
        // calls `record_composed_note` + `save_store()` at the Broadcast
        // tap — exactly what `compose_and_record` used to do before its
        // own POST — then spawns the SAME broadcast worker below.
        let coins_vec = self.selected_coins.clone();
        let created_at = now();
        let gift_amount = to
            .as_ref()
            .map(|_| w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS));
        let change_to = (!change_addr.is_empty()).then(|| change_addr.clone());
        // Multi-recipient (notebook-funded compose only, see State::
        // to_addresses_extra): the compose screen's removable To-chips,
        // beyond the primary `to`. Empty for every other pay-from source
        // and for watch-only (the picker's "+ Add recipient" affordance is
        // hidden there) — so this stays the exact single-recipient flow,
        // byte-identical, for every path but this one.
        let extra_recipients: Vec<&str> = self.to_addresses_extra.iter().map(String::as_str).collect();
        // Post-quantum layers (compose screen 6's Security section). Only
        // reachable when the section could even be showing — re-check
        // `pq_compose_eligible` rather than trusting the toggles blindly,
        // since Sign is a separate tap that could race a recipient/private
        // change made after the section last repainted.
        let pq_eligible = self.pq_compose_eligible(w);
        let pq_password = if pq_eligible && w.global::<Compose>().get_pq_passphrase_enabled() {
            let p = w.global::<Compose>().get_pq_passphrase_text().to_string();
            if p.trim().is_empty() {
                w.global::<Ui>().set_status("enter a passphrase, or turn off the passphrase layer".into());
                return;
            }
            Some(p)
        } else {
            None
        };
        let pq_mlkem = if pq_eligible && w.global::<Compose>().get_pq_mlkem_enabled() {
            match to.as_deref() {
                Some(addr) => {
                    let net_str = self.network.as_str();
                    let armor = self
                        .contacts
                        .iter()
                        .find(|c| c.address == addr && (c.network == net_str || c.network.is_empty()))
                        .and_then(|c| c.mlkem_ek.clone());
                    match armor.as_deref().map(app_core::notes_core::pq::import_public) {
                        Some(Ok(pair)) => Some(pair),
                        _ => {
                            w.global::<Ui>().set_status(
                                "couldn't read this contact's quantum key — try again, or turn off quantum encryption".into(),
                            );
                            return;
                        }
                    }
                }
                // Self-note (PLAN-graffito-self-pw.md): the imported quantum
                // key ONLY — never the notebook's seed-derived receive key
                // (see `pq_compose_eligible`'s doc). `ensure_pq_imported_
                // loaded` already ran when the Security panel was opened
                // (`on_pq_panel_toggled`); Sign is a separate tap that could
                // race the key being removed since, so re-check here rather
                // than trusting the toggle blindly.
                None => match self.pq_imported.as_ref() {
                    Some(kp) => Some((kp.alg(), kp.ek().to_vec())),
                    None => {
                        w.global::<Ui>().set_status(
                            "no quantum key — add one in Settings, or turn off quantum encryption".into(),
                        );
                        return;
                    }
                },
            }
        } else {
            None
        };
        let req = ComposeRequest {
            text: &text,
            private,
            recipient: to.as_deref(),
            extra_recipients: &extra_recipients,
            change_to: change_to.as_deref(),
            coins: (!coins_vec.is_empty()).then_some(coins_vec.as_slice()),
            fee_rate: rate,
            gift_amount,
            lock_time: self.lock_time_override_value(),
            now: created_at,
            pq_password,
            pq_pw_cost: self.pq_pw_cost,
            pq_mlkem,
        };
        let Some(store) = self.store.as_ref() else {
            w.global::<Ui>().set_status("no store".into());
            return;
        };
        match app_core::compose::compose_note(store, &identity, net, &req) {
            Ok(composed) => {
                let name = self.notebook_display_name(self.nb_index);
                let identity_addr = self.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
                let prevouts = notebook_prevouts(
                    self.store.as_ref().unwrap(),
                    &identity_addr,
                    &name,
                    &composed.tx.spent_outpoints,
                );
                let (self_spks, spending_spks) = self.confirm_self_spks();
                let contact_name = |a: &str| -> Option<String> {
                    self.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
                };
                let recipient_name = to.as_deref().and_then(contact_name);
                // Multi-recipient: `composed.recipients` is only populated
                // (2+ entries) for an actual multi-recipient note — every
                // other compose (self or ordinary single-recipient) keeps
                // this empty and relies on `recipient`/`recipient_name`
                // above, unchanged.
                let recipients: Vec<(String, Option<String>)> =
                    composed.recipients.iter().map(|a| (a.clone(), contact_name(a))).collect();
                let ctx = app_core::confirm::ConfirmCtx {
                    network: app_core::derive::btc_network(net),
                    prevouts,
                    self_spks,
                    spending_spks,
                    expected_change: change_to.clone(),
                    recipient: to.clone(),
                    recipient_name,
                    recipients,
                    note_preview: Some(if private { "Private note (encrypted)".to_string() } else { text.clone() }),
                    tip_height: self.confirm_tip_height(),
                };
                let (fchange, ffee, fvsize) = (composed.tx.change, composed.tx.fee, composed.tx.vsize);
                let pending = PendingBroadcast {
                    kind: "compose",
                    raw_hex: composed.tx.raw_hex.clone(),
                    txid: composed.tx.txid_hex.clone(),
                    vsize: composed.tx.vsize,
                    context: note_context(to.is_some(), private, net),
                    return_screen: Screen::Compose, // overwritten by show_confirm
                    payload: PendingPayload::Compose {
                        composed,
                        text: text.clone(),
                        private,
                        change_to,
                        created_at,
                        to: to.clone(),
                    },
                };
                self.show_confirm(w, pending, ctx);
                note_subdust_fold_warn(w, fchange, ffee, fvsize as u64, rate);
            }
            Err(e) => {
                println!("cb: compose err={e}");
                w.global::<Ui>().set_status(format!("{e}").into());
            }
        }
    }

pub(crate) fn on_spending_compose_send(&mut self, w: &AppWindow) {
        if self.compose_busy {
            return;
        }
        // Scan-freshness gate — see on_sweep_send.
        if w.global::<Ui>().get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=spending-compose");
            w.global::<Ui>().set_status("still syncing — one moment".into());
            return;
        }
        let text = w.global::<Compose>().get_compose_text().to_string();
        let private = w.global::<Compose>().get_compose_private();
        let rate: f64 = w.global::<Compose>().get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.global::<Ui>().set_status("empty note or bad fee rate".into());
            return;
        }
        let net = self.network;
        if self.base_url().is_none() {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        }
        let to = self.to_address.clone();
        let recipient = match to.as_deref() {
            Some(a) => match Recipient::parse(net, a) {
                Ok(r) => Some(r),
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            },
            None => None,
        };
        // Multi-recipient: the compose screen's extra To-chips — dropped
        // silently on this path before (Sal's report); now built the SAME
        // way the notebook path builds them (`compose::compose_note`).
        let extra_recipients: Vec<&str> = self.to_addresses_extra.iter().map(String::as_str).collect();
        let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
            Ok(r) => r,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let recipient_addrs: Vec<String> =
            if recipients.len() >= 2 { recipients.iter().map(|r| r.address.clone()).collect() } else { Vec::new() };
        let change_raw = normalize_addr(w.global::<Ui>().get_change_address().as_str());
        let change_override = if change_raw.is_empty() {
            None
        } else {
            match Recipient::parse(net, &change_raw) {
                Ok(r) => Some(r.spk),
                Err(_) => {
                    w.global::<Ui>().set_status(format!("change address isn't a valid {} address", net.as_str()).into());
                    return;
                }
            }
        };
        let Some(source) = self.spending_source.clone() else {
            w.global::<Ui>().set_status("spending wallet not scanned yet".into());
            return;
        };
        if self.spending_coins.is_empty() {
            w.global::<Ui>().set_status("spending wallet has no coins — fund it from Settings".into());
            return;
        }
        // Spend exactly the coins selected in the funding screen's coin
        // control — same `selected_coins`/`coins_overridden` state the
        // notebook path uses; unselected defaults to every scanned coin
        // (matches the live preview in `spending_compose_ui`).
        let spending_sel: std::collections::HashSet<(String, u32)> = if self.coins_overridden {
            self.selected_coins.iter().cloned().collect()
        } else {
            self.spending_coins.iter().map(|c| (c.txid.clone(), c.vout)).collect()
        };
        let selected_spending_coins: Vec<app_core::funding::FundingUtxo> = self
            .spending_coins
            .iter()
            .filter(|c| spending_sel.contains(&(c.txid.clone(), c.vout)))
            .cloned()
            .collect();
        if selected_spending_coins.is_empty() {
            println!("cb: compose-send bail=no-coins src=spending");
            w.global::<Ui>().set_status("no coins selected".into());
            return;
        }
        let Some(material_str) = self.material.as_ref().map(|z| String::from(z.as_str())) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        let Ok(key_material) = parse_key_material(&material_str, net) else {
            w.global::<Ui>().set_status("identity parse failed".into());
            return;
        };
        let account = self.account;
        let Some(identity) = self.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        let Some(change_index) = self.store.as_ref().map(|st| st.spending.next_change) else { return };
        let chunk = self.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);
        let gift = if recipient.is_some() {
            w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
        } else {
            0
        };
        let plan = FundingPlan {
            source: &source,
            coins: &selected_spending_coins,
            change_index,
            fee_rate: rate,
            change_override,
        };
        let np = NoteParams {
            identity: &identity,
            text: &text,
            private,
            recipient: recipient.as_ref(),
            max_op_return_bytes: chunk,
            network: net,
        };
        let built = if recipients.len() >= 2 {
            app_core::psbt_build::build_funding_psbt_multi(&plan, &np, &recipients, gift, self.effective_lock_time())
        } else {
            app_core::psbt_build::build_funding_psbt_amount(&plan, &np, gift, self.effective_lock_time())
        };
        let built = match built {
            Ok(b) => b,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let mut psbt = built.psbt.clone();
        match app_core::psbt_build::sign_own_wpkh_inputs(
            &mut psbt,
            &key_material,
            net,
            account,
            &selected_spending_coins,
        ) {
            Ok(n) if n > 0 => {}
            Ok(_) => {
                w.global::<Ui>().set_status("no spending-wallet inputs signed".into());
                return;
            }
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        // Captured before `finalize_extract` consumes the PSBT — used below
        // to drop the just-spent coins from the runtime cache the moment the
        // broadcast succeeds (finding 1: a second compose in the same
        // session must never see an already-spent UTXO).
        let spent_outpoints: Vec<(String, u32)> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|inp| (inp.previous_output.txid.to_string(), inp.previous_output.vout))
            .collect();
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        // Universal confirm screen (2026-07-17): nothing is recorded here —
        // that was already true before this refactor (unlike the notebook
        // path) — so stage A just hands the signed tx to the confirm
        // screen. Stage B (`on_confirm_broadcast`) is this exact
        // thread-spawn, moved verbatim to the Broadcast tap.
        let built_fee = built.fee;
        let built_change = built.change;
        let (mut self_spks, mut spending_spks) = self.confirm_self_spks();
        // A custom change override leaves the wallet entirely (classified
        // via `expected_change`, not self); the default spending-wallet
        // change address is freshly derived and not yet "used" bookkeeping,
        // so it must be added on top of `confirm_self_spks`'s set.
        let expected_change = if !change_raw.is_empty() {
            Some(change_raw.clone())
        } else {
            if built_change > 0 {
                if let Ok(d) = source.derive(1, change_index) {
                    self_spks.push(d.spk.clone());
                    spending_spks.push(d.spk);
                }
            }
            None
        };
        let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
        for c in &selected_spending_coins {
            prevouts.insert(
                format!("{}:{}", c.txid, c.vout),
                app_core::confirm::PrevoutInfo {
                    value: c.value,
                    address: Some(c.address.clone()),
                    source: "Spending wallet".to_string(),
                },
            );
        }
        let recipient_name = to.as_deref().and_then(|a| {
            self.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        });
        let contact_name = |a: &str| -> Option<String> {
            self.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        };
        let confirm_recipients: Vec<(String, Option<String>)> =
            recipient_addrs.iter().map(|a| (a.clone(), contact_name(a))).collect();
        let ctx = app_core::confirm::ConfirmCtx {
            network: app_core::derive::btc_network(net),
            prevouts,
            self_spks,
            spending_spks,
            expected_change,
            recipient: to.clone(),
            recipient_name,
            recipients: confirm_recipients,
            note_preview: Some(if private { "Private note (encrypted)".to_string() } else { text.clone() }),
            tip_height: self.confirm_tip_height(),
        };
        let pending = PendingBroadcast {
            kind: "compose-spending",
            raw_hex: raw,
            txid,
            vsize,
            context: note_context(to.is_some(), private, net),
            return_screen: Screen::Compose, // overwritten by show_confirm
            payload: PendingPayload::ComposeSpending {
                text: text.clone(),
                private,
                to: to.clone(),
                recipients: recipient_addrs,
                gift,
                built_fee,
                built_change,
                spent_outpoints,
                change_index,
                change_raw,
                source,
            },
        };
        self.show_confirm(w, pending, ctx);
        note_subdust_fold_warn(w, built_change, built_fee, vsize as u64, rate);
    }

pub(crate) fn on_compose_send_mixed(&mut self, w: &AppWindow) {
        if self.compose_busy {
            return;
        }
        // Scan-freshness gate — see on_sweep_send.
        if w.global::<Ui>().get_wallet_scan_busy() {
            println!("cb: sign-gate busy kind=mixed-compose");
            w.global::<Ui>().set_status("still syncing — one moment".into());
            return;
        }
        let text = w.global::<Compose>().get_compose_text().to_string();
        let private = w.global::<Compose>().get_compose_private();
        let rate: f64 = w.global::<Compose>().get_rate_text().trim().parse().unwrap_or(0.0);
        if text.is_empty() || rate <= 0.0 {
            w.global::<Ui>().set_status("empty note or bad fee rate".into());
            return;
        }
        if self.ident.as_ref().map(|i| i.is_watch()).unwrap_or(false) {
            w.global::<Ui>().set_status("watch-only identities can't mix sources".into());
            return;
        }
        let net = self.network;
        if self.base_url().is_none() {
            w.global::<Ui>().set_status("no Bitcoin node — set one in Settings".into());
            return;
        }
        let to = self.to_address.clone();
        let recipient = match to.as_deref() {
            Some(a) => match Recipient::parse(net, a) {
                Ok(r) => Some(r),
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            },
            None => None,
        };
        let gift = if recipient.is_some() {
            w.global::<Compose>().get_gift_sats().trim().parse::<u64>().unwrap_or(DUST_SATS).max(DUST_SATS)
        } else {
            0
        };
        // Multi-recipient: the compose screen's extra To-chips — dropped
        // silently on this path before (Sal's report); now built the SAME
        // way the notebook path builds them.
        let extra_recipients: Vec<&str> = self.to_addresses_extra.iter().map(String::as_str).collect();
        let recipients = match app_core::compose::parse_dedupe_recipients(net, to.as_deref(), &extra_recipients) {
            Ok(r) => r,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let recipient_addrs: Vec<String> =
            if recipients.len() >= 2 { recipients.iter().map(|r| r.address.clone()).collect() } else { Vec::new() };
        let Some(identity) = self.ident.as_ref().and_then(|i| i.full()).map(|i| i.clone_fields()) else {
            w.global::<Ui>().set_status("no identity".into());
            return;
        };
        let notebook_spk = p2tr_script_pubkey(&identity.output_x);

        // Coins + wallets + change resolution come from the SAME args-builder
        // the compose preview (`mixed_compose_ui`) dry-runs — the shared seam
        // that makes preview and send structurally identical (TestFlight
        // build-20 fix, 2026-07-18).
        let MixedComposeArgs { coins, wallets_map, change_spks, change_default, change_override, change_index } =
            match self.mixed_compose_args(w) {
                Ok(a) => a,
                Err(e) => {
                    w.global::<Ui>().set_status(e.into());
                    return;
                }
            };

        if coins.is_empty() {
            println!("cb: compose-send bail=no-coins src=mixed");
            w.global::<Ui>().set_status("no coins selected".into());
            return;
        }
        // A change-ONLY selection is single-source by `spans_multiple_wallets`'s
        // count (one distinct `CoinSource::Change`), but there IS no other
        // Sign button for it — taproot-change unit 5 — so it must still
        // route here rather than bounce with "use the Sign button on that
        // source instead".
        let has_change = coins.iter().any(|c| matches!(c.source, app_core::mixed::CoinSource::Change));
        if !has_change && !app_core::mixed::spans_multiple_wallets(&coins) {
            println!("cb: compose-send bail=single-source src=mixed");
            w.global::<Ui>().set_status("selection is single-source — use the Sign button on that source instead".into());
            return;
        }
        let chunk = self.store.as_ref().map(|st| st.chunk_size).unwrap_or(DEFAULT_CHUNK);

        // PLAN-pnte-redesign.md: a private body's AAD binds the tx's FIRST
        // input's outpoint, not a synthetic id — `coins[0]` becomes that
        // input by construction (`assemble_mixed_note_psbt_multi_ext`
        // iterates `coins` in caller order with no reordering), so it's
        // known before the tx itself is built. `coins` was checked
        // non-empty above.
        let outpoint: [u8; 36] = {
            let c = &coins[0];
            let mut txid = [0u8; 32];
            if let Err(e) = hex::decode_to_slice(&c.txid, &mut txid) {
                w.global::<Ui>().set_status(format!("bad coin txid: {e}").into());
                return;
            }
            txid.reverse();
            app_core::notes_core::tx::outpoint_bytes(&app_core::notes_core::tx::Utxo {
                txid,
                vout: c.vout,
                value: c.value,
            })
        };

        // Fresh one-shot content key for a private multi-recipient body
        // (notes-core's hybrid seal) — OS TRNG, never persisted/logged,
        // zeroized immediately after use, same convention `compose_note`
        // (the notebook path) follows. Unused (and not drawn) for 0/1
        // recipients — `sealed_note_payloads_multi` ignores it there too.
        let payloads_and_spks = if recipients.len() >= 2 {
            let content_key = match app_core::compose::fresh_content_key() {
                Ok(k) => k,
                Err(e) => {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            };
            let mut content_key = content_key;
            let result = app_core::notes_core::bundle::sealed_note_payloads_multi(
                &identity, &text, private, &recipients, outpoint, content_key, chunk,
            );
            content_key.zeroize();
            result.map_err(app_core::Error::from)
        } else {
            app_core::notes_core::bundle::sealed_note_payloads(
                &identity, &text, private, recipient.as_ref(), outpoint, chunk,
            )
            .map(|(p, spk)| (p, spk.into_iter().collect::<Vec<Vec<u8>>>()))
            .map_err(app_core::Error::from)
        };
        let (payloads, recipient_spks) = match payloads_and_spks {
            Ok(p) => p,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let recipients_out: Vec<(Vec<u8>, u64)> = recipient_spks.into_iter().map(|spk| (spk, gift)).collect();

        let mut built = match app_core::mixed::assemble_mixed_note_psbt_multi_ext(
            &coins,
            notebook_spk,
            self.spending_source.as_ref(),
            &wallets_map,
            &change_spks,
            &payloads,
            &recipients_out,
            &change_default,
            change_override,
            change_index,
            rate,
            self.effective_lock_time(),
        ) {
            Ok(b) => b,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };

        // Sign our own inputs regardless of kind — a no-op (Ok(0)) for
        // whichever kind isn't present in this selection.
        if let Err(e) =
            app_core::psbt_build::sign_own_taproot_inputs(&mut built.psbt, &identity.output_x, &identity.tweaked_seckey)
        {
            w.global::<Ui>().set_status(format!("{e}").into());
            return;
        }
        // Taproot CHANGE-chain owners (unit 5): group the selected coins by
        // UNIQUE chain-1 index and sign each owner's inputs with its OWN
        // tweaked key — exactly unit 4's `build_sweep_confirm` change-idents
        // loop, at the PSBT level. `realize_change`'s `AppIdentity` (and its
        // `Zeroizing` leaf secret) drops — and zeroizes — at the end of each
        // loop iteration, never escaping this scope.
        if has_change {
            let Some(material_str) = self.material.as_ref().map(|z| String::from(z.as_str())) else {
                w.global::<Ui>().set_status("no identity".into());
                return;
            };
            let Ok(key_material) = parse_key_material(&material_str, net) else {
                w.global::<Ui>().set_status("identity parse failed".into());
                return;
            };
            let mut seen_idx: Vec<u32> = Vec::new();
            for c in coins.iter().filter(|c| matches!(c.source, app_core::mixed::CoinSource::Change)) {
                if seen_idx.contains(&c.index) {
                    continue;
                }
                seen_idx.push(c.index);
                let owner = match realize_change(&key_material, net, self.account, c.index) {
                    Ok(o) => o,
                    Err(e) => {
                        w.global::<Ui>().set_status(format!("{e}").into());
                        return;
                    }
                };
                let Some(owner_identity) = owner.full() else {
                    w.global::<Ui>().set_status("change-chain identity has no key".into());
                    return;
                };
                if let Err(e) = app_core::psbt_build::sign_own_taproot_inputs(
                    &mut built.psbt, &owner_identity.output_x, &owner_identity.tweaked_seckey,
                ) {
                    w.global::<Ui>().set_status(format!("{e}").into());
                    return;
                }
            }
        }
        let spending_funding_utxos = app_core::mixed::spending_funding_utxos(&coins);
        if !spending_funding_utxos.is_empty() {
            let Some(material_str) = self.material.as_ref().map(|z| String::from(z.as_str())) else {
                w.global::<Ui>().set_status("no identity".into());
                return;
            };
            let Ok(key_material) = parse_key_material(&material_str, net) else {
                w.global::<Ui>().set_status("identity parse failed".into());
                return;
            };
            if let Err(e) = app_core::psbt_build::sign_own_wpkh_inputs(
                &mut built.psbt, &key_material, net, self.account, &spending_funding_utxos,
            ) {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        }

        let notebook_spent: Vec<app_core::store::OutPointRef> = coins
            .iter()
            .filter(|c| matches!(c.source, app_core::mixed::CoinSource::Notebook))
            .map(|c| app_core::store::OutPointRef { txid: c.txid.clone(), vout: c.vout })
            .collect();
        // Taproot CHANGE-chain coins ridden as inputs (unit 5): NOT part of
        // `store.utxos` (they live in `State.change_coins`, a separate
        // per-account pool), so they're tracked as their own (txid, vout)
        // list — same shape+timing as `SweepSnapshot.change_spent` (unit 4):
        // pruned from `State.change_coins` only on broadcast SUCCESS.
        let change_spent: Vec<(String, u32)> = coins
            .iter()
            .filter(|c| matches!(c.source, app_core::mixed::CoinSource::Change))
            .map(|c| (c.txid.clone(), c.vout))
            .collect();
        let has_external = coins.iter().any(|c| matches!(c.source, app_core::mixed::CoinSource::Wallet(_)));
        // Input-anchored skip (2026-07-18 dust-skip rework; extended to
        // Change by taproot-change unit 5): mirrors
        // `assemble_mixed_note_psbt`'s own `has_self_input` condition
        // exactly, so a bumped/re-read `WatchNote`'s change-vout math
        // (`wn.dust_to_self`) stays byte-true to what the built tx actually
        // contains.
        let has_notebook_input = !notebook_spent.is_empty() || !change_spent.is_empty();

        if has_external {
            // Our own inputs are already signed above; export for the
            // external wallet to complete its own via screens 13/14.
            self.watch_spend = None;
            self.watch_note = Some(WatchNote {
                text: text.clone(),
                recipient: to.clone(),
                recipients: recipient_addrs.clone(),
                gift,
                chunks: payloads.len(),
                fee: built.fee,
                change: built.change,
                spent: notebook_spent,
                funded: Some("mixed".to_string()),
                is_watch: false,
                private,
                dust_to_self: !has_notebook_input,
                change_spent: change_spent.clone(),
            });
            let n = coins.len();
            let nr = recipients.len();
            let sources: std::collections::HashSet<&str> =
                self.mixed_selected.iter().map(|(src, _, _)| src.as_str()).collect();
            println!(
                "cb: compose-mixed build txid={} fee={} inputs={n} sources={} external=1{}",
                built.txid,
                built.fee,
                sources.len(),
                if nr >= 2 { format!(" recipients={nr}") } else { String::new() }
            );
            // `today's copy` here never mentioned the gift at all (even for
            // a single recipient) — preserved for nr <= 1; nr >= 2 appends
            // the ×N total (Sal, 2026-07-19).
            let cost = format!(
                "mixed source · fee {} sats · {n} input{}{} · sign with your external wallet",
                built.fee,
                if n == 1 { "" } else { "self" },
                if nr >= 2 { gift_cost_suffix(nr, gift) } else { String::new() }
            );
            self.show_psbt_sign_screen(w, built, cost);
            return;
        }

        // No external coin: finalize + hand off to the universal confirm
        // screen. Nothing is recorded here — same "safe to retry from
        // compose on failure" shape as the spending path; stage B
        // (`on_confirm_broadcast`) is this exact thread-spawn, moved
        // verbatim to the Broadcast tap.
        let psbt = built.psbt.clone();
        let (raw, txid, vsize) = match finalize_extract(psbt) {
            Ok(x) => x,
            Err(e) => {
                w.global::<Ui>().set_status(format!("{e}").into());
                return;
            }
        };
        let spent_spending: Vec<(String, u32)> = coins
            .iter()
            .filter(|c| matches!(c.source, app_core::mixed::CoinSource::Spending))
            .map(|c| (c.txid.clone(), c.vout))
            .collect();
        let spending_source = self.spending_source.clone();
        let built_fee = built.fee;
        let built_change = built.change;
        let payloads_len = payloads.len();
        // `recipients` (the full parsed list, not the "empty means single"
        // `recipient_addrs`) already carries the exact recipient OUTPUT
        // count for every case (0 self-note / 1 ordinary / N multi).
        let recipient_count = recipients.len();

        let identity_addr = self.ident.as_ref().map(|i| i.address.clone()).unwrap_or_default();
        let name = self.notebook_display_name(self.nb_index);
        let mut prevouts: HashMap<String, app_core::confirm::PrevoutInfo> = HashMap::new();
        for c in &coins {
            let key = format!("{}:{}", c.txid, c.vout);
            match &c.source {
                app_core::mixed::CoinSource::Notebook => {
                    prevouts.insert(
                        key,
                        app_core::confirm::PrevoutInfo {
                            value: c.value,
                            address: Some(identity_addr.clone()),
                            source: format!("Notebook · {name}"),
                        },
                    );
                }
                app_core::mixed::CoinSource::Spending => {
                    let addr = self
                        .spending_coins
                        .iter()
                        .find(|sc| sc.txid == c.txid && sc.vout == c.vout)
                        .map(|sc| sc.address.clone());
                    prevouts.insert(
                        key,
                        app_core::confirm::PrevoutInfo {
                            value: c.value,
                            address: addr,
                            source: "Spending wallet".to_string(),
                        },
                    );
                }
                // Taproot CHANGE-chain coin (unit 5): same account, chain 1
                // — tagged "Change" (mirrors the sweep confirm's own
                // `source: "Change"` label from unit 4).
                app_core::mixed::CoinSource::Change => {
                    let addr = self
                        .change_coins
                        .iter()
                        .find(|cc| cc.txid == c.txid && cc.vout == c.vout)
                        .map(|cc| cc.address.clone());
                    prevouts.insert(
                        key,
                        app_core::confirm::PrevoutInfo { value: c.value, address: addr, source: "Change".to_string() },
                    );
                }
                // Unreachable here: `has_external` (Wallet(_) coins present)
                // returned above via the external-sign screen instead.
                app_core::mixed::CoinSource::Wallet(_) => {}
            }
        }
        let (mut self_spks, mut spending_spks) = self.confirm_self_spks();
        // A custom change override (screen 21 "custom") leaves the wallet
        // entirely; the default spending-wallet change address is freshly
        // derived and not yet "used" bookkeeping, so — like the spending
        // path — it must be added on top of `confirm_self_spks`'s set. A
        // notebook-default change needs no augmentation (already covered).
        let choice = w.global::<Ui>().get_change_choice().to_string();
        let expected_change = if choice == "custom" {
            Some(normalize_addr(w.global::<Ui>().get_change_address().as_str()))
        } else {
            if change_default == app_core::mixed::ChangeDefault::Spending && built_change > 0 {
                if let Some(src) = self.spending_source.as_ref() {
                    if let Ok(d) = src.derive(1, change_index) {
                        self_spks.push(d.spk.clone());
                        spending_spks.push(d.spk);
                    }
                }
            }
            None
        };
        let recipient_name = to.as_deref().and_then(|a| {
            self.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        });
        let contact_name = |a: &str| -> Option<String> {
            self.contacts.iter().find(|c| c.address == a && !c.name.is_empty()).map(|c| c.name.clone())
        };
        let confirm_recipients: Vec<(String, Option<String>)> =
            recipient_addrs.iter().map(|a| (a.clone(), contact_name(a))).collect();
        let ctx = app_core::confirm::ConfirmCtx {
            network: app_core::derive::btc_network(net),
            prevouts,
            self_spks,
            spending_spks,
            expected_change,
            recipient: to.clone(),
            recipient_name,
            recipients: confirm_recipients,
            note_preview: Some(if private { "Private note (encrypted)".to_string() } else { text.clone() }),
            tip_height: self.confirm_tip_height(),
        };
        let pending = PendingBroadcast {
            kind: "compose-mixed",
            raw_hex: raw,
            txid,
            vsize,
            context: note_context(to.is_some(), private, net),
            return_screen: Screen::Compose, // overwritten by show_confirm
            payload: PendingPayload::ComposeMixed {
                text: text.clone(),
                private,
                to: to.clone(),
                recipients: recipient_addrs,
                gift,
                built_fee,
                built_change,
                change_default,
                notebook_spent,
                spent_spending,
                change_spent,
                payloads_len,
                recipient_count,
                change_index,
                spending_source,
            },
        };
        self.show_confirm(w, pending, ctx);
        note_subdust_fold_warn(w, built_change, built_fee, vsize as u64, rate);
    }

pub(crate) fn on_set_compose_locktime(&mut self, w: &AppWindow, mode: SharedString, height: SharedString) {
        let Some(policy) = parse_locktime_mode(mode.as_str(), height.as_str()) else {
            println!("cb: compose-locktime err=range");
            w.global::<Ui>().set_status("locktime must be a block height below 500000000".into());
            return;
        };
        self.tx_lock_time_override = Some(policy);
        let effective = self.effective_lock_time();
        println!("cb: compose-locktime {} effective={effective} ok", policy.as_str());
        self.refresh_compose_locktime_panel(w);
        w.global::<Ui>().set_status("".into());
    }
}

/// Caption under the "Unlock cost" pills — the Argon2id parameters in plain
/// words. Memory is the attacker-facing number: every guess has to fill it.
pub(crate) fn pw_cost_caption(cost: app_core::notes_core::pq::PwCost) -> String {
    use app_core::notes_core::pq::PwCost;
    let (t, _, _) = cost.params();
    let mib = cost.mib();
    match cost {
        PwCost::Standard => format!("Argon2id, {mib} MiB × {t} passes — quick to unlock; each guess an attacker makes costs the same memory and time."),
        PwCost::Strong => format!("Argon2id, {mib} MiB × {t} passes — about a second to unlock on a phone. Recommended."),
        PwCost::Maximum => format!("Argon2id, {mib} MiB × {t} passes — a few seconds to unlock, and the most any guess can cost an attacker."),
    }
}
