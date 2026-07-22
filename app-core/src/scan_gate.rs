//! Pure counter-pairing core for the scan-freshness gate (the app crate's
//! `State.notebook_scan_busy`/`spending_scan_busy`/`wallet_stores_busy` +
//! `update_scan_gate`, `src/lib.rs`). No threads, no UI types — just the
//! admit/drain bookkeeping, host-testable with `cargo test -p app-core`.
//!
//! Design: `../../PLAN-chain-notes-app.md` "Network layer" — the gate keeps
//! a money-flow Sign button disabled while ANY scan that feeds its coin
//! cache is in flight (notebook refresh, spending-wallet scan, or a
//! wallet-wide stores refresh). Counters, not bools, for the two scan
//! classes that can have more than one kick in flight at once — two
//! overlapping kicks must keep the gate closed until BOTH land.
//!
//! Every increment happens on the UI thread right before a worker spawn
//! (only when the caller actually admitted the job — e.g. `scan_lane_submit`
//! returning `true`); every decrement happens once per drained result,
//! BEFORE that result's own staleness guard runs, so a stale-dropped result
//! still releases its slot and the gate can never wedge open. Decrements
//! saturate at zero rather than panic/underflow — an extra drain (which
//! should never happen given the executor's own bookkeeping, but is cheap
//! to guard) is a no-op, not a bug.

/// The three independent "is a scan in flight" signals that together decide
/// [`ScanGate::busy`]. Mirrors exactly the fields `State` used to hold
/// directly in the app crate — same names, same operations — just pulled
/// out so they're host-testable on their own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanGate {
    notebook: u32,
    spending: u32,
    wallet_stores: bool,
}

impl ScanGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// A notebook refresh (`refresh_async`) was admitted to run.
    pub fn admit_notebook(&mut self) {
        self.notebook += 1;
    }

    /// One notebook-refresh result was drained (whether or not it turned
    /// out stale) — saturates at zero, never underflows.
    pub fn drain_notebook(&mut self) {
        self.notebook = self.notebook.saturating_sub(1);
    }

    /// A spending-wallet scan (`spending_refresh_async`) was admitted to
    /// run.
    pub fn admit_spending(&mut self) {
        self.spending += 1;
    }

    /// One spending-scan result was drained (whether or not it turned out
    /// stale) — saturates at zero, never underflows.
    pub fn drain_spending(&mut self) {
        self.spending = self.spending.saturating_sub(1);
    }

    /// True while a spending-wallet scan is already in flight — the
    /// `spending_refresh_async` early-return's coalescing check.
    pub fn spending_busy(&self) -> bool {
        self.spending > 0
    }

    /// True while a wallet-wide stores refresh is in flight — the
    /// `wallet_stores_refresh_async` early-return's re-entrancy check.
    pub fn wallet_stores_busy(&self) -> bool {
        self.wallet_stores
    }

    /// Set/clear the wallet-stores-refresh flag (admitted → `true`, drained
    /// → `false`; it's a single in-flight slot, unlike the two counters).
    pub fn set_wallet_stores(&mut self, busy: bool) {
        self.wallet_stores = busy;
    }

    /// The gate value pushed to the UI (`wallet-scan-busy`) — true iff ANY
    /// of the three signals is active. Byte-identical formula to the app
    /// crate's `update_scan_gate`: `notebook_scan_busy > 0 ||
    /// spending_scan_busy > 0 || wallet_stores_busy`.
    pub fn busy(&self) -> bool {
        self.notebook > 0 || self.spending > 0 || self.wallet_stores
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Admitting N (a mix of notebook/spending kicks) opens the gate;
    /// draining exactly N closes it again.
    #[test]
    fn admit_n_then_drain_n_returns_to_idle() {
        let mut gate = ScanGate::new();
        assert!(!gate.busy());

        gate.admit_notebook();
        gate.admit_spending();
        gate.admit_notebook();
        assert!(gate.busy(), "three in-flight scans must hold the gate open");

        gate.drain_notebook();
        assert!(gate.busy(), "two still in flight");
        gate.drain_spending();
        assert!(gate.busy(), "one still in flight");
        gate.drain_notebook();
        assert!(!gate.busy(), "every admitted scan was drained — gate must close");
    }

    /// An extra drain when the counter is already at zero (models a
    /// stale-dropped result landing after its slot was already released, or
    /// any other double-drain) must saturate at zero, never underflow or
    /// panic — and must not perturb `busy()`.
    #[test]
    fn extra_drain_at_zero_saturates_and_never_panics() {
        let mut gate = ScanGate::new();
        gate.drain_notebook();
        gate.drain_notebook();
        gate.drain_spending();
        assert!(!gate.busy());

        gate.admit_notebook();
        gate.drain_notebook();
        gate.drain_notebook(); // extra drain past zero
        assert!(!gate.busy(), "an extra drain must not go negative or wedge busy() as true");
    }

    /// `wallet_stores` is a bool flag, not a counter, but it participates in
    /// `busy()` exactly like the two counters: set opens the gate (even
    /// with both counters at zero), clear closes it.
    #[test]
    fn wallet_stores_flag_participates_in_busy() {
        let mut gate = ScanGate::new();
        assert!(!gate.wallet_stores_busy());
        assert!(!gate.busy());

        gate.set_wallet_stores(true);
        assert!(gate.wallet_stores_busy());
        assert!(gate.busy(), "wallet_stores alone must hold the gate open");

        // A concurrent notebook scan on top must not affect the flag or
        // its own release.
        gate.admit_notebook();
        assert!(gate.busy());
        gate.set_wallet_stores(false);
        assert!(gate.busy(), "the notebook scan is still in flight");
        gate.drain_notebook();
        assert!(!gate.busy(), "both signals cleared — gate must close");
    }
}
