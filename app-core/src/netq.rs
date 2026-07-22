//! Pure scheduling core for the deferred network operation queue — a lane
//! that admits/coalesces/serializes scan-class jobs by a string key. No
//! threads, no I/O, no `slint`/UI types here; this is just the state
//! machine, fully host-testable with `cargo test -p app-core`. The impure
//! executor (worker threads, boxed closures, the `cb: netq …` log lines)
//! lives in the app crate's `src/lib.rs`, driven entirely through
//! [`Lane::admit`]/[`Lane::complete`].
//!
//! Design: `../../PLAN-chain-notes-app.md` "Deferred: network operation
//! queue" — two earlier slices (the scan-freshness gate counters and
//! `spending_refresh_async`'s coalescing early-return) shipped ahead of
//! this general mechanism; this module is the scheduling layer behind
//! them, not a replacement.
//!
//! # Admission rules
//!
//! A [`Lane`] tracks at most one RUNNING job plus a FIFO of QUEUED jobs,
//! each identified by a caller-chosen string key (e.g.
//! `"nbscan/<address>"`):
//!
//! - a job with the SAME key already QUEUED (not running) coalesces —
//!   [`Admit::Coalesced`] — the queued one will run fresh anyway, so a
//!   third/fourth/… kick for the same key while one is already waiting is
//!   simply dropped;
//! - a job with the same key already RUNNING does **not** coalesce — a
//!   kick that arrives mid-scan may carry fresh reality (e.g. a
//!   post-broadcast rescan racing a boot refresh), so exactly one
//!   follow-up is allowed to queue behind it;
//! - otherwise, if nothing is running, the job starts immediately
//!   ([`Admit::Run`]);
//! - otherwise it joins the queue ([`Admit::Queued`]).
//!
//! Deliberately NOT included: cancelling a queued job when a newer kick
//! for a DIFFERENT key arrives, or generation-based invalidation of a
//! running job. Dropping a queued job would leak whatever gate-counter
//! increment its caller made when it was admitted — and the existing
//! per-caller stale-drop guards (address/fp8/network/account snapshots
//! checked when a result lands) already make that staleness an
//! efficiency concern only, never a correctness one.

use std::collections::VecDeque;

/// Runs `run` under `catch_unwind`, returning `true` iff it panicked. Pulled
/// out of the app crate's `spawn_scan_lane_worker` drain loop so the
/// "run one job, swallow a panic, keep going" step is host-testable here —
/// the caller (lib.rs) still does its own logging/locking around this; this
/// function only isolates the unwind-catching mechanics. No behavior change:
/// `spawn_scan_lane_worker` calls this instead of inlining the same
/// `std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).is_err()`
/// expression it used before.
pub fn run_catching(run: impl FnOnce()) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).is_err()
}

/// Opaque job identifier, unique within a [`Lane`] — a monotonically
/// increasing counter, never reused.
pub type JobId = u64;

/// The outcome of [`Lane::admit`] — what the caller must do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admit {
    /// Nothing was running for this key — start it now.
    Run(JobId),
    /// Something is already running (same key or not) — this job was
    /// appended to the FIFO and will run when its turn comes.
    Queued(JobId),
    /// A job with the same key was already sitting in the queue
    /// (not running) — this one was dropped; the queued one will run
    /// fresh anyway.
    Coalesced,
}

/// One scheduling lane: at most one job RUNNING, plus a FIFO of QUEUED
/// jobs behind it.
pub struct Lane {
    next_id: JobId,
    running: Option<(JobId, String)>,
    queued: VecDeque<(JobId, String)>,
}

impl Lane {
    pub fn new() -> Self {
        Lane { next_id: 0, running: None, queued: VecDeque::new() }
    }

    /// Try to admit a job under `key` — see the module doc for the exact
    /// rules.
    pub fn admit(&mut self, key: &str) -> Admit {
        if self.running.is_none() {
            let id = self.next_id;
            self.next_id += 1;
            self.running = Some((id, key.to_string()));
            return Admit::Run(id);
        }
        if self.queued.iter().any(|(_, k)| k == key) {
            return Admit::Coalesced;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.queued.push_back((id, key.to_string()));
        Admit::Queued(id)
    }

    /// Mark job `id` complete. A no-op (returns `None`) if `id` doesn't
    /// match the currently running job — a stale completion from a job
    /// that was already superseded (should never happen given the
    /// executor's own bookkeeping, but cheap to guard). On a real match,
    /// promotes the queue head (if any) to running and returns it — the
    /// executor's cue to run it next.
    pub fn complete(&mut self, id: JobId) -> Option<(JobId, String)> {
        match &self.running {
            Some((running_id, _)) if *running_id == id => {}
            _ => return None,
        }
        self.running = self.queued.pop_front();
        self.running.clone()
    }

    /// Number of jobs waiting behind the running one (0 if nothing is
    /// queued, regardless of whether something is running).
    pub fn depth(&self) -> usize {
        self.queued.len()
    }

    /// True iff nothing is running and nothing is queued.
    pub fn is_idle(&self) -> bool {
        self.running.is_none() && self.queued.is_empty()
    }
}

impl Default for Lane {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three distinct keys with nothing running: the first admits as
    /// `Run`, the rest queue in the order submitted (FIFO) — and
    /// `complete`ing the running one promotes the queue head, not some
    /// other order.
    #[test]
    fn fifo_order_across_distinct_keys() {
        let mut lane = Lane::new();
        let a = lane.admit("a");
        let b = lane.admit("b");
        let c = lane.admit("c");
        assert!(matches!(a, Admit::Run(_)));
        assert!(matches!(b, Admit::Queued(_)));
        assert!(matches!(c, Admit::Queued(_)));
        let Admit::Run(a_id) = a else { unreachable!() };
        let Admit::Queued(b_id) = b else { unreachable!() };
        let Admit::Queued(c_id) = c else { unreachable!() };
        assert_eq!(lane.depth(), 2);

        let promoted = lane.complete(a_id);
        assert_eq!(promoted, Some((b_id, "b".to_string())));
        assert_eq!(lane.depth(), 1);

        let promoted2 = lane.complete(b_id);
        assert_eq!(promoted2, Some((c_id, "c".to_string())));
        assert_eq!(lane.depth(), 0);

        let promoted3 = lane.complete(c_id);
        assert_eq!(promoted3, None);
        assert!(lane.is_idle());
    }

    /// A second kick for the SAME key while one is already queued (not
    /// running) coalesces — the queued one will run fresh anyway.
    #[test]
    fn same_key_queued_coalesces() {
        let mut lane = Lane::new();
        let running = lane.admit("nbscan/addr1");
        assert!(matches!(running, Admit::Run(_)));
        let queued = lane.admit("nbscan/addr1");
        assert!(matches!(queued, Admit::Queued(_)));
        let coalesced = lane.admit("nbscan/addr1");
        assert_eq!(coalesced, Admit::Coalesced);
        assert_eq!(lane.depth(), 1, "the coalesced kick must not add a second queue entry");
    }

    /// Same key RUNNING does NOT coalesce — a kick during a running scan
    /// may carry fresh reality (post-broadcast rescan), so exactly one
    /// follow-up queues. A THIRD kick for that same key, now that one is
    /// queued, DOES coalesce.
    #[test]
    fn same_key_running_does_not_coalesce_but_third_kick_does() {
        let mut lane = Lane::new();
        let first = lane.admit("spscan/fp8/mainnet/0");
        assert!(matches!(first, Admit::Run(_)));

        // Second kick, same key, while the first is running: must queue,
        // not coalesce.
        let second = lane.admit("spscan/fp8/mainnet/0");
        assert!(matches!(second, Admit::Queued(_)), "same key running must not coalesce");
        assert_eq!(lane.depth(), 1);

        // Third kick, same key: the second is now sitting in the queue,
        // so this one coalesces.
        let third = lane.admit("spscan/fp8/mainnet/0");
        assert_eq!(third, Admit::Coalesced, "same key already queued must coalesce");
        assert_eq!(lane.depth(), 1, "the coalesced third kick must not grow the queue");
    }

    /// Completing with an id that isn't the currently running one is a
    /// no-op — the running job (and the queue) are untouched.
    #[test]
    fn complete_with_stale_id_is_a_no_op() {
        let mut lane = Lane::new();
        let Admit::Run(running_id) = lane.admit("a") else { unreachable!() };
        let Admit::Queued(queued_id) = lane.admit("b") else { unreachable!() };
        let stale_id = running_id + 100; // never issued to anything real here
        assert_ne!(stale_id, running_id);
        assert_ne!(stale_id, queued_id);

        let result = lane.complete(stale_id);
        assert_eq!(result, None);
        assert_eq!(lane.depth(), 1, "queue must be untouched by a stale complete");

        // The real running job can still complete normally afterward.
        let promoted = lane.complete(running_id);
        assert_eq!(promoted, Some((queued_id, "b".to_string())));
    }

    /// `complete` promotes EXACTLY the queue head, never a later entry.
    #[test]
    fn complete_promotes_exactly_the_head() {
        let mut lane = Lane::new();
        let Admit::Run(a_id) = lane.admit("a") else { unreachable!() };
        let Admit::Queued(b_id) = lane.admit("b") else { unreachable!() };
        let Admit::Queued(_c_id) = lane.admit("c") else { unreachable!() };

        let promoted = lane.complete(a_id);
        assert_eq!(promoted, Some((b_id, "b".to_string())), "must promote b (the head), not c");
    }

    /// `depth`/`is_idle` transitions across the full admit → complete
    /// lifecycle of a single job.
    #[test]
    fn depth_and_is_idle_transitions() {
        let mut lane = Lane::new();
        assert!(lane.is_idle());
        assert_eq!(lane.depth(), 0);

        let Admit::Run(id) = lane.admit("a") else { unreachable!() };
        assert!(!lane.is_idle(), "a job is running");
        assert_eq!(lane.depth(), 0, "nothing queued yet");

        let Admit::Queued(_) = lane.admit("b") else { unreachable!() };
        assert!(!lane.is_idle());
        assert_eq!(lane.depth(), 1);

        let promoted = lane.complete(id);
        assert!(promoted.is_some());
        assert!(!lane.is_idle(), "the queued job was promoted to running");
        assert_eq!(lane.depth(), 0);

        let promoted2 = lane.complete(promoted.unwrap().0);
        assert_eq!(promoted2, None);
        assert!(lane.is_idle());
    }

    /// Reconstructs the shape of the app crate's `spawn_scan_lane_worker`
    /// drain loop (lib.rs) over a `Lane` + a `HashMap<JobId, Box<dyn
    /// FnOnce()>>` job store, driven purely on the test thread (no real
    /// threads/mutex — this is testing the STEP logic, not the concurrency).
    /// Mirrors the real loop precisely: run the current job via
    /// `run_catching`, then `complete` it and, if that promotes a queued
    /// job, pull its closure and run it next — looping until `complete`
    /// returns `None`.
    fn drain_all(lane: &mut Lane, jobs: &mut std::collections::HashMap<JobId, Box<dyn FnOnce()>>, mut id: JobId) {
        loop {
            let job = jobs.remove(&id).expect("every id driven here must have a stored job");
            run_catching(job);
            let Some((next_id, _next_key)) = lane.complete(id) else { break };
            id = next_id;
        }
    }

    /// Submitting keyA (runs), keyB (queues), keyB again (coalesces to
    /// exactly one queued job), then completing keyA promotes exactly ONE
    /// keyB run — not zero, not two.
    #[test]
    fn drain_promotes_exactly_one_coalesced_follow_up() {
        let mut lane = Lane::new();
        let mut jobs: std::collections::HashMap<JobId, Box<dyn FnOnce()>> = std::collections::HashMap::new();
        let b_runs = std::rc::Rc::new(std::cell::Cell::new(0u32));

        let Admit::Run(a_id) = lane.admit("keyA") else { unreachable!() };
        jobs.insert(a_id, Box::new(|| {}));

        let Admit::Queued(b_id) = lane.admit("keyB") else { unreachable!() };
        {
            let b_runs = b_runs.clone();
            jobs.insert(b_id, Box::new(move || b_runs.set(b_runs.get() + 1)));
        }

        // A second kick for keyB while it's already queued (not running)
        // coalesces — dropped, no second job stored for it.
        let coalesced = lane.admit("keyB");
        assert_eq!(coalesced, Admit::Coalesced);
        assert_eq!(lane.depth(), 1, "the coalesced kick must not grow the queue");

        drain_all(&mut lane, &mut jobs, a_id);

        assert_eq!(b_runs.get(), 1, "keyB's job must have run exactly once");
        assert!(lane.is_idle());
        assert_eq!(lane.depth(), 0);
    }

    /// A panicking job must NOT wedge the lane — `run_catching` swallows the
    /// panic, `complete` still fires, and the queued follow-up still runs.
    /// Property mirrors `spawn_scan_lane_worker`'s `catch_unwind` +
    /// `cb: netq panic` handling: the drain continues past a panic.
    #[test]
    fn panicking_job_does_not_wedge_the_lane() {
        let mut lane = Lane::new();
        let mut jobs: std::collections::HashMap<JobId, Box<dyn FnOnce()>> = std::collections::HashMap::new();
        let follow_up_ran = std::rc::Rc::new(std::cell::Cell::new(false));

        let Admit::Run(a_id) = lane.admit("keyA") else { unreachable!() };
        jobs.insert(a_id, Box::new(|| panic!("simulated scan-job panic")));

        let Admit::Queued(b_id) = lane.admit("keyB") else { unreachable!() };
        {
            let follow_up_ran = follow_up_ran.clone();
            jobs.insert(b_id, Box::new(move || follow_up_ran.set(true)));
        }

        // Drive it exactly like `drain_all`, but assert the panic is caught
        // (not merely swallowed by an uncaught unwind aborting the test).
        let job = jobs.remove(&a_id).unwrap();
        let panicked = run_catching(job);
        assert!(panicked, "run_catching must report the panic");
        let promoted = lane.complete(a_id);
        assert_eq!(promoted, Some((b_id, "keyB".to_string())), "complete must still promote keyB after a panic");

        let job = jobs.remove(&b_id).unwrap();
        assert!(!run_catching(job), "the follow-up job itself must not panic");
        assert!(follow_up_ran.get(), "the queued follow-up must still run after the panic");

        let promoted2 = lane.complete(b_id);
        assert_eq!(promoted2, None);
        assert!(lane.is_idle(), "the lane must end idle, not wedged, after a panic mid-drain");
        assert_eq!(lane.depth(), 0);
    }
}
