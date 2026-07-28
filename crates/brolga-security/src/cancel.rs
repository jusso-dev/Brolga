//! Cancellation and deadlines.
//!
//! # Why a token rather than a timeout on each call
//!
//! An operation that is no longer wanted should stop, and it should stop *everywhere* — the parse,
//! the traversal, the connector fetch, and the plugin call that the request fanned out into. A
//! timeout attached to each individual call cannot express that: each one restarts its own clock, so
//! a request with a sixty-second budget can spend sixty seconds per step and run for an hour.
//!
//! A [`CancellationToken`] is passed down instead. Children are derived from parents, cancelling a
//! parent cancels every descendant, and the deadline is inherited so a child cannot outlive the
//! request that created it.
//!
//! # Why it works for both synchronous and asynchronous callers
//!
//! Brolga's storage layer is synchronous; its connectors and plugin host will be asynchronous. A
//! token that only worked in one would force a translation layer at the boundary, which is where
//! cancellation gets dropped.
//!
//! This token is a shared flag plus an optional deadline. Checking it is a cheap atomic load, so a
//! synchronous loop can poll it between records, and an asynchronous task can check it at every
//! await point. No runtime is required, and this crate takes no async dependency to provide it.
//!
//! # Deadlines are absolute, not durations
//!
//! A deadline is an instant. Passing a *duration* down would let each layer start counting again,
//! which is the same bug as per-call timeouts wearing different clothes.

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::time::Instant;

use thiserror::Error;

/// Why an operation stopped early.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Cancelled {
    /// Something asked for it to stop: an operator interrupt, a dropped client, a failing sibling.
    #[error("the operation was cancelled")]
    Requested,
    /// The deadline passed.
    #[error("the operation exceeded its deadline")]
    DeadlineExceeded,
}

/// A shared cancellation signal with an optional deadline.
///
/// Cloning shares the signal; [`CancellationToken::child`] derives a new one that a parent can
/// cancel but which cannot cancel its parent.
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<Inner>,
}

struct Inner {
    cancelled: AtomicBool,
    deadline: Option<Instant>,
    /// Held so a parent's cancellation is visible here. `None` for a root token.
    parent: Option<Arc<Inner>>,
}

impl Inner {
    fn is_cancelled(&self) -> bool {
        if self.cancelled.load(Ordering::Relaxed) {
            return true;
        }
        // Walk upwards: cancelling a parent must cancel every descendant, including ones created
        // after the cancellation.
        self.parent
            .as_ref()
            .is_some_and(|parent| parent.is_cancelled())
    }

    fn effective_deadline(&self) -> Option<Instant> {
        let parent = self
            .parent
            .as_ref()
            .and_then(|parent| parent.effective_deadline());
        match (self.deadline, parent) {
            // The earlier of the two. A child must not outlive its parent, and a child that asked
            // for less must not be given more.
            (Some(own), Some(inherited)) => Some(own.min(inherited)),
            (Some(only), None) | (None, Some(only)) => Some(only),
            (None, None) => None,
        }
    }
}

impl CancellationToken {
    /// A token that is never cancelled and has no deadline.
    ///
    /// For call sites that genuinely have no caller to inherit from — a start-up task, a test.
    /// Reaching for it inside request handling is how cancellation gets lost, so it is named to be
    /// conspicuous in review.
    #[must_use]
    pub fn never_cancelled() -> Self {
        Self {
            inner: Arc::new(Inner {
                cancelled: AtomicBool::new(false),
                deadline: None,
                parent: None,
            }),
        }
    }

    /// A root token with a deadline `budget` from now.
    #[must_use]
    pub fn with_budget(budget: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                cancelled: AtomicBool::new(false),
                deadline: Instant::now().checked_add(budget),
                parent: None,
            }),
        }
    }

    /// A token that is already cancelled, for testing a caller's stop path.
    #[must_use]
    pub fn already_cancelled() -> Self {
        let token = Self::never_cancelled();
        token.cancel();
        token
    }

    /// Derive a child.
    ///
    /// The child inherits the parent's deadline and is cancelled when the parent is. Cancelling the
    /// child does not affect the parent, so one failed branch of a fan-out does not stop the others.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            inner: Arc::new(Inner {
                cancelled: AtomicBool::new(false),
                deadline: None,
                parent: Some(Arc::clone(&self.inner)),
            }),
        }
    }

    /// Derive a child with a tighter budget.
    ///
    /// The effective deadline is the earlier of the child's and the parent's, so a child cannot ask
    /// for more time than the request has left.
    #[must_use]
    pub fn child_with_budget(&self, budget: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                cancelled: AtomicBool::new(false),
                deadline: Instant::now().checked_add(budget),
                parent: Some(Arc::clone(&self.inner)),
            }),
        }
    }

    /// Request cancellation.
    ///
    /// Idempotent, and safe from any thread.
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Relaxed);
    }

    /// Whether the operation should stop.
    ///
    /// A cheap atomic load plus, when a deadline is set, a clock read. Intended to be called in a
    /// loop between records.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.reason().is_some()
    }

    /// Why the operation should stop, if it should.
    #[must_use]
    pub fn reason(&self) -> Option<Cancelled> {
        if self.inner.is_cancelled() {
            return Some(Cancelled::Requested);
        }
        if self
            .inner
            .effective_deadline()
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Some(Cancelled::DeadlineExceeded);
        }
        None
    }

    /// Return an error if the operation should stop.
    ///
    /// The form to call inside a loop: `token.check()?` reads as the intent.
    ///
    /// # Errors
    ///
    /// Returns [`Cancelled`] if cancellation was requested or the deadline has passed.
    pub fn check(&self) -> Result<(), Cancelled> {
        self.reason().map_or(Ok(()), Err)
    }

    /// How long is left, if there is a deadline.
    ///
    /// `Some(Duration::ZERO)` once the deadline has passed, so a caller cannot mistake "expired"
    /// for "no deadline".
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.inner.effective_deadline().map(|deadline| {
            deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO)
        })
    }

    /// Whether a deadline is set, here or inherited.
    #[must_use]
    pub fn has_deadline(&self) -> bool {
        self.inner.effective_deadline().is_some()
    }
}

impl fmt::Debug for CancellationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancellationToken")
            .field("cancelled", &self.inner.is_cancelled())
            .field("has_deadline", &self.has_deadline())
            .finish()
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::never_cancelled()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_token_is_not_cancelled() {
        let token = CancellationToken::never_cancelled();
        assert!(!token.is_cancelled());
        assert!(token.check().is_ok());
        assert!(!token.has_deadline());
        assert_eq!(token.remaining(), None);
    }

    #[test]
    fn cancelling_a_parent_cancels_every_descendant() {
        // The property that makes a token worth passing down at all.
        let root = CancellationToken::never_cancelled();
        let child = root.child();
        let grandchild = child.child();

        root.cancel();

        assert!(root.is_cancelled());
        assert!(child.is_cancelled());
        assert!(grandchild.is_cancelled());
        assert_eq!(grandchild.reason(), Some(Cancelled::Requested));
    }

    #[test]
    fn a_child_created_after_cancellation_is_already_cancelled() {
        // Otherwise a fan-out that is still spawning work would keep spawning it.
        let root = CancellationToken::never_cancelled();
        root.cancel();
        assert!(root.child().is_cancelled());
        assert!(root.child().child().is_cancelled());
    }

    #[test]
    fn cancelling_a_child_does_not_cancel_its_parent_or_siblings() {
        // One failed branch of a fan-out must not stop the others.
        let root = CancellationToken::never_cancelled();
        let first = root.child();
        let second = root.child();

        first.cancel();

        assert!(first.is_cancelled());
        assert!(!second.is_cancelled());
        assert!(!root.is_cancelled());
    }

    #[test]
    fn a_deadline_is_inherited_so_a_child_cannot_outlive_its_request() {
        let root = CancellationToken::with_budget(Duration::from_secs(30));
        let child = root.child();
        let grandchild = child.child();

        assert!(child.has_deadline());
        assert!(grandchild.has_deadline());
        assert!(
            grandchild
                .remaining()
                .is_some_and(|left| left <= Duration::from_secs(30))
        );
    }

    #[test]
    fn a_child_cannot_ask_for_more_time_than_the_request_has_left() {
        // The per-call-timeout bug in a different costume: a request with a small budget must not
        // be extended by a step that wants a large one.
        let root = CancellationToken::with_budget(Duration::from_millis(50));
        let greedy = root.child_with_budget(Duration::from_secs(3600));

        let remaining = greedy.remaining().expect("a deadline is inherited");
        assert!(
            remaining <= Duration::from_millis(50),
            "child extended the request's budget: {remaining:?}",
        );
    }

    #[test]
    fn a_child_may_ask_for_less_time_than_its_parent() {
        let root = CancellationToken::with_budget(Duration::from_secs(3600));
        let modest = root.child_with_budget(Duration::from_millis(50));

        assert!(
            modest
                .remaining()
                .is_some_and(|left| left <= Duration::from_millis(50))
        );
        // And the tighter child does not shorten the parent.
        assert!(
            root.remaining()
                .is_some_and(|left| left > Duration::from_secs(3000))
        );
    }

    #[test]
    fn an_expired_deadline_cancels_with_a_distinguishable_reason() {
        // A caller retries a deadline differently from an explicit cancellation, so the two must
        // not be collapsed.
        let expired = CancellationToken::with_budget(Duration::ZERO);
        assert!(expired.is_cancelled());
        assert_eq!(expired.reason(), Some(Cancelled::DeadlineExceeded));
        assert_eq!(expired.check().unwrap_err(), Cancelled::DeadlineExceeded);

        let stopped = CancellationToken::already_cancelled();
        assert_eq!(stopped.reason(), Some(Cancelled::Requested));
    }

    #[test]
    fn an_expired_deadline_reports_zero_remaining_rather_than_none() {
        // `None` means "no deadline". Reporting it for an expired one would let a caller treat an
        // exhausted budget as an unlimited one.
        let expired = CancellationToken::with_budget(Duration::ZERO);
        assert_eq!(expired.remaining(), Some(Duration::ZERO));
        assert!(expired.has_deadline());
    }

    #[test]
    fn cancelling_is_idempotent() {
        let token = CancellationToken::never_cancelled();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn a_clone_shares_the_signal() {
        let token = CancellationToken::never_cancelled();
        let handle = token.clone();
        handle.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancellation_crosses_threads() {
        // Storage runs on a blocking pool while the request that owns the token does not, so the
        // signal has to be observable from another thread.
        let token = CancellationToken::never_cancelled();
        let worker = token.clone();

        let handle = std::thread::spawn(move || {
            for _ in 0..1_000_000 {
                if worker.is_cancelled() {
                    return true;
                }
                std::hint::spin_loop();
            }
            false
        });

        token.cancel();
        assert!(
            handle.join().unwrap(),
            "the worker must observe cancellation"
        );
    }

    #[test]
    fn a_loop_stops_at_the_next_check_rather_than_running_to_completion() {
        // How a parser or a traversal is meant to use it.
        let token = CancellationToken::never_cancelled();
        let mut processed = 0_u32;

        let outcome = (0..1000).try_for_each(|_| {
            token.check()?;
            processed += 1;
            if processed == 10 {
                token.cancel();
            }
            Ok::<(), Cancelled>(())
        });

        assert_eq!(outcome.unwrap_err(), Cancelled::Requested);
        assert_eq!(processed, 10, "work stopped at the next check");
    }

    #[test]
    fn debug_does_not_expose_internals() {
        let rendered = format!(
            "{:?}",
            CancellationToken::with_budget(Duration::from_secs(5))
        );
        assert!(rendered.contains("cancelled"));
        assert!(rendered.contains("has_deadline"));
    }
}
