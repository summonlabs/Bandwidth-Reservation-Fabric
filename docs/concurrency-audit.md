# Concurrency, lock ownership, and shutdown audit

This document records the mandatory deadlock / lock-reentrancy audit of the
authoritative core. It is a design review of ownership and call paths, not a
summary of test results: the tests exist in addition to this audit, not instead
of it.

## Lock inventory

The runtime holds exactly **one** mutable lock in its authoritative path:

| Lock | Owner | Guards |
| --- | --- | --- |
| brf::ReservationCoordinator::Impl::mutex | the coordinator | the entire authoritative state: capacity ledger, path authority table, policy registry, capacity index, reservation records, series records, lineage edges, attempt table, fences, holds, overcommit state, time queues, statistics |

Every public coordinator entry point takes that mutex once, at the outermost
boundary, and releases it on return. There is no second lock, no reader/writer
split, no recursive acquisition, and therefore no lock-ordering question between
two state locks: the global order is trivially consistent because there is only
one state lock.

Other locks that exist and what they protect:

| Lock | Scope | Note |
| --- | --- | --- |
| TcpListener / TcpSocket handles | networking only | never held while taking the coordinator mutex |
| the tool dispatcher's sessions vector | brf-coordinator only | taken to register/close sessions, never nested inside the coordinator mutex |
| std::atomic<bool> stopping | shutdown flag | lock-free; read without the mutex |

## Checklist

**Read-lock followed by write acquisition on the same lock before dropping the
read guard.** Not possible: there is no read/write lock. Every path that reads
authoritative state does so under the same exclusive guard it would need to write.

**Write lock held while calling code that reads or writes the same lock.**
Rejected by construction: the mutex is non-recursive (std::mutex), and every
internal method is suffixed _locked to make the ownership requirement explicit at
the call site. Public methods never call other public methods; they call the
_locked variants, which assume the guard is already held. A public-to-public call
inside the core would self-deadlock immediately and would be caught by the very
first test that exercises it.

**Mutex re-entry through callbacks.** The core invokes no callbacks. There is no
observer, listener, progress hook, or user-supplied function in any authority-
bearing path: callers supply data, and receive values or errors. The clock is the
only injected interface (IClock::now) and it is a pure function of the injected
implementation: ManualClock reads an atomic, SystemClock reads the operating
system clock and a monotonic guard atomic. Neither takes the coordinator mutex, so
a clock implementation cannot deadlock the core.

**Event emission while internal locks are held.** No events are emitted. Durable
records are appended under the guard; the socket write for the response happens
in the transport layer after the core call returns and the guard has been
released.

**Worker shutdown while holding locks workers need.** The core owns no worker
threads. brf-coordinator owns a connection thread per accepted socket; those
threads call into the core and never hold a coordinator lock while doing
socket work. The coordinator's own thread never waits on a connection thread while
holding the sessions lock: it closes sockets, leaves the lock, then joins.

**Joining a thread while holding state required by that thread.** The server joins
connection threads only after closing every session socket and releasing the
sessions mutex, so a thread blocked in a socket read is unblocked by the close and
can reach its join point.

**Cancellation paths with reversed lock ordering.** Cancellation is expressed as
(a) closing a socket, which unblocks the blocked read in the transport layer, and
(b) begin_shutdown(), which sets an atomic flag under the coordinator guard, fences
holds, flushes, and returns. Neither path acquires a second lock while holding the
first, so no ordering exists to reverse.

**Progress callbacks that re-enter mutable state.** None exist.

**Shutdown paths that wait on work while preventing that work from completing.**
begin_shutdown() takes the guard, mutates and flushes, and returns; it never waits
for another thread. The server closes the listener, closes client sockets, and
joins, in that order; a connection thread never blocks on the listener.

**Callbacks invoked beneath internal state locks.** None exist.

**Nested resource acquisition with inconsistent global ordering.** Inside the core
there is one lock, so multi-resource work (a commitment over N resources) cannot
deadlock: resources are ordered canonically for determinism and for the durable
record layout, not for lock acquisition, because no per-resource lock exists. The
index and the ledger are protected by the same single guard.

**Self-deadlock through re-entrancy from the test harness.** Tests call public
methods only; no public method calls another public method.

## Shutdown and cancellation guarantees

* Work that has not crossed its durable completion boundary cannot publish
  success: the core appends the durable record first, and only then updates the
  in-memory projections. An I/O failure therefore leaves memory consistent with
  the durable log and returns an error to the caller.
* begin_shutdown() is idempotent, refuses new authority-bearing work with
  SHUTTING_DOWN, fences every provisional hold, flushes the journal, and never
  waits on a thread it would need to make progress.
* Cancellation is real: a caller that abandons a request has its transient
  authority fenced explicitly (session release or fence), and no later success is
  published on its behalf.

## Index suspension (the only in-memory two-phase window)

Amendment and preemption evaluate closure with the predecessor's index entries
temporarily removed (Impl::Suspension). The window is:

* purely in memory — no durable write happens inside it;
* protected by the same single mutex, so no other decision can observe the
  intermediate state;
* unconditionally unwound on every exit path (RAII), with per-entry restoration so
  a multi-resource holder is always restored completely;
* kept only when the caller commits to the replacement set, immediately before the
  durable record is applied.

A crash during the window therefore observes either the old state or the new state,
never a mixture: the durable record has not been written yet.
