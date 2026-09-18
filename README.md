# Bandwidth Reservation Fabric

**Version 1.0.0** — a vendor-neutral C++20 runtime that owns **generation-bound
commitments of future or active fabric bandwidth** against exact resources, paths,
intervals, claimants, policies, and authority.

A reservation is a commitment, not a hint. Once committed, it constrains later
admission and arbitration until it is legitimately amended, released, expired,
recalled under permitted policy, or invalidated by loss of authority.

---

## 1. Systems boundary

Bandwidth Reservation Fabric (BRF) answers exactly one class of question:

> Given authoritative resource capacity, exact path/resource generations,
> existing commitments, a requested bandwidth amount and interval, a policy, and
> claimant authority — can this bandwidth commitment be made, what exact capacity
> is reserved where and when, which reservation is authoritative, and when must it
> be rejected, amended, recalled, released, expired, fenced, revalidated, or
> declared stale?

BRF **does not own** and does not implement:

| Adjacent responsibility | Owner |
| --- | --- |
| Physical capacity discovery | capacity authority (external) |
| Topology truth, link-state truth, path legality, path planning | traffic-engineering / path authority (external) |
| Route lifecycle | routing runtime (external) |
| Global traffic-engineering optimisation | Traffic Engineering Fabric (external) |
| Instantaneous shared-bandwidth arbitration | Bandwidth Broker (external) |
| Packet/queue scheduling, rate enforcement, congestion control | data plane (external) |
| Device programming | device manager (external) |

Capacity, path authority, and policy enter BRF as **declared, generation-stamped
statements**. BRF records them, binds commitments to them, refuses stale ones, and
never invents them. If the authority says nothing, BRF's answer is "unknown" —
never "allowed".

### Reservation vs. instantaneous bandwidth grant

A grant is an answer about *now*: whether a flow may send at a rate at this
instant. A reservation is a durable obligation about an *interval*: it holds
capacity across time, survives restarts, and must close against capacity for every
instant it covers. BRF implements the latter and never arbitrates the
instantaneous use of a link.

### Reservation vs. traffic-engineering allocation

A TE allocation is global intent computed from a network-wide objective. A
reservation is a local, auditable commitment against named resources. BRF does not
optimise; it admits, refuses, and records — deterministically.

---

## 2. Interval semantics

One convention, used everywhere, without exception:

> A reservation covering interval [start, end) occupies every instant t with
> start <= t < end.

* Adjacent intervals never conflict: [0,10) and [10,20) do not overlap.
* Zero-length, inverted, negative, and overflowing windows are rejected as
  INVALID_INTERVAL.
* Intervals are half-open, canonical, and timezone-free: absolute timestamps are
  Unix-epoch nanoseconds in UTC, printed and parsed as
  YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ.
* The fabric timeline ends at 2100-01-01T00:00:00Z and no single reservation may
  span more than 100 years, so interval arithmetic can never overflow int64.
* Wall-clock access is isolated behind brf::IClock. Tests drive a ManualClock; no
  decision depends on local time or on a background thread waking up.

Expiry is therefore a *durable state transition derived from the committed
interval and the clock*, not the effect of a timer that might be forgotten. Every
public operation reconciles elapsed intervals first, and recovery reconciles them
again from durable timestamps.

---

## 3. Identity, generations, and the authority vector

Strong types (ReservationId, ReservationGeneration, ClaimantId,
ClaimantGeneration, ResourceGeneration, PathAuthorityGeneration,
CapacitySnapshotId/Generation, PolicyGeneration, FabricEpoch, ReservationSeriesId,
AttemptId, PublisherId, PublisherBootId, HoldId) make an epoch unusable where a
generation is expected.

Every durable commitment binds an **authority vector**:

* fabric epoch and coordinator boot incarnation;
* reservation generation, claimant identity, and claimant generation;
* the exact (resource, generation) pair for **each** resource in the binding;
* the path authority generation when the binding is path-based;
* the capacity snapshot identity/generation that was in force;
* the policy name and generation.

A persisted record is *existence*; the authority vector is what makes it
*authority*. When any bound generation moves, the reservation is marked
REVALIDATION_REQUIRED — it is never silently re-pointed onto the new generation.
Resource generation changes create a **fresh ledger generation**: obligations of
the old generation stay visible and reported, but they consume no capacity of the
new one.

---

## 4. Capacity accounting

For every resource and every instant the runtime answers with exact integer
arithmetic (fixed-point bits per second, never floating point):

```
committable ceiling = reservable capacity
                    - protected headroom
                    - policy headroom
                    - reservation-requested headroom

closure holds  <=>  peak(committed + holds) over the window <= committable ceiling
```

* Peak queries use a dynamic segment tree with range-add/range-max over the
  timestamp domain: O(log T) per update and per query, independent of population
  size. The authoritative closure decision always uses that exact structure —
  never a bounded scan.
* Overlap enumeration is used only for *explanations*, and is explicitly bounded:
  the report carries the true count and a truncated flag.
* Committed reservations and provisional holds share the same index, so a closure
  check cannot forget one of them.
* Readable answers: committed bandwidth on a resource over a window, remaining
  reservable capacity, the exact conflict set behind a refusal, and a bounded step
  function of how capacity changes as commitments begin and end.
* Degraded state is never silent: if authoritative capacity falls below already
  committed obligations — in practice when a resource is withdrawn while
  commitments against it are still live — the resource enters an **emergency
  overcommit** state, the event is durable, new commitments are refused, and the
  outstanding commitments are preserved for policy-driven resolution.
* Resolution is an explicit API: `resolve_overcommit(resource, kRetain)`
  acknowledges the degraded state durably (commitments preserved, exact closure
  still enforced for new work), while `resolve_overcommit(resource, kRevoke)`
  terminates the weakest obligations first — weakest guarantee class, then
  identity order — until the resource closes.

### Atomic multi-resource commitment

A reservation covering several resources is committed **atomically**: one durable
record carries the whole commitment, and it is applied to every resource or to
none. Resources are handled in canonical order, so multi-resource admission is
deadlock-free by construction. A partially applied multi-resource commitment is
not representable in the durable format, and the invariant audit asserts it.

Amendments and preemption follow the same rule: an amendment that displaces weaker
reservations carries those recall transitions **inside the same durable record** as
the reservation that displaces them.

### Deterministic conflict resolution

Equivalent canonical inputs produce identical outcomes, identical conflict sets
(ordered by identity), and identical explanation text. Victim selection for
preemption is ordered by guarantee class and then by identity; ties are impossible
because identity order is total.

---

## 5. Lifecycle

```
DECLARED -> VALIDATED -> PENDING -> COMMITTED -> ACTIVE
                                      |            |
           AMENDMENT_PENDING <--------+            |
           RECALL_PENDING    <---------------------+
                                                  |
 RELEASED / EXPIRED / REVOKED / FENCED / STALE / SUPERSEDED / REJECTED / RETIRED
```

* **COMMITTED** is a durable commitment whose interval has not opened yet;
  **ACTIVE** is the same commitment while its interval is open. The distinction is
  maintained explicitly, not inferred from a timestamp at read time.
* **Release** is an explicit authoritative action. Repeating an identical release
  is idempotent: capacity is freed exactly once.
* **Expiry** is a time/state transition under policy, reconciled from durable
  timestamps.
* **Recall** is policy-bounded. A GUARANTEED reservation cannot be recalled unless
  its policy or its own contract explicitly permits recall; PROTECTED requires
  policy permission as well. A recall records its reason and provenance, may take
  effect at an acknowledged instant (RECALL_PENDING), and releases capacity exactly
  at that instant **plus the recall grace** (the commitment keeps consuming
  through the grace so traffic can drain) — never silently erasing history.
* **Revocation** is an authority action, distinct from claimant release.
* **Stale / revalidation** are an orthogonal axis: a COMMITTED reservation whose
  bound generations are no longer current is not enforceable, and the runtime says
  so instead of pretending otherwise. The reasons are explicit: a resource
  generation change, a resource withdrawal, a path generation change, a path
  retirement, a maintenance window, a material policy change, or a failure-domain
  generation change.
* **RETIRED** is assigned when a terminal record is archived out of the live
  history into the bounded archival set. The remaining modelled states
  (DECLARED, VALIDATED, PENDING, AMENDMENT_PENDING, FENCED, STALE-as-state,
  REJECTED) are part of the closed state vocabulary and the durable encoding, and
  the runtime expresses those situations through the mechanisms that own them
  instead: a refusal is a durable **attempt outcome** (never a fake reservation
  record), a fenced incarnation is a durable **fence record** plus a
  CLAIMANT_FENCED refusal, provisional holds carry the transient states, and
  unenforceability is the **applicability** axis rather than a lifecycle state.

### Amendment and supersession

Changing amount, interval, resources/path, guarantee class, or policy binding
produces a **new reservation generation**. The old generation remains queryable
history, is marked SUPERSEDED, and can never authorise anything again. Lineage is
recorded as explicit edges and is asserted acyclic by the invariant audit.
Repeating an identical amendment replays its durable outcome instead of committing
twice.

### Recurrence

A recurrence series expands deterministically into ordinary reservations that
share a series identity; member identities are derived from the series identity
and index, so the same request always yields the same member identities. Members
must be disjoint, and the series is admitted atomically: either every member
commits or none does. Amending a member amends the whole series as one durable
record.

### Claimant death

A durable reservation belongs to its **durable claimant identity**, not to a TCP
session: a client process dying does not erase a commitment. What dies with the
process is *transient authority*:

* provisional holds are bound to the exact publisher boot, session, claimant
  generation, and fabric epoch;
* a new claimant generation, a fenced boot, a fenced session, or a coordinator
  restart fences those holds and returns their capacity;
* holds are never durable and are never restored as live after a restart.

### Provisional holds

Holds are a separate, short-lived, explicitly bounded concept: they consume
reservable capacity while live, expire by deadline, are counted separately in
every report, and can be consumed atomically by a commit that converts them into a
durable commitment.

---

## 6. Idempotency and crash recovery

Every authority-bearing request carries an AttemptId. The coordinator stores the
request fingerprint **inside the same durable record as the mutation it
describes**, so "the attempt happened" and "the mutation is durable" can never
disagree after a crash.

* A duplicate identical create returns the same authoritative result (same
  reservation identity and generation) and consumes no additional capacity.
* Reusing an attempt identity with different terms is refused as CONFLICT.
* Duplicate release never frees capacity twice; duplicate expiry/reconciliation is
  harmless.
* A request that asserts an old fabric epoch is refused (STALE_EPOCH); a request
  replayed from a fenced boot is refused (CLAIMANT_FENCED).
* A reservation identity already bound to a commitment cannot be reused for a
  different commitment.
* A dry-run validation never commits and never records an attempt.

### Crash after commit, before the reply

If the coordinator commits durably and the caller never receives the reply, the
caller does not have to guess. reconcile_attempt(attempt) answers from durable
evidence:

* known=false when no durable record exists for the attempt — **UNKNOWN stays
  UNKNOWN**;
* known=true, committed=true plus the reservation identity and generation when the
  commit provably happened.

The multiprocess suite proves this with real processes: a client is hard-killed
after its durable commit and the outcome is reconciled from another process.

### Persistence and restart

```
fabric.brfstore     durable store identity (created once, never regenerated)
fabric.brfsnap      sealed snapshot: header + CRC + payload + seal + CRC
fabric.brfjournal   append-only records: header + CRC + payload, monotonic sequence
```

* Every record and snapshot is checksummed (CRC-32C) and versioned; an unsupported
  version is refused rather than misread.
* A **torn tail** (a partial final record) is detected and truncated back to the
  last complete record.
* **Mid-file corruption, a bad magic, or a non-monotonic sequence is refusal**: the
  store does not start rather than guess.
* A durable mutation is flushed to stable storage *before* it is acknowledged.
* On restart the coordinator advances its epoch, rebuilds its projections from
  durable facts (index and time queues are re-derived, never restored), preserves
  committed reservations, reconciles which are now active or expired from durable
  timestamps, revalidates generation-bound applicability instead of inventing new
  generations, and restores **no** live session, hold, or worker authority.

---

## 7. Build, install, and use

Requirements: CMake >= 3.20, a C++20 compiler, and a thread library. There are no
third-party dependencies.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --output-on-failure
cmake --install build --prefix /path/to/prefix
```

Options: BRF_BUILD_TOOLS, BRF_BUILD_TESTS, BRF_BUILD_BENCHMARKS,
BRF_BUILD_EXAMPLES, BRF_WARNINGS_AS_ERRORS (default ON), BRF_ENABLE_ASAN.

Consuming the installed package:

```cmake
find_package(brf 1.0 REQUIRED)
target_link_libraries(my-runtime PRIVATE brf::brf)
```

examples/consumer/main.cpp is a complete consumer: it ingests policy and capacity,
commits a reservation, queries remaining capacity, amends with lineage, and audits
invariants.

### Tools

| Tool | Purpose |
| --- | --- |
| brf-coordinator --store DIR [--port N] | serves the authoritative core over loopback TCP |
| brf-probe --port N --seed N COMMAND | real client: hello, seed, commit, commit-then-hang, remaining, reconcile, release, hold, fence-session, session-release, stats, pause |
| brf-inspect --store DIR | read-only durable integrity check and bounded state summary |
| brf-bench [population] [resources] | synthetic population benchmark |

### Public API (C++)

```cpp
auto coordinator = brf::ReservationCoordinator::open(config).value();
coordinator->ingest_policy(policy, context);
coordinator->ingest_capacity(snapshot, /*withdrawals=*/{}, context);
coordinator->ingest_paths(path_snapshot, context);

auto committed   = coordinator->create_reservation(context, terms, {}, false, {});
auto amended     = coordinator->amend_reservation(context, id, generation, new_terms, false);
auto released    = coordinator->release_reservation(context, id, generation);
auto recalled    = coordinator->recall_reservation(context, id, generation, effective_at, grace, force);
auto revoked     = coordinator->revoke_reservation(context, id, generation);
auto revalidated = coordinator->revalidate_reservation(context, id, generation, mark_stale);

auto report      = coordinator->explain_conflicts(terms, candidate);
auto capacity    = coordinator->query_remaining(resource, window);
auto timeline    = coordinator->query_timeline(resource, window, max_points);
auto lineage     = coordinator->query_lineage(id, generation);
auto attempts    = coordinator->reconcile_attempt(context, attempt);
auto violations  = coordinator->audit_invariants();
```

audit_invariants() is a brute-force recomputation of every accounting and lineage
invariant against the indexed structures. It is used by the tests, by the
benchmark, and by the example consumer; an empty result is the runtime's own
statement that it is internally consistent.

---

## 8. Validation status

**REAL** — proven on this host:

* Single-process semantics, durability, corruption refusal, torn-tail repair,
  snapshot/rotation, and epoch advancement.
* **Real OS processes and real TCP** (brf-coordinator + brf-probe on loopback):
  coordinator hard-kill and restart from the same store with epoch advancement,
  durable commitments preserved, stale-epoch and fenced-boot replay refused, client
  hard-kill after a durable commit reconciled by attempt identity, dead-publisher
  holds fenced, malformed frames refused without disturbing durable state.
* Deterministic concurrency: last-capacity races, amendment-versus-release,
  expiry-versus-release, capacity-generation changes racing commits, and readers
  racing writers, all with invariant audits afterwards.
* Seeded randomized operation sequences with per-step invariant audits and
  seed-reproducible failure reporting, plus cross-checking of every admission
  decision against an independent brute-force closure computation.
* MSVC 19.44 (/W4 /WX /permissive-) for Debug and Release, and a debug-heap
  integrity suite (`brf_runtime_checks_tests`) that validates heap integrity
  around a full workload under the MSVC debug heap with /RTC1 runtime checks.
* **Sanitizer status, stated precisely:** AddressSanitizer coverage is **not**
  claimed. On this host only the x86 sanitizer runtime is installed, so an x64
  `/fsanitize=address` link fails with a missing
  `clang_rt.asan_dynamic_runtime_thunk-x86_64.lib`. `BRF_ENABLE_ASAN=ON` is
  wired up for hosts where the runtime is present; it was not usable here, and no
  sanitizer result is reported.

**SYNTHETIC** — benchmark numbers describe a synthetic reservation population on
this host. They are never physical-network, switch, NIC, or optical measurements,
and they are not packet- or queue-scheduling results.

**UNSUPPORTED / NOT CLAIMED** — no physical network, switch, NIC, DPU, RDMA,
NVLink, optical, or multi-node validation was performed, and no such claim is made.
This runtime is vendor-neutral by construction; it consumes capacity and path
authority as declared evidence.

---

## 9. Limitations

* The authoritative core serialises admission under one mutex. Concurrency is
  proven correct, but admission throughput scales with one core; the index
  structures themselves are logarithmic.
* Conflict *explanations* are bounded by policy (max_conflict_set,
  max_explanation_bytes). The bound is reported explicitly; a bounded answer is
  never presented as complete.
* The durable store is single-writer by design: one coordinator incarnation per
  store directory. Multiple coordinators on one store are not supported.
* Attempt reconciliation history is bounded (max_attempts). Older attempts are
  evicted from memory; an evicted attempt reconciles as unknown rather than being
  guessed.
* Terminal history is bounded (max_history_records); beyond it the oldest terminal
  records are retired into an archival map and their lineage may become
  unavailable.
* Recurrence series are bounded by policy and must be non-overlapping.
* Automatic revalidation on generation change is off by default and must be
  enabled explicitly by policy; the default is to mark and wait for a decision.
* Overcommit is only possible when a policy explicitly allows it, and it is
  recorded as an emergency state requiring policy resolution — never silently.
* Wall-clock time is required for activation, expiry, and recall effect; the clock
  is injectable and monotonic-guarded per process, but BRF does not attempt to
  synchronise clocks across hosts.

---

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
