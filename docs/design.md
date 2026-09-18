# Bandwidth Reservation Fabric — Design

Applies to BRF 1.0.0 (Summon Software Labs, Apache-2.0). Every statement below was
derived by reading the headers in `include/brf/` and the sources in `src/`; no other
behaviour is claimed.

## 1. Purpose and boundary

The Bandwidth Reservation Fabric (BRF) is an in-process, single-writer reservation
core for bandwidth on named resources. It answers one question authoritatively —
*may this amount of bandwidth be committed on these resources over this half-open
interval, given the authority I hold?* — and, when the answer is yes, makes the
commitment durable before returning.

BRF is an admission and bookkeeping runtime. It does not forward, shape, police or
measure traffic, does not compute paths, does not schedule work, and does not talk
to switching or endpoint hardware. Everything it knows about the outside world
arrives through ingestion calls that carry explicit identities and generations.

| Module | Header / source | Responsibility |
| --- | --- | --- |
| Identity | `identity.hpp`/.cpp | 128-bit identities, typed generation counters, validated fixed-capacity names |
| Time | `time.hpp`/.cpp, `clock.hpp`/.cpp | Timestamps, half-open intervals, injectable clock |
| Bandwidth | `bandwidth.hpp`/.cpp | Integer bits per second and checked arithmetic |
| Authority | `authority.hpp`/.cpp | Resource and failure-domain references, provenance, authority vector, fingerprints |
| Capacity | `capacity.hpp`/.cpp | Capacity ledger, path authority table, maintenance windows |
| Policy | `policy.hpp`/.cpp | Generation-stamped policy records and the strict built-in fallback |
| Index | `index.hpp`/.cpp | Dynamic segment trees per resource plus bounded overlap enumeration |
| Store | `store.hpp`/.cpp | Append-only journal, sealed snapshot, torn-tail repair |
| Wire / codec | `wire.hpp`/.cpp, `codec.hpp`/.cpp | Canonical little-endian encoding of every domain and durable type |
| Coordinator | `coordinator*.cpp`, `coordinator_impl.hpp` | Authoritative core: admission, lifecycle, queries, recovery, audit |
| Outcome and error | `outcome.hpp`/.cpp, `error.hpp`/.cpp | Typed admission outcomes, bounded reports, closed error taxonomy |
| Protocol and transport | `protocol.hpp`, `transport.hpp` and their .cpp files | Framed messages and loopback TCP sockets (library code; see section 12) |

## 2. Strong identities and generations

**Identities.** `Identity128` is 16 opaque bytes with one binary form and two
textual forms: 32 lowercase hex characters and an 8-4-4-4-12 diagnostic spelling
(`format_identity`). Ordering is byte-lexicographic, so every ordered container in
the runtime has one canonical, platform-independent order.
`Identity128::derive(parent, index)` is `fingerprint128(parent_bytes ||
big_endian(index))`: identical inputs produce identical child identities on every
build, which is what makes series membership and hold identity reproducible.
`random_identity()` mixes `std::random_device`, a steady-clock stamp and a
process-local counter, and is used only where an identity must be fresh (for
example the coordinator boot identity).

`ReservationId`, `ClaimantId`, `AttemptId`, `HoldId`, `PublisherId`,
`PublisherBootId`, `SessionId`, `CapacitySnapshotId` and
`ReservationSeriesId` are *aliases* of `Identity128`; the tag structs are
declared but no distinct type is created, so identity kind is enforced by
convention and by codec position, not by the type system. Generations are
different: each is a distinct `Counter<Tag>`, so an epoch cannot be passed where a
reservation generation is expected.

**Counters.** `ReservationGeneration`, `ClaimantGeneration`,
`ResourceGeneration`, `PathAuthorityGeneration`,
`CapacitySnapshotGeneration`, `PolicyGeneration`,
`FailureDomainGeneration`, `SeriesGeneration`, `SeriesIndex`,
`HoldGeneration`, `SessionGeneration`, `FabricEpoch` and
`DurableSequence`. All are unsigned 64-bit, monotonic by convention, and
`next()` refuses to wrap (`kOverflow`). `FabricEpoch` advances on every
coordinator `open()`. `DurableSequence` is assigned by the store on every
appended record and is never reused.

**Regeneration rules.** The capacity ledger, path table and policy registry use the
same three-way rule, which is the core of "no silent upgrade":

| Incoming generation | Content | Result |
| --- | --- | --- |
| equal to current | identical | idempotent no-op (`apply` reports no change) |
| equal to current | different | refused: `kConflict` |
| lower than current | any | refused: `kStaleGeneration` |
| higher than current | any | replaces; the previous generation is appended to `prior_generations` for reporting only |

**Reservation generations.** A first commitment is generation 1. Amendment and
revalidation create generation *n+1* of the *same* reservation identity and record
a `SupersessionEdge`. All generations of one identity are kept in `records`
keyed by `(id, generation)`; `current_generation` maps an identity to its
highest generation. The invariant audit asserts that exactly one generation per
identity is non-terminal. A superseded generation keeps its lineage but can no
longer authorise anything.

## 3. Interval semantics

Time is `int64` nanoseconds since the Unix epoch, UTC, never negative and bounded
by `kMaxTimestampNs` (2100-01-01T00:00:00Z). The runtime uses exactly one
interval convention: a reservation over `[start, end)` occupies every instant *t*
with `start <= t < end`. `overlaps` is `start < other.end && other.start <
end`, so adjacent intervals never conflict; `contains(instant)` excludes `end`.
`validate_interval` is the only admission point for caller-supplied windows and
enforces:

| Rule | Bound |
| --- | --- |
| start | not negative |
| end | strictly greater than start, at most `kMaxTimestampNs` |
| span | at most `kMaxReservationSpanNs` (100 x 366 days) |

The *effective consuming interval* of a record is
`ReservationRecord::consuming_interval()`: the committed interval truncated at
`recall_effective_at` when a recall is scheduled, so a pending recall frees
capacity at the effect instant rather than at the interval end.
`interval_id_hex` is a deterministic textual identity of a canonical window.

## 4. Capacity closure

For each resource in the binding, admission computes (in `assess_locked`):

`committable_ceiling = reservable_capacity - protected_headroom`
`- policy_headroom - terms.headroom_requirement` (floored at zero);
`combined_peak` is the peak over the requested window of committed reservations
plus provisional holds, and `after = combined_peak + terms.amount`.

`after > committable_ceiling` is a shortfall unless `policy.allow_overcommit`
holds and `after <= ceiling + overcommit_allowance`. The closure decision always
uses the exact segment-tree peak query; the bounded overlap enumeration is used
only to *explain* a refusal. All arithmetic is integer, and saturation ceilings
(2^62 in the index, checked adds elsewhere) prevent wrap.

Refusals are evaluated in a fixed order, so a request with several problems always
reports the same one: stale path authority, then stale resource (unknown,
withdrawn or regenerated), then policy (a maintenance window overlapping the
request), then emergency overcommit, then insufficient capacity, then committable.
A resource in an unresolved emergency overcommit state blocks new commitments on
that resource unless the governing policy permits overcommit.

`query_remaining` reports the *resource-level* ceiling
(`reservable_capacity - protected_headroom`) minus the combined peak, so it does
not subtract policy or request headroom; a query can therefore report capacity
that a specific admission would still refuse. The invariant audit applies that
same resource-level ceiling, so the audit is a weaker check than admission.

Maintenance is part of the capacity record and part of its generation: a window
overlapping the request refuses the commit with `kPolicyRejected` and
`ApplicabilityReason::kMaintenanceWindowAdded`.

## 5. Authority vector

Every durable commitment stamps the exact evidence that justified it
(`AuthorityVector`): fabric epoch, reservation generation, claimant identity and
generation, capacity snapshot identity and generation, policy name and generation,
path authority generation (zero when the binding is not path-authorised), the
canonical ordered set of `ResourceRef {resource, generation}` and the canonical
set of `FailureDomainRef {domain, generation}`. `canonicalize_resources` sorts,
de-duplicates identical references, and refuses a resource bound to two different
generations (`kConflict`). `authority_fingerprint_bytes` is the byte-exact
encoding used for idempotency and integrity comparison.

The vector is evidence, not a pointer. When a bound generation moves, the record is
marked (see `docs/semantics.md`) and never silently re-pointed. A binding is
resolved afresh at admission time from the ledger (`resolve_binding_locked`), so a
commit always records the generations that were current at that instant.

## 6. Atomic multi-resource commitment

A commitment covering several resources, or a recurrence series, is written as
**one** durable record: `RecordKind::kReservationCommit` (or
`kReservationAmend`) carrying a `ReservationMutation` that contains the primary
record, the additional series members, the series grouping, any supersession edge,
companion state mutations (preemption victims) and the attempt outcome. Either all
of it is durable or none of it is.

The order of operations in `create_locked` and `amend_locked` is:

1. Validate context (epoch, publisher, attempt identity, fencing state), terms,
   claimant generation, policy bounds, identity reuse and the live-reservation
   bound.
2. Resolve the binding and expand the series intervals.
3. Evaluate every member against a *suspension*: the index entries of the caller's
   own holds, and of any preemption victims, are removed for the duration of the
   evaluation and restored on every exit path unless the caller keeps them
   (`Impl::Suspension`). No durable write happens inside a suspension, so a crash
   can never observe the intermediate state.
4. Plan preemption if the policy allows it and the coordinator kill switch
   (`CoordinatorConfig::enable_preemption`) is on: victims come from strictly
   weaker guarantee classes, in a deterministic order, bounded by
   `max_preemption_victims`, and are re-evaluated until the whole request fits or
   the plan is abandoned.
5. Predict the next durable sequence, append the single record, and verify that the
   store assigned exactly the predicted sequence; a mismatch is `kInternal`.
6. Project the durable fact into memory: state, records map, index entries,
   activation/expiry/recall queues, series registry, attempt registry.

Step 5 can succeed and step 6 can still fail (index or maintenance error), so a
returned error does not prove that nothing was committed. That ambiguity is why
attempt reconciliation exists: the attempt record is stored inside the same durable
record as the mutation it describes.

A `dry_run` stops after step 3 or 4, writes nothing, returns the same report
shape, and leaves `stats().commits` unchanged.

## 7. Deterministic conflict resolution

There is no scheduler, queue or fairness rule. Each decision is atomic with respect
to every other decision because all of them run under one mutex: when two callers
compete for the last unit of capacity, whichever decision runs first under that
mutex wins and the other is refused. Nothing else arbitrates by arrival time.

Every other ordering is a total order over canonical values:

| Structure | Order |
| --- | --- |
| Binding and authority vector | resource name, then generation |
| `CapabilityDelta` report | resource name |
| Conflict set | reservation id, then generation, then resource name |
| Preemption candidates | guarantee class (weakest first), then id, then generation |
| Activation, expiry and recall queues | timestamp, then `(id, generation)` |
| First reported problem | canonical binding order |

Because reports contain only values observed at the decision instant and are
assembled in canonical order, the same request against the same state produces
identical explanation text; the property suite asserts this.

## 8. Single-writer coordinator core

`ReservationCoordinator` owns a private `Impl` (declared in
`src/coordinator_impl.hpp`) holding the ledger, path table, policy registry,
capacity index, record maps, queues, hold registry, overcommit registry, statistics
and the durable `Store`. Every public entry point — ingestion, create/amend,
lifecycle, queries, holds, compaction, shutdown — takes `Impl::mutex` for the
whole operation, including the durable append. There is no finer-grained locking
and no background thread.

Time-driven transitions are therefore **lazy**. They happen when
`reconcile_locked(now)` runs: from `open()`, from create, amend, release,
recall, revoke, revalidate and `reconcile_lifecycle`, from `acquire_hold` and
`release_session`, and from the read entry points (`get_reservation`,
`query_claimant`, `query_resource`, `query_remaining`, `query_timeline`,
`explain_conflicts`). Ingestion, fencing, compaction and statistics calls do not
reconcile. A coordinator that is never called activates and expires nothing — and
no capacity is miscounted in the meantime, because closure reads the interval
structure rather than the state label.

`begin_shutdown()` sets an atomic flag that every validated operation checks
first, releases every hold, and flushes the journal. `open()` requires a store
directory, and two coordinators must not be pointed at the same directory: the
store takes no exclusive operating-system lock, so single-writer is a deployment
invariant rather than an enforced one.

## 9. Interval index

`CapacityIndex` is keyed by resource name. Each resource owns three
`IntervalCapacityIndex` structures — committed, provisional holds, and their
combined sum — plus a `multimap<Timestamp, IndexEntry>` keyed by interval start,
a per-resource entry count, and a global map from `(kind, holder id, resource)`
to that start timestamp. Reservations and holds share the index so a closure check
cannot forget one of them, and one holder produces one entry per resource it
covers.

`IntervalCapacityIndex` is a dynamically allocated segment tree over the domain
`[0, kMaxTimestampNs)` supporting range add (`add`, `remove`) and range maximum
queries (`peak`, `at`, `exceeds`). Nodes are allocated on demand, so memory
tracks touched paths rather than the size of the timeline; updates and queries are
O(log T). Lazy values are propagated to both children during updates, and queries
carry the pending value downward so an interval covered only by an ancestor's
pending range add is still reported; a carve-out for untouched subtrees returns the
accumulated carry rather than zero. Arithmetic saturates at 2^62, and removing the
last live interval resets the tree.

`overlapping` enumerates entries that start before the window end and do not end
before the window start, bounded by a scan limit and an output limit; the true
match count is reported separately and `truncated` is set whenever the answer was
bounded, so a bounded answer can never be mistaken for a complete one.
`timeline` projects the same data into a bounded step function of committed and
held bandwidth at interval boundaries. `replace_all` and `erase_all` move or
remove an identity's whole entry set; `erase_all` also sweeps interval-map
elements of that identity that have no bookkeeping key.

The index is derived state. It is rebuilt at recovery from the record set
(`rebuild_index_locked`), and every mutation is durable before it is indexed.

## 10. Durable journal and snapshot

Storage lives in one directory with three files: `fabric.brfstore` (a stable
store identity, created once), `fabric.brfsnap` (the sealed snapshot) and
`fabric.brfjournal` (the append-only record stream).

**Journal record.** A 22-byte header — magic `BRFJ`, total length, durable
sequence, record kind, CRC-32C of the payload — followed by the payload. The
payload is a versioned envelope: a `u16 kDurableFormatVersion` followed by the
encoded `DurableRecord` union selected by kind. `decode_record` refuses an
unknown version, refuses a payload whose embedded kind disagrees with the container
kind, and refuses trailing bytes.

**Durability contract.** `append` writes header and payload and then flushes both
the stdio buffer and the operating-system cache (`fflush` plus `_commit` on
Windows, `fsync` elsewhere) before returning the sequence; a mutation is never
acknowledged before its record is on stable storage. `sync_on_append = false`
exists for tests that inject torn writes and is never used by production paths.

**Record kinds** (the number is part of the on-disk format): `kFabricBoot`,
`kCapacitySnapshot`, `kPathSnapshot`, `kPolicyRecord`,
`kReservationCommit`, `kReservationAmend`, `kReservationSeries`,
`kReservationState`, `kReservationApplicability`, `kAttemptOutcome`,
`kOvercommit`, `kRetire`, `kFence`, `kClaimantRegistration`.

**Snapshot.** A 32-byte header (magic `BRFS`, format version, reserved, sequence,
payload length, payload CRC-32C, header CRC-32C), then the payload, then an 8-byte
footer (`SEAL` magic plus a CRC-32C over everything preceding that checksum). It is
written to a temporary file, flushed, and atomically replaced (`MoveFileEx` with
`MOVEFILE_WRITE_THROUGH` on Windows, `rename` elsewhere). A snapshot is a pure
function of the record stream that produced it (`SnapshotState`), so
snapshot-then-replay and replay-only recovery converge. After a successful snapshot
the journal is rotated (closed, removed, reopened) and the in-memory record list is
cleared. Rotation is triggered when the journal grows past
`compact_threshold_bytes` (8 MiB by default) on a successful create or amend, by
`reconcile_lifecycle`, or explicitly through `compact()`.

## 11. Recovery semantics

`ReservationCoordinator::open` performs, in order:

1. Open the `Store`: load and validate the snapshot, then read the journal suffix
   whose sequence is greater than the snapshot sequence, checking magic, CRC and
   strictly increasing sequence numbers.
2. Apply the snapshot (`apply_snapshot_locked`), then replay the suffix record by
   record (`apply_replay_locked`). A record that cannot be decoded or applied is
   a refusal: `open` returns `kCorrupt` rather than start on a partially
   understood history.
3. Rebuild the activation, expiry and recall queues and the capacity index from the
   record set, so no derived structure survives a restart in a state that disagrees
   with durable facts.
4. Advance the fabric epoch, append a `kFabricBoot` record with a fresh
   coordinator boot identity, and adopt it as the incarnation.
5. Reconcile elapsed time against durable timestamps.
6. Refresh applicability with policy-permitted automatic revalidation enabled.
7. Release terminal history above `max_history_records` into the retired map.

Consequences: durable facts (commitments, generations, lineage, attempts, fences,
claimant generations, ingested authority, overcommit state) survive the restart; the
epoch advances and every request asserting the previous epoch is refused with
`kStaleEpoch`; provisional holds are not durable and are gone; and time that
passed while the coordinator was down is applied from durable timestamps, so a
commitment whose interval opened or elapsed is reconciled without any liveness
being "restored".

**Torn tail versus corruption.** A partial header or a truncated record body at the
*end* of the journal is reported (`torn_tail_truncated`, `truncated_bytes`) and
repaired by truncating the file to the end of the last complete record. A wrong
magic, a failing CRC, an impossible length or a non-increasing sequence anywhere —
including mid-file — is `kCorrupt` and refuses the open.

## 12. Implemented surface outside the core, and known gaps

Outside the core, the tree contains a framed wire protocol
(`include/brf/protocol.hpp`, `src/protocol.cpp`: message catalogue, 16-byte frame
header with CRC-32C, and payload codecs for every request and response), a
loopback TCP transport (`include/brf/transport.hpp`, `src/transport.cpp`:
`TcpListener::bind_loopback`, `connect_loopback`, blocking send and receive,
frame read and write), and the operator-facing programs built from them:
`brf-coordinator` (the server process that owns the durable core and answers
frames), `brf-probe` (a client that drives it), `brf-inspect` (a read-only
durable-state reader), `brf-bench` (a synthetic population benchmark) and the
in-tree example consumer.

The wire path is exercised by `tests/multiprocess_tests.cpp`, which starts a real
`brf-coordinator` process on an ephemeral loopback port and drives it with real
`brf-probe` processes: hard kills of both sides, epoch advance across restart,
attempt reconciliation over the wire, session fencing, a hold that outlives its
owner, and malformed frames on raw sockets. Coverage is a subset of the message
catalogue (seed, commit, commit-then-hang, remaining, reconcile, hold,
fence-session and hello); the remaining message types are reachable only through
the in-process API. See `docs/testing.md`.

Gaps and asymmetries found while reading, stated so that they are not mistaken for
features:

| Observation | Consequence |
| --- | --- |
| No background timer; time transitions only inside `reconcile_locked` | ACTIVE, EXPIRED and recall effects lag until some call reconciles |
| `recall_grace` is applied through `consuming_interval()` | a recall releases capacity at `effective_at + grace` (capped at the interval end); the grace is durable state on the record |
| `ApplicabilityReason::kFailureDomainGenerationChanged` is produced by `refresh_applicability_locked` | failure-domain movement invalidates applicability exactly like a resource generation change |
| `ApplicabilityReason::kCapacityReducedBelowCommitments` is expressed as the emergency overcommit state plus `REVALIDATION_REQUIRED` | with generation-scoped ledgers the degraded case is a withdrawal with live commitments, which raises the emergency state |
| Overcommit resolution is public: `ReservationCoordinator::resolve_overcommit(context, resource, kRetain or kRevoke)` | kRetain acknowledges the state durably, kRevoke terminates the weakest obligations (weakest guarantee class, then identity order) until the resource closes |
| Some `ReservationState` values are defined, encodable and parseable but never assigned to a record | RETIRED is now assigned on archival retirement; DECLARED/VALIDATED/PENDING/AMENDMENT_PENDING/FENCED/STALE-as-state/REJECTED remain vocabulary only, and the situations they name are expressed as durable attempt outcomes, fence records, hold states and the applicability axis (see `docs/semantics.md`) |
| Holds have no durable record kind | all provisional authority is lost on restart, by design |
| The store takes no exclusive lock on its directory | single-writer is a deployment requirement |
| The multiprocess suite covers a subset of the protocol catalogue | message types outside seed/commit/remaining/reconcile/hold/fence/hello are only exercised in process |
