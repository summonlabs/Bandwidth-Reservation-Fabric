# Bandwidth Reservation Fabric — Semantics

Applies to BRF 1.0.0. This file states what each concept means in the implemented
runtime and which transitions the code actually performs; it is derived from
`include/brf/reservation.hpp`, `src/reservation.cpp`, `src/coordinator_lifecycle.cpp`,
`src/coordinator_admission.cpp`, `src/coordinator_core.cpp`, `src/coordinator_ops.cpp`,
`src/coordinator_records.cpp` and `src/coordinator_query.cpp`.

## 1. Three different notions, only one of which is an object here

| Notion | In BRF |
| --- | --- |
| Reservation | A durable, generation-stamped commitment of one exact amount over one half-open interval on a canonical set of resource generations. It is the only thing that is admitted, journalled, amended, released, recalled, revoked and queried. |
| Instantaneous bandwidth value | Not an object. Point-in-time values are derived from the committed intervals: `CapacityIndex::committed_at`, `query_remaining` (peak over a window) and `query_timeline` (bounded step function). A "grant" that a data plane could enforce does not exist in this runtime, and nothing in the tree programs a device, queue or token bucket. |
| Traffic-engineering allocation | Outside the boundary. `PathAuthority` records only which resources a path traverses and at which authority generation; BRF does not compute paths and has no allocation object. A path and a reservation meet in exactly one place: `BindingKind::kPath`, which expands the reservation's resource set from the recorded path components. |

## 2. Lifecycle states

`ReservationState` is a durable field of `ReservationRecord`, encoded as a
`uint8` and exposed as `DECLARED`, `VALIDATED`, `PENDING`, `COMMITTED`,
`ACTIVE`, `AMENDMENT_PENDING`, `RECALL_PENDING`, `RELEASED`, `EXPIRED`,
`REVOKED`, `FENCED`, `STALE`, `SUPERSEDED`, `REJECTED` and `RETIRED`.

| State | Meaning | `consumes_capacity` | `is_terminal` | Assigned by the coordinator? |
| --- | --- | --- | --- | --- |
| DECLARED | parsed, identity assigned | no | no | no |
| VALIDATED | structurally valid | no | no | no |
| PENDING | admission in progress | no | no | no (used only as the index entry state of a provisional hold) |
| COMMITTED | durable; interval has not opened | yes | no | yes — create, amend, revalidation |
| ACTIVE | durable; interval currently open | yes | no | yes — create, amend, revalidation, and reconcile on interval opening |
| AMENDMENT_PENDING | successor generation being admitted | no | no | no |
| RECALL_PENDING | recall recorded, effect not yet reached | yes | no | yes — `recall_reservation` with a future effect instant |
| RELEASED | explicit claimant release | no | yes | yes — `release_reservation` |
| EXPIRED | consuming interval elapsed | no | yes | yes — reconcile |
| REVOKED | authority withdrew the commitment | no | yes | yes — immediate recall, recall effect reached, explicit revoke, preemption |
| FENCED | owning session or boot lost authority before commit | no | yes | no |
| STALE | bound generation no longer current and revalidation refused | no | yes | no (the *applicability* value STALE is used; the state is not) |
| SUPERSEDED | a successor generation replaced these terms | no | yes | yes — amendment, revalidation |
| REJECTED | admission refused, history only | no | yes | no (a refused create writes an attempt record, not a reservation record) |
| RETIRED | terminal archival state | no | yes | no (retirement moves the record into the archive map and sets state RETIRED (see `release_terminal_history_locked`); placeholder marker follows: its state) |

Only `COMMITTED`, `ACTIVE` and `RECALL_PENDING` consume capacity, and a
record consumes only while its binding is current (section 3).

### 2.1 Transitions the code performs

| From | To | Trigger |
| --- | --- | --- |
| (new) | COMMITTED or ACTIVE | `create_reservation`: ACTIVE when `start <= now < end`, otherwise COMMITTED |
| (new) | COMMITTED or ACTIVE | `amend_reservation`, explicit revalidation, policy-permitted auto-revalidation (generation *n+1*) |
| COMMITTED | ACTIVE | `reconcile_locked` once `now >= start` and `now < end` |
| COMMITTED, ACTIVE | RELEASED | `release_reservation` by the owning claimant |
| COMMITTED, ACTIVE | RECALL_PENDING | `recall_reservation` with an effect instant in the future |
| COMMITTED, ACTIVE, RECALL_PENDING | REVOKED | `recall_reservation` whose effect is already reached; `revoke_reservation`; a preemption companion mutation |
| RECALL_PENDING | REVOKED | `reconcile_locked` at `recall_effective_at`, or at the interval end if that comes first |
| COMMITTED, ACTIVE, RECALL_PENDING | EXPIRED | `reconcile_locked` when the consuming interval has elapsed |
| any non-terminal | SUPERSEDED | the predecessor of an amendment, a revalidation or an auto-revalidation; companion mutations supersede the other live members of an amended series |
| terminal | (unchanged state, archived) | `release_terminal_history_locked` writes a `kRetire` record and moves the record into the retired map when terminal history exceeds `max_history_records` |

There is no transition out of a terminal state. A terminal record can still be
read, replayed into the archive, and used as lineage evidence.

### 2.2 Where legality is enforced

`Impl::transition_locked` appends the durable record and applies the state; it
does not itself decide whether the transition is legal. Each entry point guards
before calling it:

| Operation | Guard | Refusal |
| --- | --- | --- |
| release | rejects any terminal state except RELEASED (which replays) | `kIllegalTransition` |
| recall | requires `consumes()`; then guarantee-class and policy permission | `kIllegalTransition`, `kPolicyRejected` |
| revoke | requires `consumes()`; REVOKED replays | `kIllegalTransition` |
| revalidate | rejects terminal states; CURRENT replays without a write | `kIllegalTransition` |
| amend | rejects terminal states; claimant must match; claimant generation must not go backwards | `kIllegalTransition`, `kAuthorityRequired`, `kFencedClaimant` |

Repeating an operation that already reached its outcome is an idempotent replay
rather than an error: RELEASED release, REVOKED revoke, RECALL_PENDING recall with
the same effect instant, and any attempt identity with a matching fingerprint.

## 3. The applicability axis

`Applicability` is a durable field of `ReservationRecord` and is orthogonal to
state: a reservation can be COMMITTED and yet not enforceable, because the
generations it was bound to moved.

| Value | Meaning |
| --- | --- |
| CURRENT | every bound resource generation (and the bound path generation, when path-bound) is current in the ledger |
| REVALIDATION_REQUIRED | a bound generation moved, was withdrawn, a maintenance window appeared, or the governing policy changed materially; an operator decision is required |
| STALE | an operator declared the binding unusable (`revalidate_reservation(..., mark_stale = true)`) |

Reasons carried alongside are `CURRENT`, `RESOURCE_GENERATION_CHANGED`,
`RESOURCE_WITHDRAWN`, `PATH_GENERATION_CHANGED`, `PATH_RETIRED`,
`MAINTENANCE_WINDOW_ADDED`, `POLICY_MATERIAL_CHANGE`,
`FAILURE_DOMAIN_GENERATION_CHANGED` and `CAPACITY_REDUCED_BELOW_COMMITMENTS`;
the last two are defined and encodable but no code path produces them.

Applicability is recomputed from the ledger by `refresh_applicability_locked`,
which runs at `open()`, after capacity or path ingestion, and from
`reconcile_lifecycle`. It also runs with automatic revalidation enabled from
those call sites; a re-derivation only happens when the governing policy has
`auto_revalidate_on_generation_change` set (the built-in strict policy leaves it
off). A material policy change marks every non-terminal reservation bound to the
previous policy generation with `POLICY_MATERIAL_CHANGE`.

Consumption follows applicability. A record is placed in the capacity index only
when it consumes, its applicability is not STALE, its consuming interval is
non-empty, and every resource in its authority vector is current in the ledger
(`Impl::indexable_locked`). Consequences:

* A commitment bound to a resource generation that has moved stops consuming
  against the *new* generation immediately, while the record itself is preserved
  and reported as REVALIDATION_REQUIRED. It is never re-pointed silently.
* A STALE record consumes nothing.
* Because admission resolves bindings from the current ledger, no new commitment
  can be created against a moved or withdrawn generation (`kStaleResource`).

## 4. Release, expiry, recall and revocation

| | Release | Expiry | Recall | Revoke |
| --- | --- | --- | --- | --- |
| Actor | owning claimant | time | authority | authority |
| Entry point | `release_reservation` | `reconcile_locked` | `recall_reservation` | `revoke_reservation` |
| Gate | caller must be the record's claimant | consuming interval elapsed | `consumes()` plus guarantee class and policy | `consumes()` |
| Effect instant | now | consuming interval end | requested `effective_at`, or now when zero or `force`, never in the past, clamped to the interval end | now |
| Resulting state | RELEASED | EXPIRED | REVOKED (immediate) or RECALL_PENDING then REVOKED | REVOKED |
| Durable record | `kReservationState` | `kReservationState` | `kReservationState`, later another at the effect | `kReservationState` |
| Statistics | `releases` | `expiries` | `recalls` (and `revocations` when it takes effect) | `revocations` |

Recall permission is decided by guarantee class: SCAVENGER and PREEMPTIBLE are
always recallable; PROTECTED requires `policy.allow_recall_protected` (true in
the built-in policy) or `terms.recall_permitted`; GUARANTEED requires
`policy.allow_recall_guaranteed` (false by default) or `terms.recall_permitted`.
A recall that is refused changes nothing.

The `grace` argument (defaulted from `PolicyRecord::default_recall_grace` when
the caller passes zero) is part of the durable recall transition: it is stored on
the record as `recall_grace`, and `ReservationRecord::consuming_interval()`
truncates the consuming interval at `recall_effective_at + recall_grace` (capped
at the committed interval end). Capacity is therefore released exactly at the end
of the grace, which is what lets traffic drain after a recall is acknowledged.
Equality between the requested effect instant and the recorded one makes a repeated
recall idempotent.

Preemption is a recall performed inside another reservation's commit: victims are
drawn only from strictly weaker guarantee classes, filtered by the same policy
flags, ordered by (class, id, generation), and their REVOKED transitions are
written as companion mutations in the same durable record as the winner, so a
crash cannot leave a victim displaced without a winner or the reverse.

## 5. Amendment and supersession lineage

An amendment keeps the reservation identity and advances its generation by one.
The successor carries `predecessor` and `predecessor_generation`, the runtime
appends a `SupersessionEdge` (predecessor, successor, generations, timestamp,
durable sequence, sanitized reason), and the predecessor becomes SUPERSEDED and
leaves the index. The successor's authority vector is re-resolved against the
current ledger and policy, so an amendment is also the operation that moves a
commitment onto newer generations.

Series amendment supersedes every live member of the series and creates the new
member set in one durable record. Member identities are derived from the series
identity and the member index, so member *n* of the old generation and member *n*
of the new generation are the same reservation identity at successive generations.

`query_lineage` walks `predecessor` links backwards (oldest first) and
supersession edges forwards, bounded to 4096 hops with an explicit `truncated`
flag. Consequences of the model: every superseded generation remains queryable;
releasing a superseded generation is refused with `kIllegalTransition`; and
idempotency of an amendment is evaluated *before* state legality, so a retried
amendment observes its own durable outcome even though its predecessor is now
SUPERSEDED.

## 6. Claimant death semantics

Durable identity survives; transient authority does not.

| Survives | Does not survive |
| --- | --- |
| The reservation record, including claimant identity and generation, interval, amount, authority vector and lineage | Provisional holds (no durable record kind exists for them) |
| The claimant registry: highest registered generation per claimant identity | Session and publisher-boot authority, which is carried only by requests and by holds |
| Fencing records (`kFence`), including claimant-wide fences | An attempt that never reached a durable write; it leaves no trace at all |

`fence(context, claimant, generation, boot, session, claimant_wide)` appends a
durable `kFence` record and then records the fence in memory: a boot fence
(`boot != nil`), a claimant-wide fence (`claimant_wide && claimant != nil`) or
neither. Live holds matching the boot, the session, or a lower claimant generation
are released immediately (counted in `stats().fenced_holds`). Every validated
operation afterwards is refused with `kFencedClaimant` if the request carries a
fenced publisher boot or a fenced claimant identity — for reads as well as writes,
and for all future generations of that identity. There is no unfence operation.

Advancing a claimant generation (`register_claimant` with a higher generation)
updates the durable registry, fences holds of the lower generation, and causes
subsequent requests carrying the lower generation to be refused with
`kFencedClaimant`. Durable reservations of that claimant are untouched: they are
identified by claimant identity and generation, not by the session or boot that
created them. `release_session` releases every live hold of the calling session.

Because fences are durable and replayed at startup, a restarted publisher that
replays an old boot identity is refused before it can exercise any authority.

## 7. Crash-after-commit ambiguity and reconciliation by attempt identity

Every authority-bearing request carries an `AttemptId`, and `validate_context_locked`
refuses one that does not. The attempt record (`codec::AttemptMutation`) is stored
*inside* the same durable record as the mutation it describes, so "the attempt
happened" and "the mutation is durable" can never disagree after a crash. A refused
create or amendment also writes a durable `kAttemptOutcome` record and no
reservation record (its generation field is zero for a refused create and the
target generation for a refused amendment), so a retried refusal replays the same
outcome instead of being re-evaluated against changed capacity.

`reconcile_attempt(attempt)` answers from durable evidence only:

| Field | Meaning |
| --- | --- |
| `known` | a durable attempt record exists |
| `outcome` | the recorded `AdmissionOutcome` |
| `reservation`, `generation`, `sequence` | the reservation the attempt refers to and its durable sequence |
| `committed` | true only when the outcome is an acceptance *and* the referenced reservation generation is present (or archived) |
| `note` | "durable commit confirmed" or "durable outcome recorded without a commit" |

An unknown attempt stays unknown: the coordinator reports `known = false`,
`committed = false` and never promotes "no evidence" to success. Reusing an
attempt identity with a different request fingerprint is refused with
`kConflict`; reusing it with an identical fingerprint replays the recorded result
and consumes no further capacity. A refusal does not reserve the requested
reservation identity, so a later request with a new attempt identity is evaluated
normally.

## 8. Restart semantics

| Preserved | Reset or advanced |
| --- | --- |
| Reservations, generations, supersession edges, series, terminal history and archive | Fabric epoch: advanced by one, with a new boot identity recorded as `kFabricBoot` |
| Ingested capacity, paths and policies, with their generations and prior generations | Coordinator boot identity (`incarnation().boot`); a new one unless the configuration pins it |
| Attempts, fences, claimant generations, overcommit state | Activation, expiry and recall queues and the capacity index, which are rebuilt from records |
| Store identity, durable sequence, snapshot sequence | Provisional holds and released-hold history; in-memory statistics restart at their initial values |

Opening the store also reconciles time: commitments whose interval opened become
ACTIVE, commitments whose consuming interval elapsed become EXPIRED, and recalls
whose effect instant passed become REVOKED, all from durable timestamps. Nothing
is "resumed" in the sense of restoring liveness — there is no thread, timer or
connection to resume. Requests that assert the previous epoch are refused with
`kStaleEpoch`, which is how a stale client is forced to re-read the incarnation
before it can act.

## 9. Recurrence series semantics

A `RecurrenceSpec` (enabled, positive period, member count) is expanded
deterministically into member intervals: member *i* starts at
`first_interval.start + i * period` and has the duration of the first interval.
A member count above the policy bound is refused (`kResourceExhausted`); a period
shorter than the member duration is refused so members cannot overlap; expansion
that would leave the fabric timeline is refused (`kOverflow`).

A series is a *grouping of ordinary reservations*, not a special kind of capacity:

* Members are admitted atomically — if any member does not close, none is
  committed, and the refusal is durable under the attempt identity.
* Member identity is `Identity128::derive(series_id, index)` and the series
  identity is derived from claimant, attempt and an ordinal, so the same request
  reproduces the same identities.
* The first member is the record returned as `CommitResult::record`; the others
  travel in the same durable record and are returned in `members`.
* One `ReservationSeries` record groups the member ids; `series.state` is set to
  COMMITTED at creation and is not updated afterwards.
* Amending one member amends the series: every live member is superseded and the
  new member set is committed in one record, with the series generation advanced
  and `predecessor_series_generation` recorded.

## 10. Provisional holds

A hold is a short-lived, non-durable claim on capacity that lets a caller reserve
its place before committing. `acquire_hold` evaluates the same closure and
authority rules as a commit; the hold then occupies the index as
`HolderKind::kHold` with entry state `PENDING`, so it counts against
`peak_combined` but never against `peak_committed`. The hold identity is derived
from the attempt identity, its generation is 1, and it is bound to the claimant,
claimant generation, session, publisher boot and fabric epoch that created it.

Holds are bounded by policy (`max_hold_ttl`, `max_holds_per_session`,
`max_hold_bandwidth`) and by an explicit deadline that must be in the future.
They end in one of four ways: released explicitly (`release_hold`, by the owning
boot), consumed by a commit (`create_reservation` with `consume_holds`, whose
entries are suspended during evaluation and released on success), released by
session or boot fencing, or expired and released by `reconcile_locked` at the
deadline. A capacity or path ingestion that changes a generation the hold was bound
to releases it outright rather than carrying it forward. Because holds are never
journalled, a restart ends all of them.

## 11. Outcome and error vocabulary

`AdmissionOutcome` is the only value a caller may branch on for an evaluation;
`outcome_to_error_code` maps it onto the closed `ErrorCode` taxonomy for
`Status`-returning surfaces, and `outcome_is_acceptance` identifies the
outcomes that mean "the commitment exists" (`kCommittable` and
`kIdempotentReplay`).

| Outcome | Typical cause |
| --- | --- |
| `kCommittable` | the request closed against current authority |
| `kIdempotentReplay` | the attempt identity already has a durable outcome |
| `kInsufficientCapacity` | combined peak plus the request exceeds the ceiling |
| `kPolicyRejected` | maintenance window, policy bound, or a refused recall |
| `kStaleResource` | unknown, withdrawn or regenerated resource |
| `kStalePathAuthority` | unknown, retired or regenerated path |
| `kEmergencyOvercommit` | the resource is in an unresolved overcommit state and the policy forbids overcommit |
| `kInvalidInterval`, `kInvalidRequest`, `kInvalidBandwidth` | malformed input |
| `kStaleEpoch`, `kGenerationMismatch`, `kClaimantFenced` | aged or foreign authority |
| `kConflict` | identity or generation reuse with different content |
| `kResourceExhausted` | a configured bound was reached |
| `kUnsupported`, `kInternal` | defects and unimplemented paths |
