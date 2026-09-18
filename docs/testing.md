# Bandwidth Reservation Fabric — Testing

Applies to BRF 1.0.0. This file lists the suites that exist in `tests/`, states what
each one proves, describes the invariant audit, and separates what is really
exercised from what is simulated and from what is not supported at all. It was
written by reading the suites and by running the executables present in `build/`;
the workspace was under active modification while it was written, so the file
inventory below is the one observed at that moment.

## 1. How the tests are built and run

`tests/CMakeLists.txt` declares one executable per suite through `brf_add_test`,
links each against `brf` (plus `Threads` and, on Windows, `ws2_32`), applies
the project warning profile, and registers it with CTest under its target name.
The multiprocess target is declared separately because it needs the built tools:
it compiles `support/process.cpp`, receives `BRF_COORDINATOR_EXECUTABLE` and
`BRF_PROBE_EXECUTABLE` as compile definitions pointing at the `brf-coordinator`
and `brf-probe` targets, and depends on them. No test timeout is configured
anywhere; the comment in that file states the reason: a hanging test is a defect
to diagnose, never something to terminate and call passing.

The harness (`tests/support/test_harness.hpp`, `.cpp`) is minimal and
deterministic. `BRF_TEST(suite, name)` registers a function; `BRF_REQUIRE`
aborts the current test on failure, `BRF_CHECK` records it and continues,
`BRF_CHECK_OK`/`BRF_REQUIRE_OK` do the same for `Status` results, and
`BRF_CHECK_EQ` renders both values. A test counts as failed when it reported at
least one failed check; the process exits 1 if any test failed. `--list` prints
registered tests and `--filter` selects by substring.

Shared fixtures live in `tests/support/fixtures.hpp`: a `TempDir` removed on
destruction, a fixture that opens a coordinator on a `ManualClock` fixed at
2026-01-01T00:00:00Z with a pinned boot identity and a temporary store directory,
canonical claimants and authority seeding helpers, and `Fixture::reopen()`, which
reopens the same durable directory with a new boot identity (and therefore a new
fabric epoch). `tests/support/process.hpp`/`.cpp` adds process control for the
multiprocess suite: spawn with an argument vector, read one line of stdout, hard
kill, and wait for an exit code.

## 2. Suites

| File | Target | Tests | Proves |
| --- | --- | --- | --- |
| `tests/core_tests.cpp` | `brf_core_tests` | 24 | Unit-level contracts of the value types: identity, counters, names, time, intervals, bandwidth, wire reader bounds, CRC, interval index, terms validation, series expansion, state predicates, codecs, authority canonicalisation |
| `tests/store_tests.cpp` | `brf_store_tests` | 8 | The durable layer as a standalone component: record round trip, torn-tail repair, corruption refusal, sequence monotonicity, snapshot and rotation, size bounds, inspector helpers |
| `tests/coordinator_tests.cpp` | `brf_coordinator_tests` | 25 | The authoritative behaviour contract through the public API: admission closure, atomicity, idempotency, lifecycle, revalidation, holds, restart, series, preemption |
| `tests/property_tests.cpp` | `brf_property_tests` | 4 | Seeded randomized sequences: invariants hold after every step, identical seeds give identical state, admission agrees with an independent model, retries never double-commit |
| `tests/adversarial_tests.cpp` | `brf_adversarial_tests` | 11 | Hostile and degenerate input, regeneration conflicts, stale epoch and fenced replay, capacity collapse, policy churn, binding bounds, corrupt store |
| `tests/concurrency_tests.cpp` | `brf_concurrency_tests` | 6 | Real OS threads against one coordinator: exactly-once award of the last capacity, racing lifecycle operations, reader/writer consistency, generation change racing commits, shutdown barrier |
| `tests/multiprocess_tests.cpp` | `brf_multiprocess_tests` | 5 | Real OS processes over real loopback TCP: hard kill and restart, epoch advance, wire-level reconciliation, session fencing, durable survival under load, malformed frames |

## 3. What each suite proves

### 3.1 `core_tests.cpp` (24 tests)

Identity: hex round trip, malformed rejection (empty, short, non-hex, over-long,
uppercase accepted), `derive` determinism and distinctness, nil detection.
Counter overflow refusal at the ceiling. Name validation: empty, whitespace,
path traversal, over-capacity and non-ASCII are refused, separators are allowed.
Time: canonical ISO-8601 nanosecond formatting round trip; parsing refuses offsets,
space separators, month 13, February 30, hour 24, and accepts a real leap day but
not an invalid one. Intervals: inverted, zero-length, negative start, beyond the
maximum timestamp and beyond the maximum span are refused; `overlaps` and
`contains` exhibit exact half-open behaviour at adjacency.
Bandwidth: non-positive, over-ceiling, checked-add overflow, negative difference,
saturating add, textual parsing. Wire: the reader is bounds-checked and refuses
truncated reads; a hostile length prefix is refused before allocation. CRC-32C:
the standard `123456789` check value `0xE3069283`, empty input, and the
incremental builder. Index: range add and peak/at/exceeds semantics, removal
returning the tree to zero, bounded and sorted overlap enumeration, atomic
multi-resource erase, timeline step changes. Domain: terms validation, series
expansion determinism and non-overlap, state predicates (`consumes_capacity`,
`is_terminal`, parse round trip for every state), canonical codec round trip,
decoder refusal of truncated and trailing payloads, versioned record envelope with
kind mismatch and future-version refusal, authority canonicalisation conflict on
one resource bound to two generations, and reason sanitisation.

### 3.2 `store_tests.cpp` (8 tests)

The store is exercised directly, without a coordinator. Five appended records come
back in order with sequences 1..5 and identical payloads. A journal with nine
trailing garbage bytes is reported as a torn tail, truncated back to the last
complete record, and then accepts a new record at the next sequence number. A
byte flipped in the middle of the journal, a duplicated record, and a corrupt
snapshot are all refused with `kCorrupt`. Snapshot plus rotation leaves only the
journal suffix to replay, with the snapshot payload and sequence preserved.
A payload above the configured bound is refused with `kResourceExhausted` while
a bounded store still accepts a small record. `read_journal_file` and
`read_snapshot_file` report defects instead of returning partial data.

### 3.3 `coordinator_tests.cpp` (25 tests)

Admission and accounting: a future reservation commits as COMMITTED at generation
1 with a one-entry authority vector and is readable by id and by claimant;
overcommit is refused with a bounded conflict set while remaining capacity is
unchanged; adjacent windows do not conflict; protected headroom is never
committable; a maintenance window refuses the commit with POLICY_REJECTED and the
maintenance reason; a multi-resource commit that fails on the second resource
leaves the first untouched, and a fitting one consumes both.

Identity and idempotency: an identical retry replays without consuming further
capacity, and reusing an attempt identity with different terms is `kConflict`;
a dry run reports committable without writing and leaves `stats().commits` at
zero; two explain-conflict calls produce identical conflict sets and identical
explanation text.

Lifecycle: release frees capacity exactly once, replays on repetition, and refuses
a wrong generation (`kNotFound`) or a foreign claimant (`kAuthorityRequired`);
expiry is driven by durable time — the record goes COMMITTED to ACTIVE to EXPIRED
across reconciliations, capacity returns, and repeated reconciliation does not
double-count expiries; a guaranteed reservation cannot be recalled under the
default policy while a scavenger can, a scheduled recall becomes RECALL_PENDING and
frees capacity exactly at the effect instant, and reconciliation then moves it to
REVOKED.

Generations and lineage: amendment produces generation 2 with predecessor links,
supersedes generation 1, keeps lineage queryable, refuses to release the
superseded generation, and replays on retry; a resource regeneration marks the
outstanding commitment REVALIDATION_REQUIRED and it stops consuming against the
new generation; revalidation is refused when the successor terms do not close, and
an operator can mark the old binding STALE; when it does close, revalidation
derives generation 2 bound to the new resource generation; withdrawal blocks both
amendment and new commits; a path-bound reservation records the path generation
and is invalidated when the path is retired.

Restart, holds, series, preemption, ordering: restart preserves the durable
commitment, drops the provisional hold, advances the epoch, refuses the old epoch,
and still answers attempt reconciliation; holds never leak capacity and expire on
reconciliation; a series admits all members atomically and commits none when one
member does not fit; a shrunk resource generation raises the emergency path and
preserves the old obligation; a claimant generation advance fences the hold while
the durable reservation survives, and a stale generation is refused; preemption
displaces only weaker classes, revokes the victim and restores the winner's
capacity; two competing requests for the last capacity produce exactly one winner;
amending one series member supersedes all of them and advances the series
generation.

### 3.4 `property_tests.cpp` (4 tests)

`randomized_operation_sequence_preserves_invariants` runs 300 seeded steps
(splitmix64, seed `0x5EED1234`) drawing from create, amend, release, recall, clock
advance plus reconciliation, capacity regeneration and restart, and calls
`audit_invariants()` after every step; the first violation prints the seed and
step index and fails the test.
`identical_seeds_produce_identical_states` runs the same 40-step replay twice
with one seed and compares a canonical state fingerprint (sorted record fields per
resource plus remaining capacity), then checks that a different seed produces a
different fingerprint. `admission_matches_independent_brute_force_closure`
recomputes, from `query_resource` output alone, whether a candidate fits, and
requires the coordinator's outcome to agree for 120 seeded cases.
`retries_never_double_commit` repeats an identical create three times for 40
seeded requests and requires a replay each time with unchanged remaining capacity.

### 3.5 `adversarial_tests.cpp` (11 tests)

Interval hostility (zero, inverted, negative start, over-long span) and bandwidth
hostility (zero, negative, over-ceiling, minimum above amount) are refused with no
commit and a clean audit; a dense overlap population yields a conflict set bounded
by the policy, flagged truncated, with a bounded explanation; reusing a fixed
reservation identity with different terms is refused and leaves the original
commitment and remaining capacity intact; a capacity generation re-declared with
different content is `kConflict`, a backwards generation is stale, and an
identical re-ingestion is an idempotent no-op; a request asserting the previous
epoch and a replay from a fenced boot are both refused, as is a snapshot produced
for another epoch; repeated create/release/recreate returns to full capacity;
a capacity collapse preserves the commitment, marks it non-current and refuses
re-admission; a material policy change requires revalidation under the new policy
generation; a binding wider than `kMaxBindingResources` is refused; and a
coordinator refuses to open a store whose journal was corrupted mid-file.

### 3.6 `concurrency_tests.cpp` (6 tests)

These use real `std::thread` workers against one coordinator. Eight threads race
for the last 60 of 100 Gbit/s: exactly one wins, remaining is 40 Gbit/s and the
audit is clean. Amendment racing release (8 rounds) leaves at least one winner,
a clean audit and remaining capacity in the set {100, 60} Gbit/s. Expiry racing
release (8 rounds) leaves a terminal state, full capacity and a clean audit.
A reader thread polling `query_remaining` while four writers commit never sees an
error or a negative value, and the final remaining is exact. A capacity generation
change racing three commits yields only committable or stale-resource outcomes
with a clean audit. `begin_shutdown()` racing a worker causes later creates to
fail with `kShuttingDown`, releases every hold and leaves the audit clean.

### 3.7 `multiprocess_tests.cpp` (5 tests)

These run real programs: a `brf-coordinator` process started with `--store <dir>
--port 0` on an ephemeral loopback port, and `brf-probe` client processes that
speak the real framed protocol.

* `coordinator_restart_preserves_commitments_and_advances_epoch` seeds a
  resource through the wire, commits 40 of 100 Gbit/s, hard-kills the coordinator,
  restarts it on the same directory, and then requires: a strictly greater epoch
  and a different boot identity; the durable commitment still accounted (60
  Gbit/s remaining, 40 committed); a request asserting the old epoch failing with
  STALE_EPOCH; and attempt reconciliation over the wire reporting the original
  reservation identity as known and committed.
* `client_killed_after_commit_is_reconciled_by_attempt_identity` kills a client
  that has reported its commit durable but has not received the reply, then
  reconciles by attempt identity from another process and confirms the commitment
  exists exactly once.
* `dead_publisher_holds_are_fenced_by_its_incarnation` takes a provisional hold
  in one probe process that then exits without releasing it, confirms the hold is
  counted against remaining capacity, fences that boot and session from another
  process, and requires the held capacity to return immediately and a later
  request replayed from the fenced boot to fail with CLAIMANT_FENCED.
* `durable_state_survives_a_kill_during_live_traffic` commits twice and holds once
  under load, hard-kills the coordinator, and requires both commitments and none of
  the transient hold after restart.
* `malformed_frames_do_not_disturb_durable_state` writes raw garbage, a truncated
  header, and a valid hello frame with a corrupted payload checksum to real
  sockets, then requires the coordinator to still answer a query and the earlier
  commitment to be intact.

## 4. The property/invariant audit

`ReservationCoordinator::audit_invariants()` takes the coordinator mutex and
returns a list of violated invariants — empty means consistent. It is a
brute-force recomputation over in-memory state, not a self-check of cached totals:

1. Exactly one non-terminal generation exists per reservation identity.
2. The index contains exactly the consuming, current, currently-bound generations,
   in both directions (a record that should be indexed but is not, and a record
   that is indexed but should not be, are both violations).
3. For every resource in the ledger, the brute-force peak recomputed from the
   current records plus live holds equals `index.peak_combined` over the whole
   timeline; on mismatch the report includes bounded per-record evidence. The same
   block also checks that indexed commitment does not exceed the resource-level
   committable ceiling unless an unresolved emergency overcommit is recorded.
4. Hold accounting in both directions: a live hold must hold indexed capacity, and
   a released hold must hold none.
5. Lineage is acyclic and strictly decreasing in generation, walked with a bound of
   4096 hops.
6. Every record's durable sequence is at or below the journal head, and every entry
   in the expiry queue references an existing, consuming record whose consuming
   interval end equals the queued deadline.
7. Every attempt that records an acceptance references a reservation generation
   that exists (or has been archived).

Every coordinator, property, adversarial, concurrency and multiprocess test calls
this audit. The header also presents it as the check used by inspection tooling;
`brf-inspect` exists in the tree, but it reports durable integrity and a summary
rather than calling `audit_invariants` (which needs a live coordinator).
Its limits are worth stating: it compares in-memory state against the record set,
not a replay of the journal against memory, so recovery equivalence is covered only
by the restart tests, by the restart steps inside the randomized property test, and
by the multiprocess restart tests; and it says nothing about cross-process or
cross-host consistency, which the design does not claim.

## 5. Determinism

Time is a `ManualClock` that only moves when a test advances it, so activation,
expiry and recall effects are exact rather than timing-dependent. Each fixture uses
its own temporary directory and removes it afterwards. Randomness is splitmix64 with
hard-coded seeds, and every randomized failure prints its seed and step index.
Reports and orderings are canonical, which is what allows tests to compare
explanation strings and state fingerprints byte for byte.

Three inputs are not reproducible, and none of them is used as an admission
expectation: `random_identity()` (OS entropy) names temporary directories and,
when a store directory is new, the store identity is derived from a steady-clock
reading and `std::hash` of the path; thread scheduling in the concurrency suite,
which is why that suite asserts invariant and allowed-outcome sets rather than a
fixed interleaving; and process scheduling plus ephemeral port assignment in the
multiprocess suite, which likewise asserts outcomes and invariants rather than
interleavings.

## 6. REAL, SYNTHETIC, UNSUPPORTED

**REAL.** The concurrency suite runs genuine operating-system threads against a
single coordinator instance, so mutual exclusion and the absence of torn in-memory
state are exercised for real. The multiprocess suite runs genuine operating-system
processes: a real `brf-coordinator` server, real `brf-probe` clients, real TCP
sockets on the loopback interface, real framed messages, raw malformed frames on
raw sockets, and hard kills (no graceful shutdown, no flush, no notification). The
store suites and every coordinator fixture write and read real files, with the
production durability path (`fflush` plus `_commit` on Windows, `fsync`
elsewhere) and real CRC-32C validation; torn-tail and corruption tests operate on
those real files. Each suite is a native executable that returns a process exit
code. The invariant audit is a brute-force recomputation rather than a restatement
of the values it checks.

**SYNTHETIC.** All authority is synthetic: capacities, resources (`r1`, `r2`),
paths, policies, claimants, attempts and intervals are fixture constants or values
derived from fixed seeds. Time is simulated by `ManualClock` inside each process.
No production configuration, no real inventory, no real traffic and no real
network topology are involved; the loopback connections are host-local sockets
between two processes on the same machine, not a network.

**UNSUPPORTED.** There is no validation of any kind against physical network
hardware: no switch, router, NIC, DPU, SmartNIC, FPGA, RDMA/RoCE, InfiniBand or
optical transport, and no device under test. The loopback path proves framing,
checksums, request handling and process-level durability, not transport behaviour
over a real fabric. BRF does not measure, shape, police or enforce bandwidth, so no
test can show that a reservation is honoured on a wire; what is proven is
accounting, admission and protocol bookkeeping. Also absent from this tree:
multi-host, clustered, replication or failover testing (the design is single-writer
and has no consensus path, and the multiprocess cases are one server plus clients
on one host); network impairment testing (loss, reordering, duplication, MTU,
latency, congestion); fuzzing or a corpus; a sanitizer configuration
(`BRF_ENABLE_ASAN` defaults to `OFF` and the build present in `build/` is a
plain Debug build); coverage measurement; soak or long-duration tests; and any CI
configuration. Scale is fixture scale — hundreds of operations in the randomized
test, eight threads in the concurrency suite, a handful of processes in the
multiprocess suite — not the configured bounds such as
`max_live_reservations = 262144`. A synthetic benchmark exists
(`bench/brf_bench.cpp`, target `brf-bench`) but no benchmark result is asserted
by any test.

## 7. Observed run

Running the executables present in `build/tests` (MSVC 14.44, Debug, x64)
produced, at the time of writing:

| Target | Tests executed | Failed | Exit code |
| --- | --- | --- | --- |
| `brf_core_tests` | 24 | 0 | 0 |
| `brf_store_tests` | 8 | 0 | 0 |
| `brf_coordinator_tests` | 25 | 0 | 0 |
| `brf_property_tests` | 4 | 0 | 0 |
| `brf_adversarial_tests` | 11 | 0 | 0 |
| `brf_concurrency_tests` | 6 | 0 | 0 |
| `brf_multiprocess_tests` | 5 | 0 | 0 |

That is 83 tests, 0 failures. The run used prebuilt binaries whose build is not
guaranteed to track later edits, so it should be repeated after any change (and the
durability tests write only inside their own temporary directories). The
multiprocess binary needs the matching `brf-coordinator` and `brf-probe`
executables, which the build places in `build/tools` and passes to it as compile
definitions.
