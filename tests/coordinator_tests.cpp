// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Coordinator integration proofs: admission, closure, atomicity, lifecycle,
// idempotency, generations, holds, and restart.
#include <algorithm>
#include <string>
#include <vector>

#include "brf/brf.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace brf;  // NOLINT(google-build-using-namespace)
using namespace brf::test;

namespace {

constexpr std::int64_t kGbit = 1000000000LL;

[[nodiscard]] ClaimantId claimant_c() {
  return Identity128::from_hex("cccccccccccccccccccccccccccccccc").value();
}

[[nodiscard]] AttemptId attempt_of(std::uint64_t value) {
  return Identity128::derive(Identity128::from_hex("1234567890abcdef1234567890abcdef").value(), value);
}

struct Admission {
  bool committed = false;
  CommitResult result;
  std::string message;
};

[[nodiscard]] Admission create(Fixture& fixture, const codec::RequestContext& context,
                               const ReservationTerms& terms, const ReservationId& requested = {}) {
  Result<CommitResult> outcome =
      fixture.coordinator->create_reservation(context, terms, requested, false, {});
  Admission admission;
  if (!outcome) {
    admission.message = outcome.error().message;
    return admission;
  }
  admission.result = outcome.value();
  admission.committed = outcome.value().report.outcome == AdmissionOutcome::kCommittable;
  admission.message = outcome.value().report.explanation;
  return admission;
}

[[nodiscard]] std::int64_t remaining(Fixture& fixture, const char* resource, Interval window) {
  Result<std::vector<RemainingCapacity>> query =
      fixture.coordinator->query_remaining(name_of(resource), window);
  if (!query || query.value().empty()) return -1;
  return query.value().front().remaining.bps;
}

[[nodiscard]] codec::RequestContext ctx(Fixture& fixture, const ClaimantId& claimant,
                                        std::uint64_t attempt_index,
                                        ClaimantGeneration generation = ClaimantGeneration(1)) {
  return context_of(fixture.epoch(), claimant, generation, attempt_of(attempt_index));
}

}  // namespace

BRF_TEST(coordinator, commit_and_query_future_reservation) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 30 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  BRF_CHECK(admission.result.record.state == ReservationState::kCommitted);
  BRF_CHECK_EQ(admission.result.record.generation.value(), std::uint64_t{1});
  BRF_CHECK_EQ(admission.result.record.authority.resources.size(), std::size_t{1});
  BRF_CHECK_EQ(admission.result.record.authority.resources.front().generation.value(), std::uint64_t{1});
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 70 * kGbit);

  Result<ReservationRecord> fetched =
      fixture.coordinator->get_reservation(admission.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE(fetched.has_value());
  BRF_CHECK(fetched.value().id == admission.result.record.id);

  Result<std::vector<ReservationRecord>> by_claimant =
      fixture.coordinator->query_claimant(claimant_a(), false);
  BRF_REQUIRE(by_claimant.has_value());
  BRF_CHECK_EQ(by_claimant.value().size(), std::size_t{1});

  const CoordinatorStats stats = fixture.coordinator->stats();
  BRF_CHECK_EQ(stats.commits, std::uint64_t{1});
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, closure_refuses_overcommit_and_preserves_capacity) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  BRF_REQUIRE(create(fixture, ctx(fixture, claimant_a(), 1),
                     terms_of(claimant_a(), ClaimantGeneration(1), "r1", 60 * kGbit, window))
                  .committed);
  const Admission second =
      create(fixture, ctx(fixture, claimant_b(), 2),
             terms_of(claimant_b(), ClaimantGeneration(1), "r1", 50 * kGbit, window));
  BRF_CHECK(!second.committed);
  BRF_CHECK(second.result.report.outcome == AdmissionOutcome::kInsufficientCapacity);
  BRF_CHECK_EQ(second.result.report.conflicts.entries.size(), std::size_t{1});
  BRF_CHECK(!second.result.report.conflicts.entries.front().is_hold);
  BRF_CHECK(!second.result.report.explanation.empty());
  BRF_CHECK(second.result.report.explanation.size() <= 4096);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 40 * kGbit);

  // Adjacent intervals never conflict: the half-open convention is exact.
  const Interval adjacent = window_of(kBaseEpochNs + 2 * kHour, kBaseEpochNs + 3 * kHour);
  BRF_CHECK(create(fixture, ctx(fixture, claimant_b(), 3),
                   terms_of(claimant_b(), ClaimantGeneration(1), "r1", 100 * kGbit, adjacent))
                .committed);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, protected_headroom_is_never_committable) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit, 1, 25 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 75 * kGbit);
  BRF_CHECK(create(fixture, ctx(fixture, claimant_a(), 1),
                   terms_of(claimant_a(), ClaimantGeneration(1), "r1", 75 * kGbit, window))
                .committed);
  BRF_CHECK(!create(fixture, ctx(fixture, claimant_b(), 2),
                    terms_of(claimant_b(), ClaimantGeneration(1), "r1", kGbit, window))
                 .committed);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, maintenance_window_refuses_commit) {
  Fixture fixture;
  ResourceCapacity capacity = capacity_of("r1", 100 * kGbit, 1);
  MaintenanceWindow maintenance;
  maintenance.interval = window_of(kBaseEpochNs + 2 * kHour, kBaseEpochNs + 3 * kHour);
  maintenance.reason = "planned works";
  capacity.maintenance.push_back(maintenance);
  codec::RequestContext authority = ctx(fixture, claimant_a(), 99);
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity}, 1, fixture.epoch()), {}, authority));
  const Interval inside = window_of(kBaseEpochNs + 150 * kMinute, kBaseEpochNs + 4 * kHour);
  const Admission admission = create(fixture, ctx(fixture, claimant_a(), 1),
                                     terms_of(claimant_a(), ClaimantGeneration(1), "r1", kGbit, inside));
  BRF_CHECK(!admission.committed);
  BRF_CHECK(admission.result.report.outcome == AdmissionOutcome::kPolicyRejected);
  BRF_CHECK(admission.result.report.applicability_reason == ApplicabilityReason::kMaintenanceWindowAdded);
  const Interval before = window_of(kBaseEpochNs + 30 * kMinute, kBaseEpochNs + kHour);
  BRF_CHECK(create(fixture, ctx(fixture, claimant_a(), 2),
                   terms_of(claimant_a(), ClaimantGeneration(1), "r1", kGbit, before))
                .committed);
}

BRF_TEST(coordinator, multi_resource_commit_is_atomic) {
  Fixture fixture;
  codec::RequestContext authority = ctx(fixture, claimant_a(), 99);
  BRF_REQUIRE_OK(fixture.coordinator->ingest_policy(permissive_policy("fabric-default"), authority));
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 100 * kGbit, 1), capacity_of("r2", 10 * kGbit, 1)}, 1,
                  fixture.epoch()),
      {}, authority));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  ReservationTerms terms = terms_of(claimant_a(), ClaimantGeneration(1), "r1", 30 * kGbit, window);
  terms.resources.push_back(name_of("r2"));
  const Admission admission = create(fixture, ctx(fixture, claimant_a(), 1), terms);
  BRF_CHECK(!admission.committed);
  // r1 must be untouched: the runtime never leaves a partial commitment.
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 100 * kGbit);
  BRF_CHECK_EQ(remaining(fixture, "r2", window), 10 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());

  // A commitment that fits both resources is applied to both.
  ReservationTerms fitting = terms_of(claimant_a(), ClaimantGeneration(1), "r1", 5 * kGbit, window);
  fitting.resources.push_back(name_of("r2"));
  BRF_REQUIRE(create(fixture, ctx(fixture, claimant_a(), 2), fitting).committed);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 95 * kGbit);
  BRF_CHECK_EQ(remaining(fixture, "r2", window), 5 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, duplicate_create_replays_and_conflicting_reuse_is_refused) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const codec::RequestContext context = ctx(fixture, claimant_a(), 1);
  const ReservationTerms terms =
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", 10 * kGbit, window);
  const Admission first = create(fixture, context, terms);
  BRF_REQUIRE(first.committed);
  const Admission replay = create(fixture, context, terms);
  BRF_REQUIRE(replay.committed);
  BRF_CHECK(replay.result.replayed);
  BRF_CHECK(replay.result.record.id == first.result.record.id);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 90 * kGbit);

  ReservationTerms different = terms;
  different.amount = Bandwidth{20 * kGbit};
  Result<CommitResult> conflicting = fixture.coordinator->create_reservation(
      context, different, {}, false, {});
  BRF_CHECK(!conflicting.has_value());
  BRF_CHECK_EQ(conflicting.error().code, ErrorCode::kConflict);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 90 * kGbit);
}

BRF_TEST(coordinator, release_frees_capacity_once) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  Result<LifecycleResult> released = fixture.coordinator->release_reservation(
      ctx(fixture, claimant_a(), 2), admission.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE_OK(released);
  BRF_CHECK(released.value().record.state == ReservationState::kReleased);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 100 * kGbit);

  Result<LifecycleResult> again = fixture.coordinator->release_reservation(
      ctx(fixture, claimant_a(), 3), admission.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE_OK(again);
  BRF_CHECK(again.value().replayed);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 100 * kGbit);

  Result<LifecycleResult> wrong_generation = fixture.coordinator->release_reservation(
      ctx(fixture, claimant_a(), 4), admission.result.record.id, ReservationGeneration(9));
  BRF_CHECK(!wrong_generation.has_value());
  BRF_CHECK_EQ(wrong_generation.error().code, ErrorCode::kNotFound);

  Result<LifecycleResult> other_claimant = fixture.coordinator->release_reservation(
      ctx(fixture, claimant_b(), 5), admission.result.record.id, ReservationGeneration(1));
  BRF_CHECK(!other_claimant.has_value());
  BRF_CHECK_EQ(other_claimant.error().code, ErrorCode::kAuthorityRequired);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, expiry_follows_durable_time_not_a_lost_thread) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  fixture.advance(kHour);
  Result<ReservationRecord> activated =
      fixture.coordinator->get_reservation(admission.result.record.id, ReservationGeneration(0));
  BRF_REQUIRE(activated.has_value());
  BRF_CHECK(activated.value().state == ReservationState::kActive);
  fixture.advance(2 * kHour);
  Result<LifecycleResult> reconciled =
      fixture.coordinator->reconcile_lifecycle(ctx(fixture, claimant_a(), 2));
  BRF_REQUIRE_OK(reconciled);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 100 * kGbit);
  Result<ReservationRecord> expired =
      fixture.coordinator->get_reservation(admission.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE(expired.has_value());
  BRF_CHECK(expired.value().state == ReservationState::kExpired);
  const std::uint64_t expiries = fixture.coordinator->stats().expiries;
  // Repeated reconciliation is harmless: expiry happens exactly once.
  BRF_REQUIRE_OK(fixture.coordinator->reconcile_lifecycle(ctx(fixture, claimant_a(), 3)));
  BRF_CHECK_EQ(fixture.coordinator->stats().expiries, expiries);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, recall_is_policy_bounded) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission guaranteed =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 10 * kGbit, window,
                      "fabric-default", GuaranteeClass::kGuaranteed));
  BRF_REQUIRE(guaranteed.committed);
  Result<LifecycleResult> refused = fixture.coordinator->recall_reservation(
      ctx(fixture, claimant_b(), 2), guaranteed.result.record.id, ReservationGeneration(1), Timestamp{},
      Duration{}, false);
  BRF_CHECK(!refused.has_value());
  BRF_CHECK_EQ(refused.error().code, ErrorCode::kPolicyRejected);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 90 * kGbit);

  const Admission scavenger =
      create(fixture, ctx(fixture, claimant_c(), 3),
             terms_of(claimant_c(), ClaimantGeneration(1), "r1", 10 * kGbit, window, "fabric-default",
                      GuaranteeClass::kScavenger));
  BRF_REQUIRE(scavenger.committed);
  Result<LifecycleResult> pending = fixture.coordinator->recall_reservation(
      ctx(fixture, claimant_b(), 4), scavenger.result.record.id, ReservationGeneration(1),
      Timestamp{kBaseEpochNs + 90 * kMinute}, Duration{5 * kMinute}, false);
  BRF_REQUIRE_OK(pending);
  BRF_CHECK(pending.value().record.state == ReservationState::kRecallPending);
  // Capacity is released exactly at the recall effect instant plus the granted
  // grace: the commitment keeps consuming through the grace so that traffic can
  // drain, and the peak over the whole window is therefore unchanged.
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 80 * kGbit);
  BRF_CHECK_EQ(remaining(fixture, "r1", window_of(kBaseEpochNs + 90 * kMinute, kBaseEpochNs + 2 * kHour)),
               80 * kGbit);
  BRF_CHECK_EQ(remaining(fixture, "r1", window_of(kBaseEpochNs + 92 * kMinute, kBaseEpochNs + 2 * kHour)),
               80 * kGbit);
  BRF_CHECK_EQ(remaining(fixture, "r1", window_of(kBaseEpochNs + 96 * kMinute, kBaseEpochNs + 2 * kHour)),
               90 * kGbit);
  fixture.advance(2 * kHour);
  BRF_REQUIRE_OK(fixture.coordinator->reconcile_lifecycle(ctx(fixture, claimant_b(), 5)));
  Result<ReservationRecord> revoked = fixture.coordinator->get_reservation(
      scavenger.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE(revoked.has_value());
  BRF_CHECK(revoked.value().state == ReservationState::kRevoked);
  // Both intervals have now elapsed: the guaranteed reservation expired at its
  // committed end and the recalled one was revoked, so the resource is free.
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 100 * kGbit);
  Result<ReservationRecord> expired_guaranteed = fixture.coordinator->get_reservation(
      guaranteed.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE(expired_guaranteed.has_value());
  BRF_CHECK(expired_guaranteed.value().state == ReservationState::kExpired);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, amendment_advances_generation_and_keeps_lineage) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 20 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  ReservationTerms amended = admission.result.record.terms;
  amended.amount = Bandwidth{35 * kGbit};
  Result<AmendmentResult> result = fixture.coordinator->amend_reservation(
      ctx(fixture, claimant_a(), 2), admission.result.record.id, ReservationGeneration(1), amended, false);
  BRF_REQUIRE_OK(result);
  BRF_CHECK_EQ(result.value().successor.generation.value(), std::uint64_t{2});
  BRF_CHECK(result.value().successor.predecessor == admission.result.record.id);
  BRF_CHECK_EQ(result.value().successor.predecessor_generation.value(), std::uint64_t{1});
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 65 * kGbit);

  Result<ReservationRecord> predecessor = fixture.coordinator->get_reservation(
      admission.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE(predecessor.has_value());
  BRF_CHECK(predecessor.value().state == ReservationState::kSuperseded);

  Result<LineageView> lineage =
      fixture.coordinator->query_lineage(admission.result.record.id, ReservationGeneration(2));
  BRF_REQUIRE(lineage.has_value());
  BRF_CHECK_EQ(lineage.value().ancestry.size(), std::size_t{1});
  BRF_CHECK_EQ(lineage.value().ancestry.front().predecessor_generation.value(), std::uint64_t{1});

  // The superseded generation cannot authorise anything: releasing it is illegal.
  Result<LifecycleResult> release_old = fixture.coordinator->release_reservation(
      ctx(fixture, claimant_a(), 3), admission.result.record.id, ReservationGeneration(1));
  BRF_CHECK(!release_old.has_value());
  BRF_CHECK_EQ(release_old.error().code, ErrorCode::kIllegalTransition);

  // Repeating the same amendment attempt replays instead of double-committing.
  Result<AmendmentResult> replay = fixture.coordinator->amend_reservation(
      ctx(fixture, claimant_a(), 2), admission.result.record.id, ReservationGeneration(1), amended, false);
  BRF_REQUIRE_OK(replay);
  BRF_CHECK(replay.value().replayed);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 65 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, resource_generation_change_requires_revalidation) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit, 1));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  codec::RequestContext authority = ctx(fixture, claimant_a(), 99);
  // The new generation cannot honour the outstanding commitment.
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 30 * kGbit, 2)}, 2, fixture.epoch()), {}, authority));

  Result<ReservationRecord> record = fixture.coordinator->get_reservation(
      admission.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE(record.has_value());
  BRF_CHECK(record.value().applicability == Applicability::kRevalidationRequired);
  BRF_CHECK(record.value().applicability_reason == ApplicabilityReason::kResourceGenerationChanged);
  // The new generation is a different resource instance: it is not silently
  // consumed by the old commitment.
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 30 * kGbit);

  // Revalidation refuses to move the binding when the successor terms do not
  // close against the new generation.
  Result<LifecycleResult> refused = fixture.coordinator->revalidate_reservation(
      ctx(fixture, claimant_a(), 2), admission.result.record.id, ReservationGeneration(1), false);
  BRF_CHECK(!refused.has_value());
  BRF_CHECK_EQ(refused.error().code, ErrorCode::kStaleGeneration);

  // An explicit operator decision can declare the old binding stale.
  Result<LifecycleResult> marked = fixture.coordinator->revalidate_reservation(
      ctx(fixture, claimant_a(), 3), admission.result.record.id, ReservationGeneration(1), true);
  BRF_REQUIRE_OK(marked);
  BRF_CHECK(marked.value().record.applicability == Applicability::kStale);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, explicit_revalidation_derives_a_new_generation) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit, 1));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  codec::RequestContext authority = ctx(fixture, claimant_a(), 99);
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 80 * kGbit, 2)}, 2, fixture.epoch()), {}, authority));
  Result<LifecycleResult> revalidated = fixture.coordinator->revalidate_reservation(
      ctx(fixture, claimant_a(), 2), admission.result.record.id, ReservationGeneration(1), false);
  BRF_REQUIRE_OK(revalidated);
  BRF_CHECK_EQ(revalidated.value().record.generation.value(), std::uint64_t{2});
  BRF_CHECK(revalidated.value().record.applicability == Applicability::kCurrent);
  BRF_CHECK_EQ(revalidated.value().record.authority.resources.front().generation.value(), std::uint64_t{2});
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 40 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, resource_withdrawal_blocks_amendment_and_new_commits) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit, 1));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  codec::RequestContext authority = ctx(fixture, claimant_a(), 99);
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r2", 100 * kGbit, 1)}, 2, fixture.epoch()), {name_of("r1")}, authority));
  const Admission after = create(fixture, ctx(fixture, claimant_b(), 2),
                                 terms_of(claimant_b(), ClaimantGeneration(1), "r1", kGbit, window));
  BRF_CHECK(!after.committed);
  Result<ReservationRecord> record = fixture.coordinator->get_reservation(
      admission.result.record.id, ReservationGeneration(0));
  BRF_REQUIRE(record.has_value());
  BRF_CHECK(record.value().applicability_reason == ApplicabilityReason::kResourceWithdrawn);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, holds_are_transient_and_never_leak_capacity) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const codec::RequestContext holder = ctx(fixture, claimant_a(), 1);
  Result<codec::HoldRecord> hold = fixture.coordinator->acquire_hold(
      holder, terms_of(claimant_a(), ClaimantGeneration(1), "r1", 30 * kGbit, window),
      Timestamp{kBaseEpochNs + kSecond});
  BRF_REQUIRE_OK(hold);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 70 * kGbit);

  const Admission blocked =
      create(fixture, ctx(fixture, claimant_b(), 2),
             terms_of(claimant_b(), ClaimantGeneration(1), "r1", 80 * kGbit, window));
  BRF_CHECK(!blocked.committed);

  fixture.advance(2 * kSecond);
  BRF_REQUIRE_OK(fixture.coordinator->reconcile_lifecycle(ctx(fixture, claimant_a(), 3)));
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 100 * kGbit);
  BRF_CHECK(hold.value().id.is_nil() == false);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, restart_preserves_commitments_and_fences_transient_authority) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  const FabricEpoch before = fixture.epoch();
  Result<codec::HoldRecord> hold = fixture.coordinator->acquire_hold(
      ctx(fixture, claimant_a(), 2),
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", 10 * kGbit, window),
      Timestamp{kBaseEpochNs + 5 * kSecond});
  BRF_REQUIRE_OK(hold);

  fixture.reopen();
  BRF_CHECK(fixture.epoch() > before);

  // Durable commitment survives; transient hold authority does not.
  Result<ReservationRecord> record = fixture.coordinator->get_reservation(
      admission.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE(record.has_value());
  BRF_CHECK(record.value().state == ReservationState::kCommitted);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 60 * kGbit);
  BRF_CHECK(fixture.coordinator->holds().empty());

  // The previous epoch is refused outright.
  codec::RequestContext stale = ctx(fixture, claimant_a(), 3);
  stale.asserted_epoch = before;
  Result<CommitResult> refused = fixture.coordinator->create_reservation(
      stale, terms_of(claimant_a(), ClaimantGeneration(1), "r1", kGbit, window), {}, false, {});
  BRF_CHECK(!refused.has_value());
  BRF_CHECK_EQ(refused.error().code, ErrorCode::kStaleEpoch);

  // Reconciliation of a durable attempt survives restart.
  Result<AttemptReconciliation> reconciliation =
      fixture.coordinator->reconcile_attempt(ctx(fixture, claimant_a(), 4), attempt_of(1));
  BRF_REQUIRE_OK(reconciliation);
  BRF_CHECK(reconciliation.value().known);
  BRF_CHECK(reconciliation.value().committed);
  BRF_CHECK(reconciliation.value().reservation == admission.result.record.id);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, ambiguous_attempt_is_resolved_by_identity) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 7),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 10 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  // The caller never saw the reply; reconciliation by stable attempt identity
  // answers with the durable fact.
  Result<AttemptReconciliation> reconciliation =
      fixture.coordinator->reconcile_attempt(ctx(fixture, claimant_a(), 8), attempt_of(7));
  BRF_REQUIRE_OK(reconciliation);
  BRF_CHECK(reconciliation.value().known);
  BRF_CHECK(reconciliation.value().committed);
  BRF_CHECK(reconciliation.value().reservation == admission.result.record.id);
  BRF_CHECK_EQ(reconciliation.value().generation.value(), std::uint64_t{1});

  // An unknown attempt stays UNKNOWN: no evidence is never promoted to success.
  Result<AttemptReconciliation> unknown =
      fixture.coordinator->reconcile_attempt(ctx(fixture, claimant_a(), 9), attempt_of(12345));
  BRF_REQUIRE_OK(unknown);
  BRF_CHECK(!unknown.value().known);
  BRF_CHECK(!unknown.value().committed);
}

BRF_TEST(coordinator, series_members_are_admitted_atomically) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  ReservationTerms terms =
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit,
               window_of(kBaseEpochNs + kHour, kBaseEpochNs + 90 * kMinute));
  terms.recurrence.enabled = true;
  terms.recurrence.period = Duration{kHour};
  terms.recurrence.count = 3;
  const Admission admission = create(fixture, ctx(fixture, claimant_a(), 1), terms);
  BRF_REQUIRE(admission.committed);
  BRF_CHECK(admission.result.has_series);
  BRF_CHECK_EQ(admission.result.members.size(), std::size_t{3});
  BRF_CHECK_EQ(admission.result.series.members.size(), std::size_t{3});
  BRF_CHECK_EQ(remaining(fixture, "r1", window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour)),
               60 * kGbit);
  BRF_CHECK_EQ(remaining(fixture, "r1", window_of(kBaseEpochNs + 2 * kHour, kBaseEpochNs + 3 * kHour)),
               60 * kGbit);

  // A series that cannot fit all members commits none of them.
  ReservationTerms oversized =
      terms_of(claimant_b(), ClaimantGeneration(1), "r1", 70 * kGbit,
               window_of(kBaseEpochNs + 10 * kHour, kBaseEpochNs + 10 * kHour + 30 * kMinute));
  oversized.recurrence.enabled = true;
  oversized.recurrence.period = Duration{kHour};
  oversized.recurrence.count = 3;
  BRF_CHECK(create(fixture, ctx(fixture, claimant_b(), 2), oversized).committed);
  BRF_CHECK_EQ(remaining(fixture, "r1", window_of(kBaseEpochNs + 10 * kHour, kBaseEpochNs + 11 * kHour)),
               30 * kGbit);

  ReservationTerms conflicting =
      terms_of(claimant_c(), ClaimantGeneration(1), "r1", 40 * kGbit,
               window_of(kBaseEpochNs + 10 * kHour, kBaseEpochNs + 10 * kHour + 30 * kMinute));
  conflicting.recurrence.enabled = true;
  conflicting.recurrence.period = Duration{kHour};
  conflicting.recurrence.count = 3;
  const Admission rejected = create(fixture, ctx(fixture, claimant_c(), 3), conflicting);
  BRF_CHECK(!rejected.committed);
  // The rejected series committed no member at all: only the second series
  // occupies the overlapping windows, and the third claimant owns nothing.
  BRF_CHECK_EQ(
      remaining(fixture, "r1", window_of(kBaseEpochNs + 10 * kHour, kBaseEpochNs + 10 * kHour + 30 * kMinute)),
      30 * kGbit);
  BRF_CHECK_EQ(
      remaining(fixture, "r1", window_of(kBaseEpochNs + 12 * kHour, kBaseEpochNs + 12 * kHour + 30 * kMinute)),
      30 * kGbit);
  Result<std::vector<ReservationRecord>> third = fixture.coordinator->query_claimant(claimant_c(), false);
  BRF_REQUIRE_OK(third);
  BRF_CHECK(third.value().empty());
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, capacity_reduction_below_commitments_raises_emergency) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit, 1));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 90 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  // The authority declares a smaller resource generation while the commitment
  // is outstanding. The commitment is preserved, not discarded.
  codec::RequestContext authority = ctx(fixture, claimant_a(), 99);
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 10 * kGbit, 2)}, 2, fixture.epoch()), {}, authority));
  Result<OvercommitReport> report = fixture.coordinator->overcommit_report();
  BRF_REQUIRE_OK(report);
  // Old-generation obligations are reported as revalidation-required rather
  // than silently counted against the new generation.
  Result<ReservationRecord> record = fixture.coordinator->get_reservation(
      admission.result.record.id, ReservationGeneration(0));
  BRF_REQUIRE(record.has_value());
  BRF_CHECK(record.value().applicability == Applicability::kRevalidationRequired);
  BRF_CHECK(fixture.coordinator->stats().generation_advances >= 1);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, path_binding_uses_path_authority_generation) {
  Fixture fixture;
  codec::RequestContext authority = ctx(fixture, claimant_a(), 99);
  BRF_REQUIRE_OK(fixture.coordinator->ingest_policy(permissive_policy("fabric-default"), authority));
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 100 * kGbit, 1), capacity_of("r2", 100 * kGbit, 1)}, 1,
                  fixture.epoch()),
      {}, authority));
  PathAuthoritySnapshot paths;
  paths.id = Identity128::from_hex("00ff00ff00ff00ff00ff00ff00ff00ff").value();
  paths.generation = CapacitySnapshotGeneration(1);
  paths.fabric_epoch = fixture.epoch();
  PathAuthority path;
  path.path = path_of("path-a");
  path.generation = PathAuthorityGeneration(1);
  path.components = {name_of("r1"), name_of("r2")};
  paths.paths.push_back(path);
  BRF_REQUIRE_OK(fixture.coordinator->ingest_paths(paths, authority));

  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  ReservationTerms terms;
  terms.claimant = claimant_a();
  terms.claimant_generation = ClaimantGeneration(1);
  terms.binding_kind = BindingKind::kPath;
  terms.path = path_of("path-a");
  terms.interval = window;
  terms.amount = Bandwidth{10 * kGbit};
  terms.policy = policy_of("fabric-default");
  const Admission admission = create(fixture, ctx(fixture, claimant_a(), 1), terms);
  BRF_REQUIRE(admission.committed);
  BRF_CHECK_EQ(admission.result.record.authority.resources.size(), std::size_t{2});
  BRF_CHECK_EQ(admission.result.record.authority.path_generation.value(), std::uint64_t{1});
  BRF_CHECK_EQ(remaining(fixture, "r2", window), 90 * kGbit);

  // Retiring the path invalidates the binding; it is never re-pointed.
  PathAuthority retired = path;
  retired.generation = PathAuthorityGeneration(2);
  retired.retired = true;
  paths.generation = CapacitySnapshotGeneration(2);
  paths.paths = {retired};
  BRF_REQUIRE_OK(fixture.coordinator->ingest_paths(paths, authority));
  Result<ReservationRecord> record = fixture.coordinator->get_reservation(
      admission.result.record.id, ReservationGeneration(0));
  BRF_REQUIRE(record.has_value());
  BRF_CHECK(record.value().applicability != Applicability::kCurrent);
  const Admission after = create(fixture, ctx(fixture, claimant_b(), 2), terms);
  BRF_CHECK(!after.committed);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, claimant_generation_advance_fences_transient_authority) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  BRF_REQUIRE_OK(fixture.coordinator->acquire_hold(
      ctx(fixture, claimant_a(), 2),
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", 10 * kGbit, window),
      Timestamp{kBaseEpochNs + 5 * kSecond}));

  // The claimant restarts with generation 2: the durable reservation survives,
  // the provisional hold does not.
  BRF_REQUIRE_OK(fixture.coordinator->register_claimant(claimant_a(), ClaimantGeneration(2),
                                                        ctx(fixture, claimant_a(), 3,
                                                            ClaimantGeneration(2))));
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 60 * kGbit);
  // A stale claimant generation is refused.
  Result<CommitResult> stale = fixture.coordinator->create_reservation(
      ctx(fixture, claimant_a(), 4, ClaimantGeneration(1)),
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", kGbit, window), {}, false, {});
  BRF_CHECK(!stale.has_value());
  BRF_CHECK_EQ(stale.error().code, ErrorCode::kFencedClaimant);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, dry_run_never_commits) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  Result<CommitResult> preview = fixture.coordinator->create_reservation(
      ctx(fixture, claimant_a(), 1),
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", 10 * kGbit, window), {}, true, {});
  BRF_REQUIRE_OK(preview);
  BRF_CHECK(preview.value().report.outcome == AdmissionOutcome::kCommittable);
  BRF_CHECK(preview.value().record.id.is_nil());
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 100 * kGbit);
  BRF_CHECK_EQ(fixture.coordinator->stats().commits, std::uint64_t{0});

  Result<CommitResult> rejected = fixture.coordinator->create_reservation(
      ctx(fixture, claimant_a(), 2),
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", 200 * kGbit, window), {}, true, {});
  BRF_REQUIRE_OK(rejected);
  BRF_CHECK(rejected.value().report.outcome == AdmissionOutcome::kInsufficientCapacity);
}

BRF_TEST(coordinator, conflict_explanations_are_bounded_and_deterministic) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  for (std::uint64_t i = 0; i < 8; ++i) {
    const ClaimantId claimant = Identity128::derive(claimant_a(), i);
    BRF_REQUIRE(create(fixture, context_of(fixture.epoch(), claimant, ClaimantGeneration(1),
                                           attempt_of(100 + i)),
                       terms_of(claimant, ClaimantGeneration(1), "r1", 10 * kGbit, window))
                    .committed);
  }
  const ReservationTerms request =
      terms_of(claimant_b(), ClaimantGeneration(1), "r1", 50 * kGbit, window);
  Result<AdmissionReport> first = fixture.coordinator->explain_conflicts(request, {});
  BRF_REQUIRE_OK(first);
  Result<AdmissionReport> second = fixture.coordinator->explain_conflicts(request, {});
  BRF_REQUIRE_OK(second);
  BRF_CHECK(first.value().outcome == AdmissionOutcome::kInsufficientCapacity);
  BRF_CHECK_EQ(first.value().conflicts.entries.size(), second.value().conflicts.entries.size());
  BRF_CHECK(first.value().explanation == second.value().explanation);
  for (std::size_t i = 1; i < first.value().conflicts.entries.size(); ++i) {
    const ConflictEntry& previous = first.value().conflicts.entries[i - 1];
    const ConflictEntry& current = first.value().conflicts.entries[i];
    BRF_CHECK(!(current.id < previous.id));
  }
}

BRF_TEST(coordinator, preemption_displaces_only_weaker_classes) {
  Fixture fixture;
  PolicyRecord policy = permissive_policy("preempting");
  policy.allow_preemption_on_commit = true;
  policy.max_preemption_victims = 4;
  codec::RequestContext authority = ctx(fixture, claimant_a(), 99);
  BRF_REQUIRE_OK(fixture.coordinator->ingest_policy(policy, authority));
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 100 * kGbit, 1)}, 1, fixture.epoch()), {}, authority));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission scavenger =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 80 * kGbit, window, "preempting",
                      GuaranteeClass::kScavenger));
  BRF_REQUIRE(scavenger.committed);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 20 * kGbit);

  const Admission guaranteed =
      create(fixture, ctx(fixture, claimant_b(), 2),
             terms_of(claimant_b(), ClaimantGeneration(1), "r1", 50 * kGbit, window, "preempting",
                      GuaranteeClass::kGuaranteed));
  BRF_REQUIRE(guaranteed.committed);
  BRF_CHECK(guaranteed.result.report.preemption_planned);
  BRF_CHECK_EQ(guaranteed.result.report.preemption_plan.size(), std::size_t{1});
  Result<ReservationRecord> victim = fixture.coordinator->get_reservation(
      scavenger.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE(victim.has_value());
  BRF_CHECK(victim.value().state == ReservationState::kRevoked);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 50 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, competing_requests_for_last_capacity_are_serialised) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission first =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 60 * kGbit, window));
  const Admission second =
      create(fixture, ctx(fixture, claimant_b(), 2),
             terms_of(claimant_b(), ClaimantGeneration(1), "r1", 60 * kGbit, window));
  BRF_CHECK(first.committed != second.committed);
  BRF_CHECK_EQ(remaining(fixture, "r1", window), 40 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, series_amendment_supersedes_all_members) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  ReservationTerms terms =
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", 20 * kGbit,
               window_of(kBaseEpochNs + kHour, kBaseEpochNs + 90 * kMinute));
  terms.recurrence.enabled = true;
  terms.recurrence.period = Duration{kHour};
  terms.recurrence.count = 3;
  const Admission admission = create(fixture, ctx(fixture, claimant_a(), 1), terms);
  BRF_REQUIRE(admission.committed);
  ReservationTerms amended = terms;
  amended.amount = Bandwidth{25 * kGbit};
  Result<AmendmentResult> result = fixture.coordinator->amend_reservation(
      ctx(fixture, claimant_a(), 2), admission.result.record.id, ReservationGeneration(1), amended, false);
  BRF_REQUIRE_OK(result);
  BRF_CHECK(result.value().has_series);
  BRF_CHECK_EQ(result.value().members.size(), std::size_t{3});
  BRF_CHECK_EQ(result.value().series.generation.value(), std::uint64_t{2});
  for (const ReservationRecord& member : result.value().members) {
    BRF_CHECK_EQ(member.generation.value(), std::uint64_t{2});
    BRF_CHECK(member.series_member);
  }
  BRF_CHECK_EQ(remaining(fixture, "r1", window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour)),
               75 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, overcommit_resolution_is_explicit_and_durable) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit, 1));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission first =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit, window,
                      "fabric-default", GuaranteeClass::kGuaranteed));
  const Admission second =
      create(fixture, ctx(fixture, claimant_b(), 2),
             terms_of(claimant_b(), ClaimantGeneration(1), "r1", 40 * kGbit, window, "fabric-default",
                      GuaranteeClass::kScavenger));
  BRF_REQUIRE(first.committed);
  BRF_REQUIRE(second.committed);

  // The authority withdraws the resource while both commitments are live: the
  // degraded state appears, both commitments survive, and new work is refused
  // until policy resolves it.
  codec::RequestContext authority = ctx(fixture, claimant_a(), 99);
  authority.actor = actor_of("brf-authority");
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r2", 100 * kGbit, 1)}, 2, fixture.epoch()), {name_of("r1")}, authority));
  Result<OvercommitReport> report = fixture.coordinator->overcommit_report();
  BRF_REQUIRE_OK(report);
  BRF_CHECK(report.value().emergency_active);
  BRF_CHECK_EQ(report.value().entries.size(), std::size_t{1});

  // Resolution revokes the weakest obligation first and clears the emergency.
  BRF_REQUIRE_OK(fixture.coordinator->resolve_overcommit(
      ctx(fixture, claimant_a(), 100), name_of("r1"), ReservationCoordinator::OvercommitResolution::kRevoke));
  Result<ReservationRecord> scavenger = fixture.coordinator->get_reservation(
      second.result.record.id, ReservationGeneration(1));
  BRF_REQUIRE(scavenger.has_value());
  BRF_CHECK(scavenger.value().state == ReservationState::kRevoked);
  Result<OvercommitReport> resolved = fixture.coordinator->overcommit_report();
  BRF_REQUIRE_OK(resolved);
  BRF_CHECK(!resolved.value().emergency_active);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, recall_grace_defers_capacity_release) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 3 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 50 * kGbit, window, "fabric-default",
                      GuaranteeClass::kScavenger));
  BRF_REQUIRE(admission.committed);
  Result<LifecycleResult> recalled = fixture.coordinator->recall_reservation(
      ctx(fixture, claimant_b(), 2), admission.result.record.id, ReservationGeneration(1),
      Timestamp{kBaseEpochNs + 2 * kHour}, Duration{10 * kMinute}, false);
  BRF_REQUIRE_OK(recalled);
  BRF_CHECK_EQ(recalled.value().record.recall_grace.ns, 10 * kMinute);
  // Capacity returns only after the grace has elapsed.
  BRF_CHECK_EQ(remaining(fixture, "r1", window_of(kBaseEpochNs + 2 * kHour + kMinute,
                                                  kBaseEpochNs + 3 * kHour)),
               50 * kGbit);
  BRF_CHECK_EQ(remaining(fixture, "r1", window_of(kBaseEpochNs + 2 * kHour + 11 * kMinute,
                                                  kBaseEpochNs + 3 * kHour)),
               100 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(coordinator, failure_domain_generation_change_invalidates_applicability) {
  Fixture fixture;
  ResourceCapacity capacity = capacity_of("r1", 100 * kGbit, 1);
  capacity.failure_domain = FailureDomainName::from_string("pod-a").value();
  capacity.failure_domain_generation = FailureDomainGeneration(1);
  codec::RequestContext authority = ctx(fixture, claimant_a(), 99);
  authority.actor = actor_of("brf-authority");
  BRF_REQUIRE_OK(fixture.coordinator->ingest_policy(permissive_policy("fabric-default"), authority));
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(snapshot_of({capacity}, 1, fixture.epoch()), {},
                                                      authority));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  const Admission admission =
      create(fixture, ctx(fixture, claimant_a(), 1),
             terms_of(claimant_a(), ClaimantGeneration(1), "r1", 20 * kGbit, window));
  BRF_REQUIRE(admission.committed);
  BRF_CHECK_EQ(admission.result.record.authority.failure_domains.size(), std::size_t{1});

  ResourceCapacity next = capacity;
  next.generation = ResourceGeneration(2);
  next.failure_domain_generation = FailureDomainGeneration(2);
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(snapshot_of({next}, 2, fixture.epoch()), {},
                                                      authority));
  Result<ReservationRecord> record =
      fixture.coordinator->get_reservation(admission.result.record.id, ReservationGeneration(0));
  BRF_REQUIRE(record.has_value());
  BRF_CHECK(record.value().applicability != Applicability::kCurrent);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}
