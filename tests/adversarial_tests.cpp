// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Adversarial hardening: hostile, malformed, contradictory, stale, and
// oversized input must be refused deterministically without corrupting state.
#include <algorithm>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "brf/brf.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace brf;  // NOLINT(google-build-using-namespace)
using namespace brf::test;

namespace {

constexpr std::int64_t kGbit = 1000000000LL;

[[nodiscard]] AttemptId attempt_of(std::uint64_t value) {
  return Identity128::derive(Identity128::from_hex("feedfacefeedfacefeedfacefeedface").value(), value);
}

[[nodiscard]] codec::RequestContext ctx(Fixture& fixture, const ClaimantId& claimant,
                                        std::uint64_t attempt_index) {
  return context_of(fixture.epoch(), claimant, ClaimantGeneration(1), attempt_of(attempt_index));
}

[[nodiscard]] AdmissionOutcome commit(Fixture& fixture, const codec::RequestContext& context,
                                      const ReservationTerms& terms) {
  Result<CommitResult> outcome = fixture.coordinator->create_reservation(context, terms, {}, false, {});
  return outcome ? outcome.value().report.outcome : AdmissionOutcome::kInvalidRequest;
}

[[nodiscard]] codec::RequestContext authority_ctx(Fixture& fixture) {
  // Authority traffic uses its own publisher identity so that fencing a
  // claimant boot cannot accidentally fence the authority itself.
  codec::RequestContext context = context_of(fixture.epoch(), claimant_b(), ClaimantGeneration(1),
                                             attempt_of(900));
  context.publisher = Identity128::from_hex("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f").value();
  context.publisher_boot = Identity128::from_hex("f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0").value();
  context.session = Identity128::from_hex("11223344556677881122334455667788").value();
  context.claimant = ClaimantId{};
  context.actor = actor_of("brf-authority");
  return context;
}

}  // namespace

BRF_TEST(adversarial, interval_hostility) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const ClaimantId claimant = claimant_a();
  std::uint64_t attempt = 1;

  // Zero duration, inverted, negative start, and a span beyond the maximum.
  const std::vector<Interval> hostile = {
      window_of(kBaseEpochNs + kHour, kBaseEpochNs + kHour),
      window_of(kBaseEpochNs + kHour, kBaseEpochNs),
      Interval{Timestamp{-1}, Timestamp{kBaseEpochNs + kHour}},
      window_of(0, kMaxReservationSpanNs + 1),
      window_of(kMaxTimestampNs - kHour, kMaxTimestampNs + kHour),
  };
  for (const Interval& interval : hostile) {
    ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1", kGbit, interval);
    const AdmissionOutcome outcome = commit(fixture, ctx(fixture, claimant, attempt++), terms);
    BRF_CHECK(outcome == AdmissionOutcome::kInvalidRequest || outcome == AdmissionOutcome::kInvalidInterval);
  }
  BRF_CHECK_EQ(fixture.coordinator->stats().commits, std::uint64_t{0});
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(adversarial, bandwidth_hostility) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const ClaimantId claimant = claimant_a();
  ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1", 1, window_of(kBaseEpochNs, kBaseEpochNs + kHour));

  ReservationTerms zero = terms;
  zero.amount = Bandwidth{0};
  BRF_CHECK_EQ(validate_terms(zero).error().code, ErrorCode::kInvalidBandwidth);

  ReservationTerms negative = terms;
  negative.amount = Bandwidth{-1};
  BRF_CHECK_EQ(validate_terms(negative).error().code, ErrorCode::kInvalidBandwidth);

  ReservationTerms absurd = terms;
  absurd.amount = Bandwidth{INT64_MAX};
  BRF_CHECK_EQ(validate_terms(absurd).error().code, ErrorCode::kInvalidBandwidth);

  // A structurally valid but unsatisfiable amount is refused by admission, not
  // by structural validation.
  ReservationTerms over_ceiling = terms;
  over_ceiling.amount = Bandwidth{kMaxBandwidthBps};
  BRF_CHECK(validate_terms(over_ceiling).has_value());
  BRF_CHECK(commit(fixture, ctx(fixture, claimant_a(), 77), over_ceiling) ==
            AdmissionOutcome::kInsufficientCapacity);

  ReservationTerms contradictory = terms;
  contradictory.minimum_amount = Bandwidth{50 * kGbit};
  BRF_CHECK_EQ(validate_terms(contradictory).error().code, ErrorCode::kInvalidBandwidth);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(adversarial, dense_overlap_conflict_set_is_bounded) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  PolicyRecord policy = PolicyRegistry::strict_default(policy_of("fabric-default"));
  policy.generation = PolicyGeneration(2);
  policy.max_conflict_set = 4;
  policy.max_explanation_bytes = 256;
  BRF_REQUIRE_OK(fixture.coordinator->ingest_policy(policy, authority_ctx(fixture)));

  const Interval shared = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  std::uint64_t attempt = 1;
  for (std::uint64_t i = 0; i < 20; ++i) {
    const ClaimantId claimant = Identity128::derive(claimant_a(), i);
    ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1", 4 * kGbit, shared);
    (void)commit(fixture, context_of(fixture.epoch(), claimant, ClaimantGeneration(1), attempt_of(attempt++)),
                 terms);
  }
  ReservationTerms request = terms_of(claimant_b(), ClaimantGeneration(1), "r1", 50 * kGbit, shared);
  Result<AdmissionReport> report = fixture.coordinator->explain_conflicts(request, {});
  BRF_REQUIRE_OK(report);
  BRF_CHECK(report.value().outcome == AdmissionOutcome::kInsufficientCapacity);
  BRF_CHECK(report.value().conflicts.entries.size() <= 4);
  BRF_CHECK(report.value().conflicts.truncated);
  BRF_CHECK(report.value().explanation.size() <= 256);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(adversarial, duplicate_identity_reuse_is_refused) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  ReservationTerms terms = terms_of(claimant_a(), ClaimantGeneration(1), "r1", 10 * kGbit, window);
  const ReservationId fixed = Identity128::from_hex("deadbeefdeadbeefdeadbeefdeadbeef").value();
  Result<CommitResult> first = fixture.coordinator->create_reservation(ctx(fixture, claimant_a(), 1),
                                                                      terms, fixed, false, {});
  BRF_REQUIRE_OK(first);
  BRF_CHECK(first.value().record.id == fixed);

  // The same identity with different terms under a fresh attempt is a conflict.
  ReservationTerms different = terms;
  different.amount = Bandwidth{11 * kGbit};
  Result<CommitResult> second = fixture.coordinator->create_reservation(ctx(fixture, claimant_a(), 2),
                                                                       different, fixed, false, {});
  BRF_CHECK(!second || second.value().report.outcome != AdmissionOutcome::kCommittable);
  BRF_CHECK_EQ(fixture.coordinator->stats().commits, std::uint64_t{1});
  // The first commitment is untouched by the refused reuse.
  Result<ReservationRecord> original =
      fixture.coordinator->get_reservation(fixed, ReservationGeneration(1));
  BRF_REQUIRE(original.has_value());
  BRF_CHECK_EQ(original.value().terms.amount.bps, 10 * kGbit);
  Result<std::vector<RemainingCapacity>> after_refusal =
      fixture.coordinator->query_remaining(name_of("r1"), window);
  BRF_REQUIRE_OK(after_refusal);
  BRF_REQUIRE(!after_refusal.value().empty());
  BRF_CHECK_EQ(after_refusal.value().front().remaining.bps, 90 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(adversarial, conflicting_capacity_generations_are_refused) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit, 1));
  codec::RequestContext authority = authority_ctx(fixture);
  // Same resource generation, different content.
  Status conflict = fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 90 * kGbit, 1)}, 2, fixture.epoch()), {}, authority);
  BRF_CHECK(!conflict);
  BRF_CHECK_EQ(conflict.code(), ErrorCode::kConflict);
  // A generation that moves backwards is stale, not a silent downgrade.
  Status stale = fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 100 * kGbit, 0)}, 3, fixture.epoch()), {}, authority);
  BRF_CHECK(!stale);
  // Re-ingesting byte-identical authoritative content at the same resource
  // generation is an idempotent no-op, not a conflict.
  Status identical = fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 100 * kGbit, 1)}, 4, fixture.epoch()), {}, authority);
  BRF_CHECK(identical);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(adversarial, stale_epoch_and_boot_replay_are_refused) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);

  codec::RequestContext stale = ctx(fixture, claimant_a(), 1);
  stale.asserted_epoch = FabricEpoch(stale.asserted_epoch.value() + 5);
  Result<CommitResult> refused = fixture.coordinator->create_reservation(
      stale, terms_of(claimant_a(), ClaimantGeneration(1), "r1", kGbit, window), {}, false, {});
  BRF_CHECK(!refused);
  BRF_CHECK_EQ(refused.error().code, ErrorCode::kStaleEpoch);

  // Fence a boot, then attempt to replay from it.
  const PublisherBootId boot = ctx(fixture, claimant_a(), 2).publisher_boot;
  BRF_REQUIRE_OK(fixture.coordinator->fence(authority_ctx(fixture), ClaimantId{}, ClaimantGeneration(0),
                                            boot, SessionId{}, false));
  Result<CommitResult> replayed = fixture.coordinator->create_reservation(
      ctx(fixture, claimant_a(), 3), terms_of(claimant_a(), ClaimantGeneration(1), "r1", kGbit, window), {},
      false, {});
  BRF_CHECK(!replayed);
  BRF_CHECK_EQ(replayed.error().code, ErrorCode::kFencedClaimant);

  // A capacity snapshot produced for another epoch is refused.
  CapacitySnapshot foreign = snapshot_of({capacity_of("r1", 100 * kGbit, 2)}, 9, FabricEpoch(999));
  Status ingest = fixture.coordinator->ingest_capacity(foreign, {}, authority_ctx(fixture));
  BRF_CHECK(!ingest);
  BRF_CHECK_EQ(ingest.code(), ErrorCode::kStaleEpoch);
}

BRF_TEST(adversarial, repeated_create_release_recreate_is_stable) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  std::uint64_t attempt = 1;
  for (int cycle = 0; cycle < 20; ++cycle) {
    ReservationTerms terms = terms_of(claimant_a(), ClaimantGeneration(1), "r1", 90 * kGbit, window);
    Result<CommitResult> created = fixture.coordinator->create_reservation(
        ctx(fixture, claimant_a(), attempt++), terms, {}, false, {});
    BRF_REQUIRE_OK(created);
    BRF_REQUIRE(created.value().report.outcome == AdmissionOutcome::kCommittable);
    Result<std::vector<RemainingCapacity>> remaining =
        fixture.coordinator->query_remaining(name_of("r1"), window);
    BRF_REQUIRE_OK(remaining);
    BRF_REQUIRE(!remaining.value().empty());
    BRF_CHECK_EQ(remaining.value().front().remaining.bps, 10 * kGbit);
    Result<LifecycleResult> released = fixture.coordinator->release_reservation(
        ctx(fixture, claimant_a(), attempt++), created.value().record.id, created.value().record.generation);
    BRF_REQUIRE_OK(released);
    Result<std::vector<RemainingCapacity>> after_release =
        fixture.coordinator->query_remaining(name_of("r1"), window);
    BRF_REQUIRE_OK(after_release);
    BRF_REQUIRE(!after_release.value().empty());
    BRF_CHECK_EQ(after_release.value().front().remaining.bps, 100 * kGbit);
  }
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(adversarial, capacity_collapse_blocks_new_commits_until_resolved) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit, 1));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  Result<CommitResult> committed = fixture.coordinator->create_reservation(
      ctx(fixture, claimant_a(), 1),
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", 90 * kGbit, window), {}, false, {});
  BRF_REQUIRE_OK(committed);
  // The authority shrinks the resource: the commitment is preserved as a
  // revalidation-required obligation and the resource enters an emergency state.
  codec::RequestContext authority = authority_ctx(fixture);
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 5 * kGbit, 2)}, 2, fixture.epoch()), {}, authority));
  Result<OvercommitReport> report = fixture.coordinator->overcommit_report();
  BRF_REQUIRE_OK(report);
  Result<ReservationRecord> preserved = fixture.coordinator->get_reservation(
      committed.value().record.id, ReservationGeneration(1));
  BRF_REQUIRE(preserved.has_value());
  BRF_CHECK(preserved.value().state == ReservationState::kCommitted);
  BRF_CHECK(preserved.value().applicability != Applicability::kCurrent);

  // Re-admitting the old obligation onto the new generation is refused when it
  // does not fit, and the old generation is never silently re-pointed.
  Result<LifecycleResult> revalidated = fixture.coordinator->revalidate_reservation(
      ctx(fixture, claimant_a(), 2), committed.value().record.id, ReservationGeneration(1), false);
  BRF_CHECK(!revalidated.has_value());
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(adversarial, policy_change_beneath_active_commitments_requires_revalidation) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  Result<CommitResult> committed = fixture.coordinator->create_reservation(
      ctx(fixture, claimant_a(), 1),
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit, window), {}, false, {});
  BRF_REQUIRE_OK(committed);

  PolicyRecord changed = permissive_policy("fabric-default", 2);
  changed.allow_recall_guaranteed = true;  // material change
  BRF_REQUIRE_OK(fixture.coordinator->ingest_policy(changed, authority_ctx(fixture)));
  Result<ReservationRecord> record = fixture.coordinator->get_reservation(
      committed.value().record.id, ReservationGeneration(1));
  BRF_REQUIRE(record.has_value());
  BRF_CHECK(record.value().applicability == Applicability::kRevalidationRequired);
  BRF_CHECK(record.value().applicability_reason == ApplicabilityReason::kPolicyMaterialChange);
  // The commitment survives; revalidation restores applicability under the new
  // policy generation.
  Result<LifecycleResult> revalidated = fixture.coordinator->revalidate_reservation(
      ctx(fixture, claimant_a(), 2), committed.value().record.id, ReservationGeneration(1), false);
  BRF_REQUIRE_OK(revalidated);
  BRF_CHECK(revalidated.value().record.applicability == Applicability::kCurrent);
  BRF_CHECK_EQ(revalidated.value().record.authority.policy_generation.value(), std::uint64_t{2});
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(adversarial, widened_binding_is_refused_beyond_the_bound) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  ReservationTerms terms =
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", kGbit, window_of(kBaseEpochNs, kBaseEpochNs + kHour));
  for (std::size_t i = 0; i <= kMaxBindingResources; ++i) {
    terms.resources.push_back(name_of(("r" + std::to_string(i)).c_str()));
  }
  Result<CommitResult> refused = fixture.coordinator->create_reservation(
      ctx(fixture, claimant_a(), 1), terms, {}, false, {});
  BRF_CHECK(!refused);
  BRF_CHECK_EQ(refused.error().code, ErrorCode::kResourceExhausted);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(adversarial, coordinator_refuses_a_corrupt_store) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  (void)fixture.coordinator->create_reservation(
      ctx(fixture, claimant_a(), 1),
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", kGbit, window_of(kBaseEpochNs, kBaseEpochNs + kHour)),
      {}, false, {});
  fixture.coordinator.reset();
  // Corrupt the journal in the middle, then try to reopen.
  const std::string path = fixture.directory_.str() + "/fabric.brfjournal";
  {
    std::ifstream stream(path, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    BRF_REQUIRE(bytes.size() > 40);
    bytes[30] = static_cast<char>(bytes[30] ^ 0xFF);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }
  CoordinatorConfig config;
  config.store_directory = fixture.directory_.str();
  config.clock = fixture.clock_;
  Result<std::unique_ptr<ReservationCoordinator>> refused = ReservationCoordinator::open(config);
  BRF_CHECK(!refused.has_value());
  BRF_CHECK_EQ(refused.error().code, ErrorCode::kCorrupt);
}
