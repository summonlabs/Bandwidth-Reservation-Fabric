// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Seeded randomized proofs. Every sequence is deterministic and reproducible
// from its seed; a failure prints the seed and the operation index.
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

/// splitmix64: a small, fully specified generator so a seed reproduces a
/// sequence on every platform and every compiler.
class Rng {
 public:
  explicit Rng(std::uint64_t seed) : state_(seed + 0x9E3779B97F4A7C15ULL) {}

  [[nodiscard]] std::uint64_t next() {
    state_ += 0x9E3779B97F4A7C15ULL;
    std::uint64_t z = state_;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
  [[nodiscard]] std::uint64_t below(std::uint64_t bound) { return bound == 0 ? 0 : next() % bound; }

 private:
  std::uint64_t state_;
};

struct Population {
  std::vector<ReservationId> ids;
  std::vector<ReservationGeneration> generations;
};

/// Independent brute-force closure check: recompute the peak committed
/// bandwidth from the reported reservations instead of trusting the index.
[[nodiscard]] bool brute_force_fits(ReservationCoordinator& coordinator, const ResourceName& resource,
                                    const Interval& candidate, std::int64_t candidate_amount,
                                    std::int64_t ceiling, std::int64_t additional_headroom) {
  Result<std::vector<ReservationRecord>> existing =
      coordinator.query_resource(resource, Interval{Timestamp{0}, Timestamp{kMaxTimestampNs}}, true);
  if (!existing) return false;
  std::vector<Interval> windows;
  std::vector<std::int64_t> amounts;
  for (const ReservationRecord& record : existing.value()) {
    if (!consumes_capacity(record.state)) continue;
    if (record.applicability != Applicability::kCurrent) continue;
    windows.push_back(record.consuming_interval());
    amounts.push_back(record.terms.amount.bps);
  }
  windows.push_back(candidate);
  amounts.push_back(candidate_amount);
  const std::int64_t limit = ceiling - additional_headroom;
  for (std::size_t i = 0; i < windows.size(); ++i) {
    if (windows[i].empty()) continue;
    std::int64_t sum = 0;
    for (std::size_t j = 0; j < windows.size(); ++j) {
      if (windows[j].empty()) continue;
      if (windows[j].contains(windows[i].start)) sum += amounts[j];
    }
    if (sum > limit) return false;
  }
  return true;
}

[[nodiscard]] std::string state_fingerprint(ReservationCoordinator& coordinator,
                                            const std::vector<ResourceName>& resources) {
  std::string text;
  for (const ResourceName& resource : resources) {
    Result<std::vector<ReservationRecord>> records =
        coordinator.query_resource(resource, Interval{Timestamp{0}, Timestamp{kMaxTimestampNs}}, true);
    if (!records) return "query-failed";
    std::vector<std::string> lines;
    for (const ReservationRecord& record : records.value()) {
      lines.push_back(record.id.to_hex() + ":" + to_decimal(record.generation.value()) + ":" +
                      to_string(record.state) + ":" + to_string(record.applicability) + ":" +
                      to_decimal(static_cast<std::uint64_t>(record.terms.amount.bps)) + ":" +
                      to_decimal(static_cast<std::uint64_t>(record.terms.interval.start.ns)) + ":" +
                      to_decimal(static_cast<std::uint64_t>(record.terms.interval.end.ns)));
    }
    std::sort(lines.begin(), lines.end());
    for (const std::string& line : lines) {
      text += line + "\n";
    }
    Result<std::vector<RemainingCapacity>> remaining = coordinator.query_remaining(
        resource, Interval{Timestamp{kBaseEpochNs}, Timestamp{kBaseEpochNs + 48 * kHour}});
    if (!remaining) return "remaining-failed";
    text += "remaining:" + to_decimal(static_cast<std::uint64_t>(remaining.value().front().remaining.bps)) + "\n";
  }
  return text;
}

}  // namespace

BRF_TEST(property, randomized_operation_sequence_preserves_invariants) {
  const std::uint64_t seed = 0x5EED1234ULL;
  Rng rng(seed);
  Fixture fixture;
  codec::RequestContext authority =
      context_of(fixture.epoch(), claimant_a(), ClaimantGeneration(1), Identity128{});
  authority.actor = actor_of("brf-authority");
  BRF_REQUIRE_OK(fixture.coordinator->ingest_policy(permissive_policy("fabric-default"), authority));
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 100 * kGbit, 1), capacity_of("r2", 60 * kGbit, 1)}, 1, fixture.epoch()),
      {}, authority));

  Population population;
  std::uint64_t attempt_counter = 1;
  std::uint64_t capacity_generation = 1;
  std::uint64_t capacity_snapshot_generation = 1;

  for (std::uint64_t step = 0; step < 300; ++step) {
    const std::uint64_t choice = rng.below(100);
    const ClaimantId claimant = Identity128::derive(claimant_a(), rng.below(4));
    const Interval window = window_of(kBaseEpochNs + static_cast<std::int64_t>(rng.below(6)) * kHour,
                                      kBaseEpochNs + static_cast<std::int64_t>(6 + rng.below(4)) * kHour);
    const std::int64_t amount = static_cast<std::int64_t>(1 + rng.below(40)) * kGbit;
    const codec::RequestContext context =
        context_of(fixture.epoch(), claimant, ClaimantGeneration(1), Identity128::derive(claimant_a(), attempt_counter++));

    if (choice < 40) {
      ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1", amount, window);
      if (rng.below(4) == 0) {
        terms.resources.push_back(name_of("r2"));
      }
      Result<CommitResult> outcome =
          fixture.coordinator->create_reservation(context, terms, {}, false, {});
      if (outcome && outcome.value().report.outcome == AdmissionOutcome::kCommittable) {
        population.ids.push_back(outcome.value().record.id);
        population.generations.push_back(outcome.value().record.generation);
      }
    } else if (choice < 55 && !population.ids.empty()) {
      const std::size_t index = static_cast<std::size_t>(rng.below(population.ids.size()));
      Result<ReservationRecord> current =
          fixture.coordinator->get_reservation(population.ids[index], ReservationGeneration(0));
      if (current && !is_terminal(current.value().state)) {
        ReservationTerms amended = current.value().terms;
        amended.amount = Bandwidth{amount};
        Result<AmendmentResult> outcome = fixture.coordinator->amend_reservation(
            context, current.value().id, current.value().generation, amended, false);
        if (outcome && outcome.value().successor.generation.value() != 0) {
          population.generations[index] = outcome.value().successor.generation;
        }
      }
    } else if (choice < 70 && !population.ids.empty()) {
      const std::size_t index = static_cast<std::size_t>(rng.below(population.ids.size()));
      Result<ReservationRecord> current =
          fixture.coordinator->get_reservation(population.ids[index], ReservationGeneration(0));
      if (current && !is_terminal(current.value().state)) {
        (void)fixture.coordinator->release_reservation(context, current.value().id,
                                                       current.value().generation);
      }
    } else if (choice < 80 && !population.ids.empty()) {
      const std::size_t index = static_cast<std::size_t>(rng.below(population.ids.size()));
      Result<ReservationRecord> current =
          fixture.coordinator->get_reservation(population.ids[index], ReservationGeneration(0));
      if (current && !is_terminal(current.value().state)) {
        (void)fixture.coordinator->recall_reservation(context, current.value().id,
                                                      current.value().generation, Timestamp{},
                                                      Duration{}, true);
      }
    } else if (choice < 88) {
      fixture.advance(30 * kMinute);
      (void)fixture.coordinator->reconcile_lifecycle(context);
    } else if (choice < 94) {
      // Capacity regeneration: a new authoritative statement for one resource.
      ++capacity_generation;
      ++capacity_snapshot_generation;
      const std::int64_t new_capacity =
          static_cast<std::int64_t>(20 + rng.below(120)) * kGbit;
      const ResourceName target = rng.below(2) == 0 ? name_of("r1") : name_of("r2");
      (void)fixture.coordinator->ingest_capacity(
          snapshot_of({capacity_of(target.str().c_str(), new_capacity, capacity_generation)},
                      capacity_snapshot_generation, fixture.epoch()),
          {}, authority);
    } else {
      // Restart from the same durable store.
      fixture.reopen(Identity128::derive(claimant_a(), 0x424F4F54ULL + step));
    }

    const std::vector<std::string> violations = fixture.coordinator->audit_invariants();
    if (!violations.empty()) {
      report_note("seed=" + std::to_string(seed) + " step=" + std::to_string(step));
      for (const std::string& violation : violations) {
        report_note("violation: " + violation);
      }
      BRF_CHECK(violations.empty());
      return;
    }
  }
  BRF_CHECK(true);
}

BRF_TEST(property, identical_seeds_produce_identical_states) {
  const auto run = [](std::uint64_t seed) {
    Rng rng(seed);
    Fixture fixture;
    codec::RequestContext authority = context_of(fixture.epoch(), claimant_a(), ClaimantGeneration(1), {});
    authority.actor = actor_of("brf-authority");
    (void)fixture.coordinator->ingest_policy(permissive_policy("fabric-default"), authority);
    (void)fixture.coordinator->ingest_capacity(
        snapshot_of({capacity_of("r1", 100 * kGbit, 1)}, 1, fixture.epoch()), {}, authority);
    for (std::uint64_t step = 0; step < 40; ++step) {
      const ClaimantId claimant = Identity128::derive(claimant_a(), rng.below(3));
      const Interval window =
          window_of(kBaseEpochNs + static_cast<std::int64_t>(rng.below(4)) * kHour,
                    kBaseEpochNs + static_cast<std::int64_t>(4 + rng.below(4)) * kHour);
      ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1",
                                        static_cast<std::int64_t>(1 + rng.below(30)) * kGbit, window);
      const codec::RequestContext context = context_of(fixture.epoch(), claimant, ClaimantGeneration(1),
                                                       Identity128::derive(claimant_a(), 1000 + step));
      Result<CommitResult> outcome = fixture.coordinator->create_reservation(context, terms, {}, false, {});
      if (outcome && outcome.value().report.outcome == AdmissionOutcome::kCommittable &&
          rng.below(3) == 0) {
        (void)fixture.coordinator->release_reservation(context, outcome.value().record.id,
                                                       outcome.value().record.generation);
      }
    }
    return state_fingerprint(*fixture.coordinator, {name_of("r1")});
  };
  const std::string first = run(0xABCDEF01ULL);
  const std::string second = run(0xABCDEF01ULL);
  BRF_CHECK(!first.empty());
  BRF_CHECK(first == second);
  const std::string other = run(0xABCDEF02ULL);
  BRF_CHECK(!(other == first));
}

BRF_TEST(property, admission_matches_independent_brute_force_closure) {
  Rng rng(0x1234ABCDULL);
  Fixture fixture;
  codec::RequestContext authority = context_of(fixture.epoch(), claimant_a(), ClaimantGeneration(1), {});
  authority.actor = actor_of("brf-authority");
  const std::int64_t ceiling = 100 * kGbit;
  const std::int64_t headroom = 5 * kGbit;
  BRF_REQUIRE_OK(fixture.coordinator->ingest_policy(permissive_policy("fabric-default"), authority));
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", ceiling, 1, headroom)}, 1, fixture.epoch()), {}, authority));

  std::uint64_t attempt_counter = 1;
  for (std::uint64_t step = 0; step < 120; ++step) {
    const ClaimantId claimant = Identity128::derive(claimant_a(), 1 + rng.below(3));
    const std::int64_t start_hour = static_cast<std::int64_t>(rng.below(5));
    const Interval window = window_of(kBaseEpochNs + start_hour * kHour,
                                      kBaseEpochNs + (start_hour + 2) * kHour);
    const std::int64_t amount = static_cast<std::int64_t>(5 + rng.below(45)) * kGbit;
    ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1", amount, window);
    const codec::RequestContext context = context_of(fixture.epoch(), claimant, ClaimantGeneration(1),
                                                     Identity128::derive(claimant_a(), attempt_counter++));
    const bool expected =
        brute_force_fits(*fixture.coordinator, name_of("r1"), window, amount, ceiling, headroom);
    Result<CommitResult> outcome = fixture.coordinator->create_reservation(context, terms, {}, false, {});
    BRF_REQUIRE(outcome.has_value());
    const bool actual = outcome.value().report.outcome == AdmissionOutcome::kCommittable;
    if (expected != actual) {
      report_note("seed=0x1234ABCD step=" + std::to_string(step) + " expected=" +
                  std::to_string(expected) + " actual=" + std::to_string(actual) + " " +
                  outcome.value().report.explanation);
    }
    BRF_CHECK_EQ(actual, expected);
    BRF_CHECK(fixture.coordinator->audit_invariants().empty());
  }
}

BRF_TEST(property, retries_never_double_commit) {
  Rng rng(0x0BADF00DULL);
  Fixture fixture;
  codec::RequestContext authority = context_of(fixture.epoch(), claimant_a(), ClaimantGeneration(1), {});
  authority.actor = actor_of("brf-authority");
  BRF_REQUIRE_OK(fixture.coordinator->ingest_policy(permissive_policy("fabric-default"), authority));
  BRF_REQUIRE_OK(fixture.coordinator->ingest_capacity(
      snapshot_of({capacity_of("r1", 100 * kGbit, 1)}, 1, fixture.epoch()), {}, authority));
  for (std::uint64_t step = 0; step < 40; ++step) {
    const ClaimantId claimant = Identity128::derive(claimant_a(), 1 + rng.below(4));
    const Interval window = window_of(kBaseEpochNs + static_cast<std::int64_t>(rng.below(4)) * kHour,
                                      kBaseEpochNs + 8 * kHour);
    ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1",
                                      static_cast<std::int64_t>(1 + rng.below(40)) * kGbit, window);
    const codec::RequestContext context = context_of(fixture.epoch(), claimant, ClaimantGeneration(1),
                                                     Identity128::derive(claimant_a(), 5000 + step));
    Result<CommitResult> first = fixture.coordinator->create_reservation(context, terms, {}, false, {});
    BRF_REQUIRE(first.has_value());
    const std::int64_t after_first =
        fixture.coordinator
            ->query_remaining(name_of("r1"), window)
            .value()
            .front()
            .remaining.bps;
    // Every retry of the identical request must observe the same result and
    // must not consume further capacity.
    for (int retry = 0; retry < 3; ++retry) {
      Result<CommitResult> again = fixture.coordinator->create_reservation(context, terms, {}, false, {});
      BRF_REQUIRE(again.has_value());
      BRF_CHECK(again.value().replayed);
      BRF_CHECK(again.value().report.outcome == first.value().report.outcome);
      const std::int64_t now_remaining =
          fixture.coordinator
              ->query_remaining(name_of("r1"), window)
              .value()
              .front()
              .remaining.bps;
      BRF_CHECK_EQ(now_remaining, after_first);
    }
    BRF_CHECK(fixture.coordinator->audit_invariants().empty());
  }
}
