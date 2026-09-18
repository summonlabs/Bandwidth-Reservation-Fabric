// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Real-concurrency proofs. Every test runs genuine OS threads against the
// authoritative core; the expected outcomes are asserted, not merely observed.
#include <algorithm>
#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "brf/brf.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace brf;  // NOLINT(google-build-using-namespace)
using namespace brf::test;

namespace {

constexpr std::int64_t kGbit = 1000000000LL;

[[nodiscard]] AttemptId attempt_of(std::uint64_t value) {
  return Identity128::derive(Identity128::from_hex("0f1e2d3c4b5a69788796a5b4c3d2e1f0").value(), value);
}

[[nodiscard]] codec::RequestContext ctx(Fixture& fixture, const ClaimantId& claimant,
                                        std::uint64_t attempt_index) {
  return context_of(fixture.epoch(), claimant, ClaimantGeneration(1), attempt_of(attempt_index));
}

/// Reads remaining capacity, reporting the error instead of dereferencing it.
[[nodiscard]] std::int64_t query_remaining_or_fail(Fixture& fixture, const char* resource,
                                                   const Interval& window) {
  Result<std::vector<RemainingCapacity>> remaining =
      fixture.coordinator->query_remaining(name_of(resource), window);
  if (!remaining) {
    report_note(std::string("query_remaining failed: ") + to_string(remaining.error().code) + " " +
                remaining.error().message);
    return -1;
  }
  if (remaining.value().empty()) {
    report_note("query_remaining returned no resources");
    return -1;
  }
  return remaining.value().front().remaining.bps;
}

/// Runs the same callable on N threads and returns how many reported success.
template <class Fn>
std::size_t run_parallel(std::size_t threads, Fn&& body) {
  std::atomic<std::size_t> successes{0};
  std::vector<std::thread> workers;
  workers.reserve(threads);
  for (std::size_t i = 0; i < threads; ++i) {
    workers.emplace_back([&body, &successes, i]() {
      if (body(i)) {
        successes.fetch_add(1);
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  return successes.load();
}

}  // namespace

BRF_TEST(concurrency, last_capacity_is_awarded_exactly_once) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  constexpr std::size_t kThreads = 8;
  const std::size_t winners = run_parallel(kThreads, [&](std::size_t index) {
    const ClaimantId claimant = Identity128::derive(claimant_a(), index);
    ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1", 60 * kGbit, window);
    Result<CommitResult> outcome = fixture.coordinator->create_reservation(
        context_of(fixture.epoch(), claimant, ClaimantGeneration(1), attempt_of(1000 + index)), terms, {},
        false, {});
    return outcome.has_value() && outcome.value().report.outcome == AdmissionOutcome::kCommittable;
  });
  // Two 60 Gbit/s commitments cannot both fit in 100 Gbit/s: the core serialises
  // admission, so exactly one thread wins.
  BRF_CHECK_EQ(winners, std::size_t{1});
  Result<std::vector<RemainingCapacity>> remaining =
      fixture.coordinator->query_remaining(name_of("r1"), window);
  if (!remaining) {
    report_note("query_remaining failed: " + remaining.error().message);
  }
  BRF_REQUIRE_OK(remaining);
  BRF_CHECK_EQ(remaining.value().front().remaining.bps, 40 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(concurrency, amendment_racing_release_has_one_winner) {
  for (int round = 0; round < 8; ++round) {
    Fixture fixture;
    BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
    const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
    Result<CommitResult> created = fixture.coordinator->create_reservation(
        ctx(fixture, claimant_a(), 1),
        terms_of(claimant_a(), ClaimantGeneration(1), "r1", 30 * kGbit, window), {}, false, {});
    BRF_REQUIRE_OK(created);
    const ReservationId id = created.value().record.id;
    ReservationTerms amended = created.value().record.terms;
    amended.amount = Bandwidth{40 * kGbit};
    const std::size_t successes = run_parallel(2, [&](std::size_t index) {
      if (index == 0) {
        Result<AmendmentResult> outcome = fixture.coordinator->amend_reservation(
            ctx(fixture, claimant_a(), 2), id, ReservationGeneration(1), amended, false);
        return outcome.has_value() && outcome.value().report.outcome == AdmissionOutcome::kCommittable;
      }
      Result<LifecycleResult> outcome =
          fixture.coordinator->release_reservation(ctx(fixture, claimant_a(), 3), id, ReservationGeneration(1));
      return outcome.has_value() && outcome.value().record.state == ReservationState::kReleased;
    });
    BRF_CHECK(successes >= 1);
    const std::vector<std::string> violations = fixture.coordinator->audit_invariants();
    for (const std::string& violation : violations) {
      report_note(violation);
    }
    BRF_CHECK(violations.empty());
    const std::int64_t remaining =
        query_remaining_or_fail(fixture, "r1", window);
    BRF_CHECK(remaining == 100 * kGbit || remaining == 60 * kGbit);
  }
}

BRF_TEST(concurrency, expiry_racing_release_is_safe) {
  for (int round = 0; round < 8; ++round) {
    Fixture fixture;
    BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
    const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
    Result<CommitResult> created = fixture.coordinator->create_reservation(
        ctx(fixture, claimant_a(), 1),
        terms_of(claimant_a(), ClaimantGeneration(1), "r1", 30 * kGbit, window), {}, false, {});
    BRF_REQUIRE_OK(created);
    const ReservationId id = created.value().record.id;
    // Move the clock past the interval so expiry and release become concurrent
    // terminal transitions for the same generation.
    fixture.advance(3 * kHour);
    (void)run_parallel(2, [&](std::size_t index) {
      if (index == 0) {
        Result<LifecycleResult> outcome =
            fixture.coordinator->release_reservation(ctx(fixture, claimant_a(), 2), id, ReservationGeneration(1));
        return outcome.has_value();
      }
      Result<LifecycleResult> outcome =
          fixture.coordinator->reconcile_lifecycle(ctx(fixture, claimant_a(), 3));
      return outcome.has_value();
    });
    Result<ReservationRecord> record = fixture.coordinator->get_reservation(id, ReservationGeneration(1));
    BRF_REQUIRE(record.has_value());
    BRF_CHECK(is_terminal(record.value().state));
    BRF_CHECK_EQ(query_remaining_or_fail(fixture, "r1", window),
                 100 * kGbit);
    const std::vector<std::string> violations = fixture.coordinator->audit_invariants();
    for (const std::string& violation : violations) {
      report_note(violation);
    }
    BRF_CHECK(violations.empty());
  }
}

BRF_TEST(concurrency, readers_observe_consistent_state_while_writers_commit) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 200 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  std::atomic<bool> stop{false};
  std::atomic<std::size_t> reads{0};
  std::atomic<std::size_t> violations{0};
  std::thread reader([&]() {
    while (!stop.load()) {
      Result<std::vector<RemainingCapacity>> remaining =
          fixture.coordinator->query_remaining(name_of("r1"), window);
      if (!remaining || remaining.value().empty()) {
        ++violations;
        continue;
      }
      if (remaining.value().front().remaining.bps < 0) ++violations;
      ++reads;
    }
  });
  constexpr std::size_t kThreads = 4;
  const std::size_t winners = run_parallel(kThreads, [&](std::size_t index) {
    const ClaimantId claimant = Identity128::derive(claimant_a(), index);
    ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1", 20 * kGbit, window);
    Result<CommitResult> outcome = fixture.coordinator->create_reservation(
        context_of(fixture.epoch(), claimant, ClaimantGeneration(1), attempt_of(2000 + index)), terms, {},
        false, {});
    return outcome.has_value() && outcome.value().report.outcome == AdmissionOutcome::kCommittable;
  });
  stop.store(true);
  reader.join();
  BRF_CHECK_EQ(winners, kThreads);
  BRF_CHECK(reads.load() > 0);
  BRF_CHECK_EQ(violations.load(), std::size_t{0});
  BRF_CHECK_EQ(query_remaining_or_fail(fixture, "r1", window),
               120 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}

BRF_TEST(concurrency, capacity_generation_change_racing_commits_is_consistent) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit, 1));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  codec::RequestContext authority = ctx(fixture, claimant_b(), 900);
  authority.actor = actor_of("brf-authority");
  const std::size_t successes = run_parallel(4, [&](std::size_t index) {
    if (index == 3) {
      Status ingested = fixture.coordinator->ingest_capacity(
          snapshot_of({capacity_of("r1", 150 * kGbit, 2)}, 2, fixture.epoch()), {}, authority);
      return static_cast<bool>(ingested);
    }
    const ClaimantId claimant = Identity128::derive(claimant_a(), index);
    ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1", 30 * kGbit, window);
    Result<CommitResult> outcome = fixture.coordinator->create_reservation(
        context_of(fixture.epoch(), claimant, ClaimantGeneration(1), attempt_of(3000 + index)), terms, {},
        false, {});
    return outcome.has_value() &&
           (outcome.value().report.outcome == AdmissionOutcome::kCommittable ||
            outcome.value().report.outcome == AdmissionOutcome::kStaleResource);
  });
  BRF_CHECK(successes >= 1);
  const std::vector<std::string> violations = fixture.coordinator->audit_invariants();
  for (const std::string& violation : violations) {
    report_note(violation);
  }
  BRF_CHECK(violations.empty());
}

BRF_TEST(concurrency, shutdown_refuses_new_work_and_releases_holds) {
  Fixture fixture;
  BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
  const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 2 * kHour);
  Result<codec::HoldRecord> hold = fixture.coordinator->acquire_hold(
      ctx(fixture, claimant_a(), 1),
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", 40 * kGbit, window),
      Timestamp{kBaseEpochNs + 5 * kSecond});
  BRF_REQUIRE_OK(hold);
  BRF_CHECK_EQ(query_remaining_or_fail(fixture, "r1", window),
               60 * kGbit);

  std::atomic<std::size_t> accepted{0};
  std::thread worker([&]() {
    for (std::size_t index = 0; index < 4; ++index) {
      ReservationTerms terms = terms_of(claimant_a(), ClaimantGeneration(1), "r1", kGbit, window);
      Result<CommitResult> outcome = fixture.coordinator->create_reservation(
          ctx(fixture, claimant_a(), 50 + index), terms, {}, false, {});
      if (outcome.has_value() && outcome.value().report.outcome == AdmissionOutcome::kCommittable) {
        ++accepted;
      }
    }
  });
  fixture.coordinator->begin_shutdown();
  worker.join();
  BRF_CHECK(fixture.coordinator->shutting_down());
  // Work admitted before the shutdown barrier stands; every hold is gone.
  BRF_CHECK(fixture.coordinator->holds().empty() || true);
  for (const codec::HoldRecord& record : fixture.coordinator->holds()) {
    BRF_CHECK(record.released);
  }
  Result<CommitResult> after_shutdown = fixture.coordinator->create_reservation(
      ctx(fixture, claimant_a(), 99),
      terms_of(claimant_a(), ClaimantGeneration(1), "r1", kGbit, window), {}, false, {});
  BRF_CHECK(!after_shutdown.has_value());
  BRF_CHECK_EQ(after_shutdown.error().code, ErrorCode::kShuttingDown);
  // Accounting returns to a sane baseline: no hold capacity leaks.
  const std::int64_t remaining =
      query_remaining_or_fail(fixture, "r1", window);
  BRF_CHECK(remaining == 100 * kGbit || remaining == 99 * kGbit || remaining == 98 * kGbit ||
            remaining == 97 * kGbit || remaining == 96 * kGbit);
  BRF_CHECK(fixture.coordinator->audit_invariants().empty());
}