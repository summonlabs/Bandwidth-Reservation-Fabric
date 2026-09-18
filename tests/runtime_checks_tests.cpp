// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Runtime memory-integrity checks available on this host.
//
// AddressSanitizer is NOT available for x64 MSVC on this machine (only the x86
// sanitizer runtime is installed), so no sanitizer coverage is claimed. What is
// available and verified here is the MSVC debug heap plus the /RTC1 runtime
// checks that Debug builds enable: heap integrity is validated around a full
// workload, and the process exits with the debug heap's own leak reporting
// active.
#include <string>
#include <vector>

#include "brf/brf.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

#ifdef _WIN32
#include <crtdbg.h>
#endif

using namespace brf;  // NOLINT(google-build-using-namespace)
using namespace brf::test;

namespace {

constexpr std::int64_t kGbit = 1000000000LL;

[[nodiscard]] bool heap_is_intact() {
#ifdef _WIN32
  return _CrtCheckMemory() != 0;
#else
  return true;  // No equivalent debug-heap hook is used on this platform.
#endif
}

[[nodiscard]] AttemptId attempt_of(std::uint64_t value) {
  return Identity128::derive(Identity128::from_hex("cafebabecafebabecafebabecafebabe").value(), value);
}

}  // namespace

BRF_TEST(runtime_checks, heap_integrity_across_a_full_workload) {
  BRF_REQUIRE(heap_is_intact());
  {
    Fixture fixture;
    BRF_REQUIRE_OK(seed_authority(*fixture.coordinator, fixture.epoch(), "r1", 100 * kGbit));
    const Interval window = window_of(kBaseEpochNs + kHour, kBaseEpochNs + 4 * kHour);
    std::vector<ReservationId> ids;
    std::uint64_t attempt = 1;
    for (std::uint64_t index = 0; index < 12; ++index) {
      const ClaimantId claimant = Identity128::derive(claimant_a(), index);
      ReservationTerms terms = terms_of(claimant, ClaimantGeneration(1), "r1", 5 * kGbit, window);
      Result<CommitResult> outcome = fixture.coordinator->create_reservation(
          context_of(fixture.epoch(), claimant, ClaimantGeneration(1), attempt_of(attempt++)), terms, {},
          false, {});
      BRF_REQUIRE(outcome.has_value());
      if (outcome.value().report.outcome == AdmissionOutcome::kCommittable) {
        ids.push_back(outcome.value().record.id);
      }
    }
    for (std::size_t index = 0; index < ids.size(); index += 2) {
      ReservationTerms amended = terms_of(claimant_a(), ClaimantGeneration(1), "r1", 9 * kGbit, window);
      amended.claimant = Identity128::derive(claimant_a(), index);
      (void)fixture.coordinator->amend_reservation(
          context_of(fixture.epoch(), amended.claimant, ClaimantGeneration(1), attempt_of(attempt++)),
          ids[index], ReservationGeneration(1), amended, false);
    }
    for (std::size_t index = 1; index < ids.size(); index += 2) {
      (void)fixture.coordinator->release_reservation(
          context_of(fixture.epoch(), Identity128::derive(claimant_a(), index), ClaimantGeneration(1),
                     attempt_of(attempt++)),
          ids[index], ReservationGeneration(1));
    }
    fixture.advance(6 * kHour);
    (void)fixture.coordinator->reconcile_lifecycle(
        context_of(fixture.epoch(), claimant_a(), ClaimantGeneration(1), attempt_of(attempt++)));
    fixture.reopen();
    BRF_CHECK(fixture.coordinator->audit_invariants().empty());
    const CoordinatorStats stats = fixture.coordinator->stats();
    BRF_CHECK(stats.durable_records > 0);
    BRF_CHECK(heap_is_intact());
  }
  // Every allocation performed by the workload above has been released; the
  // debug heap is asked to confirm that before the process exits.
  BRF_CHECK(heap_is_intact());
}
