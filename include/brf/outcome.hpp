// Bandwidth Reservation Fabric - typed admission outcomes and bounded reports.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_OUTCOME_HPP
#define BRF_OUTCOME_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "brf/bandwidth.hpp"
#include "brf/capacity.hpp"
#include "brf/error.hpp"
#include "brf/identity.hpp"
#include "brf/policy.hpp"
#include "brf/reservation.hpp"
#include "brf/time.hpp"

namespace brf {

/// Typed admission outcome. Exactly one is produced per evaluation, and it is
/// the only thing callers are permitted to branch on.
enum class AdmissionOutcome : std::uint8_t {
  kCommittable = 0,
  kInsufficientCapacity = 1,
  kPolicyRejected = 2,
  kStaleResource = 3,
  kStalePathAuthority = 4,
  kConflictingReservation = 5,
  kInvalidInterval = 6,
  kClaimantFenced = 7,
  kUnsupported = 8,
  kEmergencyOvercommit = 9,
  kIdempotentReplay = 10,
  kStaleEpoch = 11,
  kInvalidRequest = 12,
  kGenerationMismatch = 13,
  kResourceExhausted = 14,
  kConflict = 15,
};

[[nodiscard]] const char* to_string(AdmissionOutcome outcome) noexcept;
[[nodiscard]] Result<AdmissionOutcome> parse_admission_outcome(std::string_view text) noexcept;
/// Maps an outcome onto the error taxonomy used by Status-returning APIs.
[[nodiscard]] ErrorCode outcome_to_error_code(AdmissionOutcome outcome) noexcept;
/// True when the outcome means "the commitment exists / was made".
[[nodiscard]] bool outcome_is_acceptance(AdmissionOutcome outcome) noexcept;

/// Per-resource accounting evidence for one decision. Every field is the value
/// observed at the decision instant, so a report can be replayed as evidence.
struct CapabilityDelta {
  ResourceName resource;
  ResourceGeneration generation;
  Bandwidth reservable_capacity{0};
  Bandwidth protected_headroom{0};
  Bandwidth committable_ceiling{0};
  Bandwidth committed_peak_before{0};
  Bandwidth committed_peak_after{0};
  Bandwidth holds_peak{0};
  Bandwidth remaining_after{0};
  Interval window;
  bool maintenance_covers = false;
  bool overcommit_emergency = false;

  friend bool operator==(const CapabilityDelta& a, const CapabilityDelta& b) noexcept;
};

struct ConflictEntry {
  ReservationId id;                  ///< Reservation or hold identity.
  ReservationGeneration generation;
  ResourceName resource;
  Interval interval;
  Bandwidth amount{0};
  GuaranteeClass guarantee = GuaranteeClass::kGuaranteed;
  ReservationState state = ReservationState::kCommitted;
  bool is_hold = false;

  friend bool operator==(const ConflictEntry& a, const ConflictEntry& b) noexcept;
};

/// Bounded conflict explanation. total_considered is the true count; entries is
/// truncated to the policy bound with an explicit flag, never silently.
struct ConflictSet {
  std::vector<ConflictEntry> entries;
  std::size_t total_considered = 0;
  std::size_t scan_limit_hit = 0;  ///< >0 when the underlying scan was bounded.
  bool truncated = false;

  [[nodiscard]] bool empty() const noexcept { return entries.empty(); }
};

struct AdmissionReport {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  std::string explanation;  ///< Deterministic, bounded text.
  std::vector<CapabilityDelta> resources;  ///< Canonical resource order.
  ConflictSet conflicts;
  std::vector<ReservationId> preemption_plan;
  std::vector<ReservationGeneration> preemption_plan_generations;
  bool preemption_planned = false;
  ApplicabilityReason applicability_reason = ApplicabilityReason::kCurrent;
};

struct CommitResult {
  ReservationRecord record;
  bool has_series = false;
  ReservationSeries series;
  std::vector<ReservationRecord> members;  ///< Series members in index order.
  AdmissionReport report;
  bool replayed = false;  ///< True when an identical attempt returned a prior result.
  AttemptId attempt;
  DurableSequence sequence;
};

struct AmendmentResult {
  ReservationRecord predecessor;
  ReservationRecord successor;
  bool has_series = false;
  ReservationSeries series;
  std::vector<ReservationRecord> members;
  AdmissionReport report;
  bool replayed = false;
};

struct LifecycleResult {
  ReservationRecord record;
  bool replayed = false;
  std::size_t transitions = 0;
};

struct AttemptReconciliation {
  AttemptId attempt;
  bool known = false;             ///< False means: the coordinator has no record.
  AdmissionOutcome outcome = AdmissionOutcome::kInvalidRequest;
  ReservationId reservation;
  ReservationGeneration generation;
  DurableSequence sequence;
  bool committed = false;         ///< True only when durable commit provably happened.
  std::string note;
};

struct RemainingCapacity {
  ResourceName resource;
  ResourceGeneration generation;
  Interval window;
  Bandwidth committable_ceiling{0};
  Bandwidth committed_peak{0};
  Bandwidth holds_peak{0};
  Bandwidth remaining{0};
  bool maintenance_covers = false;
  bool overcommit_emergency = false;
};

struct ChangePoint {
  Timestamp at;
  Bandwidth committed{0};
  Bandwidth holds{0};
};

struct CapacityTimeline {
  ResourceName resource;
  Interval window;
  std::vector<ChangePoint> points;
  bool truncated = false;
};

struct LineageView {
  ReservationId id;
  ReservationGeneration generation;
  std::vector<SupersessionEdge> ancestry;    ///< Oldest first, toward the root.
  std::vector<SupersessionEdge> descendants; ///< Newest last.
  bool truncated = false;
};

/// Degraded-state report: authoritative capacity is below committed
/// obligations. Commitments are never silently discarded; a policy decision is
/// required to resolve each entry.
struct OvercommitReport {
  struct Entry {
    ResourceName resource;
    ResourceGeneration generation;
    Bandwidth committed_peak{0};
    Bandwidth committable_ceiling{0};
    Interval window;
    Timestamp detected_at;
  };
  std::vector<Entry> entries;  ///< Active, unresolved entries.
  bool emergency_active = false;
};

struct CoordinatorStats {
  std::uint64_t commits = 0;
  std::uint64_t commit_rejections = 0;
  std::uint64_t replayed_attempts = 0;
  std::uint64_t amendments = 0;
  std::uint64_t releases = 0;
  std::uint64_t expiries = 0;
  std::uint64_t recalls = 0;
  std::uint64_t revocations = 0;
  std::uint64_t revalidations = 0;
  std::uint64_t fenced_holds = 0;
  std::uint64_t capacity_ingestions = 0;
  std::uint64_t generation_advances = 0;
  std::uint64_t durable_records = 0;
  std::uint64_t overcommit_events = 0;
  std::size_t tracked_reservations = 0;
  std::size_t tracked_series = 0;
  std::size_t live_holds = 0;
  std::size_t index_entries = 0;
  FabricEpoch epoch;
  Identity128 coordinator_boot;
  std::uint64_t journal_bytes = 0;
  std::uint64_t snapshot_sequence = 0;
};

}  // namespace brf

#endif  // BRF_OUTCOME_HPP
