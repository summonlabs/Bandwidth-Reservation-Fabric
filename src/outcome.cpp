// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/outcome.hpp"

#include <array>
#include <utility>

namespace brf {
namespace {

constexpr std::array<std::pair<std::string_view, AdmissionOutcome>, 16> kOutcomes{{
    {"COMMITTABLE", AdmissionOutcome::kCommittable},
    {"INSUFFICIENT_CAPACITY", AdmissionOutcome::kInsufficientCapacity},
    {"POLICY_REJECTED", AdmissionOutcome::kPolicyRejected},
    {"STALE_RESOURCE", AdmissionOutcome::kStaleResource},
    {"STALE_PATH_AUTHORITY", AdmissionOutcome::kStalePathAuthority},
    {"CONFLICTING_RESERVATION", AdmissionOutcome::kConflictingReservation},
    {"INVALID_INTERVAL", AdmissionOutcome::kInvalidInterval},
    {"CLAIMANT_FENCED", AdmissionOutcome::kClaimantFenced},
    {"UNSUPPORTED", AdmissionOutcome::kUnsupported},
    {"EMERGENCY_OVERCOMMIT", AdmissionOutcome::kEmergencyOvercommit},
    {"IDEMPOTENT_REPLAY", AdmissionOutcome::kIdempotentReplay},
    {"STALE_EPOCH", AdmissionOutcome::kStaleEpoch},
    {"INVALID_REQUEST", AdmissionOutcome::kInvalidRequest},
    {"GENERATION_MISMATCH", AdmissionOutcome::kGenerationMismatch},
    {"RESOURCE_EXHAUSTED", AdmissionOutcome::kResourceExhausted},
    {"CONFLICT", AdmissionOutcome::kConflict},
}};

}  // namespace

const char* to_string(AdmissionOutcome outcome) noexcept {
  for (const auto& entry : kOutcomes) {
    if (entry.second == outcome) return entry.first.data();
  }
  return "UNKNOWN";
}

Result<AdmissionOutcome> parse_admission_outcome(std::string_view text) noexcept {
  for (const auto& entry : kOutcomes) {
    if (entry.first == text) return entry.second;
  }
  return make_error(ErrorCode::kInvalidArgument, "unknown admission outcome");
}

ErrorCode outcome_to_error_code(AdmissionOutcome outcome) noexcept {
  switch (outcome) {
    case AdmissionOutcome::kCommittable: return ErrorCode::kOk;
    case AdmissionOutcome::kInsufficientCapacity: return ErrorCode::kInsufficientCapacity;
    case AdmissionOutcome::kPolicyRejected: return ErrorCode::kPolicyRejected;
    case AdmissionOutcome::kStaleResource: return ErrorCode::kStaleGeneration;
    case AdmissionOutcome::kStalePathAuthority: return ErrorCode::kStaleGeneration;
    case AdmissionOutcome::kConflictingReservation: return ErrorCode::kConflict;
    case AdmissionOutcome::kInvalidInterval: return ErrorCode::kInvalidInterval;
    case AdmissionOutcome::kClaimantFenced: return ErrorCode::kFencedClaimant;
    case AdmissionOutcome::kUnsupported: return ErrorCode::kUnsupported;
    case AdmissionOutcome::kEmergencyOvercommit: return ErrorCode::kCapacityOvercommit;
    case AdmissionOutcome::kIdempotentReplay: return ErrorCode::kIdempotentReplay;
    case AdmissionOutcome::kStaleEpoch: return ErrorCode::kStaleEpoch;
    case AdmissionOutcome::kInvalidRequest: return ErrorCode::kInvalidArgument;
    case AdmissionOutcome::kGenerationMismatch: return ErrorCode::kGenerationMismatch;
    case AdmissionOutcome::kResourceExhausted: return ErrorCode::kResourceExhausted;
    case AdmissionOutcome::kConflict: return ErrorCode::kConflict;
  }
  return ErrorCode::kInternal;
}

bool outcome_is_acceptance(AdmissionOutcome outcome) noexcept {
  return outcome == AdmissionOutcome::kCommittable || outcome == AdmissionOutcome::kIdempotentReplay;
}

bool operator==(const CapabilityDelta& a, const CapabilityDelta& b) noexcept {
  return a.resource == b.resource && a.generation == b.generation &&
         a.reservable_capacity == b.reservable_capacity &&
         a.protected_headroom == b.protected_headroom &&
         a.committable_ceiling == b.committable_ceiling &&
         a.committed_peak_before == b.committed_peak_before &&
         a.committed_peak_after == b.committed_peak_after && a.holds_peak == b.holds_peak &&
         a.remaining_after == b.remaining_after && a.window == b.window &&
         a.maintenance_covers == b.maintenance_covers &&
         a.overcommit_emergency == b.overcommit_emergency;
}

bool operator==(const ConflictEntry& a, const ConflictEntry& b) noexcept {
  return a.id == b.id && a.generation == b.generation && a.resource == b.resource &&
         a.interval == b.interval && a.amount == b.amount && a.guarantee == b.guarantee &&
         a.state == b.state && a.is_hold == b.is_hold;
}

}  // namespace brf
