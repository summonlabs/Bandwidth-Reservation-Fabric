// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/reservation.hpp"

#include <algorithm>
#include <array>

#include "brf/capacity.hpp"
#include "brf/hash.hpp"

namespace brf {
namespace {

[[nodiscard]] bool label_is_safe(std::string_view label) noexcept {
  if (label.empty() || label.size() > kMaxLabelBytes) return false;
  for (char ch : label) {
    const unsigned char raw = static_cast<unsigned char>(ch);
    if (raw < 0x20U || raw > 0x7EU) return false;
  }
  return true;
}

}  // namespace

const char* to_string(ReservationState state) noexcept {
  switch (state) {
    case ReservationState::kDeclared: return "DECLARED";
    case ReservationState::kValidated: return "VALIDATED";
    case ReservationState::kPending: return "PENDING";
    case ReservationState::kCommitted: return "COMMITTED";
    case ReservationState::kActive: return "ACTIVE";
    case ReservationState::kAmendmentPending: return "AMENDMENT_PENDING";
    case ReservationState::kRecallPending: return "RECALL_PENDING";
    case ReservationState::kReleased: return "RELEASED";
    case ReservationState::kExpired: return "EXPIRED";
    case ReservationState::kRevoked: return "REVOKED";
    case ReservationState::kFenced: return "FENCED";
    case ReservationState::kStale: return "STALE";
    case ReservationState::kSuperseded: return "SUPERSEDED";
    case ReservationState::kRejected: return "REJECTED";
    case ReservationState::kRetired: return "RETIRED";
  }
  return "UNKNOWN";
}

Result<ReservationState> parse_reservation_state(std::string_view text) noexcept {
  constexpr std::array<std::pair<std::string_view, ReservationState>, 15> kStates{{
      {"DECLARED", ReservationState::kDeclared},
      {"VALIDATED", ReservationState::kValidated},
      {"PENDING", ReservationState::kPending},
      {"COMMITTED", ReservationState::kCommitted},
      {"ACTIVE", ReservationState::kActive},
      {"AMENDMENT_PENDING", ReservationState::kAmendmentPending},
      {"RECALL_PENDING", ReservationState::kRecallPending},
      {"RELEASED", ReservationState::kReleased},
      {"EXPIRED", ReservationState::kExpired},
      {"REVOKED", ReservationState::kRevoked},
      {"FENCED", ReservationState::kFenced},
      {"STALE", ReservationState::kStale},
      {"SUPERSEDED", ReservationState::kSuperseded},
      {"REJECTED", ReservationState::kRejected},
      {"RETIRED", ReservationState::kRetired},
  }};
  for (const auto& entry : kStates) {
    if (entry.first == text) return entry.second;
  }
  return make_error(ErrorCode::kInvalidArgument, "unknown reservation state");
}

bool consumes_capacity(ReservationState state) noexcept {
  switch (state) {
    case ReservationState::kCommitted:
    case ReservationState::kActive:
    case ReservationState::kRecallPending:
      return true;
    default:
      return false;
  }
}

bool is_terminal(ReservationState state) noexcept {
  switch (state) {
    case ReservationState::kReleased:
    case ReservationState::kExpired:
    case ReservationState::kRevoked:
    case ReservationState::kFenced:
    case ReservationState::kStale:
    case ReservationState::kSuperseded:
    case ReservationState::kRejected:
    case ReservationState::kRetired:
      return true;
    default:
      return false;
  }
}

const char* to_string(ApplicabilityReason reason) noexcept {
  switch (reason) {
    case ApplicabilityReason::kCurrent: return "CURRENT";
    case ApplicabilityReason::kResourceGenerationChanged: return "RESOURCE_GENERATION_CHANGED";
    case ApplicabilityReason::kResourceWithdrawn: return "RESOURCE_WITHDRAWN";
    case ApplicabilityReason::kPathGenerationChanged: return "PATH_GENERATION_CHANGED";
    case ApplicabilityReason::kPathRetired: return "PATH_RETIRED";
    case ApplicabilityReason::kMaintenanceWindowAdded: return "MAINTENANCE_WINDOW_ADDED";
    case ApplicabilityReason::kPolicyMaterialChange: return "POLICY_MATERIAL_CHANGE";
    case ApplicabilityReason::kFailureDomainGenerationChanged: return "FAILURE_DOMAIN_GENERATION_CHANGED";
    case ApplicabilityReason::kCapacityReducedBelowCommitments: return "CAPACITY_REDUCED_BELOW_COMMITMENTS";
  }
  return "UNKNOWN";
}

const char* to_string(Applicability applicability) noexcept {
  switch (applicability) {
    case Applicability::kCurrent: return "CURRENT";
    case Applicability::kRevalidationRequired: return "REVALIDATION_REQUIRED";
    case Applicability::kStale: return "STALE";
  }
  return "UNKNOWN";
}

bool operator==(const ReservationTerms& a, const ReservationTerms& b) noexcept {
  return a.claimant == b.claimant && a.claimant_generation == b.claimant_generation &&
         a.binding_kind == b.binding_kind && a.resources == b.resources && a.path == b.path &&
         a.required_path_generation == b.required_path_generation && a.interval == b.interval &&
         a.amount == b.amount && a.minimum_amount == b.minimum_amount &&
         a.maximum_amount == b.maximum_amount && a.guarantee == b.guarantee && a.priority == b.priority &&
         a.preemptible == b.preemptible && a.recall_permitted == b.recall_permitted && a.grace == b.grace &&
         a.headroom_requirement == b.headroom_requirement && a.policy == b.policy &&
         a.policy_labels == b.policy_labels && a.recurrence == b.recurrence;
}

bool operator==(const ReservationSeries& a, const ReservationSeries& b) noexcept {
  return a.id == b.id && a.generation == b.generation && a.claimant == b.claimant &&
         a.claimant_generation == b.claimant_generation && a.spec == b.spec &&
         a.first_interval == b.first_interval && a.amount == b.amount && a.state == b.state &&
         a.members == b.members;
}

Status validate_terms(const ReservationTerms& terms) {
  if (terms.claimant.is_nil()) {
    return make_error(ErrorCode::kInvalidIdentity, "claimant identity must not be nil");
  }
  if (terms.claimant_generation.value() == 0) {
    return make_error(ErrorCode::kInvalidIdentity, "claimant generation must be non-zero");
  }
  Status interval_ok = validate_interval(terms.interval);
  if (!interval_ok) return interval_ok.error();

  if (terms.amount.bps <= 0) {
    return make_error(ErrorCode::kInvalidBandwidth, "reservation amount must be strictly positive");
  }
  if (terms.amount.bps > kMaxBandwidthBps) {
    return make_error(ErrorCode::kInvalidBandwidth, "reservation amount exceeds the representable range");
  }
  if (terms.minimum_amount.has_value()) {
    if (terms.minimum_amount->bps <= 0 || terms.minimum_amount->bps > kMaxBandwidthBps) {
      return make_error(ErrorCode::kInvalidBandwidth, "minimum amount is out of range");
    }
    if (terms.minimum_amount->bps > terms.amount.bps) {
      return make_error(ErrorCode::kInvalidBandwidth, "minimum amount exceeds the requested amount");
    }
  }
  if (terms.maximum_amount.has_value()) {
    if (terms.maximum_amount->bps <= 0 || terms.maximum_amount->bps > kMaxBandwidthBps) {
      return make_error(ErrorCode::kInvalidBandwidth, "maximum amount is out of range");
    }
    if (terms.maximum_amount->bps < terms.amount.bps) {
      return make_error(ErrorCode::kInvalidBandwidth, "maximum amount is below the requested amount");
    }
  }
  if (terms.headroom_requirement.bps < 0 || terms.headroom_requirement.bps > kMaxBandwidthBps) {
    return make_error(ErrorCode::kInvalidBandwidth, "headroom requirement is out of range");
  }

  if (terms.binding_kind == BindingKind::kResources) {
    if (terms.resources.empty()) {
      return make_error(ErrorCode::kInvalidArgument, "a resource binding must name at least one resource");
    }
    if (terms.resources.size() > kMaxBindingResources) {
      return make_error(ErrorCode::kResourceExhausted, "resource binding exceeds the maximum width");
    }
    if (!terms.path.empty()) {
      return make_error(ErrorCode::kInvalidArgument, "a resource binding must not carry a path name");
    }
    std::vector<ResourceName> sorted = terms.resources;
    std::sort(sorted.begin(), sorted.end());
    if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
      return make_error(ErrorCode::kConflict, "resource binding names the same resource twice");
    }
    for (const ResourceName& name : terms.resources) {
      if (name.empty()) {
        return make_error(ErrorCode::kInvalidName, "resource binding contains an empty name");
      }
    }
  } else {
    if (terms.path.empty()) {
      return make_error(ErrorCode::kInvalidName, "a path binding must name a path");
    }
    if (!terms.resources.empty()) {
      return make_error(ErrorCode::kInvalidArgument,
                        "a path binding must not pre-declare resources; components come from path authority");
    }
  }

  if (terms.policy.empty()) {
    return make_error(ErrorCode::kInvalidName, "reservation terms must name a policy");
  }
  if (terms.priority > kMaxPriority) {
    return make_error(ErrorCode::kInvalidArgument, "priority is out of range");
  }
  if (terms.guarantee == GuaranteeClass::kGuaranteed && terms.preemptible) {
    return make_error(ErrorCode::kConflict, "a guaranteed reservation cannot be preemptible");
  }
  if (terms.grace.ns < 0 || terms.grace.ns > kMaxReservationSpanNs) {
    return make_error(ErrorCode::kInvalidInterval, "grace interval is out of range");
  }
  if (terms.policy_labels.size() > kMaxPolicyLabels) {
    return make_error(ErrorCode::kResourceExhausted, "too many policy labels");
  }
  for (const std::string& label : terms.policy_labels) {
    if (!label_is_safe(label)) {
      return make_error(ErrorCode::kInvalidArgument, "policy label is empty, too long, or not printable ASCII");
    }
  }
  if (terms.recurrence.enabled) {
    if (terms.recurrence.count < 1) {
      return make_error(ErrorCode::kInvalidArgument, "a recurrence series must have at least one member");
    }
    if (terms.recurrence.count > 1 && terms.recurrence.period.ns <= 0) {
      return make_error(ErrorCode::kInvalidArgument, "a recurring series must have a positive period");
    }
    if (terms.recurrence.period.ns < 0) {
      return make_error(ErrorCode::kInvalidArgument, "recurrence period must not be negative");
    }
  }
  return {};
}

Interval ReservationRecord::consuming_interval() const noexcept {
  Interval window = terms.interval;
  if (recall_effective_at.ns > 0 && recall_effective_at < window.end) {
    // The commitment keeps consuming capacity through its recall grace: the
    // grace exists precisely so that traffic can drain after a recall is
    // acknowledged rather than the capacity vanishing underneath it.
    const std::int64_t released_at = recall_effective_at.ns + recall_grace.ns;
    const std::int64_t effective_end = released_at > window.end.ns ? window.end.ns : released_at;
    window.end = Timestamp{effective_end < window.start.ns ? window.start.ns : effective_end};
  }
  return window;
}

Result<std::vector<Interval>> expand_series(const Interval& first_interval, const RecurrenceSpec& spec,
                                            std::uint32_t max_members) noexcept {
  if (!spec.enabled) {
    return std::vector<Interval>{first_interval};
  }
  if (spec.count == 0) {
    return make_error(ErrorCode::kInvalidArgument, "series member count must be non-zero");
  }
  if (spec.count > max_members) {
    return make_error(ErrorCode::kResourceExhausted, "series member count exceeds the policy bound");
  }
  Status first_ok = validate_interval(first_interval);
  if (!first_ok) return first_ok.error();
  if (spec.count > 1 && spec.period.ns <= 0) {
    return make_error(ErrorCode::kInvalidArgument, "series period must be positive");
  }
  const std::int64_t span = first_interval.end.ns - first_interval.start.ns;
  if (spec.count > 1 && spec.period.ns < span) {
    return make_error(ErrorCode::kInvalidArgument,
                      "series members must not overlap: the period must be at least the member duration");
  }
  std::vector<Interval> members;
  members.reserve(spec.count);
  const std::int64_t count = static_cast<std::int64_t>(spec.count);
  if (spec.period.ns > 0 && count - 1 > (kMaxTimestampNs - first_interval.start.ns) / spec.period.ns) {
    return make_error(ErrorCode::kOverflow, "series expansion overflows the fabric timeline");
  }
  for (std::int64_t i = 0; i < count; ++i) {
    const std::int64_t offset = i * spec.period.ns;
    const std::int64_t start = first_interval.start.ns + offset;
    if (start > kMaxTimestampNs || span > kMaxTimestampNs - start) {
      return make_error(ErrorCode::kOverflow, "series member interval overflows the fabric timeline");
    }
    Interval member{Timestamp{start}, Timestamp{start + span}};
    Status member_ok = validate_interval(member);
    if (!member_ok) return member_ok.error();
    members.push_back(member);
  }
  return members;
}

ReservationId derive_member_id(const ReservationSeriesId& series, SeriesIndex index) noexcept {
  return Identity128::derive(series, index.value());
}

ReservationId derive_series_id(const ClaimantId& claimant, const AttemptId& attempt,
                               std::uint64_t ordinal) noexcept {
  std::array<std::uint8_t, 16 * 2 + 8> buffer{};
  std::copy(claimant.bytes().begin(), claimant.bytes().end(), buffer.begin());
  std::copy(attempt.bytes().begin(), attempt.bytes().end(), buffer.begin() + 16);
  for (std::size_t i = 0; i < 8; ++i) {
    buffer[32 + i] = static_cast<std::uint8_t>((ordinal >> (8 * (7 - i))) & 0xFFU);
  }
  return fingerprint128(buffer.data(), buffer.size());
}

}  // namespace brf
