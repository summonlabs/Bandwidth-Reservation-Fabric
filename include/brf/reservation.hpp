// Bandwidth Reservation Fabric - reservation terms, records, and lifecycle.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_RESERVATION_HPP
#define BRF_RESERVATION_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "brf/authority.hpp"
#include "brf/bandwidth.hpp"
#include "brf/error.hpp"
#include "brf/identity.hpp"
#include "brf/policy.hpp"
#include "brf/time.hpp"

namespace brf {

/// Lifecycle states. Separations that matter are preserved explicitly:
/// COMMITTED (durable, future) is distinct from ACTIVE (enforceable now), and
/// RELEASED (claimant action) is distinct from EXPIRED (time) and REVOKED
/// (authority action).
enum class ReservationState : std::uint8_t {
  kDeclared = 0,          ///< Parsed; identity assigned; nothing validated.
  kValidated = 1,         ///< Structurally valid; no capacity decision made.
  kPending = 2,           ///< Admission in progress under one attempt.
  kCommitted = 3,         ///< Durable commitment; interval has not opened yet.
  kActive = 4,            ///< Durable commitment; interval currently open.
  kAmendmentPending = 5,  ///< A successor generation is being admitted.
  kRecallPending = 6,     ///< Recall recorded; effect not yet reached.
  kReleased = 7,          ///< Explicit claimant release.
  kExpired = 8,           ///< Interval ended.
  kRevoked = 9,           ///< Authority withdrew the commitment.
  kFenced = 10,           ///< Owning session/boot lost authority before commit.
  kStale = 11,            ///< Bound generation no longer current; revalidation refused.
  kSuperseded = 12,       ///< A successor generation replaced these terms.
  kRejected = 13,         ///< Admission refused; retained as history only.
  kRetired = 14,          ///< Terminal archival state; lineage retained.
};

[[nodiscard]] const char* to_string(ReservationState state) noexcept;
[[nodiscard]] Result<ReservationState> parse_reservation_state(std::string_view text) noexcept;

/// True for states that consume reservable capacity for at least part of their
/// interval. This is the single predicate the accounting layer trusts.
[[nodiscard]] bool consumes_capacity(ReservationState state) noexcept;

/// True for terminal states: no further authority-bearing transition is legal.
[[nodiscard]] bool is_terminal(ReservationState state) noexcept;

/// Orthogonal applicability axis. A reservation can be COMMITTED yet not
/// currently enforceable because the generations it was bound to moved.
enum class Applicability : std::uint8_t {
  kCurrent = 0,
  kRevalidationRequired = 1,
  kStale = 2,
};

[[nodiscard]] const char* to_string(Applicability applicability) noexcept;

/// Why a bound generation stopped being current.
enum class ApplicabilityReason : std::uint8_t {
  kCurrent = 0,
  kResourceGenerationChanged,
  kResourceWithdrawn,
  kPathGenerationChanged,
  kPathRetired,
  kMaintenanceWindowAdded,
  kPolicyMaterialChange,
  kFailureDomainGenerationChanged,
  kCapacityReducedBelowCommitments,
};

[[nodiscard]] const char* to_string(ApplicabilityReason reason) noexcept;

/// Recurrence description. Members are expanded deterministically at admission
/// time; a series is a grouping of ordinary reservations, not a special kind of
/// capacity.
struct RecurrenceSpec {
  bool enabled = false;
  Duration period{0};   ///< Gap between consecutive member starts; must be > 0.
  std::uint32_t count = 1;  ///< Member count, bounded by policy.

  friend bool operator==(const RecurrenceSpec& a, const RecurrenceSpec& b) noexcept {
    return a.enabled == b.enabled && a.period == b.period && a.count == b.count;
  }
};

/// Requested reservation terms. Everything an admission decision needs, and
/// nothing that belongs to another runtime (no queue, scheduler, or path-plan
/// state).
struct ReservationTerms {
  ClaimantId claimant;
  ClaimantGeneration claimant_generation;
  BindingKind binding_kind = BindingKind::kResources;

  /// Direct resource set (binding_kind == kResources). Canonical order.
  std::vector<ResourceName> resources;
  /// Path binding (binding_kind == kPath). Components are expanded from the
  /// bound path authority generation, never guessed.
  PathName path;
  PathAuthorityGeneration required_path_generation;  ///< Zero means "current at admission".

  Interval interval;
  Bandwidth amount;
  std::optional<Bandwidth> minimum_amount;  ///< Negotiation floor.
  std::optional<Bandwidth> maximum_amount;  ///< Negotiation ceiling.
  GuaranteeClass guarantee = GuaranteeClass::kGuaranteed;
  std::uint32_t priority = 0;  ///< 0..kMaxPriority; higher wins ties.
  bool preemptible = false;
  /// Contract-level permission to recall this reservation. Guaranteed and
  /// protected reservations are not recallable without it.
  bool recall_permitted = false;
  Duration grace{0};                ///< Interval after the end during which the
                                    ///< commitment is retained before retirement.
  Bandwidth headroom_requirement{0};  ///< Extra uncommitted headroom demanded.
  PolicyName policy;                ///< Governing policy.
  std::vector<std::string> policy_labels;  ///< Bounded labels, canonical order.
  RecurrenceSpec recurrence;

  friend bool operator==(const ReservationTerms& a, const ReservationTerms& b) noexcept;
};

/// Structural validation of caller-supplied terms, before any capacity or
/// generation reasoning happens.
[[nodiscard]] Status validate_terms(const ReservationTerms& terms);

/// A durable, generation-stamped reservation record.
struct ReservationRecord {
  ReservationId id;
  ReservationGeneration generation;
  bool series_member = false;
  ReservationSeriesId series;
  SeriesIndex series_index;
  ReservationTerms terms;
  AuthorityVector authority;
  ReservationState state = ReservationState::kDeclared;
  Applicability applicability = Applicability::kCurrent;
  ApplicabilityReason applicability_reason = ApplicabilityReason::kCurrent;
  Timestamp declared_at;
  Timestamp committed_at;
  Timestamp activated_at;
  Timestamp state_changed_at;
  Timestamp recall_effective_at;   ///< Zero when no recall is pending/effective.
  /// Grace interval granted after the recall effect instant before the
  /// commitment stops consuming capacity. Zero means the recall takes effect
  /// exactly at recall_effective_at.
  Duration recall_grace{0};
  Timestamp terminated_at;
  /// Lineage: the generation this record replaced (nil for a first generation).
  ReservationId predecessor;
  ReservationGeneration predecessor_generation;
  /// Bounded, sanitized explanation for the current state.
  std::string state_reason;
  Provenance last_provenance;
  DurableSequence sequence;

  [[nodiscard]] bool consumes() const noexcept { return consumes_capacity(state) && applicability != Applicability::kStale; }
  [[nodiscard]] Bandwidth amount() const noexcept { return terms.amount; }
  [[nodiscard]] const Interval& interval() const noexcept { return terms.interval; }
  /// Effective consuming interval: a recall shortens it at the effect instant.
  [[nodiscard]] Interval consuming_interval() const noexcept;
};

/// Durable amendment/supersession edge. Lineage must remain acyclic and every
/// superseded generation must remain queryable.
struct SupersessionEdge {
  ReservationId predecessor;
  ReservationGeneration predecessor_generation;
  ReservationId successor;
  ReservationGeneration successor_generation;
  Timestamp recorded_at;
  DurableSequence sequence;
  std::string reason;

  friend bool operator==(const SupersessionEdge& a, const SupersessionEdge& b) noexcept {
    return a.predecessor == b.predecessor && a.predecessor_generation == b.predecessor_generation &&
           a.successor == b.successor && a.successor_generation == b.successor_generation;
  }
};

/// A recurrence series: a durable grouping of member reservations that were
/// admitted, amended, and released together.
struct ReservationSeries {
  ReservationSeriesId id;
  SeriesGeneration generation;
  ClaimantId claimant;
  ClaimantGeneration claimant_generation;
  RecurrenceSpec spec;
  Interval first_interval;
  Bandwidth amount;  ///< Amount of each member.
  ReservationState state = ReservationState::kDeclared;
  Timestamp created_at;
  Timestamp state_changed_at;
  ReservationId predecessor_series_generation;  ///< Series this one replaced (nil if first).
  SeriesGeneration predecessor_generation;
  std::vector<ReservationId> members;  ///< Canonical order by series index.
  Provenance last_provenance;
  DurableSequence sequence;

  friend bool operator==(const ReservationSeries& a, const ReservationSeries& b) noexcept;
};

/// Deterministic expansion of a recurrence spec. Member i starts at
/// first_interval.start + i*period and has the same duration as the first
/// interval. Identity of member i is derived from the series identity and i, so
/// the same request always produces the same member identities.
[[nodiscard]] Result<std::vector<Interval>> expand_series(const Interval& first_interval,
                                                          const RecurrenceSpec& spec,
                                                          std::uint32_t max_members) noexcept;

[[nodiscard]] ReservationId derive_member_id(const ReservationSeriesId& series, SeriesIndex index) noexcept;
[[nodiscard]] ReservationId derive_series_id(const ClaimantId& claimant, const AttemptId& attempt,
                                             std::uint64_t ordinal) noexcept;

}  // namespace brf

#endif  // BRF_RESERVATION_HPP
