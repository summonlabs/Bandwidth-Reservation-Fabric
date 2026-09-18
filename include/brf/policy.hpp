// Bandwidth Reservation Fabric - reservation policy records.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_POLICY_HPP
#define BRF_POLICY_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "brf/bandwidth.hpp"
#include "brf/error.hpp"
#include "brf/identity.hpp"
#include "brf/time.hpp"

namespace brf {

/// Guarantee classes, ordered from weakest to strongest. Ordering is load
/// bearing: deterministic victim selection and recall permission derive from it.
enum class GuaranteeClass : std::uint8_t {
  kScavenger = 0,   ///< Recallable at will; first to be displaced.
  kPreemptible = 1, ///< Recallable under policy.
  kProtected = 2,   ///< Recallable only when the contract permits it.
  kGuaranteed = 3,  ///< Not recallable unless the contract explicitly permits it.
};

[[nodiscard]] const char* to_string(GuaranteeClass cls) noexcept;
[[nodiscard]] Result<GuaranteeClass> parse_guarantee_class(std::string_view text) noexcept;

inline constexpr std::uint32_t kMaxPriority = 1000;
inline constexpr std::size_t kMaxPolicyLabels = 16;
inline constexpr std::size_t kMaxLabelBytes = 64;

/// Policy record. Policies never hold runtime state; they are immutable,
/// generation-stamped statements consulted during admission.
struct PolicyRecord {
  PolicyName name;
  PolicyGeneration generation;
  Timestamp ingested_at;

  // --- Recall and preemption -------------------------------------------------
  /// Contract override: permit recall of kGuaranteed reservations. Off by
  /// default; a guarantee that can be recalled silently is not a guarantee.
  bool allow_recall_guaranteed = false;
  /// Permit recalling kProtected reservations.
  bool allow_recall_protected = true;
  /// Permit admission to displace weaker reservations when capacity is short.
  bool allow_preemption_on_commit = false;
  std::uint32_t max_preemption_victims = 0;
  /// Grace interval applied after a recall takes effect before the reservation
  /// stops consuming capacity, when the caller does not specify one.
  Duration default_recall_grace{0};

  // --- Capacity semantics ----------------------------------------------------
  /// Controlled overbooking: allow commits that exceed the committable ceiling
  /// by at most overcommit_allowance.
  bool allow_overcommit = false;
  Bandwidth overcommit_allowance{0};
  /// Reject a commit whose amount is below this fraction of capacity? No:
  /// minimum acceptable reservation amount for this policy (0 = no minimum).
  Bandwidth minimum_reservation_amount{0};

  // --- Interval semantics ----------------------------------------------------
  /// Permit a requested start earlier than "now". Off by default: a commitment
  /// that begins in the past cannot be honoured as a future commitment.
  bool allow_past_start = false;
  /// Maximum distance between now and the interval start.
  Duration max_future_horizon{0};  ///< 0 means unlimited within kMaxReservationSpanNs.
  /// Maximum headroom that may be requested on top of the resource headroom.
  Bandwidth max_extra_headroom{0};

  // --- Generation semantics --------------------------------------------------
  /// Automatically re-derive a new reservation generation when the bound
  /// resource/path generation advances. Off by default: revalidation is an
  /// explicit authority transition, never a silent upgrade.
  bool auto_revalidate_on_generation_change = false;
  /// Additional headroom required by policy, per resource.
  Bandwidth policy_headroom{0};

  // --- Bounded outputs -------------------------------------------------------
  std::uint32_t max_conflict_set = 64;
  std::uint32_t max_explanation_bytes = 4096;
  std::uint32_t max_series_members = 64;
  Duration max_hold_ttl{0};
  std::uint32_t max_holds_per_session = 32;
  Bandwidth max_hold_bandwidth{0};

  /// Fields whose change is material enough to require revalidation of
  /// reservations bound to the previous generation.
  [[nodiscard]] bool materially_differs(const PolicyRecord& other) const noexcept;

  friend bool operator==(const PolicyRecord& a, const PolicyRecord& b) noexcept;
};

/// Current policy table. Same regeneration rules as the capacity ledger.
class PolicyRegistry {
 public:
  [[nodiscard]] Result<bool> apply(const PolicyRecord& record);

  struct Entry {
    PolicyRecord record;
    std::vector<PolicyGeneration> prior_generations;
    Timestamp ingested_at;
  };

  /// Snapshot restore only (see CapacityLedger::inject).
  void inject(Entry entry);

  [[nodiscard]] const Entry* find(const PolicyName& name) const noexcept;
  [[nodiscard]] const PolicyRecord* current(const PolicyName& name) const noexcept;
  [[nodiscard]] std::vector<PolicyName> policy_names() const;
  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
  void clear() noexcept { entries_.clear(); }

  /// Built-in fallback policy, used when a request names an unknown policy.
  [[nodiscard]] static PolicyRecord strict_default(PolicyName name);

 private:
  std::map<PolicyName, Entry> entries_;
};

/// Structural validation for a policy record as supplied by an authority.
[[nodiscard]] Status validate_policy(const PolicyRecord& record);

}  // namespace brf

#endif  // BRF_POLICY_HPP
