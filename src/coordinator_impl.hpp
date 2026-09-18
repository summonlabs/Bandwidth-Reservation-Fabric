// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Private coordinator implementation. Not installed: this header exists only to
// keep the authoritative core in reviewable translation units.
#ifndef BRF_SRC_COORDINATOR_IMPL_HPP
#define BRF_SRC_COORDINATOR_IMPL_HPP

#include <atomic>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "brf/codec.hpp"
#include "brf/coordinator.hpp"
#include "brf/index.hpp"

namespace brf::detail {

struct ReservationKey {
  ReservationId id;
  ReservationGeneration generation;

  friend bool operator<(const ReservationKey& a, const ReservationKey& b) {
    if (!(a.id == b.id)) return a.id < b.id;
    return a.generation < b.generation;
  }
  friend bool operator==(const ReservationKey& a, const ReservationKey& b) {
    return a.id == b.id && a.generation == b.generation;
  }
};

struct SeriesKey {
  ReservationSeriesId id;
  SeriesGeneration generation;

  friend bool operator<(const SeriesKey& a, const SeriesKey& b) {
    if (!(a.id == b.id)) return a.id < b.id;
    return a.generation < b.generation;
  }
};

struct AttemptRecord {
  AttemptId attempt;
  Identity128 fingerprint;
  AdmissionOutcome outcome = AdmissionOutcome::kInvalidRequest;
  ReservationId reservation;
  ReservationGeneration generation;
  DurableSequence sequence;
  Identity128 claimant;
  Timestamp at;
};

struct FenceRecord {
  ClaimantId claimant;
  ClaimantGeneration claimant_generation;
  PublisherBootId boot;
  SessionId session;
  Timestamp at;
  std::string reason;
  bool claimant_wide = false;
};

struct OvercommitState {
  codec::OvercommitMutation mutation;
  bool resolved = false;
};

struct ResolvedBinding {
  BindingKind kind = BindingKind::kResources;
  PathName path;
  PathAuthorityGeneration path_generation;
  std::vector<ResourceRef> resources;
  std::vector<FailureDomainRef> failure_domains;
};

/// Result of one admission evaluation.
struct Assessment {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  std::string explanation;
  std::vector<CapabilityDelta> deltas;
  ConflictSet conflicts;
  std::vector<ReservationId> victims;
  std::vector<ReservationGeneration> victim_generations;
  bool preemption_planned = false;
  ApplicabilityReason reason = ApplicabilityReason::kCurrent;
};

[[nodiscard]] inline std::string window_text(const Interval& window) {
  return "[" + format_timestamp(window.start) + "," + format_timestamp(window.end) + ")";
}

}  // namespace brf::detail

namespace brf {

struct ReservationCoordinator::Impl {
  CoordinatorConfig config;
  std::shared_ptr<IClock> clock;
  std::unique_ptr<Store> store;
  CoordinatorIncarnation incarnation;
  Identity128 store_id;
  mutable std::mutex mutex;
  std::atomic<bool> stopping{false};
  CoordinatorStats stats;
  RecoveryReport recovery;

  CapacityLedger ledger;
  PathAuthorityTable paths;
  PolicyRegistry policies;
  CapacityIndex index;

  CapacitySnapshotId last_capacity_snapshot;
  CapacitySnapshotGeneration last_capacity_generation;
  CapacitySnapshotId last_path_snapshot;
  CapacitySnapshotGeneration last_path_generation;

  std::map<detail::ReservationKey, ReservationRecord> records;
  std::map<ReservationId, std::vector<ReservationGeneration>> generations;
  std::map<ReservationId, ReservationGeneration> current_generation;
  std::vector<SupersessionEdge> edges;
  std::map<detail::SeriesKey, ReservationSeries> series_records;
  std::map<ReservationSeriesId, SeriesGeneration> current_series;
  std::map<AttemptId, detail::AttemptRecord> attempts;
  std::deque<AttemptId> attempt_order;
  std::map<ClaimantId, ClaimantGeneration> claimants;
  std::map<PublisherBootId, detail::FenceRecord> fenced_boots;
  std::map<ClaimantId, detail::FenceRecord> fenced_claimants;
  std::map<HoldId, codec::HoldRecord> holds;
  std::deque<HoldId> released_holds;
  std::map<ResourceName, detail::OvercommitState> overcommit;
  std::map<ReservationId, ReservationRecord> retired;

  std::multimap<Timestamp, detail::ReservationKey> activation_queue;
  std::multimap<Timestamp, detail::ReservationKey> expiry_queue;
  std::multimap<Timestamp, detail::ReservationKey> recall_queue;

  std::size_t live_count = 0;
  std::size_t history_count = 0;
  PolicyRecord fallback_policy;

  Impl() = default;

  // ---- utility -------------------------------------------------------------
  [[nodiscard]] Timestamp now_locked() const { return clock->now(); }

  [[nodiscard]] Status validate_context_locked(const codec::RequestContext& context, bool require_attempt);
  [[nodiscard]] Result<DurableSequence> append_locked(codec::DurableRecord& record);
  [[nodiscard]] Provenance make_provenance_locked(const codec::RequestContext& context,
                                                  DurableSequence sequence, Timestamp at) const;
  [[nodiscard]] Status ensure_claimant_locked(const ClaimantId& claimant, ClaimantGeneration generation,
                                              Timestamp now);
  [[nodiscard]] Status release_hold_locked(const HoldId& id, const std::string& reason, bool fenced);
  void fence_holds_for_claimant_locked(const ClaimantId& claimant, ClaimantGeneration generation,
                                       const std::string& reason);
  void fence_holds_for_boot_locked(const PublisherBootId& boot, const std::string& reason);
  void fence_holds_for_session_locked(const SessionId& session, const std::string& reason);
  [[nodiscard]] const PolicyRecord& policy_for_locked(const PolicyName& name, std::string* note);
  [[nodiscard]] Result<detail::ResolvedBinding> resolve_binding_locked(const ReservationTerms& terms);

  // ---- index ---------------------------------------------------------------
  [[nodiscard]] bool indexable_locked(const ReservationRecord& record) const;
  [[nodiscard]] Status index_insert_locked(const ReservationRecord& record);
  [[nodiscard]] Status index_erase_locked(const ReservationRecord& record);
  [[nodiscard]] bool index_holds_locked(const ReservationRecord& record) const;
  [[nodiscard]] Status sync_index_locked(const ReservationRecord& record);
  [[nodiscard]] Status update_index_locked(const ReservationRecord& record);
  [[nodiscard]] Status rebuild_index_locked();
  /// Re-derives activation/expiry/recall schedules from the record set. Used
  /// once at the end of recovery so that no derived structure can survive a
  /// restart in a state that disagrees with durable facts.
  void rebuild_queues_locked();

  // ---- records -------------------------------------------------------------
  void register_record_locked(const ReservationRecord& record);
  void set_state_locked(ReservationRecord& record, ReservationState state, Timestamp at,
                        const std::string& reason, const Provenance& provenance);
  [[nodiscard]] ReservationRecord* current_record_locked(const ReservationId& id);
  [[nodiscard]] ReservationRecord* find_record_locked(const ReservationId& id,
                                                      ReservationGeneration generation);
  [[nodiscard]] const ReservationRecord* find_record_const_locked(const ReservationId& id,
                                                                  ReservationGeneration generation) const;
  [[nodiscard]] detail::AttemptRecord* find_attempt_locked(const AttemptId& attempt);
  void remember_attempt_locked(const detail::AttemptRecord& record);
  void sync_queues_locked(const ReservationRecord& record);
  [[nodiscard]] Status mark_applicability_locked(ReservationRecord& record, Applicability applicability,
                                                 ApplicabilityReason reason, Timestamp at);

  // ---- admission -----------------------------------------------------------
  [[nodiscard]] detail::Assessment assess_locked(const ReservationTerms& terms,
                                                 const detail::ResolvedBinding& binding,
                                                 const PolicyRecord& policy, Timestamp now,
                                                 std::size_t conflict_bound, std::size_t explanation_bound);
  [[nodiscard]] std::vector<IndexEntry> preemption_candidates_locked(const ResourceName& resource,
                                                                     const Interval& window,
                                                                     GuaranteeClass requester,
                                                                     const PolicyRecord& policy,
                                                                     const ReservationId& self) const;

  /// Removes entries from the live index for the duration of an evaluation and
  /// restores them unless the caller commits to their replacement. Rollback is
  /// purely in-memory: no durable write happens inside the window, so a crash
  /// can never observe the intermediate state.
  struct Suspension {
    Impl& impl;
    std::vector<IndexEntry> entries;
    bool kept = false;

    explicit Suspension(Impl& owner) : impl(owner) {}
    Suspension(const Suspension&) = delete;
    Suspension& operator=(const Suspension&) = delete;
    ~Suspension() {
      if (!kept) restore();
    }
    [[nodiscard]] Status suspend(const ReservationRecord& record);
    [[nodiscard]] Status suspend_hold(const HoldId& id);
    void restore();
    void keep() { kept = true; }
  };

  // ---- lifecycle -----------------------------------------------------------
  [[nodiscard]] Status transition_locked(ReservationRecord& record, ReservationState target, Timestamp at,
                                         const std::string& reason,
                                         const codec::RequestContext& context,
                                         Timestamp recall_effective_at, detail::AttemptRecord* attempt_out);
  [[nodiscard]] Status reconcile_locked(Timestamp now);
  [[nodiscard]] Status release_terminal_history_locked(Timestamp now);
  [[nodiscard]] Status detect_overcommit_locked(const ResourceName& resource, Timestamp now);
  [[nodiscard]] Status refresh_applicability_locked(Timestamp now, bool auto_revalidate);
  [[nodiscard]] Status auto_revalidate_record_locked(ReservationRecord& record, ApplicabilityReason reason,
                                                     Timestamp now,
                                                     const codec::RequestContext& context);

  // ---- operations ----------------------------------------------------------
  [[nodiscard]] Result<CommitResult> create_locked(const codec::RequestContext& context,
                                                   const ReservationTerms& terms,
                                                   const ReservationId& requested_id, bool dry_run,
                                                   const std::vector<HoldId>& consume_holds);
  [[nodiscard]] Result<AmendmentResult> amend_locked(const codec::RequestContext& context,
                                                     const ReservationId& target,
                                                     ReservationGeneration target_generation,
                                                     const ReservationTerms& terms, bool dry_run);
  [[nodiscard]] Result<LifecycleResult> release_locked(const codec::RequestContext& context,
                                                       const ReservationId& id,
                                                       ReservationGeneration generation);
  [[nodiscard]] Result<LifecycleResult> recall_locked(const codec::RequestContext& context,
                                                      const ReservationId& id,
                                                      ReservationGeneration generation,
                                                      Timestamp effective_at, Duration grace, bool force);
  [[nodiscard]] Result<LifecycleResult> revoke_locked(const codec::RequestContext& context,
                                                      const ReservationId& id,
                                                      ReservationGeneration generation);
  [[nodiscard]] Result<LifecycleResult> revalidate_locked(const codec::RequestContext& context,
                                                          const ReservationId& id,
                                                          ReservationGeneration generation,
                                                          bool mark_stale);
  [[nodiscard]] Result<LifecycleResult> reconcile_lifecycle_locked(const codec::RequestContext& context);
  [[nodiscard]] Result<AttemptReconciliation> reconcile_attempt_locked(const codec::RequestContext& context,
                                                                       const AttemptId& attempt);

  [[nodiscard]] Status ingest_capacity_locked(const CapacitySnapshot& snapshot,
                                              const std::vector<ResourceName>& withdrawals,
                                              const codec::RequestContext& context);
  [[nodiscard]] Status ingest_paths_locked(const PathAuthoritySnapshot& snapshot,
                                           const codec::RequestContext& context);
  [[nodiscard]] Status ingest_policy_locked(const PolicyRecord& record,
                                            const codec::RequestContext& context);
  [[nodiscard]] Status register_claimant_locked(const ClaimantId& claimant, ClaimantGeneration generation,
                                                const codec::RequestContext& context);
  [[nodiscard]] Status fence_locked(const codec::RequestContext& context, const ClaimantId& claimant,
                                    ClaimantGeneration generation, const PublisherBootId& boot,
                                    const SessionId& session, bool claimant_wide);

  // ---- persistence ---------------------------------------------------------
  [[nodiscard]] codec::SnapshotState snapshot_state_locked() const;
  void apply_snapshot_locked(const codec::SnapshotState& state);
  [[nodiscard]] Status apply_replay_locked(const codec::DurableRecord& record);
  [[nodiscard]] Status compact_locked();

  // ---- audit ---------------------------------------------------------------
  [[nodiscard]] std::vector<std::string> audit_locked() const;
};

}  // namespace brf

#endif  // BRF_SRC_COORDINATOR_IMPL_HPP
