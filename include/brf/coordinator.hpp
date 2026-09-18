// Bandwidth Reservation Fabric - reservation coordinator (authoritative core).
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_COORDINATOR_HPP
#define BRF_COORDINATOR_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "brf/capacity.hpp"
#include "brf/clock.hpp"
#include "brf/codec.hpp"
#include "brf/index.hpp"
#include "brf/outcome.hpp"
#include "brf/policy.hpp"
#include "brf/reservation.hpp"
#include "brf/store.hpp"

namespace brf {

struct CoordinatorConfig {
  std::string store_directory;
  std::shared_ptr<IClock> clock;
  /// Bound on tracked live reservations (committed/active/pending).
  std::size_t max_live_reservations = 262144;
  /// Bound on terminal history retained in memory (lineage queries).
  std::size_t max_history_records = 262144;
  /// Bound on recorded attempts used for idempotency/reconciliation.
  std::size_t max_attempts = 262144;
  /// Bound on overlap enumeration performed by one admission decision.
  std::size_t index_scan_limit = 8192;
  /// Coordinator-level kill switch: even when a policy permits preemption,
  /// preemption is only planned when this is enabled.
  bool enable_preemption = true;
  /// Retain every durable record in memory for replay. Disabled in long runs to
  /// bound memory; enabled by default so inspection tooling sees full history.
  bool retain_journal_records = true;
  /// Optional fixed boot identity. Nil means "generate a fresh one", which is
  /// what production uses; tests pin it to make provenance reproducible.
  Identity128 boot_identity;
};

/// Deterministic identity of one coordinator boot.
struct CoordinatorIncarnation {
  Identity128 boot;   ///< Fresh on every open().
  FabricEpoch epoch;  ///< Monotonic across restarts; advanced on every open().
  DurableSequence sequence;
  Identity128 store;  ///< Identity of the durable store (snapshot/epoch lineage).
};

/// Authoritative reservation core. All authority-bearing operations take the
/// internal mutex for the whole decision, so a decision is atomic with respect
/// to every other decision. Durable records are flushed before the call
/// returns, so a returned success is always a durable fact.
class ReservationCoordinator {
 public:
  static Result<std::unique_ptr<ReservationCoordinator>> open(const CoordinatorConfig& config,
                                                              RecoveryReport* report_out = nullptr);

  ~ReservationCoordinator();
  ReservationCoordinator(const ReservationCoordinator&) = delete;
  ReservationCoordinator& operator=(const ReservationCoordinator&) = delete;

  // --- authority ingestion --------------------------------------------------
  [[nodiscard]] Status ingest_capacity(const CapacitySnapshot& snapshot, const std::vector<ResourceName>& withdrawals,
                                       const codec::RequestContext& context);
  [[nodiscard]] Status ingest_paths(const PathAuthoritySnapshot& snapshot, const codec::RequestContext& context);
  [[nodiscard]] Status ingest_policy(const PolicyRecord& record, const codec::RequestContext& context);
  [[nodiscard]] Status register_claimant(const ClaimantId& claimant, ClaimantGeneration generation,
                                         const codec::RequestContext& context);
  [[nodiscard]] Status fence(const codec::RequestContext& context, const ClaimantId& claimant,
                             ClaimantGeneration generation, const PublisherBootId& boot, const SessionId& session,
                             bool claimant_wide);

  // --- reservation operations ----------------------------------------------
  [[nodiscard]] Result<CommitResult> create_reservation(const codec::RequestContext& context,
                                                        const ReservationTerms& terms,
                                                        const ReservationId& requested_id, bool dry_run,
                                                        const std::vector<HoldId>& consume_holds);
  [[nodiscard]] Result<AmendmentResult> amend_reservation(const codec::RequestContext& context,
                                                          const ReservationId& target,
                                                          ReservationGeneration target_generation,
                                                          const ReservationTerms& terms, bool dry_run);
  [[nodiscard]] Result<LifecycleResult> release_reservation(const codec::RequestContext& context,
                                                            const ReservationId& id,
                                                            ReservationGeneration generation);
  [[nodiscard]] Result<LifecycleResult> recall_reservation(const codec::RequestContext& context,
                                                           const ReservationId& id,
                                                           ReservationGeneration generation,
                                                           Timestamp effective_at, Duration grace, bool force);
  [[nodiscard]] Result<LifecycleResult> revoke_reservation(const codec::RequestContext& context,
                                                           const ReservationId& id,
                                                           ReservationGeneration generation);
  [[nodiscard]] Result<LifecycleResult> revalidate_reservation(const codec::RequestContext& context,
                                                               const ReservationId& id,
                                                               ReservationGeneration generation,
                                                               bool mark_stale);
  [[nodiscard]] Result<AttemptReconciliation> reconcile_attempt(const codec::RequestContext& context,
                                                                const AttemptId& attempt);
  [[nodiscard]] Result<LifecycleResult> reconcile_lifecycle(const codec::RequestContext& context);

  // --- queries --------------------------------------------------------------
  [[nodiscard]] Result<ReservationRecord> get_reservation(const ReservationId& id,
                                                          const ReservationGeneration& generation);
  [[nodiscard]] Result<std::vector<ReservationRecord>> query_claimant(const ClaimantId& claimant,
                                                                      bool include_terminal);
  [[nodiscard]] Result<std::vector<ReservationRecord>> query_resource(const ResourceName& resource,
                                                                      const Interval& window,
                                                                      bool include_terminal);
  [[nodiscard]] Result<std::vector<RemainingCapacity>> query_remaining(const ResourceName& resource,
                                                                       const Interval& window);
  [[nodiscard]] Result<CapacityTimeline> query_timeline(const ResourceName& resource, const Interval& window,
                                                        std::size_t max_points);
  [[nodiscard]] Result<LineageView> query_lineage(const ReservationId& id,
                                                  const ReservationGeneration& generation);
  [[nodiscard]] Result<AdmissionReport> explain_conflicts(const ReservationTerms& terms,
                                                          const ReservationId& candidate);
  [[nodiscard]] Result<OvercommitReport> overcommit_report();
  [[nodiscard]] CoordinatorStats stats() const;
  [[nodiscard]] CoordinatorIncarnation incarnation() const;
  [[nodiscard]] RecoveryReport recovery_report() const;
  [[nodiscard]] std::vector<codec::HoldRecord> holds() const;

  /// Brute-force recomputation of every accounting invariant, used by property
  /// tests and by the inspection tool. Returns a list of violated invariants
  /// (empty means the runtime is consistent).
  [[nodiscard]] std::vector<std::string> audit_invariants() const;

  // --- holds ----------------------------------------------------------------
  [[nodiscard]] Result<codec::HoldRecord> acquire_hold(const codec::RequestContext& context,
                                                       const ReservationTerms& terms, Timestamp expires_at);
  [[nodiscard]] Result<codec::HoldRecord> release_hold(const codec::RequestContext& context, const HoldId& id,
                                                       HoldGeneration generation);
  [[nodiscard]] Status release_session(const codec::RequestContext& context);

  /// Policy-driven resolution of an emergency overcommit state.
  ///
  /// kRetain acknowledges the degraded state: the emergency flag is cleared
  /// durably, existing commitments are preserved, and exact closure continues to
  /// be enforced for new commitments. kRevoke terminates the weakest
  /// reservations on the resource (weakest guarantee class first, then identity
  /// order) until the resource closes, durably, in one transition per revocation.
  enum class OvercommitResolution : std::uint8_t {
    kRetain = 0,
    kRevoke = 1,
  };

  [[nodiscard]] Status resolve_overcommit(const codec::RequestContext& context,
                                          const ResourceName& resource,
                                          OvercommitResolution resolution);

  // --- maintenance ----------------------------------------------------------
  [[nodiscard]] Status compact();
  [[nodiscard]] Status flush();
  /// Stops accepting new work. In-flight operations complete; no new operation
  /// starts after this returns. Idempotent.
  void begin_shutdown() noexcept;
  [[nodiscard]] bool shutting_down() const noexcept;

 private:
  ReservationCoordinator();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace brf

#endif  // BRF_COORDINATOR_HPP
