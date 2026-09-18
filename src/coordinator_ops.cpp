// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Coordinator public surface: request entry points and authority ingestion.
#include <algorithm>
#include <string>
#include <vector>

#include "coordinator_impl.hpp"

namespace brf {

// ---------------------------------------------------------------------------
// Path authority ingestion
// ---------------------------------------------------------------------------
Status ReservationCoordinator::Impl::ingest_paths_locked(const PathAuthoritySnapshot& snapshot,
                                                         const codec::RequestContext& context) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/false);
  if (!valid) return valid;
  if (snapshot.id.is_nil()) {
    return make_error(ErrorCode::kInvalidIdentity, "path snapshot must carry an identity");
  }
  if (snapshot.generation.value() == 0) {
    return make_error(ErrorCode::kInvalidArgument, "path snapshot generation must be non-zero");
  }
  if (snapshot.fabric_epoch.value() != 0 && snapshot.fabric_epoch != incarnation.epoch) {
    return make_error(ErrorCode::kStaleEpoch, "path snapshot was produced for a different fabric epoch");
  }
  if (snapshot.paths.size() > kMaxResourcesPerSnapshot) {
    return make_error(ErrorCode::kResourceExhausted, "path snapshot exceeds the path bound");
  }
  std::vector<PathName> names;
  for (const PathAuthority& path : snapshot.paths) {
    names.push_back(path.path);
  }
  std::vector<PathName> sorted = names;
  std::sort(sorted.begin(), sorted.end());
  if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
    return make_error(ErrorCode::kConflict, "path snapshot names the same path twice");
  }

  std::vector<PathName> changed;
  for (const PathAuthority& path : snapshot.paths) {
    Result<bool> applied = paths.apply(path, snapshot.id, now);
    if (!applied) return applied.error();
    if (applied.value()) changed.push_back(path.path);
  }
  if (changed.empty()) {
    return {};
  }
  codec::DurableRecord record;
  record.kind = RecordKind::kPathSnapshot;
  record.path = snapshot;
  record.path.ingested_at = now;
  Result<DurableSequence> appended = append_locked(record);
  if (!appended) return appended.error();
  last_path_snapshot = snapshot.id;
  last_path_generation = snapshot.generation;

  Status refreshed = refresh_applicability_locked(now, /*auto_revalidate=*/true);
  if (!refreshed) return refreshed;
  std::vector<HoldId> victims;
  for (const auto& pair : holds) {
    if (pair.second.released || pair.second.path.empty()) continue;
    if (std::find(changed.begin(), changed.end(), pair.second.path) != changed.end()) {
      victims.push_back(pair.first);
    }
  }
  for (const HoldId& id : victims) {
    Status released = release_hold_locked(id, "path authority changed under a provisional hold", true);
    (void)released;
  }
  return {};
}

// ---------------------------------------------------------------------------
// Policy ingestion
// ---------------------------------------------------------------------------
Status ReservationCoordinator::Impl::ingest_policy_locked(const PolicyRecord& record,
                                                          const codec::RequestContext& context) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/false);
  if (!valid) return valid;
  // The previous record is copied, not referenced: the registry replaces its
  // entry in place, so a pointer into it would silently become the new record
  // and every material change would then compare equal to itself.
  const PolicyRegistry::Entry* previous = policies.find(record.name);
  const bool had_previous = previous != nullptr;
  const PolicyRecord previous_record = had_previous ? previous->record : PolicyRecord{};
  Result<bool> applied = policies.apply(record);
  if (!applied) return applied.error();
  if (!applied.value()) {
    return {};
  }
  codec::DurableRecord durable;
  durable.kind = RecordKind::kPolicyRecord;
  durable.policy = record;
  durable.policy.ingested_at = now;
  Result<DurableSequence> appended = append_locked(durable);
  if (!appended) return appended.error();

  const bool material = !had_previous || record.materially_differs(previous_record);
  if (!material) {
    return {};
  }
  // A material policy change invalidates the authority of reservations bound to
  // the previous generation. They are marked, never silently re-interpreted.
  std::vector<detail::ReservationKey> affected;
  for (const auto& pair : records) {
    if (is_terminal(pair.second.state)) continue;
    if (pair.second.authority.policy == record.name &&
        pair.second.authority.policy_generation != record.generation) {
      affected.push_back(pair.first);
    }
  }
  for (const detail::ReservationKey& key : affected) {
    auto it = records.find(key);
    if (it == records.end()) continue;
    Status marked = mark_applicability_locked(it->second, Applicability::kRevalidationRequired,
                                              ApplicabilityReason::kPolicyMaterialChange, now);
    if (!marked) return marked;
  }
  return {};
}

Status ReservationCoordinator::Impl::register_claimant_locked(const ClaimantId& claimant,
                                                              ClaimantGeneration generation,
                                                              const codec::RequestContext& context) {
  Status valid = validate_context_locked(context, /*require_attempt=*/false);
  if (!valid) return valid;
  if (generation.value() == 0) {
    return make_error(ErrorCode::kInvalidIdentity, "claimant generation must be non-zero");
  }
  return ensure_claimant_locked(claimant, generation, now_locked());
}

Status ReservationCoordinator::Impl::fence_locked(const codec::RequestContext& context,
                                                  const ClaimantId& claimant,
                                                  ClaimantGeneration generation,
                                                  const PublisherBootId& boot, const SessionId& session,
                                                  bool claimant_wide) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/false);
  if (!valid) return valid;
  if (claimant.is_nil() && boot.is_nil() && session.is_nil()) {
    return make_error(ErrorCode::kInvalidArgument, "a fence must name a claimant, a boot, or a session");
  }
  codec::DurableRecord record;
  record.kind = RecordKind::kFence;
  record.fence.claimant = claimant;
  record.fence.claimant_generation = generation;
  record.fence.boot = boot;
  record.fence.session = session;
  record.fence.at = now;
  record.fence.reason = sanitize_reason(context.reason);
  record.fence.claimant_wide = claimant_wide;
  Result<DurableSequence> appended = append_locked(record);
  if (!appended) return appended.error();

  detail::FenceRecord fence;
  fence.claimant = claimant;
  fence.claimant_generation = generation;
  fence.boot = boot;
  fence.session = session;
  fence.at = now;
  fence.reason = sanitize_reason(context.reason);
  fence.claimant_wide = claimant_wide;
  if (claimant_wide && !claimant.is_nil()) {
    fenced_claimants[claimant] = fence;
  }
  if (!boot.is_nil()) {
    fenced_boots[boot] = fence;
    fence_holds_for_boot_locked(boot, fence.reason);
  }
  if (!session.is_nil()) {
    fence_holds_for_session_locked(session, fence.reason);
  }
  if (claimant_wide && !claimant.is_nil()) {
    fence_holds_for_claimant_locked(claimant, generation, fence.reason);
  }
  return {};
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------
Status ReservationCoordinator::ingest_capacity(const CapacitySnapshot& snapshot,
                                               const std::vector<ResourceName>& withdrawals,
                                               const codec::RequestContext& context) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->ingest_capacity_locked(snapshot, withdrawals, context);
}

Status ReservationCoordinator::ingest_paths(const PathAuthoritySnapshot& snapshot,
                                            const codec::RequestContext& context) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->ingest_paths_locked(snapshot, context);
}

Status ReservationCoordinator::ingest_policy(const PolicyRecord& record,
                                             const codec::RequestContext& context) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->ingest_policy_locked(record, context);
}

Status ReservationCoordinator::register_claimant(const ClaimantId& claimant, ClaimantGeneration generation,
                                                 const codec::RequestContext& context) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->register_claimant_locked(claimant, generation, context);
}

Status ReservationCoordinator::fence(const codec::RequestContext& context, const ClaimantId& claimant,
                                     ClaimantGeneration generation, const PublisherBootId& boot,
                                     const SessionId& session, bool claimant_wide) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->fence_locked(context, claimant, generation, boot, session, claimant_wide);
}

Result<CommitResult> ReservationCoordinator::create_reservation(const codec::RequestContext& context,
                                                                const ReservationTerms& terms,
                                                                const ReservationId& requested_id,
                                                                bool dry_run,
                                                                const std::vector<HoldId>& consume_holds) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->create_locked(context, terms, requested_id, dry_run, consume_holds);
}

Result<AmendmentResult> ReservationCoordinator::amend_reservation(const codec::RequestContext& context,
                                                                  const ReservationId& target,
                                                                  ReservationGeneration target_generation,
                                                                  const ReservationTerms& terms,
                                                                  bool dry_run) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->amend_locked(context, target, target_generation, terms, dry_run);
}

Result<LifecycleResult> ReservationCoordinator::release_reservation(const codec::RequestContext& context,
                                                                    const ReservationId& id,
                                                                    ReservationGeneration generation) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->release_locked(context, id, generation);
}

Result<LifecycleResult> ReservationCoordinator::recall_reservation(const codec::RequestContext& context,
                                                                   const ReservationId& id,
                                                                   ReservationGeneration generation,
                                                                   Timestamp effective_at, Duration grace,
                                                                   bool force) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->recall_locked(context, id, generation, effective_at, grace, force);
}

Result<LifecycleResult> ReservationCoordinator::revoke_reservation(const codec::RequestContext& context,
                                                                   const ReservationId& id,
                                                                   ReservationGeneration generation) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->revoke_locked(context, id, generation);
}

Result<LifecycleResult> ReservationCoordinator::revalidate_reservation(const codec::RequestContext& context,
                                                                       const ReservationId& id,
                                                                       ReservationGeneration generation,
                                                                       bool mark_stale) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->revalidate_locked(context, id, generation, mark_stale);
}

Result<AttemptReconciliation> ReservationCoordinator::reconcile_attempt(const codec::RequestContext& context,
                                                                        const AttemptId& attempt) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->reconcile_attempt_locked(context, attempt);
}

Result<LifecycleResult> ReservationCoordinator::reconcile_lifecycle(const codec::RequestContext& context) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->reconcile_lifecycle_locked(context);
}

Result<codec::HoldRecord> ReservationCoordinator::acquire_hold(const codec::RequestContext& context,
                                                               const ReservationTerms& terms,
                                                               Timestamp expires_at) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Timestamp now = impl_->now_locked();
  Status valid = impl_->validate_context_locked(context, /*require_attempt=*/true);
  if (!valid) return valid.error();
  Status terms_ok = validate_terms(terms);
  if (!terms_ok) return terms_ok.error();
  Status claimant_ok = impl_->ensure_claimant_locked(terms.claimant, terms.claimant_generation, now);
  if (!claimant_ok) return claimant_ok.error();
  Status reconciled = impl_->reconcile_locked(now);
  if (!reconciled) return reconciled.error();

  std::string note;
  const PolicyRecord& policy = impl_->policy_for_locked(terms.policy, &note);
  if (policy.max_hold_ttl.ns > 0 && expires_at.ns - now.ns > policy.max_hold_ttl.ns) {
    return make_error(ErrorCode::kPolicyRejected, "requested hold lifetime exceeds the policy bound");
  }
  if (!(now < expires_at)) {
    return make_error(ErrorCode::kInvalidInterval, "hold deadline must be in the future");
  }
  std::size_t session_holds = 0;
  std::int64_t session_bandwidth = 0;
  for (const auto& pair : impl_->holds) {
    if (pair.second.released || pair.second.session != context.session) continue;
    ++session_holds;
    session_bandwidth += pair.second.amount.bps;
  }
  if (policy.max_holds_per_session != 0 && session_holds >= policy.max_holds_per_session) {
    return make_error(ErrorCode::kResourceExhausted, "session hold count exceeds the policy bound");
  }
  if (policy.max_hold_bandwidth.bps > 0 && session_bandwidth + terms.amount.bps > policy.max_hold_bandwidth.bps) {
    return make_error(ErrorCode::kResourceExhausted, "session hold bandwidth exceeds the policy bound");
  }

  Result<detail::ResolvedBinding> binding = impl_->resolve_binding_locked(terms);
  if (!binding) return binding.error();
  detail::Assessment assessment =
      impl_->assess_locked(terms, binding.value(), policy, now, policy.max_conflict_set,
                           policy.max_explanation_bytes);
  if (assessment.outcome != AdmissionOutcome::kCommittable) {
    return make_error(outcome_to_error_code(assessment.outcome), assessment.explanation);
  }

  codec::HoldRecord hold;
  hold.id = Identity128::derive(context.attempt, 0x484F4C44ULL);
  hold.generation = HoldGeneration(1);
  hold.claimant = terms.claimant;
  hold.claimant_generation = terms.claimant_generation;
  hold.session = context.session;
  hold.boot = context.publisher_boot;
  hold.epoch = impl_->incarnation.epoch;
  hold.binding_kind = binding.value().kind;
  for (const ResourceRef& ref : binding.value().resources) {
    hold.resources.push_back(ref.resource);
  }
  hold.path = binding.value().path;
  hold.path_generation = binding.value().path_generation;
  hold.interval = terms.interval;
  hold.amount = terms.amount;
  hold.guarantee = terms.guarantee;
  hold.created_at = now;
  hold.expires_at = expires_at;

  for (const ResourceRef& ref : binding.value().resources) {
    IndexEntry entry;
    entry.kind = HolderKind::kHold;
    entry.id = hold.id;
    entry.holder_generation = hold.generation.value();
    entry.resource = ref.resource;
    entry.interval = terms.interval;
    entry.amount = terms.amount;
    entry.guarantee = terms.guarantee;
    entry.state = ReservationState::kPending;
    Status inserted = impl_->index.insert(entry);
    if (!inserted) {
      Status erased = impl_->index.erase_all(HolderKind::kHold, hold.id, hold.generation.value());
      (void)erased;
      return inserted.error();
    }
  }
  impl_->holds[hold.id] = hold;
  return hold;
}

Result<codec::HoldRecord> ReservationCoordinator::release_hold(const codec::RequestContext& context,
                                                               const HoldId& id,
                                                               HoldGeneration generation) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status valid = impl_->validate_context_locked(context, /*require_attempt=*/false);
  if (!valid) return valid.error();
  auto it = impl_->holds.find(id);
  if (it == impl_->holds.end()) {
    return make_error(ErrorCode::kNotFound, "hold does not exist");
  }
  if (it->second.generation != generation) {
    return make_error(ErrorCode::kGenerationMismatch, "hold generation does not match");
  }
  if (it->second.boot != context.publisher_boot && !context.publisher_boot.is_nil()) {
    return make_error(ErrorCode::kAuthorityRequired, "only the owning boot may release a hold");
  }
  if (!it->second.released) {
    Status released = impl_->release_hold_locked(id, context.reason, /*fenced=*/false);
    if (!released) return released.error();
  }
  return impl_->holds[id];
}

Status ReservationCoordinator::release_session(const codec::RequestContext& context) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Timestamp now = impl_->now_locked();
  Status valid = impl_->validate_context_locked(context, /*require_attempt=*/false);
  if (!valid) return valid;
  Status reconciled = impl_->reconcile_locked(now);
  if (!reconciled) return reconciled;
  impl_->fence_holds_for_session_locked(context.session, "session released");
  return {};
}

Status ReservationCoordinator::compact() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->compact_locked();
}

Status ReservationCoordinator::flush() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->store->flush();
}

void ReservationCoordinator::begin_shutdown() noexcept {
  impl_->stopping.store(true);
  std::lock_guard<std::mutex> guard(impl_->mutex);
  impl_->fence_holds_for_session_locked(SessionId{}, "coordinator shutdown");
  std::vector<HoldId> victims;
  for (const auto& pair : impl_->holds) {
    if (!pair.second.released) victims.push_back(pair.first);
  }
  for (const HoldId& id : victims) {
    Status released = impl_->release_hold_locked(id, "coordinator shutdown", /*fenced=*/false);
    (void)released;
  }
  Status flushed = impl_->store->flush();
  (void)flushed;
}

bool ReservationCoordinator::shutting_down() const noexcept { return impl_->stopping.load(); }

CoordinatorIncarnation ReservationCoordinator::incarnation() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  CoordinatorIncarnation incarnation = impl_->incarnation;
  incarnation.sequence = DurableSequence(impl_->store->last_sequence());
  return incarnation;
}

RecoveryReport ReservationCoordinator::recovery_report() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->recovery;
}

}  // namespace brf
