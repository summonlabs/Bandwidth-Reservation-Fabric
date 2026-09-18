// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Lifecycle: transition legality, deterministic time reconciliation, release,
// recall, revocation, and generation-bound revalidation.
#include <algorithm>
#include <string>
#include <vector>

#include "coordinator_impl.hpp"
#include "brf/hash.hpp"

namespace brf {
namespace {

[[nodiscard]] bool commits_as_active(Timestamp now, const Interval& window) {
  return !(now < window.start) && now < window.end;
}

[[nodiscard]] AdmissionReport to_report(const detail::Assessment& assessment) {
  AdmissionReport report;
  report.outcome = assessment.outcome;
  report.explanation = assessment.explanation;
  report.resources = assessment.deltas;
  report.conflicts = assessment.conflicts;
  report.preemption_plan = assessment.victims;
  report.preemption_plan_generations = assessment.victim_generations;
  report.preemption_planned = assessment.preemption_planned;
  report.applicability_reason = assessment.reason;
  return report;
}

}  // namespace

// ---------------------------------------------------------------------------
// Transitions
// ---------------------------------------------------------------------------
Status ReservationCoordinator::Impl::transition_locked(ReservationRecord& record, ReservationState target,
                                                       Timestamp at, const std::string& reason,
                                                       const codec::RequestContext& context,
                                                       Timestamp recall_effective_at,
                                                       detail::AttemptRecord* attempt_out) {
  const ReservationState previous = record.state;
  codec::DurableRecord durable;
  durable.kind = RecordKind::kReservationState;
  durable.state.id = record.id;
  durable.state.generation = record.generation;
  durable.state.from_state = previous;
  durable.state.to_state = target;
  durable.state.at = at;
  durable.state.reason = sanitize_reason(reason);
  durable.state.recall_effective_at = recall_effective_at;
  if (!context.attempt.is_nil()) {
    durable.state.has_attempt = true;
    durable.state.attempt.attempt = context.attempt;
    durable.state.attempt.fingerprint =
        fingerprint128(std::string("state|") + record.id.to_hex() + "|" + to_decimal(record.generation.value()) +
                       "|" + to_decimal(static_cast<std::uint64_t>(target)));
    durable.state.attempt.outcome = AdmissionOutcome::kCommittable;
    durable.state.attempt.reservation = record.id;
    durable.state.attempt.generation = record.generation;
    durable.state.attempt.claimant = record.terms.claimant;
    durable.state.attempt.at = at;
  }
  Result<DurableSequence> sequence = append_locked(durable);
  if (!sequence) return sequence.error();

  if (recall_effective_at.ns > 0) {
    record.recall_effective_at = recall_effective_at;
  }
  set_state_locked(record, target, at, reason, make_provenance_locked(context, sequence.value(), at));
  record.sequence = sequence.value();
  Status synced = target == ReservationState::kRecallPending ? update_index_locked(record)
                                                             : sync_index_locked(record);
  if (!synced) return synced;
  sync_queues_locked(record);
  if (attempt_out != nullptr && !context.attempt.is_nil()) {
    attempt_out->attempt = context.attempt;
    attempt_out->fingerprint = durable.state.attempt.fingerprint;
    attempt_out->outcome = AdmissionOutcome::kCommittable;
    attempt_out->reservation = record.id;
    attempt_out->generation = record.generation;
    attempt_out->sequence = sequence.value();
    attempt_out->claimant = record.terms.claimant;
    attempt_out->at = at;
  }
  return {};
}

// ---------------------------------------------------------------------------
// Time reconciliation
// ---------------------------------------------------------------------------
Status ReservationCoordinator::Impl::reconcile_locked(Timestamp now) {
  std::vector<detail::ReservationKey> work;
  for (auto it = activation_queue.begin(); it != activation_queue.end() && !(now < it->first); ++it) {
    work.push_back(it->second);
  }
  for (auto it = expiry_queue.begin(); it != expiry_queue.end() && !(now < it->first); ++it) {
    work.push_back(it->second);
  }
  for (auto it = recall_queue.begin(); it != recall_queue.end() && !(now < it->first); ++it) {
    work.push_back(it->second);
  }
  std::sort(work.begin(), work.end());
  work.erase(std::unique(work.begin(), work.end()), work.end());

  codec::RequestContext context;
  context.actor = ActorName::from_string("brf-coordinator").value();
  context.publisher = incarnation.boot;
  context.publisher_boot = incarnation.boot;
  context.asserted_epoch = incarnation.epoch;
  context.attempt = Identity128{};  // Internal transitions carry no caller attempt.
  context.reason = "time reconciliation";

  for (const detail::ReservationKey& key : work) {
    auto it = records.find(key);
    if (it == records.end()) continue;
    ReservationRecord& record = it->second;

    if (record.state == ReservationState::kRecallPending && record.recall_effective_at.ns > 0 &&
        !(now < record.recall_effective_at)) {
      Status transitioned = transition_locked(record, ReservationState::kRevoked, now,
                                              "recall effect reached", context, Timestamp{}, nullptr);
      if (!transitioned) return transitioned;
      ++stats.recalls;
      ++stats.revocations;
      continue;
    }
    if (record.state == ReservationState::kCommitted && !(now < record.terms.interval.start) &&
        now < record.terms.interval.end) {
      Status transitioned = transition_locked(record, ReservationState::kActive, now, "interval opened",
                                              context, Timestamp{}, nullptr);
      if (!transitioned) return transitioned;
    }
    if (record.consumes()) {
      const Interval window = record.consuming_interval();
      if (window.empty() || !(now < window.end)) {
        const bool recall_pending = record.state == ReservationState::kRecallPending;
        const ReservationState target =
            recall_pending ? ReservationState::kRevoked : ReservationState::kExpired;
        const std::string reason =
            recall_pending ? "recall effect reached at the committed interval end"
                           : "committed interval elapsed";
        Status transitioned = transition_locked(record, target, now, reason, context, Timestamp{}, nullptr);
        if (!transitioned) return transitioned;
        if (recall_pending) {
          ++stats.recalls;
          ++stats.revocations;
        } else {
          ++stats.expiries;
        }
      }
    }
  }

  // An abandoned hold must never leak capacity: expired holds are fenced here.
  std::vector<HoldId> expired_holds;
  for (const auto& pair : holds) {
    if (!pair.second.released && !(now < pair.second.expires_at)) {
      expired_holds.push_back(pair.first);
    }
  }
  for (const HoldId& id : expired_holds) {
    Status released = release_hold_locked(id, "hold deadline reached", /*fenced=*/false);
    if (!released) return released;
  }
  return {};
}

Status ReservationCoordinator::Impl::release_terminal_history_locked(Timestamp now) {
  if (history_count <= config.max_history_records) return {};
  std::vector<detail::ReservationKey> terminal;
  for (const auto& pair : records) {
    if (is_terminal(pair.second.state)) terminal.push_back(pair.first);
  }
  std::sort(terminal.begin(), terminal.end(),
            [this](const detail::ReservationKey& a, const detail::ReservationKey& b) {
              const ReservationRecord& left = records[a];
              const ReservationRecord& right = records[b];
              if (left.sequence != right.sequence) return left.sequence < right.sequence;
              return a < b;
            });
  const std::size_t overflow = history_count - config.max_history_records;
  const std::size_t batch = std::min<std::size_t>(overflow, 64);
  if (batch == 0 || terminal.empty()) return {};
  codec::DurableRecord durable;
  durable.kind = RecordKind::kRetire;
  durable.retire.at = now;
  for (std::size_t i = 0; i < batch && i < terminal.size(); ++i) {
    durable.retire.ids.push_back(terminal[i].id);
    durable.retire.generations.push_back(terminal[i].generation);
  }
  if (durable.retire.ids.empty()) return {};
  Result<DurableSequence> appended = append_locked(durable);
  if (!appended) return appended.error();
  for (std::size_t i = 0; i < durable.retire.ids.size(); ++i) {
    const detail::ReservationKey key{durable.retire.ids[i], durable.retire.generations[i]};
    auto it = records.find(key);
    if (it == records.end()) continue;
    ReservationRecord archived = it->second;
    archived.state = ReservationState::kRetired;
    archived.state_changed_at = now;
    archived.state_reason = "retired from live history into the archival record set";
    retired[key.id] = archived;
    records.erase(it);
    if (history_count > 0) --history_count;
  }
  return {};
}

// ---------------------------------------------------------------------------
// Degraded capacity state
// ---------------------------------------------------------------------------
Status ReservationCoordinator::Impl::detect_overcommit_locked(const ResourceName& resource, Timestamp now) {
  const CapacityLedger::Entry* entry = ledger.find(resource);
  if (entry == nullptr) return {};
  const Interval horizon{Timestamp{0}, Timestamp{kMaxTimestampNs}};
  const Bandwidth ceiling =
      entry->withdrawn ? Bandwidth{0} : entry->capacity.committable_ceiling();

  // Capacity that is counted against a live generation.
  Bandwidth peak = index.peak_committed(resource, horizon);

  // Obligations bound to a generation that is no longer live are still
  // obligations. They are never discarded silently: when the resource has been
  // withdrawn, or its live ceiling can no longer cover them together with the
  // live commitments, the resource enters the degraded state that requires an
  // explicit policy decision.
  {
    IntervalCapacityIndex outstanding;
    bool any_stale = false;
    for (const auto& pair : records) {
      const ReservationRecord& record = pair.second;
      if (!record.consumes()) continue;
      bool bound = false;
      bool live = true;
      for (const ResourceRef& ref : record.authority.resources) {
        if (ref.resource == resource) bound = true;
        if (!ledger.is_current(ref)) live = false;
      }
      if (!bound) continue;
      if (live) continue;
      const Interval window = record.consuming_interval();
      if (window.empty()) continue;
      outstanding.add(window, record.terms.amount);
      any_stale = true;
    }
    if (any_stale) {
      const Bandwidth stale_peak = outstanding.peak(horizon);
      if (stale_peak.bps > peak.bps) peak = stale_peak;
    }
  }
  const bool over = peak.bps > ceiling.bps;

  auto existing = overcommit.find(resource);
  if (!over) {
    if (existing != overcommit.end() && !existing->second.resolved) {
      codec::DurableRecord durable;
      durable.kind = RecordKind::kOvercommit;
      durable.overcommit.resource = resource;
      durable.overcommit.generation = entry->capacity.generation;
      durable.overcommit.committed_peak = peak;
      durable.overcommit.ceiling = ceiling;
      durable.overcommit.window = horizon;
      durable.overcommit.at = now;
      durable.overcommit.resolved = true;
      Result<DurableSequence> appended = append_locked(durable);
      if (!appended) return appended.error();
      existing->second.resolved = true;
      existing->second.mutation = durable.overcommit;
    }
    return {};
  }
  if (existing != overcommit.end() && !existing->second.resolved) {
    return {};
  }
  // Authoritative capacity fell below already committed obligations. Existing
  // commitments are never discarded silently: the resource enters an emergency
  // state that blocks new commitments until policy resolves it.
  codec::DurableRecord durable;
  durable.kind = RecordKind::kOvercommit;
  durable.overcommit.resource = resource;
  durable.overcommit.generation = entry->capacity.generation;
  durable.overcommit.committed_peak = peak;
  durable.overcommit.ceiling = ceiling;
  durable.overcommit.window = horizon;
  durable.overcommit.at = now;
  durable.overcommit.resolved = false;
  Result<DurableSequence> appended = append_locked(durable);
  if (!appended) return appended.error();
  detail::OvercommitState state;
  state.mutation = durable.overcommit;
  state.resolved = false;
  overcommit[resource] = state;
  ++stats.overcommit_events;
  return {};
}

// ---------------------------------------------------------------------------
// Applicability and revalidation
// ---------------------------------------------------------------------------
Status ReservationCoordinator::Impl::refresh_applicability_locked(Timestamp now, bool auto_revalidate) {
  std::vector<detail::ReservationKey> live;
  for (const auto& pair : records) {
    if (!is_terminal(pair.second.state)) live.push_back(pair.first);
  }
  for (const detail::ReservationKey& key : live) {
    auto it = records.find(key);
    if (it == records.end()) continue;
    ReservationRecord& record = it->second;
    bool current = true;
    ApplicabilityReason reason = ApplicabilityReason::kCurrent;
    for (const ResourceRef& ref : record.authority.resources) {
      const CapacityLedger::Entry* entry = ledger.find(ref.resource);
      if (entry == nullptr || entry->withdrawn) {
        current = false;
        reason = ApplicabilityReason::kResourceWithdrawn;
        break;
      }
      if (entry->capacity.generation != ref.generation) {
        current = false;
        reason = ApplicabilityReason::kResourceGenerationChanged;
        break;
      }
    }
    if (current && record.authority.path_generation.value() != 0) {
      const PathAuthorityTable::Entry* path = paths.find(record.terms.path);
      if (path == nullptr || path->retired) {
        current = false;
        reason = ApplicabilityReason::kPathRetired;
      } else if (path->path.generation != record.authority.path_generation) {
        current = false;
        reason = ApplicabilityReason::kPathGenerationChanged;
      }
    }
    // A failure domain carried in the authority vector is material evidence: if
    // its generation moved, the topology assumption behind the commitment did
    // too, and the reservation is no longer automatically authorisable.
    if (current) {
      for (const FailureDomainRef& ref : record.authority.failure_domains) {
        if (!ledger.is_current_failure_domain(ref)) {
          current = false;
          reason = ApplicabilityReason::kFailureDomainGenerationChanged;
          break;
        }
      }
    }
    if (current) {
      if (record.applicability != Applicability::kCurrent) {
        Status marked =
            mark_applicability_locked(record, Applicability::kCurrent, ApplicabilityReason::kCurrent, now);
        if (!marked) return marked;
      }
      continue;
    }
    if (auto_revalidate) {
      std::string note;
      const PolicyRecord& policy = policy_for_locked(record.authority.policy, &note);
      if (policy.auto_revalidate_on_generation_change) {
        codec::RequestContext context;
        context.actor = ActorName::from_string("brf-coordinator").value();
        context.publisher = incarnation.boot;
        context.publisher_boot = incarnation.boot;
        context.asserted_epoch = incarnation.epoch;
        context.reason = "policy-permitted revalidation";
        Status revalidated = auto_revalidate_record_locked(record, reason, now, context);
        if (!revalidated) return revalidated;
        if (record.applicability == Applicability::kCurrent) continue;
      }
    }
    Status marked = mark_applicability_locked(record, Applicability::kRevalidationRequired, reason, now);
    if (!marked) return marked;
  }
  return {};
}

Status ReservationCoordinator::Impl::auto_revalidate_record_locked(ReservationRecord& record,
                                                                  ApplicabilityReason reason, Timestamp now,
                                                                  const codec::RequestContext& context) {
  (void)reason;
  ReservationTerms terms = record.terms;
  Result<detail::ResolvedBinding> binding = resolve_binding_locked(terms);
  if (!binding) {
    return {};  // Still not current: the caller marks REVALIDATION_REQUIRED.
  }
  std::string note;
  const PolicyRecord& policy = policy_for_locked(record.authority.policy.empty() ? terms.policy
                                                                               : record.authority.policy,
                                                &note);
  const Interval window = record.terms.interval;
  Suspension suspension(*this);
  Status suspended = suspension.suspend(record);
  if (!suspended) return suspended;
  terms.interval = window;
  detail::Assessment assessment = assess_locked(terms, binding.value(), policy, now, policy.max_conflict_set,
                                                policy.max_explanation_bytes);
  if (assessment.outcome != AdmissionOutcome::kCommittable) {
    return {};
  }

  const DurableSequence predicted(store->last_sequence() + 1);
  Provenance provenance = make_provenance_locked(context, predicted, now);
  ReservationRecord successor = record;
  successor.generation = ReservationGeneration(record.generation.value() + 1);
  successor.authority.reservation_generation = successor.generation;
  successor.authority.fabric_epoch = incarnation.epoch;
  successor.authority.capacity_snapshot = last_capacity_snapshot;
  successor.authority.capacity_generation = last_capacity_generation;
  successor.authority.policy = policy.name;
  successor.authority.policy_generation = policy.generation;
  successor.authority.path_generation = binding.value().path_generation;
  successor.authority.resources = binding.value().resources;
  successor.authority.failure_domains = binding.value().failure_domains;
  successor.authority.claimant = terms.claimant;
  successor.authority.claimant_generation = terms.claimant_generation;
  successor.predecessor = record.id;
  successor.predecessor_generation = record.generation;
  successor.applicability = Applicability::kCurrent;
  successor.applicability_reason = ApplicabilityReason::kCurrent;
  successor.state = commits_as_active(now, window) ? ReservationState::kActive : ReservationState::kCommitted;
  if (successor.state == ReservationState::kActive && successor.activated_at.ns == 0) {
    successor.activated_at = now;
  }
  successor.state_changed_at = now;
  successor.last_provenance = provenance;
  successor.sequence = predicted;

  codec::ReservationMutation mutation;
  mutation.record = successor;
  mutation.supersede_record = true;
  mutation.has_edge = true;
  mutation.edge.predecessor = record.id;
  mutation.edge.predecessor_generation = record.generation;
  mutation.edge.successor = successor.id;
  mutation.edge.successor_generation = successor.generation;
  mutation.edge.recorded_at = now;
  mutation.edge.sequence = predicted;
  mutation.edge.reason = "revalidated against authoritative generations";

  codec::DurableRecord durable;
  durable.kind = RecordKind::kReservationAmend;
  durable.reservation = mutation;
  Result<DurableSequence> appended = append_locked(durable);
  if (!appended) return appended.error();
  if (!(appended.value() == predicted)) {
    return make_error(ErrorCode::kInternal, "durable sequence prediction disagrees with the journal");
  }

  set_state_locked(record, ReservationState::kSuperseded, now, "superseded by revalidation", provenance);
  Status erased = index_erase_locked(record);
  if (!erased) return erased;
  sync_queues_locked(record);
  edges.push_back(mutation.edge);
  register_record_locked(successor);
  Status synced = sync_index_locked(successor);
  if (!synced) return synced;
  sync_queues_locked(successor);
  suspension.keep();
  ++stats.revalidations;
  return {};
}

// ---------------------------------------------------------------------------
// Explicit lifecycle operations
// ---------------------------------------------------------------------------
Result<LifecycleResult> ReservationCoordinator::Impl::release_locked(const codec::RequestContext& context,
                                                                    const ReservationId& id,
                                                                    ReservationGeneration generation) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/true);
  if (!valid) return valid.error();
  ReservationRecord* record = find_record_locked(id, generation);
  if (record == nullptr) {
    return make_error(ErrorCode::kNotFound, "the reservation generation to release does not exist");
  }
  if (!context.claimant.is_nil() && !(context.claimant == record->terms.claimant)) {
    return make_error(ErrorCode::kAuthorityRequired, "only the owning claimant may release a reservation");
  }
  if (!context.claimant.is_nil()) {
    Status claimant_ok = ensure_claimant_locked(context.claimant, context.claimant_generation, now);
    if (!claimant_ok) return claimant_ok.error();
  }
  Status reconciled = reconcile_locked(now);
  if (!reconciled) return reconciled.error();

  LifecycleResult result;
  if (record->state == ReservationState::kReleased) {
    // Idempotent: a repeated release never frees capacity twice.
    result.record = *record;
    result.replayed = true;
    return result;
  }
  if (is_terminal(record->state)) {
    return make_error(ErrorCode::kIllegalTransition,
                      std::string("a reservation in state ") + to_string(record->state) + " cannot be released");
  }
  detail::AttemptRecord attempt;
  const std::string reason = context.reason.empty() ? "released by claimant" : context.reason;
  Status transitioned = transition_locked(*record, ReservationState::kReleased, now, reason, context,
                                          Timestamp{}, &attempt);
  if (!transitioned) return transitioned.error();
  remember_attempt_locked(attempt);
  ++stats.releases;
  result.record = *record;
  result.transitions = 1;
  return result;
}

Result<LifecycleResult> ReservationCoordinator::Impl::recall_locked(const codec::RequestContext& context,
                                                                    const ReservationId& id,
                                                                    ReservationGeneration generation,
                                                                    Timestamp effective_at, Duration grace,
                                                                    bool force) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/true);
  if (!valid) return valid.error();
  ReservationRecord* record = find_record_locked(id, generation);
  if (record == nullptr) {
    return make_error(ErrorCode::kNotFound, "the reservation generation to recall does not exist");
  }
  if (detail::AttemptRecord* previous = find_attempt_locked(context.attempt)) {
    ++stats.replayed_attempts;
    LifecycleResult replay;
    replay.replayed = true;
    replay.record = *record;
    (void)previous;
    return replay;
  }
  Status reconciled = reconcile_locked(now);
  if (!reconciled) return reconciled.error();
  if (!record->consumes()) {
    return make_error(ErrorCode::kIllegalTransition,
                      std::string("a reservation in state ") + to_string(record->state) +
                          " does not consume capacity and cannot be recalled");
  }
  std::string note;
  const PolicyRecord& policy = policy_for_locked(record->authority.policy, &note);
  bool permitted = false;
  switch (record->terms.guarantee) {
    case GuaranteeClass::kScavenger:
    case GuaranteeClass::kPreemptible:
      permitted = true;
      break;
    case GuaranteeClass::kProtected:
      permitted = policy.allow_recall_protected || record->terms.recall_permitted;
      break;
    case GuaranteeClass::kGuaranteed:
      permitted = policy.allow_recall_guaranteed || record->terms.recall_permitted;
      break;
  }
  if (!permitted) {
    return make_error(ErrorCode::kPolicyRejected,
                      std::string("a ") + to_string(record->terms.guarantee) +
                          " reservation cannot be recalled under policy '" + policy.name.str() +
                          "' and its contract does not permit recall");
  }
  Timestamp effect = effective_at;
  if (force || effect.ns == 0) {
    effect = now;
  }
  if (effect < now) {
    return make_error(ErrorCode::kInvalidInterval, "recall effect must not be scheduled in the past");
  }
  if (record->terms.interval.end < effect) {
    effect = record->terms.interval.end;
  }
  Duration effective_grace = grace;
  if (effective_grace.ns == 0) {
    effective_grace = policy.default_recall_grace;
  }

  LifecycleResult result;
  if (record->state == ReservationState::kRecallPending && record->recall_effective_at == effect) {
    result.record = *record;
    result.replayed = true;
    return result;
  }
  if (!(now < effect)) {
    detail::AttemptRecord attempt;
    Status transitioned = transition_locked(*record, ReservationState::kRevoked, now,
                                            context.reason.empty() ? "recalled with immediate effect"
                                                                   : context.reason,
                                            context, Timestamp{}, &attempt);
    if (!transitioned) return transitioned.error();
    remember_attempt_locked(attempt);
    ++stats.recalls;
    ++stats.revocations;
    result.record = *record;
    result.transitions = 1;
    return result;
  }
  const std::string reason =
      context.reason.empty() ? "recall recorded; effect pending" : context.reason;
  detail::AttemptRecord attempt;
  Status transitioned = transition_locked(*record, ReservationState::kRecallPending, now, reason, context,
                                          effect, &attempt);
  if (!transitioned) return transitioned.error();
  // The grace is part of the durable recall transition: capacity is released at
  // the effect instant plus the grace, never earlier.
  record->recall_grace = effective_grace;
  records[detail::ReservationKey{record->id, record->generation}] = *record;
  Status updated = update_index_locked(*record);
  if (!updated) return updated.error();
  sync_queues_locked(*record);
  remember_attempt_locked(attempt);
  ++stats.recalls;
  result.record = *record;
  result.transitions = 1;
  return result;
}

Result<LifecycleResult> ReservationCoordinator::Impl::revoke_locked(const codec::RequestContext& context,
                                                                    const ReservationId& id,
                                                                    ReservationGeneration generation) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/true);
  if (!valid) return valid.error();
  ReservationRecord* record = find_record_locked(id, generation);
  if (record == nullptr) {
    return make_error(ErrorCode::kNotFound, "the reservation generation to revoke does not exist");
  }
  Status reconciled = reconcile_locked(now);
  if (!reconciled) return reconciled.error();
  LifecycleResult result;
  if (detail::AttemptRecord* previous = find_attempt_locked(context.attempt)) {
    (void)previous;
    result.record = *record;
    result.replayed = true;
    ++stats.replayed_attempts;
    return result;
  }
  if (record->state == ReservationState::kRevoked) {
    result.record = *record;
    result.replayed = true;
    return result;
  }
  if (!record->consumes()) {
    return make_error(ErrorCode::kIllegalTransition,
                      std::string("a reservation in state ") + to_string(record->state) +
                          " cannot be revoked");
  }
  detail::AttemptRecord attempt;
  const std::string reason = context.reason.empty() ? "revoked by authority" : context.reason;
  Status transitioned =
      transition_locked(*record, ReservationState::kRevoked, now, reason, context, Timestamp{}, &attempt);
  if (!transitioned) return transitioned.error();
  remember_attempt_locked(attempt);
  ++stats.revocations;
  result.record = *record;
  result.transitions = 1;
  return result;
}

Result<LifecycleResult> ReservationCoordinator::Impl::revalidate_locked(
    const codec::RequestContext& context, const ReservationId& id, ReservationGeneration generation,
    bool mark_stale) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/true);
  if (!valid) return valid.error();
  ReservationRecord* record = find_record_locked(id, generation);
  if (record == nullptr) {
    return make_error(ErrorCode::kNotFound, "the reservation generation to revalidate does not exist");
  }
  Status reconciled = reconcile_locked(now);
  if (!reconciled) return reconciled.error();
  LifecycleResult result;
  if (is_terminal(record->state)) {
    return make_error(ErrorCode::kIllegalTransition,
                      std::string("a reservation in state ") + to_string(record->state) +
                          " has no live authority to revalidate");
  }
  if (record->applicability == Applicability::kCurrent) {
    result.record = *record;
    result.replayed = true;
    return result;
  }
  if (mark_stale) {
    Status marked = mark_applicability_locked(*record, Applicability::kStale,
                                              record->applicability_reason, now);
    if (!marked) return marked.error();
    result.record = *record;
    result.transitions = 1;
    return result;
  }
  Status revalidated = auto_revalidate_record_locked(*record, record->applicability_reason, now, context);
  if (!revalidated) return revalidated.error();
  // Re-derivation advances the generation in place: report the successor that
  // now carries authority, not the superseded record the caller named.
  ReservationRecord* latest = current_record_locked(id);
  if (latest != nullptr && latest->applicability == Applicability::kCurrent) {
    result.record = *latest;
    result.transitions = latest->generation == generation ? 0 : 1;
    return result;
  }
  return make_error(ErrorCode::kStaleGeneration,
                    "revalidation refused: the bound generations are not current and the successor terms "
                    "do not close against authoritative capacity");
}

Result<LifecycleResult> ReservationCoordinator::Impl::reconcile_lifecycle_locked(
    const codec::RequestContext& context) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/false);
  if (!valid) return valid.error();
  const std::uint64_t expiries_before = stats.expiries;
  const std::uint64_t revocations_before = stats.revocations;
  Status reconciled = reconcile_locked(now);
  if (!reconciled) return reconciled.error();
  Status refreshed = refresh_applicability_locked(now, /*auto_revalidate=*/true);
  if (!refreshed) return refreshed.error();
  Status history = release_terminal_history_locked(now);
  if (!history) return history.error();
  if (store->should_compact()) {
    Status compacted = compact_locked();
    if (!compacted) return compacted.error();
  }
  LifecycleResult result;
  result.transitions = static_cast<std::size_t>((stats.expiries - expiries_before) +
                                                (stats.revocations - revocations_before));
  return result;
}

}  // namespace brf
