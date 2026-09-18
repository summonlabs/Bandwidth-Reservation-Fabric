// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Admission: capacity closure evaluation, deterministic preemption planning,
// duplicate-safe commit, and lineage-preserving amendment.
#include <algorithm>
#include <string>
#include <vector>

#include "coordinator_impl.hpp"
#include "brf/hash.hpp"

namespace brf {
namespace {

/// Canonical fingerprint of one authority-bearing request. Two requests are the
/// same request if and only if this value is equal: retries replay, and reuse of
/// an attempt identity with different terms is a conflict.
[[nodiscard]] Identity128 request_fingerprint(const ReservationTerms& terms, const ReservationId& id,
                                              const std::vector<HoldId>& holds) {
  Writer writer(512);
  codec::encode(writer, terms);
  writer.fixed128(id);
  writer.count(holds.size());
  for (const HoldId& hold : holds) {
    writer.fixed128(hold);
  }
  return fingerprint128(writer.buffer());
}

[[nodiscard]] Identity128 amendment_fingerprint(const ReservationId& target,
                                                ReservationGeneration generation,
                                                const ReservationTerms& terms) {
  Writer writer(512);
  writer.fixed128(target);
  codec::encode(writer, generation);
  codec::encode(writer, terms);
  return fingerprint128(writer.buffer());
}

[[nodiscard]] bool commits_as_active(Timestamp now, const Interval& window) {
  return !(now < window.start) && now < window.end;
}

/// Projects an evaluation onto the caller-visible report type. The report is
/// the evidence a caller may rely on: it carries the observed values at the
/// decision instant and never depends on later state.
[[nodiscard]] AdmissionReport to_admission_report(const detail::Assessment& assessment) {
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
// Binding resolution
// ---------------------------------------------------------------------------
Result<detail::ResolvedBinding> ReservationCoordinator::Impl::resolve_binding_locked(
    const ReservationTerms& terms) {
  detail::ResolvedBinding binding;
  binding.kind = terms.binding_kind;
  if (terms.binding_kind == BindingKind::kResources) {
    for (const ResourceName& name : terms.resources) {
      const CapacityLedger::Entry* entry = ledger.find(name);
      if (entry == nullptr) {
        return make_error(ErrorCode::kStaleGeneration,
                          "resource '" + name.str() + "' is not present in the authoritative ledger");
      }
      if (entry->withdrawn) {
        return make_error(ErrorCode::kStaleGeneration, "resource '" + name.str() + "' has been withdrawn");
      }
      binding.resources.push_back(ResourceRef{name, entry->capacity.generation});
      if (!entry->capacity.failure_domain.empty()) {
        binding.failure_domains.push_back(FailureDomainRef{entry->capacity.failure_domain,
                                                           entry->capacity.failure_domain_generation});
      }
    }
  } else {
    const PathAuthorityTable::Entry* entry = paths.find(terms.path);
    if (entry == nullptr) {
      return make_error(ErrorCode::kStaleGeneration,
                        "path '" + terms.path.str() + "' has no authority record");
    }
    if (entry->retired) {
      return make_error(ErrorCode::kStaleGeneration, "path '" + terms.path.str() + "' is retired");
    }
    if (terms.required_path_generation.value() != 0 &&
        entry->path.generation != terms.required_path_generation) {
      return make_error(ErrorCode::kStaleGeneration,
                        "path '" + terms.path.str() + "' is at authority generation " +
                            to_string(entry->path.generation) + ", not the required " +
                            to_string(terms.required_path_generation));
    }
    binding.path = terms.path;
    binding.path_generation = entry->path.generation;
    for (const ResourceName& name : entry->path.components) {
      const CapacityLedger::Entry* resource = ledger.find(name);
      if (resource == nullptr || resource->withdrawn) {
        return make_error(ErrorCode::kStaleGeneration,
                          "path component '" + name.str() + "' has no current authoritative capacity");
      }
      binding.resources.push_back(ResourceRef{name, resource->capacity.generation});
      if (!resource->capacity.failure_domain.empty()) {
        binding.failure_domains.push_back(FailureDomainRef{resource->capacity.failure_domain,
                                                           resource->capacity.failure_domain_generation});
      }
    }
  }
  Result<std::vector<ResourceRef>> canonical = canonicalize_resources(binding.resources);
  if (!canonical) return canonical.error();
  binding.resources = canonical.value();
  Result<std::vector<FailureDomainRef>> domains = canonicalize_failure_domains(binding.failure_domains);
  if (!domains) return domains.error();
  binding.failure_domains = domains.value();
  return binding;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------
detail::Assessment ReservationCoordinator::Impl::assess_locked(const ReservationTerms& terms,
                                                               const detail::ResolvedBinding& binding,
                                                               const PolicyRecord& policy, Timestamp now,
                                                               std::size_t conflict_bound,
                                                               std::size_t explanation_bound) {
  (void)now;
  detail::Assessment assessment;
  const std::size_t max_conflicts = conflict_bound == 0 ? policy.max_conflict_set : conflict_bound;
  const std::size_t max_explanation =
      explanation_bound == 0 ? policy.max_explanation_bytes : explanation_bound;

  bool short_capacity = false;
  bool stale = false;
  bool policy_rejected = false;
  bool emergency = false;
  bool stale_path = false;
  std::string first_problem;
  ApplicabilityReason reason = ApplicabilityReason::kCurrent;
  std::vector<ResourceName> short_resources;

  if (terms.binding_kind == BindingKind::kPath) {
    const PathAuthorityTable::Entry* path = paths.find(terms.path);
    if (path == nullptr) {
      stale_path = true;
      first_problem = "path '" + terms.path.str() + "' has no current authority";
    } else if (path->retired) {
      stale_path = true;
      first_problem = "path '" + terms.path.str() + "' is retired";
    } else if (path->path.generation != binding.path_generation) {
      stale_path = true;
      first_problem = "path '" + terms.path.str() + "' moved authority generation";
    }
  }

  for (const ResourceRef& ref : binding.resources) {
    CapabilityDelta delta;
    delta.resource = ref.resource;
    delta.generation = ref.generation;
    delta.window = terms.interval;

    const CapacityLedger::Entry* entry = ledger.find(ref.resource);
    if (entry == nullptr || entry->withdrawn) {
      stale = true;
      reason = ApplicabilityReason::kResourceWithdrawn;
      if (first_problem.empty()) {
        first_problem = "resource '" + ref.resource.str() + "' is withdrawn or unknown";
      }
      assessment.deltas.push_back(delta);
      continue;
    }
    if (entry->capacity.generation != ref.generation) {
      stale = true;
      reason = ApplicabilityReason::kResourceGenerationChanged;
      if (first_problem.empty()) {
        first_problem = "resource '" + ref.resource.str() + "' moved from generation " +
                        to_string(ref.generation) + " to " + to_string(entry->capacity.generation);
      }
      assessment.deltas.push_back(delta);
      continue;
    }

    delta.reservable_capacity = entry->capacity.reservable_capacity;
    delta.protected_headroom = entry->capacity.protected_headroom;
    std::int64_t required_headroom = entry->capacity.protected_headroom.bps;
    required_headroom += policy.policy_headroom.bps;
    required_headroom += terms.headroom_requirement.bps;
    const std::int64_t ceiling_raw = entry->capacity.reservable_capacity.bps - required_headroom;
    delta.committable_ceiling = Bandwidth{ceiling_raw > 0 ? ceiling_raw : 0};
    delta.committed_peak_before = index.peak_committed(ref.resource, terms.interval);
    delta.holds_peak = index.peak_holds(ref.resource, terms.interval);
    const std::int64_t combined = index.peak_combined(ref.resource, terms.interval).bps;
    const std::int64_t after = saturating_add(Bandwidth{combined}, terms.amount).bps;
    delta.committed_peak_after = Bandwidth{after};
    const std::int64_t remaining = delta.committable_ceiling.bps - after;
    delta.remaining_after = Bandwidth{remaining > 0 ? remaining : 0};

    auto emergency_entry = overcommit.find(ref.resource);
    if (emergency_entry != overcommit.end() && !emergency_entry->second.resolved) {
      delta.overcommit_emergency = true;
      if (!policy.allow_overcommit) {
        emergency = true;
        if (first_problem.empty()) {
          first_problem = "resource '" + ref.resource.str() +
                          "' is in an emergency overcommit state pending policy resolution";
        }
      }
    }

    Interval maintenance{};
    if (CapacityLedger::maintenance_covers(entry->capacity, terms.interval, &maintenance)) {
      delta.maintenance_covers = true;
      policy_rejected = true;
      reason = ApplicabilityReason::kMaintenanceWindowAdded;
      if (first_problem.empty()) {
        first_problem = "resource '" + ref.resource.str() + "' is under maintenance during " +
                        detail::window_text(maintenance);
      }
    }

    if (after > delta.committable_ceiling.bps) {
      const bool allowance_covers = policy.allow_overcommit &&
                                    after <= delta.committable_ceiling.bps + policy.overcommit_allowance.bps;
      if (!allowance_covers) {
        short_capacity = true;
        short_resources.push_back(ref.resource);
      }
    }
    assessment.deltas.push_back(delta);
  }

  std::sort(assessment.deltas.begin(), assessment.deltas.end(),
            [](const CapabilityDelta& a, const CapabilityDelta& b) { return a.resource < b.resource; });

  if (stale_path) {
    assessment.outcome = AdmissionOutcome::kStalePathAuthority;
    assessment.reason = ApplicabilityReason::kPathGenerationChanged;
    assessment.explanation = "STALE_PATH_AUTHORITY: " + first_problem;
    return assessment;
  }
  if (stale) {
    assessment.outcome = AdmissionOutcome::kStaleResource;
    assessment.reason = reason;
    assessment.explanation = "STALE_RESOURCE: " + first_problem;
    return assessment;
  }
  if (policy_rejected) {
    assessment.outcome = AdmissionOutcome::kPolicyRejected;
    assessment.reason = reason;
    assessment.explanation = "POLICY_REJECTED: " + first_problem;
    return assessment;
  }
  if (emergency) {
    assessment.outcome = AdmissionOutcome::kEmergencyOvercommit;
    assessment.explanation = "EMERGENCY_OVERCOMMIT: " + first_problem;
    return assessment;
  }
  if (short_capacity) {
    for (const ResourceName& name : short_resources) {
      std::size_t total = 0;
      bool truncated = false;
      const std::vector<IndexEntry> overlaps = index.overlapping(name, terms.interval, max_conflicts,
                                                                 config.index_scan_limit, &total, &truncated);
      for (const IndexEntry& entry : overlaps) {
        ConflictEntry conflict;
        conflict.id = entry.id;
        conflict.generation = ReservationGeneration(entry.holder_generation);
        conflict.resource = entry.resource;
        conflict.interval = entry.interval;
        conflict.amount = entry.amount;
        conflict.guarantee = entry.guarantee;
        conflict.state = entry.state;
        conflict.is_hold = entry.kind == HolderKind::kHold;
        assessment.conflicts.entries.push_back(conflict);
      }
      assessment.conflicts.total_considered += total;
      if (truncated) {
        assessment.conflicts.truncated = true;
        ++assessment.conflicts.scan_limit_hit;
      }
    }
    std::sort(assessment.conflicts.entries.begin(), assessment.conflicts.entries.end(),
              [](const ConflictEntry& a, const ConflictEntry& b) {
                if (!(a.id == b.id)) return a.id < b.id;
                if (a.generation != b.generation) return a.generation < b.generation;
                return a.resource < b.resource;
              });
    if (assessment.conflicts.entries.size() > max_conflicts) {
      assessment.conflicts.entries.resize(max_conflicts);
      assessment.conflicts.truncated = true;
    }
    assessment.outcome = AdmissionOutcome::kInsufficientCapacity;
    std::string detail = " resource=" + short_resources.front().str();
    std::string text = "INSUFFICIENT_CAPACITY:" + detail + " window=" +
                       detail::window_text(terms.interval) + " amount=" + format_bandwidth(terms.amount) +
                       " conflicts=" + to_decimal(assessment.conflicts.total_considered);
    if (assessment.conflicts.truncated) {
      text += " (conflict set truncated)";
    }
    if (text.size() > max_explanation) text.resize(max_explanation);
    assessment.explanation = std::move(text);
    return assessment;
  }

  assessment.outcome = AdmissionOutcome::kCommittable;
  std::string text = "COMMITTABLE window=" + detail::window_text(terms.interval) +
                     " amount=" + format_bandwidth(terms.amount);
  for (const CapabilityDelta& delta : assessment.deltas) {
    text += " | " + delta.resource.str() + ":" + to_string(delta.generation) +
            " ceiling=" + format_bandwidth(delta.committable_ceiling) +
            " before=" + format_bandwidth(delta.committed_peak_before) +
            " holds=" + format_bandwidth(delta.holds_peak) +
            " after=" + format_bandwidth(delta.committed_peak_after) +
            " remaining=" + format_bandwidth(delta.remaining_after);
  }
  if (text.size() > max_explanation) text.resize(max_explanation);
  assessment.explanation = std::move(text);
  return assessment;
}

std::vector<IndexEntry> ReservationCoordinator::Impl::preemption_candidates_locked(
    const ResourceName& resource, const Interval& window, GuaranteeClass requester,
    const PolicyRecord& policy, const ReservationId& self) const {
  std::size_t total = 0;
  bool truncated = false;
  std::vector<IndexEntry> overlaps = index.overlapping(resource, window, config.index_scan_limit,
                                                      config.index_scan_limit, &total, &truncated);
  std::vector<IndexEntry> candidates;
  for (const IndexEntry& entry : overlaps) {
    if (entry.kind != HolderKind::kReservation) continue;
    if (entry.id == self) continue;
    const GuaranteeClass cls = entry.guarantee;
    if (!(cls < requester)) continue;
    if (cls == GuaranteeClass::kGuaranteed && !policy.allow_recall_guaranteed) continue;
    if (cls == GuaranteeClass::kProtected && !policy.allow_recall_protected) continue;
    candidates.push_back(entry);
  }
  std::sort(candidates.begin(), candidates.end(), [](const IndexEntry& a, const IndexEntry& b) {
    if (a.guarantee != b.guarantee) return a.guarantee < b.guarantee;
    if (!(a.id == b.id)) return a.id < b.id;
    return a.holder_generation < b.holder_generation;
  });
  candidates.erase(std::unique(candidates.begin(), candidates.end(),
                               [](const IndexEntry& a, const IndexEntry& b) {
                                 return a.id == b.id && a.holder_generation == b.holder_generation;
                               }),
                   candidates.end());
  return candidates;
}

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------
namespace {

/// Builds the replay answer for an attempt that already has a durable outcome.
[[nodiscard]] CommitResult build_replay_result(const detail::AttemptRecord& attempt,
                                               const AttemptId& attempt_id) {
  CommitResult result;
  result.replayed = true;
  result.attempt = attempt_id;
  result.sequence = attempt.sequence;
  result.report.outcome = attempt.outcome;
  result.report.explanation = std::string("IDEMPOTENT_REPLAY: attempt ") + format_identity(attempt_id) +
                              " already has durable outcome " + to_string(attempt.outcome);
  return result;
}

}  // namespace

Result<CommitResult> ReservationCoordinator::Impl::create_locked(
    const codec::RequestContext& context, const ReservationTerms& terms, const ReservationId& requested_id,
    bool dry_run, const std::vector<HoldId>& consume_holds) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/true);
  if (!valid) return valid.error();
  Status terms_ok = validate_terms(terms);
  if (!terms_ok) return terms_ok.error();
  if (!context.claimant.is_nil() && !(context.claimant == terms.claimant)) {
    return make_error(ErrorCode::kAuthorityRequired,
                      "request claimant identity does not match the reservation claimant");
  }
  Status claimant_ok = ensure_claimant_locked(terms.claimant, terms.claimant_generation, now);
  if (!claimant_ok) return claimant_ok.error();
  Status reconciled = reconcile_locked(now);
  if (!reconciled) return reconciled.error();

  std::string policy_note;
  const PolicyRecord& policy = policy_for_locked(terms.policy, &policy_note);

  if (!policy.allow_past_start && terms.interval.start < now) {
    return make_error(ErrorCode::kPolicyRejected,
                      "policy '" + policy.name.str() + "' forbids a reservation that starts in the past");
  }
  if (policy.max_future_horizon.ns > 0 && terms.interval.start.ns - now.ns > policy.max_future_horizon.ns) {
    return make_error(ErrorCode::kPolicyRejected,
                      "requested start is beyond the policy future horizon");
  }
  if (policy.minimum_reservation_amount.bps > 0 &&
      terms.amount.bps < policy.minimum_reservation_amount.bps) {
    return make_error(ErrorCode::kPolicyRejected, "requested amount is below the policy minimum");
  }
  if (policy.max_extra_headroom.bps > 0 && terms.headroom_requirement.bps > policy.max_extra_headroom.bps) {
    return make_error(ErrorCode::kPolicyRejected, "requested headroom exceeds the policy allowance");
  }
  if (terms.recurrence.enabled && terms.recurrence.count > policy.max_series_members) {
    return make_error(ErrorCode::kPolicyRejected, "recurrence series exceeds the policy member bound");
  }

  const ReservationId id =
      requested_id.is_nil() ? derive_series_id(terms.claimant, context.attempt, 1) : requested_id;
  const ReservationSeriesId series_id =
      terms.recurrence.enabled ? derive_series_id(terms.claimant, context.attempt, 2) : ReservationSeriesId{};
  const Identity128 fingerprint = request_fingerprint(terms, id, consume_holds);

  if (detail::AttemptRecord* previous = find_attempt_locked(context.attempt)) {
    if (!(previous->fingerprint == fingerprint)) {
      return make_error(ErrorCode::kConflict,
                        "attempt identity was already used for a different request");
    }
    ++stats.replayed_attempts;
    CommitResult replay = build_replay_result(*previous, context.attempt);
    if (ReservationRecord* record = find_record_locked(previous->reservation, previous->generation)) {
      replay.record = *record;
      replay.has_series = record->series_member;
      if (record->series_member) {
        auto series = series_records.find(detail::SeriesKey{record->series, current_series[record->series]});
        if (series != series_records.end()) {
          replay.series = series->second;
          for (const ReservationId& member_id : series->second.members) {
            ReservationRecord* member = current_record_locked(member_id);
            if (member != nullptr) replay.members.push_back(*member);
          }
        }
      }
    }
    if (!policy_note.empty()) {
      replay.report.explanation += " | " + policy_note;
    }
    return replay;
  }

  // A reservation identity owns exactly one authoritative definition. Accepting
  // a second definition under the same identity would silently replace the
  // first commitment rather than refusing the contradiction.
  if (current_generation.find(id) != current_generation.end()) {
    return make_error(ErrorCode::kConflict,
                      "reservation identity " + format_identity(id) +
                          " is already bound to an authoritative commitment");
  }
  if (terms.recurrence.enabled) {
    for (std::size_t i = 0; i < static_cast<std::size_t>(terms.recurrence.count); ++i) {
      const ReservationId member_id =
          derive_member_id(series_id, SeriesIndex(static_cast<std::uint64_t>(i)));
      if (current_generation.find(member_id) != current_generation.end()) {
        return make_error(ErrorCode::kConflict, "series member identity is already in use");
      }
    }
  }
  if (!dry_run && live_count >= config.max_live_reservations) {
    return make_error(ErrorCode::kResourceExhausted,
                      "the coordinator live-reservation bound has been reached");
  }

  Result<detail::ResolvedBinding> binding = resolve_binding_locked(terms);
  if (!binding) return binding.error();
  Result<std::vector<Interval>> expanded =
      expand_series(terms.interval, terms.recurrence, policy.max_series_members);
  if (!expanded) return expanded.error();
  const std::vector<Interval>& intervals = expanded.value();

  Suspension suspension(*this);
  for (const HoldId& hold_id : consume_holds) {
    auto hold = holds.find(hold_id);
    if (hold == holds.end() || hold->second.released) {
      return make_error(ErrorCode::kNotFound, "a hold named for consumption does not exist");
    }
    if (!(hold->second.session == context.session)) {
      return make_error(ErrorCode::kAuthorityRequired,
                        "only the owning session may consume a provisional hold");
    }
    Status suspended = suspension.suspend_hold(hold_id);
    if (!suspended) return suspended.error();
  }

  detail::Assessment failure;
  bool committable = true;
  std::vector<detail::Assessment> evaluations;
  std::size_t failing_member = 0;
  for (std::size_t i = 0; i < intervals.size(); ++i) {
    ReservationTerms shifted = terms;
    shifted.interval = intervals[i];
    detail::Assessment evaluation = assess_locked(shifted, binding.value(), policy, now,
                                                  policy.max_conflict_set, policy.max_explanation_bytes);
    if (evaluation.outcome != AdmissionOutcome::kCommittable) {
      failure = evaluation;
      failing_member = i;
      committable = false;
      break;
    }
    evaluations.push_back(evaluation);
  }

  std::vector<IndexEntry> victims;
  if (!committable && policy.allow_preemption_on_commit && config.enable_preemption &&
      !(terms.interval.start < now) && policy.max_preemption_victims > 0) {
    for (const ResourceRef& ref : binding.value().resources) {
      if (victims.size() >= policy.max_preemption_victims) break;
      const std::vector<IndexEntry> candidates = preemption_candidates_locked(
          ref.resource, intervals[failing_member], terms.guarantee, policy, id);
      for (const IndexEntry& candidate : candidates) {
        if (victims.size() >= policy.max_preemption_victims) break;
        ReservationRecord* victim =
            find_record_locked(candidate.id, ReservationGeneration(candidate.holder_generation));
        if (victim == nullptr) continue;
        Status suspended = suspension.suspend(*victim);
        if (!suspended) continue;
        victims.push_back(candidate);
        bool all_committable = true;
        std::vector<detail::Assessment> retry;
        for (const Interval& window : intervals) {
          ReservationTerms shifted = terms;
          shifted.interval = window;
          detail::Assessment evaluation = assess_locked(shifted, binding.value(), policy, now,
                                                        policy.max_conflict_set, policy.max_explanation_bytes);
          if (evaluation.outcome != AdmissionOutcome::kCommittable) {
            all_committable = false;
            break;
          }
          retry.push_back(evaluation);
        }
        if (all_committable) {
          evaluations = std::move(retry);
          committable = true;
          break;
        }
      }
      if (committable) break;
    }
    if (!committable) {
      victims.clear();
    }
  }

  if (!committable) {
    if (dry_run) {
      CommitResult rejected;
      rejected.report = to_admission_report(failure);
      rejected.attempt = context.attempt;
      return rejected;
    }
    if (!policy_note.empty()) {
      failure.explanation += " | " + policy_note;
    }
    // The refusal itself is durable: a retry of the same attempt must observe
    // the same outcome instead of re-evaluating against changed capacity.
    codec::DurableRecord refusal;
    refusal.kind = RecordKind::kAttemptOutcome;
    refusal.attempt.attempt = context.attempt;
    refusal.attempt.fingerprint = fingerprint;
    refusal.attempt.outcome = failure.outcome;
    refusal.attempt.reservation = id;
    refusal.attempt.generation = ReservationGeneration(0);
    refusal.attempt.claimant = terms.claimant;
    refusal.attempt.at = now;
    Result<DurableSequence> sequence = append_locked(refusal);
    if (!sequence) return sequence.error();
    detail::AttemptRecord attempt_record;
    attempt_record.attempt = context.attempt;
    attempt_record.fingerprint = fingerprint;
    attempt_record.outcome = failure.outcome;
    attempt_record.reservation = id;
    attempt_record.generation = ReservationGeneration(0);
    attempt_record.sequence = sequence.value();
    attempt_record.claimant = terms.claimant;
    attempt_record.at = now;
    remember_attempt_locked(attempt_record);
    ++stats.commit_rejections;
    CommitResult rejected;
    rejected.report = to_admission_report(failure);
    rejected.attempt = context.attempt;
    rejected.sequence = sequence.value();
    return rejected;
  }

  detail::Assessment accepted = evaluations.empty() ? failure : evaluations.front();
  if (intervals.size() > 1) {
    accepted.explanation += " | series members=" + to_decimal(intervals.size());
  }
  if (!policy_note.empty()) {
    accepted.explanation += " | " + policy_note;
  }
  accepted.victims.clear();
  accepted.victim_generations.clear();
  for (const IndexEntry& victim : victims) {
    accepted.victims.push_back(victim.id);
    accepted.victim_generations.push_back(ReservationGeneration(victim.holder_generation));
  }
  accepted.preemption_planned = !victims.empty();
  if (!victims.empty()) {
    accepted.explanation += " | preemption victims=" + to_decimal(victims.size());
  }

  if (dry_run) {
    CommitResult preview;
    preview.report = to_admission_report(accepted);
    preview.attempt = context.attempt;
    return preview;
  }

  const DurableSequence predicted(store->last_sequence() + 1);
  Provenance provenance = make_provenance_locked(context, predicted, now);

  AuthorityVector authority;
  authority.fabric_epoch = incarnation.epoch;
  authority.reservation_generation = ReservationGeneration(1);
  authority.claimant = terms.claimant;
  authority.claimant_generation = terms.claimant_generation;
  authority.capacity_snapshot = last_capacity_snapshot;
  authority.capacity_generation = last_capacity_generation;
  authority.policy = policy.name;
  authority.policy_generation = policy.generation;
  authority.path_generation = binding.value().path_generation;
  authority.resources = binding.value().resources;
  authority.failure_domains = binding.value().failure_domains;

  auto make_record = [&](const ReservationId& record_id, const Interval& window, SeriesIndex index,
                         bool is_member) {
    ReservationRecord record;
    record.id = record_id;
    record.generation = ReservationGeneration(1);
    record.series_member = is_member;
    record.series = series_id;
    record.series_index = index;
    record.terms = terms;
    record.terms.interval = window;
    record.authority = authority;
    record.applicability = Applicability::kCurrent;
    record.applicability_reason = ApplicabilityReason::kCurrent;
    record.declared_at = now;
    record.committed_at = now;
    record.state_changed_at = now;
    record.state = commits_as_active(now, window) ? ReservationState::kActive : ReservationState::kCommitted;
    record.activated_at = record.state == ReservationState::kActive ? now : Timestamp{};
    record.last_provenance = provenance;
    record.sequence = predicted;
    return record;
  };

  // A series member is an ordinary reservation: the first member IS the record
  // returned to the caller, and the remaining members are committed in the same
  // durable record. A series therefore never double-counts its first interval.
  std::vector<ReservationRecord> all_members;
  if (terms.recurrence.enabled) {
    for (std::size_t i = 0; i < intervals.size(); ++i) {
      const ReservationId member_id = derive_member_id(series_id, SeriesIndex(static_cast<std::uint64_t>(i)));
      all_members.push_back(
          make_record(member_id, intervals[i], SeriesIndex(static_cast<std::uint64_t>(i)), true));
    }
  } else {
    all_members.push_back(make_record(id, intervals.front(), SeriesIndex(0), false));
  }

  codec::ReservationMutation mutation;
  mutation.record = all_members.front();
  mutation.members.assign(all_members.begin() + 1, all_members.end());
  if (terms.recurrence.enabled) {
    mutation.has_series = true;
    ReservationSeries series;
    series.id = series_id;
    series.generation = SeriesGeneration(1);
    series.claimant = terms.claimant;
    series.claimant_generation = terms.claimant_generation;
    series.spec = terms.recurrence;
    series.first_interval = intervals.front();
    series.amount = terms.amount;
    series.state = ReservationState::kCommitted;
    series.created_at = now;
    series.state_changed_at = now;
    series.last_provenance = provenance;
    series.sequence = predicted;
    for (const ReservationRecord& member : all_members) {
      series.members.push_back(member.id);
    }
    mutation.series = series;
  }
  for (const IndexEntry& victim : victims) {
    ReservationRecord* record =
        find_record_locked(victim.id, ReservationGeneration(victim.holder_generation));
    if (record == nullptr) continue;
    codec::StateMutation companion;
    companion.id = record->id;
    companion.generation = record->generation;
    companion.from_state = record->state;
    companion.to_state = ReservationState::kRevoked;
    companion.at = now;
    companion.reason = "preempted by reservation " + id.to_hex();
    companion.provenance = provenance;
    mutation.companions.push_back(companion);
  }
  mutation.has_attempt = true;
  mutation.attempt.attempt = context.attempt;
  mutation.attempt.fingerprint = fingerprint;
  mutation.attempt.outcome = AdmissionOutcome::kCommittable;
  mutation.attempt.reservation = mutation.record.id;
  mutation.attempt.generation = mutation.record.generation;
  mutation.attempt.result_sequence = predicted;
  mutation.attempt.claimant = terms.claimant;
  mutation.attempt.at = now;

  codec::DurableRecord durable;
  durable.kind = RecordKind::kReservationCommit;
  durable.reservation = mutation;
  Result<DurableSequence> appended = append_locked(durable);
  if (!appended) return appended.error();
  if (!(appended.value() == predicted)) {
    return make_error(ErrorCode::kInternal, "durable sequence prediction disagrees with the journal");
  }

  // Durable state is now authoritative; the in-memory projection follows.
  for (const codec::StateMutation& companion : mutation.companions) {
    ReservationRecord* record = find_record_locked(companion.id, companion.generation);
    if (record == nullptr) continue;
    set_state_locked(*record, companion.to_state, companion.at, companion.reason, companion.provenance);
    records[detail::ReservationKey{record->id, record->generation}] = *record;
    Status synced = sync_index_locked(*record);
    if (!synced) return synced.error();
    sync_queues_locked(*record);
    ++stats.recalls;
  }
  register_record_locked(mutation.record);
  Status synced = sync_index_locked(mutation.record);
  if (!synced) return synced.error();
  sync_queues_locked(mutation.record);
  for (const ReservationRecord& member : mutation.members) {
    register_record_locked(member);
    Status member_sync = sync_index_locked(member);
    if (!member_sync) return member_sync.error();
    sync_queues_locked(member);
  }
  if (mutation.has_series) {
    const detail::SeriesKey key{mutation.series.id, mutation.series.generation};
    series_records[key] = mutation.series;
    current_series[mutation.series.id] = mutation.series.generation;
  }
  detail::AttemptRecord attempt_record;
  attempt_record.attempt = context.attempt;
  attempt_record.fingerprint = fingerprint;
  attempt_record.outcome = AdmissionOutcome::kCommittable;
  attempt_record.reservation = mutation.record.id;
  attempt_record.generation = mutation.record.generation;
  attempt_record.sequence = appended.value();
  attempt_record.claimant = terms.claimant;
  attempt_record.at = now;
  remember_attempt_locked(attempt_record);

  for (const HoldId& hold_id : consume_holds) {
    auto hold = holds.find(hold_id);
    if (hold == holds.end()) continue;
    hold->second.released = true;
    hold->second.released_at = now;
    hold->second.release_reason = "consumed by reservation " + id.to_hex();
  }
  suspension.keep();

  ++stats.commits;
  CommitResult result;
  result.record = mutation.record;
  result.has_series = mutation.has_series;
  result.series = mutation.series;
  result.members = all_members;
  result.report = to_admission_report(accepted);
  result.attempt = context.attempt;
  result.sequence = appended.value();
  Status history = release_terminal_history_locked(now);
  if (!history) return history.error();
  if (store->should_compact()) {
    Status compacted = compact_locked();
    if (!compacted) return compacted.error();
  }
  return result;
}

// ---------------------------------------------------------------------------
// Amendment
// ---------------------------------------------------------------------------
Result<AmendmentResult> ReservationCoordinator::Impl::amend_locked(
    const codec::RequestContext& context, const ReservationId& target,
    ReservationGeneration target_generation, const ReservationTerms& terms, bool dry_run) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/true);
  if (!valid) return valid.error();
  Status terms_ok = validate_terms(terms);
  if (!terms_ok) return terms_ok.error();
  ReservationRecord* predecessor = find_record_locked(target, target_generation);
  if (predecessor == nullptr) {
    return make_error(ErrorCode::kNotFound, "the reservation generation to amend does not exist");
  }
  // Idempotency is evaluated before state legality: a retried amendment must
  // observe its own durable outcome even though the predecessor it targeted is
  // now SUPERSEDED.
  const Identity128 fingerprint = amendment_fingerprint(target, target_generation, terms);
  if (detail::AttemptRecord* previous = find_attempt_locked(context.attempt)) {
    if (!(previous->fingerprint == fingerprint)) {
      return make_error(ErrorCode::kConflict,
                        "attempt identity was already used for a different amendment");
    }
    ++stats.replayed_attempts;
    AmendmentResult replay;
    replay.replayed = true;
    replay.predecessor = *predecessor;
    if (ReservationRecord* successor = find_record_locked(previous->reservation, previous->generation)) {
      replay.successor = *successor;
      if (successor->series_member) {
        replay.has_series = true;
        auto series = series_records.find(
            detail::SeriesKey{successor->series, current_series[successor->series]});
        if (series != series_records.end()) {
          replay.series = series->second;
          for (const ReservationId& member_id : series->second.members) {
            ReservationRecord* member = current_record_locked(member_id);
            if (member != nullptr) replay.members.push_back(*member);
          }
        }
      }
    }
    replay.report.outcome = previous->outcome;
    replay.report.explanation = "IDEMPOTENT_REPLAY: amendment attempt already durable";
    return replay;
  }
  if (is_terminal(predecessor->state)) {
    return make_error(ErrorCode::kIllegalTransition,
                      "a reservation in state " + std::string(to_string(predecessor->state)) +
                          " cannot be amended");
  }
  if (!(terms.claimant == predecessor->terms.claimant)) {
    return make_error(ErrorCode::kAuthorityRequired, "an amendment must keep the same claimant identity");
  }
  if (terms.claimant_generation < predecessor->terms.claimant_generation) {
    return make_error(ErrorCode::kFencedClaimant, "the amendment carries a stale claimant generation");
  }
  Status claimant_ok = ensure_claimant_locked(terms.claimant, terms.claimant_generation, now);
  if (!claimant_ok) return claimant_ok.error();
  Status reconciled = reconcile_locked(now);
  if (!reconciled) return reconciled.error();

  const bool series_amendment = predecessor->series_member;
  std::string policy_note;
  const PolicyRecord& policy = policy_for_locked(terms.policy, &policy_note);
  Result<detail::ResolvedBinding> binding = resolve_binding_locked(terms);
  if (!binding) return binding.error();
  Result<std::vector<Interval>> expanded =
      expand_series(terms.interval, terms.recurrence, policy.max_series_members);
  if (!expanded) return expanded.error();
  const std::vector<Interval>& intervals = expanded.value();

  // The predecessor stops consuming capacity for the duration of the
  // evaluation. The suspension is purely in memory and is restored on any
  // failure, so a crash can never observe the intermediate state.
  Suspension suspension(*this);
  std::vector<ReservationRecord> superseded;
  if (series_amendment) {
    auto series = series_records.find(detail::SeriesKey{predecessor->series,
                                                       current_series[predecessor->series]});
    if (series == series_records.end()) {
      return make_error(ErrorCode::kCorrupt, "series member has no series record");
    }
    for (const ReservationId& member_id : series->second.members) {
      ReservationRecord* member = current_record_locked(member_id);
      if (member == nullptr) continue;
      if (is_terminal(member->state)) continue;
      superseded.push_back(*member);
      Status suspended = suspension.suspend(*member);
      if (!suspended) return suspended.error();
    }
  } else {
    superseded.push_back(*predecessor);
    Status suspended = suspension.suspend(*predecessor);
    if (!suspended) return suspended.error();
  }

  detail::Assessment failure;
  bool committable = true;
  std::vector<detail::Assessment> evaluations;
  for (const Interval& window : intervals) {
    ReservationTerms shifted = terms;
    shifted.interval = window;
    detail::Assessment evaluation = assess_locked(shifted, binding.value(), policy, now,
                                                  policy.max_conflict_set, policy.max_explanation_bytes);
    if (evaluation.outcome != AdmissionOutcome::kCommittable) {
      failure = evaluation;
      committable = false;
      break;
    }
    evaluations.push_back(evaluation);
  }
  if (!committable) {
    if (dry_run) {
      AmendmentResult rejected;
      rejected.predecessor = *predecessor;
      rejected.report = to_admission_report(failure);
      return rejected;
    }
    codec::DurableRecord refusal;
    refusal.kind = RecordKind::kAttemptOutcome;
    refusal.attempt.attempt = context.attempt;
    refusal.attempt.fingerprint = fingerprint;
    refusal.attempt.outcome = failure.outcome;
    refusal.attempt.reservation = target;
    refusal.attempt.generation = target_generation;
    refusal.attempt.claimant = terms.claimant;
    refusal.attempt.at = now;
    Result<DurableSequence> sequence = append_locked(refusal);
    if (!sequence) return sequence.error();
    detail::AttemptRecord attempt_record;
    attempt_record.attempt = context.attempt;
    attempt_record.fingerprint = fingerprint;
    attempt_record.outcome = failure.outcome;
    attempt_record.reservation = target;
    attempt_record.generation = target_generation;
    attempt_record.sequence = sequence.value();
    attempt_record.claimant = terms.claimant;
    attempt_record.at = now;
    remember_attempt_locked(attempt_record);
    ++stats.commit_rejections;
    AmendmentResult rejected;
    rejected.predecessor = *predecessor;
    rejected.report = to_admission_report(failure);
    return rejected;
  }

  detail::Assessment accepted = evaluations.front();
  if (!policy_note.empty()) accepted.explanation += " | " + policy_note;
  if (dry_run) {
    AmendmentResult preview;
    preview.predecessor = *predecessor;
    preview.report = to_admission_report(accepted);
    return preview;
  }

  const DurableSequence predicted(store->last_sequence() + 1);
  Provenance provenance = make_provenance_locked(context, predicted, now);

  AuthorityVector authority = predecessor->authority;
  authority.fabric_epoch = incarnation.epoch;
  authority.reservation_generation = ReservationGeneration(target_generation.value() + 1);
  authority.claimant = terms.claimant;
  authority.claimant_generation = terms.claimant_generation;
  authority.capacity_snapshot = last_capacity_snapshot;
  authority.capacity_generation = last_capacity_generation;
  authority.policy = policy.name;
  authority.policy_generation = policy.generation;
  authority.path_generation = binding.value().path_generation;
  authority.resources = binding.value().resources;
  authority.failure_domains = binding.value().failure_domains;

  auto make_successor = [&](const ReservationRecord& previous, const Interval& window) {
    ReservationRecord record = previous;
    record.generation = ReservationGeneration(previous.generation.value() + 1);
    record.terms = terms;
    record.terms.interval = window;
    record.authority = authority;
    record.predecessor = previous.id;
    record.predecessor_generation = previous.generation;
    record.applicability = Applicability::kCurrent;
    record.applicability_reason = ApplicabilityReason::kCurrent;
    record.state = commits_as_active(now, window) ? ReservationState::kActive : ReservationState::kCommitted;
    record.activated_at = record.state == ReservationState::kActive ? now : Timestamp{};
    record.committed_at = now;
    record.state_changed_at = now;
    record.recall_effective_at = Timestamp{};
    record.terminated_at = Timestamp{};
    record.state_reason.clear();
    record.last_provenance = provenance;
    record.sequence = predicted;
    return record;
  };

  codec::ReservationMutation mutation;
  std::vector<ReservationRecord> successors;

  if (!series_amendment) {
    mutation.record = make_successor(*predecessor, intervals.front());
    mutation.supersede_record = true;
    successors.push_back(mutation.record);
    mutation.has_edge = true;
    mutation.edge.predecessor = predecessor->id;
    mutation.edge.predecessor_generation = predecessor->generation;
    mutation.edge.successor = mutation.record.id;
    mutation.edge.successor_generation = mutation.record.generation;
    mutation.edge.recorded_at = now;
    mutation.edge.sequence = predicted;
    mutation.edge.reason = sanitize_reason(context.reason.empty() ? "amendment" : context.reason);
  } else {
    auto series_it =
        series_records.find(detail::SeriesKey{predecessor->series, current_series[predecessor->series]});
    if (series_it == series_records.end()) {
      return make_error(ErrorCode::kCorrupt, "series member has no series record");
    }
    // A series amendment supersedes the whole live series and creates the new
    // member set in one durable record. Member identities are derived from the
    // (stable) series identity and the member index, so member N of the old
    // generation and member N of the new generation are the same reservation
    // identity at successive generations.
    std::size_t target_index = 0;
    bool target_found = false;
    for (std::size_t i = 0; i < superseded.size(); ++i) {
      if (superseded[i].id == predecessor->id) {
        target_index = i;
        target_found = true;
        break;
      }
    }
    if (!target_found) {
      return make_error(ErrorCode::kCorrupt, "the amended member is not part of its own series");
    }
    for (std::size_t i = 0; i < intervals.size(); ++i) {
      ReservationRecord member;
      if (i < superseded.size()) {
        member = make_successor(superseded[i], intervals[i]);
      } else {
        member = make_successor(*predecessor, intervals[i]);
        member.id = derive_member_id(predecessor->series, SeriesIndex(static_cast<std::uint64_t>(i)));
        member.generation = ReservationGeneration(1);
        member.predecessor = ReservationId{};
        member.predecessor_generation = ReservationGeneration(0);
      }
      member.series_member = true;
      member.series = predecessor->series;
      member.series_index = SeriesIndex(static_cast<std::uint64_t>(i));
      successors.push_back(member);
    }
    mutation.record = successors[target_index];
    for (std::size_t i = 0; i < successors.size(); ++i) {
      if (i != target_index) mutation.members.push_back(successors[i]);
    }
    mutation.supersede_record = true;
    mutation.has_edge = true;
    mutation.edge.predecessor = predecessor->id;
    mutation.edge.predecessor_generation = predecessor->generation;
    mutation.edge.successor = mutation.record.id;
    mutation.edge.successor_generation = mutation.record.generation;
    mutation.edge.recorded_at = now;
    mutation.edge.sequence = predicted;
    mutation.edge.reason = sanitize_reason(context.reason.empty() ? "amendment" : context.reason);
    // Every other superseded member is retired by a companion mutation carried
    // in the same durable record, so replay reconstructs the same lineage.
    for (std::size_t i = 0; i < superseded.size(); ++i) {
      if (superseded[i].id == predecessor->id) continue;
      codec::StateMutation companion;
      companion.id = superseded[i].id;
      companion.generation = superseded[i].generation;
      companion.from_state = superseded[i].state;
      companion.to_state = ReservationState::kSuperseded;
      companion.at = now;
      companion.reason = "superseded by series generation " +
                         to_decimal(static_cast<std::uint64_t>(successors.empty() ? 0 : 1) +
                                    predecessor->generation.value());
      companion.provenance = provenance;
      mutation.companions.push_back(companion);
    }

    ReservationSeries series = series_it->second;
    series.generation = SeriesGeneration(series.generation.value() + 1);
    series.spec = terms.recurrence;
    series.first_interval = intervals.front();
    series.amount = terms.amount;
    series.created_at = now;
    series.state_changed_at = now;
    series.predecessor_series_generation = series_it->second.id;
    series.predecessor_generation = series_it->second.generation;
    series.members.clear();
    series.last_provenance = provenance;
    series.sequence = predicted;
    for (const ReservationRecord& successor : successors) {
      series.members.push_back(successor.id);
    }
    mutation.has_series = true;
    mutation.series = series;
  }

  mutation.has_attempt = true;
  mutation.attempt.attempt = context.attempt;
  mutation.attempt.fingerprint = fingerprint;
  mutation.attempt.outcome = AdmissionOutcome::kCommittable;
  mutation.attempt.reservation = mutation.record.id;
  mutation.attempt.generation = mutation.record.generation;
  mutation.attempt.result_sequence = predicted;
  mutation.attempt.claimant = terms.claimant;
  mutation.attempt.at = now;

  codec::DurableRecord durable;
  durable.kind = RecordKind::kReservationAmend;
  durable.reservation = mutation;
  Result<DurableSequence> appended = append_locked(durable);
  if (!appended) return appended.error();
  if (!(appended.value() == predicted)) {
    return make_error(ErrorCode::kInternal, "durable sequence prediction disagrees with the journal");
  }

  for (const ReservationRecord& previous : superseded) {
    ReservationRecord* record = find_record_locked(previous.id, previous.generation);
    if (record == nullptr) continue;
    set_state_locked(*record, ReservationState::kSuperseded, now,
                     "superseded by generation " + to_decimal(record->generation.value() + 1), provenance);
    records[detail::ReservationKey{record->id, record->generation}] = *record;
    Status erased = index_erase_locked(*record);
    if (!erased) return erased.error();
    sync_queues_locked(*record);
  }
  edges.push_back(mutation.edge);
  // Successors are applied in one pass over the complete successor set, so a
  // series amendment can never leave an index entry with a stale interval.
  for (const ReservationRecord& successor : successors) {
    register_record_locked(successor);
    Status successor_sync = update_index_locked(successor);
    if (!successor_sync) return successor_sync.error();
    sync_queues_locked(successor);
  }
  if (mutation.has_series) {
    const detail::SeriesKey key{mutation.series.id, mutation.series.generation};
    series_records[key] = mutation.series;
    current_series[mutation.series.id] = mutation.series.generation;
  }
  detail::AttemptRecord attempt_record;
  attempt_record.attempt = context.attempt;
  attempt_record.fingerprint = fingerprint;
  attempt_record.outcome = AdmissionOutcome::kCommittable;
  attempt_record.reservation = mutation.record.id;
  attempt_record.generation = mutation.record.generation;
  attempt_record.sequence = appended.value();
  attempt_record.claimant = terms.claimant;
  attempt_record.at = now;
  remember_attempt_locked(attempt_record);
  suspension.keep();
  ++stats.amendments;

  AmendmentResult result;
  result.predecessor = *predecessor;
  result.successor = mutation.record;
  result.has_series = mutation.has_series;
  result.series = mutation.series;
  result.members = successors;
  result.report = to_admission_report(accepted);
  Status history = release_terminal_history_locked(now);
  if (!history) return history.error();
  if (store->should_compact()) {
    Status compacted = compact_locked();
    if (!compacted) return compacted.error();
  }
  return result;
}

// ---------------------------------------------------------------------------
// Reconciliation of an ambiguous attempt
// ---------------------------------------------------------------------------
Result<AttemptReconciliation> ReservationCoordinator::Impl::reconcile_attempt_locked(
    const codec::RequestContext& context, const AttemptId& attempt) {
  Status valid = validate_context_locked(context, /*require_attempt=*/false);
  if (!valid) return valid.error();
  AttemptReconciliation out;
  out.attempt = attempt;
  detail::AttemptRecord* record = find_attempt_locked(attempt);
  if (record == nullptr) {
    // UNKNOWN stays UNKNOWN: the coordinator has no durable evidence for this
    // attempt, so it cannot claim either outcome.
    out.known = false;
    out.committed = false;
    out.note = "no durable record exists for this attempt";
    return out;
  }
  out.known = true;
  out.outcome = record->outcome;
  out.reservation = record->reservation;
  out.generation = record->generation;
  out.sequence = record->sequence;
  out.committed = outcome_is_acceptance(record->outcome) &&
                  find_record_locked(record->reservation, record->generation) != nullptr;
  out.note = out.committed ? "durable commit confirmed" : "durable outcome recorded without a commit";
  return out;
}

}  // namespace brf
