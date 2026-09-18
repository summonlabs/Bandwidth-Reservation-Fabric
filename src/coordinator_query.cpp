// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Inspection: queries, bounded explanations, and the invariant audit used by
// property tests and by brf-inspect.
#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "coordinator_impl.hpp"

namespace brf {
namespace {

constexpr std::size_t kMaxQueryResults = 4096;

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

[[nodiscard]] bool binding_contains(const ReservationRecord& record, const ResourceName& resource) {
  for (const ResourceRef& ref : record.authority.resources) {
    if (ref.resource == resource) return true;
  }
  return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// Invariant audit
// ---------------------------------------------------------------------------
std::vector<std::string> ReservationCoordinator::Impl::audit_locked() const {
  std::vector<std::string> violations;

  // 1. Exactly one non-terminal generation per reservation identity.
  std::map<ReservationId, std::size_t> live_per_id;
  for (const auto& pair : records) {
    if (!is_terminal(pair.second.state)) {
      ++live_per_id[pair.first.id];
    }
  }
  for (const auto& pair : live_per_id) {
    if (pair.second > 1) {
      violations.push_back("reservation " + pair.first.to_hex() + " owns " + to_decimal(pair.second) +
                           " live generations");
    }
  }

  // 2. The index contains exactly the capacity-consuming, currently bound
  //    generations, and nothing else.
  for (const auto& pair : records) {
    const ReservationRecord& record = pair.second;
    const bool indexed = index.contains(HolderKind::kReservation, record.id) &&
                         [&]() {
                           for (const IndexEntry& entry :
                                index.find_all(HolderKind::kReservation, record.id)) {
                             if (entry.holder_generation == record.generation.value()) return true;
                           }
                           return false;
                         }();
    const bool should_index = indexable_locked(record);
    auto current = current_generation.find(record.id);
    const bool is_current = current != current_generation.end() && current->second == record.generation;
    if (should_index && (!indexed || !is_current)) {
      violations.push_back("record " + record.id.to_hex() + ":" + to_decimal(record.generation.value()) +
                           " consumes capacity but is not indexed as the current generation");
    }
    if (indexed && !should_index) {
      violations.push_back("record " + record.id.to_hex() + ":" + to_decimal(record.generation.value()) +
                           " is indexed but is not a consuming current generation");
    }
  }

  // 3. Brute-force accounting equals the index, and closure holds per resource.
  for (const ResourceName& resource : ledger.resource_names()) {
    struct Contribution {
      Interval window;
      std::int64_t amount = 0;
    };
    std::vector<Contribution> contributions;
    for (const auto& pair : records) {
      const ReservationRecord& record = pair.second;
      auto current = current_generation.find(record.id);
      if (current == current_generation.end() || current->second != record.generation) continue;
      if (!indexable_locked(record)) continue;
      if (!binding_contains(record, resource)) continue;
      contributions.push_back(Contribution{record.consuming_interval(), record.terms.amount.bps});
    }
    for (const auto& pair : holds) {
      const codec::HoldRecord& hold = pair.second;
      if (hold.released) continue;
      if (std::find(hold.resources.begin(), hold.resources.end(), resource) == hold.resources.end()) {
        continue;
      }
      contributions.push_back(Contribution{hold.interval, hold.amount.bps});
    }
    std::vector<Timestamp> samples;
    for (const Contribution& contribution : contributions) {
      samples.push_back(contribution.window.start);
    }
    std::sort(samples.begin(), samples.end());
    samples.erase(std::unique(samples.begin(), samples.end()), samples.end());
    std::int64_t brute = 0;
    for (const Timestamp sample : samples) {
      std::int64_t sum = 0;
      for (const Contribution& contribution : contributions) {
        if (contribution.window.contains(sample)) sum += contribution.amount;
      }
      brute = std::max(brute, sum);
    }
    const Interval horizon{Timestamp{0}, Timestamp{kMaxTimestampNs}};
    const std::int64_t indexed = index.peak_combined(resource, horizon).bps;
    if (brute != indexed) {
      // Bounded, deterministic evidence: the first few contributing records
      // with their index presence, so the defect is reproducible from the report.
      std::string detail = "resource " + resource.str() + ": index accounts " +
                           to_decimal(static_cast<std::uint64_t>(indexed)) +
                           " bps but the records sum to " +
                           to_decimal(static_cast<std::uint64_t>(brute)) + " bps | contributions:";
      std::size_t shown = 0;
      for (const auto& pair : records) {
        const ReservationRecord& record = pair.second;
        auto current_it = current_generation.find(record.id);
        if (current_it == current_generation.end() || current_it->second != record.generation) continue;
        if (!indexable_locked(record)) continue;
        if (!binding_contains(record, resource)) continue;
        if (shown++ >= 8) {
          detail += " ...";
          break;
        }
        bool indexed_here = false;
        for (const IndexEntry& entry : index.find_all(HolderKind::kReservation, record.id)) {
          if (entry.resource == resource && entry.holder_generation == record.generation.value()) {
            indexed_here = true;
          }
        }
        detail += " " + record.id.to_hex().substr(0, 8) + ":" + to_decimal(record.generation.value()) +
                  "(" + to_decimal(static_cast<std::uint64_t>(record.terms.amount.bps)) + "bps," +
                  to_decimal(static_cast<std::uint64_t>(record.consuming_interval().start.ns)) + "-" +
                  to_decimal(static_cast<std::uint64_t>(record.consuming_interval().end.ns)) + "," +
                  (indexed_here ? "indexed" : "MISSING") + "," + to_string(record.state) + ")";
      }
      violations.push_back(std::move(detail));
    }
    const CapacityLedger::Entry* entry = ledger.find(resource);
    if (entry != nullptr && !entry->withdrawn) {
      const std::int64_t ceiling = entry->capacity.committable_ceiling().bps;
      if (indexed > ceiling) {
        auto emergency = overcommit.find(resource);
        if (emergency == overcommit.end() || emergency->second.resolved) {
          violations.push_back("resource " + resource.str() + ": committed " +
                               to_decimal(static_cast<std::uint64_t>(indexed)) +
                               " bps exceeds the committable ceiling " +
                               to_decimal(static_cast<std::uint64_t>(ceiling)) +
                               " bps without a recorded emergency state");
        }
      }
    }
  }

  // 4. Hold accounting: every live hold owns index entries, and vice versa.
  for (const auto& pair : holds) {
    const codec::HoldRecord& hold = pair.second;
    const bool indexed = index.contains(HolderKind::kHold, hold.id);
    if (!hold.released && !indexed) {
      violations.push_back("hold " + hold.id.to_hex() + " is live but holds no indexed capacity");
    }
    if (hold.released && indexed) {
      violations.push_back("hold " + hold.id.to_hex() + " was released but still holds capacity");
    }
  }

  // 5. Lineage is acyclic and strictly decreasing across generations.
  for (const auto& pair : records) {
    const ReservationRecord& record = pair.second;
    if (record.predecessor.is_nil()) continue;
    if (!(record.predecessor_generation < record.generation)) {
      violations.push_back("record " + record.id.to_hex() + ":" + to_decimal(record.generation.value()) +
                           " has a predecessor generation that is not older");
    }
    ReservationId cursor = record.predecessor;
    ReservationGeneration cursor_generation = record.predecessor_generation;
    std::size_t hops = 0;
    while (!cursor.is_nil()) {
      if (++hops > 4096) {
        violations.push_back("lineage from " + record.id.to_hex() + " exceeds the walk bound (cycle?)");
        break;
      }
      auto it = records.find(detail::ReservationKey{cursor, cursor_generation});
      if (it == records.end()) break;
      cursor = it->second.predecessor;
      cursor_generation = it->second.predecessor_generation;
      if (cursor == record.id) {
        violations.push_back("lineage cycle detected at " + record.id.to_hex());
        break;
      }
    }
  }

  // 6. Durable sequences never exceed the journal head, and the expiry queue
  //    matches the consuming records.
  const std::uint64_t head = store->last_sequence();
  for (const auto& pair : records) {
    if (pair.second.sequence.value() > head) {
      violations.push_back("record " + pair.first.id.to_hex() + " carries a sequence beyond the journal head");
    }
  }
  for (const auto& pair : expiry_queue) {
    auto it = records.find(pair.second);
    if (it == records.end()) {
      violations.push_back("expiry queue references an unknown record");
      continue;
    }
    if (!it->second.consumes()) {
      violations.push_back("expiry queue references a non-consuming record");
      continue;
    }
    if (!(it->second.consuming_interval().end == pair.first)) {
      violations.push_back("expiry queue deadline disagrees with the record interval");
    }
  }

  // 7. Attempts that claim acceptance must reference a durable record.
  for (const auto& pair : attempts) {
    if (!outcome_is_acceptance(pair.second.outcome)) continue;
    if (pair.second.reservation.is_nil()) continue;
    if (find_record_const_locked(pair.second.reservation, pair.second.generation) == nullptr &&
        retired.find(pair.second.reservation) == retired.end()) {
      violations.push_back("attempt " + pair.first.to_hex() +
                           " records an acceptance whose reservation is missing");
    }
  }
  return violations;
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------
Result<ReservationRecord> ReservationCoordinator::get_reservation(const ReservationId& id,
                                                                  const ReservationGeneration& generation) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status reconciled = impl_->reconcile_locked(impl_->now_locked());
  if (!reconciled) return reconciled.error();
  ReservationRecord* record = nullptr;
  if (generation.value() == 0) {
    record = impl_->current_record_locked(id);
  } else {
    record = impl_->find_record_locked(id, generation);
  }
  if (record == nullptr) {
    auto archived = impl_->retired.find(id);
    if (archived != impl_->retired.end()) {
      return archived->second;
    }
    return make_error(ErrorCode::kNotFound, "reservation is not known to this coordinator");
  }
  return *record;
}

Result<std::vector<ReservationRecord>> ReservationCoordinator::query_claimant(const ClaimantId& claimant,
                                                                              bool include_terminal) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status reconciled = impl_->reconcile_locked(impl_->now_locked());
  if (!reconciled) return reconciled.error();
  std::vector<ReservationRecord> out;
  for (const auto& pair : impl_->records) {
    const ReservationRecord& record = pair.second;
    if (!(record.terms.claimant == claimant)) continue;
    if (!include_terminal && is_terminal(record.state)) continue;
    out.push_back(record);
    if (out.size() >= kMaxQueryResults) break;
  }
  std::sort(out.begin(), out.end(), [](const ReservationRecord& a, const ReservationRecord& b) {
    if (!(a.id == b.id)) return a.id < b.id;
    return a.generation < b.generation;
  });
  return out;
}

Result<std::vector<ReservationRecord>> ReservationCoordinator::query_resource(const ResourceName& resource,
                                                                              const Interval& window,
                                                                              bool include_terminal) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status reconciled = impl_->reconcile_locked(impl_->now_locked());
  if (!reconciled) return reconciled.error();
  std::vector<ReservationRecord> out;
  for (const auto& pair : impl_->records) {
    const ReservationRecord& record = pair.second;
    if (!include_terminal) {
      auto current = impl_->current_generation.find(record.id);
      if (current == impl_->current_generation.end() || current->second != record.generation) continue;
    }
    if (!binding_contains(record, resource)) continue;
    if (!window.empty() && !record.terms.interval.overlaps(window)) continue;
    out.push_back(record);
    if (out.size() >= kMaxQueryResults) break;
  }
  std::sort(out.begin(), out.end(), [](const ReservationRecord& a, const ReservationRecord& b) {
    if (!(a.id == b.id)) return a.id < b.id;
    return a.generation < b.generation;
  });
  return out;
}

Result<std::vector<RemainingCapacity>> ReservationCoordinator::query_remaining(const ResourceName& resource,
                                                                               const Interval& window) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Timestamp now = impl_->now_locked();
  Status reconciled = impl_->reconcile_locked(now);
  if (!reconciled) return reconciled.error();
  Status valid = validate_interval(window);
  if (!valid) return valid.error();
  const CapacityLedger::Entry* entry = impl_->ledger.find(resource);
  if (entry == nullptr) {
    return make_error(ErrorCode::kNotFound, "resource '" + resource.str() + "' is not known to the ledger");
  }
  RemainingCapacity out;
  out.resource = resource;
  out.generation = entry->capacity.generation;
  out.window = window;
  out.committable_ceiling = entry->withdrawn ? Bandwidth{0} : entry->capacity.committable_ceiling();
  out.committed_peak = impl_->index.peak_committed(resource, window);
  out.holds_peak = impl_->index.peak_holds(resource, window);
  const std::int64_t used = impl_->index.peak_combined(resource, window).bps;
  const std::int64_t remaining = out.committable_ceiling.bps - used;
  out.remaining = Bandwidth{remaining > 0 ? remaining : 0};
  Interval maintenance{};
  out.maintenance_covers =
      !entry->withdrawn && CapacityLedger::maintenance_covers(entry->capacity, window, &maintenance);
  auto emergency = impl_->overcommit.find(resource);
  out.overcommit_emergency = emergency != impl_->overcommit.end() && !emergency->second.resolved;
  return std::vector<RemainingCapacity>{out};
}

Result<CapacityTimeline> ReservationCoordinator::query_timeline(const ResourceName& resource,
                                                                const Interval& window,
                                                                std::size_t max_points) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  Status reconciled = impl_->reconcile_locked(impl_->now_locked());
  if (!reconciled) return reconciled.error();
  Status valid = validate_interval(window);
  if (!valid) return valid.error();
  if (max_points == 0 || max_points > 4096) {
    return make_error(ErrorCode::kInvalidArgument, "timeline point bound must be within [1, 4096]");
  }
  CapacityTimeline timeline;
  timeline.resource = resource;
  timeline.window = window;
  bool truncated = false;
  timeline.points = impl_->index.timeline(resource, window, max_points, &truncated);
  timeline.truncated = truncated;
  return timeline;
}

Result<LineageView> ReservationCoordinator::query_lineage(const ReservationId& id,
                                                          const ReservationGeneration& generation) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  LineageView view;
  view.id = id;
  ReservationGeneration effective = generation;
  if (effective.value() == 0) {
    auto current = impl_->current_generation.find(id);
    if (current == impl_->current_generation.end()) {
      return make_error(ErrorCode::kNotFound, "reservation is not known to this coordinator");
    }
    effective = current->second;
  }
  view.generation = effective;
  ReservationRecord* record = impl_->find_record_locked(id, effective);
  if (record == nullptr) {
    return make_error(ErrorCode::kNotFound, "the requested reservation generation does not exist");
  }
  // Ancestry: walk predecessors from the requested generation to the root.
  ReservationId cursor = record->predecessor;
  ReservationGeneration cursor_generation = record->predecessor_generation;
  std::size_t hops = 0;
  while (!cursor.is_nil() && hops < 4096) {
    SupersessionEdge edge;
    edge.predecessor = cursor;
    edge.predecessor_generation = cursor_generation;
    edge.successor = id;
    edge.successor_generation = effective;
    ReservationRecord* predecessor = impl_->find_record_locked(cursor, cursor_generation);
    if (predecessor == nullptr) break;
    edge.successor = predecessor->id;
    edge.successor_generation = ReservationGeneration(predecessor->generation.value() + 1);
    edge.recorded_at = predecessor->state_changed_at;
    edge.reason = predecessor->state_reason;
    view.ancestry.push_back(edge);
    cursor = predecessor->predecessor;
    cursor_generation = predecessor->predecessor_generation;
    ++hops;
  }
  std::reverse(view.ancestry.begin(), view.ancestry.end());
  if (hops >= 4096) view.truncated = true;
  // Descendants: follow recorded supersession edges forward.
  std::size_t descendants = 0;
  ReservationId forward = id;
  ReservationGeneration forward_generation = effective;
  while (descendants < 4096) {
    SupersessionEdge next;
    bool found = false;
    for (const SupersessionEdge& edge : impl_->edges) {
      if (edge.predecessor == forward && edge.predecessor_generation == forward_generation) {
        next = edge;
        found = true;
        break;
      }
    }
    if (!found) {
      // A series amendment carries one explicit edge and derives the rest from
      // each member's predecessor field, so lineage stays queryable either way.
      for (const auto& pair : impl_->records) {
        if (pair.second.predecessor == forward &&
            pair.second.predecessor_generation == forward_generation) {
          next.predecessor = forward;
          next.predecessor_generation = forward_generation;
          next.successor = pair.second.id;
          next.successor_generation = pair.second.generation;
          next.recorded_at = pair.second.state_changed_at;
          next.reason = pair.second.state_reason;
          found = true;
          break;
        }
      }
    }
    if (!found) break;
    view.descendants.push_back(next);
    forward = next.successor;
    forward_generation = next.successor_generation;
    ++descendants;
  }
  if (descendants >= 4096) view.truncated = true;
  return view;
}

Result<AdmissionReport> ReservationCoordinator::explain_conflicts(const ReservationTerms& terms,
                                                                  const ReservationId& candidate) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Timestamp now = impl_->now_locked();
  Status valid = validate_terms(terms);
  if (!valid) return valid.error();
  Status reconciled = impl_->reconcile_locked(now);
  if (!reconciled) return reconciled.error();
  std::string note;
  const PolicyRecord& policy = impl_->policy_for_locked(terms.policy, &note);
  Result<detail::ResolvedBinding> binding = impl_->resolve_binding_locked(terms);
  if (!binding) return binding.error();
  ReservationCoordinator::Impl::Suspension suspension(*impl_);
  if (!candidate.is_nil()) {
    if (ReservationRecord* record = impl_->current_record_locked(candidate)) {
      Status suspended = suspension.suspend(*record);
      if (!suspended) return suspended.error();
    }
  }
  detail::Assessment assessment = impl_->assess_locked(terms, binding.value(), policy, now,
                                                       policy.max_conflict_set, policy.max_explanation_bytes);
  if (!note.empty()) assessment.explanation += " | " + note;
  return to_report(assessment);
}

Result<OvercommitReport> ReservationCoordinator::overcommit_report() {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  OvercommitReport report;
  for (const auto& pair : impl_->overcommit) {
    if (pair.second.resolved) continue;
    OvercommitReport::Entry entry;
    entry.resource = pair.second.mutation.resource;
    entry.generation = pair.second.mutation.generation;
    entry.committed_peak = pair.second.mutation.committed_peak;
    entry.committable_ceiling = pair.second.mutation.ceiling;
    entry.window = pair.second.mutation.window;
    entry.detected_at = pair.second.mutation.at;
    report.entries.push_back(entry);
  }
  std::sort(report.entries.begin(), report.entries.end(),
            [](const OvercommitReport::Entry& a, const OvercommitReport::Entry& b) {
              return a.resource < b.resource;
            });
  report.emergency_active = !report.entries.empty();
  return report;
}

CoordinatorStats ReservationCoordinator::stats() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  CoordinatorStats stats = impl_->stats;
  stats.epoch = impl_->incarnation.epoch;
  stats.coordinator_boot = impl_->incarnation.boot;
  stats.tracked_reservations = impl_->records.size();
  stats.tracked_series = impl_->series_records.size();
  std::size_t live_holds = 0;
  for (const auto& pair : impl_->holds) {
    if (!pair.second.released) ++live_holds;
  }
  stats.live_holds = live_holds;
  stats.index_entries = impl_->index.entry_count();
  stats.journal_bytes = impl_->store->journal_bytes();
  stats.snapshot_sequence = impl_->store->snapshot_sequence();
  return stats;
}

std::vector<codec::HoldRecord> ReservationCoordinator::holds() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  std::vector<codec::HoldRecord> out;
  out.reserve(impl_->holds.size());
  for (const auto& pair : impl_->holds) {
    out.push_back(pair.second);
  }
  std::sort(out.begin(), out.end(), [](const codec::HoldRecord& a, const codec::HoldRecord& b) {
    if (a.created_at != b.created_at) return a.created_at < b.created_at;
    return a.id < b.id;
  });
  return out;
}

std::vector<std::string> ReservationCoordinator::audit_invariants() const {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  return impl_->audit_locked();
}

}  // namespace brf
