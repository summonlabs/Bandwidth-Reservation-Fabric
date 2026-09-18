// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <string>
#include <vector>

#include "coordinator_impl.hpp"

namespace brf {

Status ReservationCoordinator::resolve_overcommit(const codec::RequestContext& context,
                                                  const ResourceName& resource,
                                                  OvercommitResolution resolution) {
  std::lock_guard<std::mutex> guard(impl_->mutex);
  const Timestamp now = impl_->now_locked();
  Status valid = impl_->validate_context_locked(context, /*require_attempt=*/true);
  if (!valid) return valid;
  auto entry = impl_->overcommit.find(resource);
  if (entry == impl_->overcommit.end() || entry->second.resolved) {
    return make_error(ErrorCode::kNotFound, "resource '" + resource.str() +
                                                "' has no unresolved overcommit state");
  }
  const CapacityLedger::Entry* ledger_entry = impl_->ledger.find(resource);
  if (ledger_entry == nullptr) {
    return make_error(ErrorCode::kNotFound, "resource '" + resource.str() + "' is not known");
  }
  if (resolution == OvercommitResolution::kRevoke) {
    const std::int64_t ceiling = ledger_entry->withdrawn
                                     ? 0
                                     : ledger_entry->capacity.committable_ceiling().bps;
    const Interval horizon{Timestamp{0}, Timestamp{kMaxTimestampNs}};
    std::size_t revoked = 0;
    for (;;) {
      // Outstanding obligations may be indexed (live generation) or unindexed
      // (a generation that is no longer live). Both are eligible victims.
      std::size_t total = 0;
      bool truncated = false;
      const std::vector<IndexEntry> overlaps =
          impl_->index.overlapping(resource, horizon, impl_->config.index_scan_limit,
                                   impl_->config.index_scan_limit, &total, &truncated);
      std::vector<IndexEntry> candidates;
      for (const IndexEntry& candidate : overlaps) {
        if (candidate.kind == HolderKind::kReservation) candidates.push_back(candidate);
      }
      for (const auto& pair : impl_->records) {
        const ReservationRecord& record = pair.second;
        if (!record.consumes()) continue;
        bool bound = false;
        bool live = true;
        for (const ResourceRef& ref : record.authority.resources) {
          if (ref.resource == resource) bound = true;
          if (!impl_->ledger.is_current(ref)) live = false;
        }
        if (!bound || live) continue;
        IndexEntry stale_entry;
        stale_entry.kind = HolderKind::kReservation;
        stale_entry.id = record.id;
        stale_entry.holder_generation = record.generation.value();
        stale_entry.resource = resource;
        stale_entry.interval = record.consuming_interval();
        stale_entry.amount = record.terms.amount;
        stale_entry.guarantee = record.terms.guarantee;
        stale_entry.state = record.state;
        candidates.push_back(stale_entry);
      }
      if (candidates.empty()) break;
      // Stop as soon as the resource closes.
      IntervalCapacityIndex effective;
      for (const IndexEntry& candidate : candidates) {
        if (candidate.interval.empty()) continue;
        effective.add(candidate.interval, candidate.amount);
      }
      if (effective.peak(horizon).bps <= ceiling) break;
      std::sort(candidates.begin(), candidates.end(), [](const IndexEntry& a, const IndexEntry& b) {
        if (a.guarantee != b.guarantee) return a.guarantee < b.guarantee;
        if (!(a.id == b.id)) return a.id < b.id;
        return a.holder_generation < b.holder_generation;
      });
      ReservationRecord* victim = impl_->find_record_locked(
          candidates.front().id, ReservationGeneration(candidates.front().holder_generation));
      if (victim == nullptr) break;
      codec::RequestContext revoke_context = context;
      revoke_context.reason = "overcommit resolution on " + resource.str();
      Status transitioned = impl_->transition_locked(*victim, ReservationState::kRevoked, now,
                                                     revoke_context.reason, revoke_context, Timestamp{},
                                                     nullptr);
      if (!transitioned) return transitioned;
      ++revoked;
      if (revoked > 4096) break;  // Bound the resolution work per call.
    }
  }
  codec::DurableRecord durable;
  durable.kind = RecordKind::kOvercommit;
  durable.overcommit.resource = resource;
  durable.overcommit.generation = ledger_entry->capacity.generation;
  durable.overcommit.committed_peak = impl_->index.peak_committed(
      resource, Interval{Timestamp{0}, Timestamp{kMaxTimestampNs}});
  durable.overcommit.ceiling =
      ledger_entry->withdrawn ? Bandwidth{0} : ledger_entry->capacity.committable_ceiling();
  durable.overcommit.window = Interval{Timestamp{0}, Timestamp{kMaxTimestampNs}};
  durable.overcommit.at = now;
  durable.overcommit.resolved = true;
  Result<DurableSequence> appended = impl_->append_locked(durable);
  if (!appended) return appended.error();
  entry->second.resolved = true;
  entry->second.mutation = durable.overcommit;
  return {};
}

}  // namespace brf
