// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Coordinator record, index, and queue bookkeeping.
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "coordinator_impl.hpp"

namespace brf {

// ---------------------------------------------------------------------------
// Index maintenance
// ---------------------------------------------------------------------------
bool ReservationCoordinator::Impl::indexable_locked(const ReservationRecord& record) const {
  if (!record.consumes()) return false;
  if (record.applicability == Applicability::kStale) return false;
  if (record.consuming_interval().empty()) return false;
  for (const ResourceRef& ref : record.authority.resources) {
    if (!ledger.is_current(ref)) return false;
  }
  return true;
}

Status ReservationCoordinator::Impl::index_insert_locked(const ReservationRecord& record) {
  const Interval window = record.consuming_interval();
  if (window.empty()) return {};
  // Indexing an identity replaces whatever that identity previously held. An
  // earlier generation of the same reservation can therefore never block or
  // duplicate the entry set of the generation that now carries authority.
  std::vector<IndexEntry> entries;
  entries.reserve(record.authority.resources.size());
  for (const ResourceRef& ref : record.authority.resources) {
    IndexEntry entry;
    entry.kind = HolderKind::kReservation;
    entry.id = record.id;
    entry.holder_generation = record.generation.value();
    entry.resource = ref.resource;
    entry.interval = window;
    entry.amount = record.terms.amount;
    entry.guarantee = record.terms.guarantee;
    entry.state = record.state;
    entries.push_back(entry);
  }
  return index.replace_all(HolderKind::kReservation, record.id, record.generation.value(), entries);
}

Status ReservationCoordinator::Impl::index_erase_locked(const ReservationRecord& record) {
  if (!index.contains(HolderKind::kReservation, record.id)) return {};
  return index.erase_all(HolderKind::kReservation, record.id, record.generation.value());
}

bool ReservationCoordinator::Impl::index_holds_locked(const ReservationRecord& record) const {
  const std::vector<IndexEntry> entries = index.find_all(HolderKind::kReservation, record.id);
  for (const IndexEntry& entry : entries) {
    if (entry.holder_generation == record.generation.value()) return true;
  }
  return false;
}

Status ReservationCoordinator::Impl::sync_index_locked(const ReservationRecord& record) {
  const bool should_index = indexable_locked(record);
  const bool indexed = index_holds_locked(record);
  if (should_index && !indexed) return index_insert_locked(record);
  if (!should_index && indexed) return index_erase_locked(record);
  return {};
}

Status ReservationCoordinator::Impl::update_index_locked(const ReservationRecord& record) {
  if (index_holds_locked(record)) {
    Status erased = index_erase_locked(record);
    if (!erased) return erased;
  }
  return sync_index_locked(record);
}

void ReservationCoordinator::Impl::rebuild_queues_locked() {
  activation_queue.clear();
  expiry_queue.clear();
  recall_queue.clear();
  for (const auto& pair : records) {
    sync_queues_locked(pair.second);
  }
}

Status ReservationCoordinator::Impl::rebuild_index_locked() {
  index.clear();
  for (const auto& pair : records) {
    auto current = current_generation.find(pair.first.id);
    if (current == current_generation.end() || pair.first.generation != current->second) continue;
    Status synced = sync_index_locked(pair.second);
    if (!synced) return synced;
  }
  return {};
}

// ---------------------------------------------------------------------------
// Record bookkeeping
// ---------------------------------------------------------------------------
void ReservationCoordinator::Impl::register_record_locked(const ReservationRecord& record) {
  const detail::ReservationKey key{record.id, record.generation};
  const bool existed = records.find(key) != records.end();
  records[key] = record;
  std::vector<ReservationGeneration>& history = generations[record.id];
  if (std::find(history.begin(), history.end(), record.generation) == history.end()) {
    history.push_back(record.generation);
    std::sort(history.begin(), history.end());
  }
  auto current = current_generation.find(record.id);
  if (current == current_generation.end() || record.generation > current->second) {
    current_generation[record.id] = record.generation;
  }
  if (!existed) {
    if (is_terminal(record.state)) {
      ++history_count;
    } else {
      ++live_count;
    }
  }
}

void ReservationCoordinator::Impl::set_state_locked(ReservationRecord& record, ReservationState state,
                                                    Timestamp at, const std::string& reason,
                                                    const Provenance& provenance) {
  const bool was_terminal = is_terminal(record.state);
  const bool now_terminal = is_terminal(state);
  if (!was_terminal && now_terminal) {
    if (live_count > 0) --live_count;
    ++history_count;
  } else if (was_terminal && !now_terminal) {
    if (history_count > 0) --history_count;
    ++live_count;
  }
  record.state = state;
  record.state_changed_at = at;
  record.state_reason = sanitize_reason(reason);
  record.last_provenance = provenance;
  if (now_terminal) {
    record.terminated_at = at;
  }
}

ReservationRecord* ReservationCoordinator::Impl::current_record_locked(const ReservationId& id) {
  auto current = current_generation.find(id);
  if (current == current_generation.end()) return nullptr;
  auto record = records.find(detail::ReservationKey{id, current->second});
  if (record == records.end()) return nullptr;
  return &record->second;
}

ReservationRecord* ReservationCoordinator::Impl::find_record_locked(const ReservationId& id,
                                                                    ReservationGeneration generation) {
  auto record = records.find(detail::ReservationKey{id, generation});
  if (record == records.end()) return nullptr;
  return &record->second;
}

const ReservationRecord* ReservationCoordinator::Impl::find_record_const_locked(
    const ReservationId& id, ReservationGeneration generation) const {
  auto record = records.find(detail::ReservationKey{id, generation});
  if (record == records.end()) return nullptr;
  return &record->second;
}

detail::AttemptRecord* ReservationCoordinator::Impl::find_attempt_locked(const AttemptId& attempt) {
  auto it = attempts.find(attempt);
  return it == attempts.end() ? nullptr : &it->second;
}

void ReservationCoordinator::Impl::remember_attempt_locked(const detail::AttemptRecord& record) {
  if (attempts.find(record.attempt) == attempts.end()) {
    attempt_order.push_back(record.attempt);
  }
  attempts[record.attempt] = record;
  while (attempt_order.size() > config.max_attempts && !attempt_order.empty()) {
    const AttemptId oldest = attempt_order.front();
    attempt_order.pop_front();
    attempts.erase(oldest);
  }
}

void ReservationCoordinator::Impl::sync_queues_locked(const ReservationRecord& record) {
  const detail::ReservationKey key{record.id, record.generation};
  auto remove_from = [&key](std::multimap<Timestamp, detail::ReservationKey>& queue) {
    for (auto it = queue.begin(); it != queue.end();) {
      if (it->second == key) {
        it = queue.erase(it);
      } else {
        ++it;
      }
    }
  };
  remove_from(activation_queue);
  remove_from(expiry_queue);
  remove_from(recall_queue);
  if (!record.consumes()) return;
  if (record.state == ReservationState::kCommitted) {
    activation_queue.emplace(record.terms.interval.start, key);
  }
  const Interval window = record.consuming_interval();
  if (!window.empty()) {
    expiry_queue.emplace(window.end, key);
  }
  if (record.state == ReservationState::kRecallPending && record.recall_effective_at.ns > 0) {
    recall_queue.emplace(record.recall_effective_at, key);
  }
}

Status ReservationCoordinator::Impl::mark_applicability_locked(ReservationRecord& record,
                                                               Applicability applicability,
                                                               ApplicabilityReason reason, Timestamp at) {
  if (record.applicability == applicability && record.applicability_reason == reason) {
    return {};
  }
  codec::DurableRecord durable;
  durable.kind = RecordKind::kReservationApplicability;
  durable.applicability.id = record.id;
  durable.applicability.generation = record.generation;
  durable.applicability.applicability = applicability;
  durable.applicability.reason = reason;
  durable.applicability.at = at;
  Result<DurableSequence> sequence = append_locked(durable);
  if (!sequence) return sequence.error();
  record.applicability = applicability;
  record.applicability_reason = reason;
  record.sequence = sequence.value();
  record.state_changed_at = at;
  records[detail::ReservationKey{record.id, record.generation}] = record;
  // A record that stops being applicable stops consuming capacity, so its
  // time-queue entries must go with it.
  sync_queues_locked(record);
  return sync_index_locked(record);
}

// ---------------------------------------------------------------------------
// Evaluation suspension
// ---------------------------------------------------------------------------
Status ReservationCoordinator::Impl::Suspension::suspend(const ReservationRecord& record) {
  const std::vector<IndexEntry> held = impl.index.find_all(HolderKind::kReservation, record.id);
  for (const IndexEntry& entry : held) {
    if (entry.holder_generation != record.generation.value()) continue;
    entries.push_back(entry);
    Status erased =
        impl.index.erase(HolderKind::kReservation, entry.id, entry.holder_generation, entry.resource);
    if (!erased) return erased;
  }
  return {};
}

Status ReservationCoordinator::Impl::Suspension::suspend_hold(const HoldId& id) {
  const std::vector<IndexEntry> held = impl.index.find_all(HolderKind::kHold, id);
  for (const IndexEntry& entry : held) {
    entries.push_back(entry);
    Status erased = impl.index.erase(HolderKind::kHold, entry.id, entry.holder_generation, entry.resource);
    if (!erased) return erased;
  }
  return {};
}

void ReservationCoordinator::Impl::Suspension::restore() {
  // Restoration must be per entry, not per identity: a multi-resource holder is
  // suspended as several entries, and skipping the rest of an identity merely
  // because its first resource was restored would silently drop capacity.
  for (const IndexEntry& entry : entries) {
    Status inserted = impl.index.insert(entry);
    if (!inserted && inserted.code() != ErrorCode::kAlreadyExists) {
      std::fprintf(stderr, "index restore failed for %s: %s\n", entry.id.to_hex().c_str(),
                   inserted.error().message.c_str());
    }
  }
  entries.clear();
}

}  // namespace brf
