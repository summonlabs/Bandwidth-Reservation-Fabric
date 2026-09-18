// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/capacity.hpp"

#include <algorithm>

#include "brf/codec.hpp"

namespace brf {

bool operator==(const ResourceCapacity& a, const ResourceCapacity& b) noexcept {
  return a.resource == b.resource && a.generation == b.generation &&
         a.reservable_capacity == b.reservable_capacity && a.protected_headroom == b.protected_headroom &&
         a.failure_domain == b.failure_domain &&
         a.failure_domain_generation == b.failure_domain_generation && a.maintenance == b.maintenance;
}

bool operator==(const CapacitySnapshot& a, const CapacitySnapshot& b) noexcept {
  return a.id == b.id && a.generation == b.generation && a.fabric_epoch == b.fabric_epoch &&
         a.complete == b.complete && a.resources == b.resources;
}

bool operator==(const PathAuthority& a, const PathAuthority& b) noexcept {
  return a.path == b.path && a.generation == b.generation && a.components == b.components &&
         a.retired == b.retired;
}

bool operator==(const PathAuthoritySnapshot& a, const PathAuthoritySnapshot& b) noexcept {
  return a.id == b.id && a.generation == b.generation && a.fabric_epoch == b.fabric_epoch &&
         a.complete == b.complete && a.paths == b.paths;
}

Result<bool> CapacityLedger::apply(const ResourceCapacity& capacity, const CapacitySnapshotId& snapshot,
                                   Timestamp now) {
  if (capacity.resource.empty()) {
    return make_error(ErrorCode::kInvalidName, "capacity record has an empty resource name");
  }
  if (capacity.reservable_capacity.bps <= 0) {
    return make_error(ErrorCode::kInvalidBandwidth, "reservable capacity must be strictly positive");
  }
  if (capacity.reservable_capacity.bps > kMaxBandwidthBps) {
    return make_error(ErrorCode::kInvalidBandwidth, "reservable capacity exceeds the representable range");
  }
  if (capacity.protected_headroom.bps < 0 || capacity.protected_headroom.bps > kMaxBandwidthBps) {
    return make_error(ErrorCode::kInvalidBandwidth, "protected headroom is out of range");
  }
  if (capacity.maintenance.size() > kMaxMaintenanceWindowsPerResource) {
    return make_error(ErrorCode::kResourceExhausted, "too many maintenance windows for one resource");
  }
  for (const MaintenanceWindow& window : capacity.maintenance) {
    Status valid = validate_interval(window.interval);
    if (!valid) return valid.error();
  }

  auto it = entries_.find(capacity.resource);
  if (it == entries_.end()) {
    Entry entry;
    entry.capacity = capacity;
    entry.snapshot = snapshot;
    entry.ingested_at = now;
    entries_.emplace(capacity.resource, std::move(entry));
    return true;
  }

  Entry& entry = it->second;
  if (capacity.generation == entry.capacity.generation) {
    if (!(capacity == entry.capacity)) {
      return make_error(ErrorCode::kConflict,
                        "resource '" + capacity.resource.str() +
                            "' was re-declared at the same generation with different content");
    }
    if (entry.withdrawn) {
      entry.withdrawn = false;
      entry.snapshot = snapshot;
      entry.ingested_at = now;
      return true;
    }
    return false;  // Idempotent re-ingestion of identical authoritative state.
  }
  if (capacity.generation < entry.capacity.generation) {
    return make_error(ErrorCode::kStaleGeneration,
                      "resource '" + capacity.resource.str() + "' was offered a stale capacity generation");
  }

  Entry next;
  next.capacity = capacity;
  next.snapshot = snapshot;
  next.ingested_at = now;
  next.prior_generations = entry.prior_generations;
  next.prior_generations.push_back(entry.capacity.generation);
  entry = std::move(next);
  return true;
}

Status CapacityLedger::withdraw(const ResourceName& resource, Timestamp now) {
  auto it = entries_.find(resource);
  if (it == entries_.end()) {
    return make_error(ErrorCode::kNotFound, "resource '" + resource.str() + "' is not known to the ledger");
  }
  if (it->second.withdrawn) {
    return {};  // Idempotent.
  }
  it->second.withdrawn = true;
  it->second.withdrawn_at = now;
  return {};
}

void CapacityLedger::inject(Entry entry) { entries_[entry.capacity.resource] = std::move(entry); }

const CapacityLedger::Entry* CapacityLedger::find(const ResourceName& resource) const noexcept {
  auto it = entries_.find(resource);
  return it == entries_.end() ? nullptr : &it->second;
}

bool CapacityLedger::is_current(const ResourceRef& ref) const noexcept {
  const Entry* entry = find(ref.resource);
  if (entry == nullptr || entry->withdrawn) return false;
  return entry->capacity.generation == ref.generation;
}

bool CapacityLedger::is_current_failure_domain(const FailureDomainRef& ref) const noexcept {
  for (const auto& pair : entries_) {
    const Entry& entry = pair.second;
    if (entry.withdrawn) continue;
    if (entry.capacity.failure_domain == ref.domain) {
      return entry.capacity.failure_domain_generation == ref.generation;
    }
  }
  return false;
}

std::vector<ResourceName> CapacityLedger::resource_names() const {
  std::vector<ResourceName> names;
  names.reserve(entries_.size());
  for (const auto& pair : entries_) {
    names.push_back(pair.first);
  }
  return names;
}

bool CapacityLedger::maintenance_covers(const ResourceCapacity& capacity, const Interval& interval,
                                        Interval* first_window) {
  for (const MaintenanceWindow& window : capacity.maintenance) {
    if (window.interval.overlaps(interval)) {
      if (first_window != nullptr) {
        *first_window = window.interval;
      }
      return true;
    }
  }
  return false;
}

Result<bool> PathAuthorityTable::apply(const PathAuthority& path, const CapacitySnapshotId& snapshot,
                                       Timestamp now) {
  if (path.path.empty()) {
    return make_error(ErrorCode::kInvalidName, "path authority record has an empty path name");
  }
  if (path.components.empty()) {
    return make_error(ErrorCode::kInvalidArgument, "path authority record has no components");
  }
  if (path.components.size() > kMaxPathComponents) {
    return make_error(ErrorCode::kResourceExhausted, "path exceeds the maximum component count");
  }
  std::vector<ResourceName> sorted = path.components;
  std::sort(sorted.begin(), sorted.end());
  if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
    return make_error(ErrorCode::kConflict, "path contains a duplicate component");
  }

  auto it = entries_.find(path.path);
  if (it == entries_.end()) {
    Entry entry;
    entry.path = path;
    entry.snapshot = snapshot;
    entry.ingested_at = now;
    entry.retired = path.retired;
    entries_.emplace(path.path, std::move(entry));
    return true;
  }
  Entry& entry = it->second;
  if (path.generation == entry.path.generation) {
    if (!(path == entry.path)) {
      return make_error(ErrorCode::kConflict,
                        "path '" + path.path.str() +
                            "' was re-declared at the same generation with different content");
    }
    if (entry.retired != path.retired) {
      entry.retired = path.retired;
      return true;
    }
    return false;
  }
  if (path.generation < entry.path.generation) {
    return make_error(ErrorCode::kStaleGeneration,
                      "path '" + path.path.str() + "' was offered a stale authority generation");
  }
  Entry next;
  next.path = path;
  next.snapshot = snapshot;
  next.ingested_at = now;
  next.retired = path.retired;
  next.prior_generations = entry.prior_generations;
  next.prior_generations.push_back(entry.path.generation);
  entry = std::move(next);
  return true;
}

Status PathAuthorityTable::retire(const PathName& path, Timestamp now) {
  auto it = entries_.find(path);
  if (it == entries_.end()) {
    return make_error(ErrorCode::kNotFound, "path '" + path.str() + "' is not known to the path authority table");
  }
  if (it->second.retired) return {};
  it->second.retired = true;
  it->second.ingested_at = now;
  return {};
}

void PathAuthorityTable::inject(Entry entry) { entries_[entry.path.path] = std::move(entry); }

const PathAuthorityTable::Entry* PathAuthorityTable::find(const PathName& path) const noexcept {
  auto it = entries_.find(path);
  return it == entries_.end() ? nullptr : &it->second;
}

bool PathAuthorityTable::is_current(const PathName& path, PathAuthorityGeneration generation) const noexcept {
  const Entry* entry = find(path);
  if (entry == nullptr || entry->retired) return false;
  return entry->path.generation == generation;
}

std::vector<PathName> PathAuthorityTable::path_names() const {
  std::vector<PathName> names;
  names.reserve(entries_.size());
  for (const auto& pair : entries_) {
    names.push_back(pair.first);
  }
  return names;
}

}  // namespace brf
