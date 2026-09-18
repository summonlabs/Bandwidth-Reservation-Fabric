// Bandwidth Reservation Fabric - authoritative capacity and path authority.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_CAPACITY_HPP
#define BRF_CAPACITY_HPP

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "brf/authority.hpp"
#include "brf/bandwidth.hpp"
#include "brf/error.hpp"
#include "brf/identity.hpp"
#include "brf/time.hpp"

namespace brf {

/// Bounded count of maintenance windows honoured per resource.
inline constexpr std::size_t kMaxMaintenanceWindowsPerResource = 64;
/// Bounded count of components in a single path authority record.
inline constexpr std::size_t kMaxPathComponents = 64;
/// Bounded count of resources in a single capacity snapshot.
inline constexpr std::size_t kMaxResourcesPerSnapshot = 4096;

/// Declared unavailability of a resource. Maintenance reduces reservable
/// capacity to zero for the declared window and is part of the capacity
/// generation: changing maintenance requires advancing the generation.
struct MaintenanceWindow {
  Interval interval;
  std::string reason;

  friend bool operator==(const MaintenanceWindow& a, const MaintenanceWindow& b) noexcept {
    return a.interval == b.interval && a.reason == b.reason;
  }
  friend std::strong_ordering operator<=>(const MaintenanceWindow& a, const MaintenanceWindow& b) noexcept {
    return a.interval <=> b.interval;
  }
};

/// One authoritative capacity statement for exactly one resource generation.
struct ResourceCapacity {
  ResourceName resource;
  ResourceGeneration generation;
  Bandwidth reservable_capacity;   ///< Total bandwidth that may be committed.
  Bandwidth protected_headroom;    ///< Bandwidth that must remain uncommitted.
  FailureDomainName failure_domain;
  FailureDomainGeneration failure_domain_generation;
  std::vector<MaintenanceWindow> maintenance;  ///< Canonical order.

  [[nodiscard]] Bandwidth committable_ceiling() const noexcept {
    if (reservable_capacity.bps <= protected_headroom.bps) return Bandwidth{0};
    return Bandwidth{reservable_capacity.bps - protected_headroom.bps};
  }

  friend bool operator==(const ResourceCapacity& a, const ResourceCapacity& b) noexcept;
};

/// A complete authoritative statement about reservable capacity. The snapshot
/// carries its own identity and generation so every downstream decision can be
/// traced to the exact evidence that justified it.
struct CapacitySnapshot {
  CapacitySnapshotId id;
  CapacitySnapshotGeneration generation;
  FabricEpoch fabric_epoch;
  Timestamp ingested_at;
  /// Whether the snapshot is authoritative for the whole known resource set.
  /// When true, resources absent from the snapshot are withdrawn.
  bool complete = true;
  std::vector<ResourceCapacity> resources;  ///< Canonical order by resource name.

  friend bool operator==(const CapacitySnapshot& a, const CapacitySnapshot& b) noexcept;
};

/// Path authority statement: which resources a path currently traverses, under
/// which generation. Path legality and planning belong to adjacent runtimes;
/// this record only records the authority that was granted and its generation.
struct PathAuthority {
  PathName path;
  PathAuthorityGeneration generation;
  std::vector<ResourceName> components;  ///< Ordered, unique.
  Timestamp issued_at;
  bool retired = false;  ///< A retired path grants no new commitments.

  friend bool operator==(const PathAuthority& a, const PathAuthority& b) noexcept;
};

struct PathAuthoritySnapshot {
  CapacitySnapshotId id;  ///< Reuses the 128-bit identity space for correlation.
  CapacitySnapshotGeneration generation;
  FabricEpoch fabric_epoch;
  Timestamp ingested_at;
  bool complete = true;
  std::vector<PathAuthority> paths;  ///< Canonical order by path name.

  friend bool operator==(const PathAuthoritySnapshot& a, const PathAuthoritySnapshot& b) noexcept;
};

/// Live view of authoritative capacity maintained by the coordinator. The
/// ledger is a pure function of ingested snapshots: identical ingest sequences
/// yield identical ledger state.
class CapacityLedger {
 public:
  struct Entry {
    ResourceCapacity capacity;
    CapacitySnapshotId snapshot;
    Timestamp ingested_at;
    bool withdrawn = false;
    Timestamp withdrawn_at{};
    // Previous generations are retained (not authority) so that revalidation
    // can report exactly which generation a stale reservation was bound to.
    std::vector<ResourceGeneration> prior_generations;
  };

  /// Applies one capacity statement. Fails closed on regeneration conflicts:
  /// reusing a generation with different content is a CONFLICT, a lower
  /// generation is STALE. Returns true when authoritative state changed.
  [[nodiscard]] Result<bool> apply(const ResourceCapacity& capacity, const CapacitySnapshotId& snapshot,
                                   Timestamp now);

  /// Marks a resource withdrawn (removed from a complete snapshot). Existing
  /// generations are retained for reporting but grant no new authority.
  [[nodiscard]] Status withdraw(const ResourceName& resource, Timestamp now);

  /// Snapshot restore only. Injects a previously durable entry without
  /// re-deriving authority: this is recovery, not ingestion, and it never runs
  /// on a live ledger without a preceding clear().
  void inject(Entry entry);

  [[nodiscard]] const Entry* find(const ResourceName& resource) const noexcept;
  [[nodiscard]] bool is_current(const ResourceRef& ref) const noexcept;
  [[nodiscard]] bool is_current_failure_domain(const FailureDomainRef& ref) const noexcept;
  [[nodiscard]] std::vector<ResourceName> resource_names() const;
  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
  void clear() noexcept { entries_.clear(); }

  /// True when a maintenance window covers any part of the interval.
  [[nodiscard]] static bool maintenance_covers(const ResourceCapacity& capacity, const Interval& interval,
                                               Interval* first_window = nullptr);

 private:
  std::map<ResourceName, Entry> entries_;
};

/// Authoritative path table.
class PathAuthorityTable {
 public:
  [[nodiscard]] Result<bool> apply(const PathAuthority& path, const CapacitySnapshotId& snapshot, Timestamp now);
  [[nodiscard]] Status retire(const PathName& path, Timestamp now);

  struct Entry {
    PathAuthority path;
    CapacitySnapshotId snapshot;
    Timestamp ingested_at;
    bool retired = false;
    std::vector<PathAuthorityGeneration> prior_generations;
  };

  /// Snapshot restore only (see CapacityLedger::inject).
  void inject(Entry entry);

  [[nodiscard]] const Entry* find(const PathName& path) const noexcept;
  [[nodiscard]] bool is_current(const PathName& path, PathAuthorityGeneration generation) const noexcept;
  [[nodiscard]] std::vector<PathName> path_names() const;
  [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
  void clear() noexcept { entries_.clear(); }

 private:
  std::map<PathName, Entry> entries_;
};

}  // namespace brf

#endif  // BRF_CAPACITY_HPP
