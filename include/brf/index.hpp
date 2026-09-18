// Bandwidth Reservation Fabric - interval/resource capacity index.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_INDEX_HPP
#define BRF_INDEX_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>

#include "brf/bandwidth.hpp"
#include "brf/error.hpp"
#include "brf/identity.hpp"
#include "brf/outcome.hpp"
#include "brf/policy.hpp"
#include "brf/reservation.hpp"
#include "brf/time.hpp"

namespace brf {

/// Why an entry occupies capacity in the index.
enum class HolderKind : std::uint8_t {
  kReservation = 0,
  kHold = 1,
};

[[nodiscard]] const char* to_string(HolderKind kind) noexcept;

/// One capacity-occupying interval on one resource. Reservations and holds
/// share the index so that closure checks cannot forget one of them, and a
/// multi-resource commitment produces one entry per resource.
struct IndexEntry {
  HolderKind kind = HolderKind::kReservation;
  ReservationId id;  ///< Reservation id, or hold id for kHold.
  /// Reservation generation, or hold generation. The index is deliberately
  /// untyped here: generations are opaque tags for accounting, and the typed
  /// authority layer converts at the boundary.
  std::uint64_t holder_generation = 0;
  ResourceName resource;
  Interval interval;
  Bandwidth amount{0};
  GuaranteeClass guarantee = GuaranteeClass::kGuaranteed;
  ReservationState state = ReservationState::kCommitted;
};

/// Aggregate accounting for one resource: three interval structures that are
/// maintained together, so committed + holds == combined at every instant.
/// Range updates and peak queries are O(log T) in the timestamp domain rather
/// than O(N) in the population.
class IntervalCapacityIndex {
 public:
  IntervalCapacityIndex();
  ~IntervalCapacityIndex();
  IntervalCapacityIndex(IntervalCapacityIndex&&) noexcept;
  IntervalCapacityIndex& operator=(IntervalCapacityIndex&&) noexcept;
  IntervalCapacityIndex(const IntervalCapacityIndex&) = delete;
  IntervalCapacityIndex& operator=(const IntervalCapacityIndex&) = delete;

  void add(const Interval& interval, Bandwidth amount) noexcept;
  void remove(const Interval& interval, Bandwidth amount) noexcept;

  /// Peak simultaneous commitment over the query window. Zero for an empty or
  /// invalid window.
  [[nodiscard]] Bandwidth peak(const Interval& window) const noexcept;
  [[nodiscard]] Bandwidth at(Timestamp instant) const noexcept;

  /// True as soon as any point in the window exceeds the limit. Equivalent to
  /// peak(window) > limit but may terminate early.
  [[nodiscard]] bool exceeds(const Interval& window, Bandwidth limit) const noexcept;

  [[nodiscard]] std::size_t node_count() const noexcept;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

/// Resource-keyed capacity index with bounded overlap enumeration.
class CapacityIndex {
 public:
  CapacityIndex() = default;

  [[nodiscard]] Status insert(const IndexEntry& entry);
  [[nodiscard]] Status erase(HolderKind kind, const ReservationId& id, std::uint64_t holder_generation,
                             const ResourceName& resource);
  /// Removes every resource entry belonging to one holder generation.
  [[nodiscard]] Status erase_all(HolderKind kind, const ReservationId& id, std::uint64_t holder_generation);
  /// Replaces every entry of one holder generation with the supplied set.
  [[nodiscard]] Status replace_all(HolderKind kind, const ReservationId& id, std::uint64_t holder_generation,
                                   const std::vector<IndexEntry>& entries);

  [[nodiscard]] bool contains(HolderKind kind, const ReservationId& id) const;
  [[nodiscard]] std::vector<IndexEntry> find_all(HolderKind kind, const ReservationId& id) const;

  [[nodiscard]] Bandwidth peak_committed(const ResourceName& resource, const Interval& window) const noexcept;
  [[nodiscard]] Bandwidth peak_holds(const ResourceName& resource, const Interval& window) const noexcept;
  [[nodiscard]] Bandwidth peak_combined(const ResourceName& resource, const Interval& window) const noexcept;
  [[nodiscard]] Bandwidth committed_at(const ResourceName& resource, Timestamp instant) const noexcept;

  /// Enumerates entries overlapping the window. The scan is bounded by
  /// scan_limit entries; the true number of overlaps is reported in total, and
  /// truncated flags any bounding so callers never mistake a bounded answer for
  /// a complete one. The authoritative closure decision never uses this method:
  /// it uses peak(), which is exact.
  [[nodiscard]] std::vector<IndexEntry> overlapping(const ResourceName& resource, const Interval& window,
                                                    std::size_t output_limit, std::size_t scan_limit,
                                                    std::size_t* total_out, bool* truncated_out) const;

  /// Step function of committed and held bandwidth across the window. Bounded
  /// by max_points.
  [[nodiscard]] std::vector<ChangePoint> timeline(const ResourceName& resource, const Interval& window,
                                                  std::size_t max_points, bool* truncated_out) const;

  [[nodiscard]] std::size_t entry_count() const noexcept { return entry_count_; }
  [[nodiscard]] std::size_t resource_count() const noexcept { return resources_.size(); }
  [[nodiscard]] std::vector<ResourceName> resource_names() const;
  void clear() noexcept;

 private:
  struct ResourceState {
    IntervalCapacityIndex committed;
    IntervalCapacityIndex holds;
    IntervalCapacityIndex combined;
    std::multimap<Timestamp, IndexEntry> by_start;
    std::size_t entry_count = 0;
  };

  struct EntryIdentity {
    HolderKind kind = HolderKind::kReservation;
    ReservationId id;
    ResourceName resource;

    friend bool operator<(const EntryIdentity& a, const EntryIdentity& b) {
      if (a.kind != b.kind) return a.kind < b.kind;
      if (!(a.id == b.id)) return a.id < b.id;
      return a.resource < b.resource;
    }
  };

  struct EntryKey {
    Timestamp start;
  };

  [[nodiscard]] ResourceState* state_for(const ResourceName& resource);
  [[nodiscard]] const ResourceState* state_for(const ResourceName& resource) const;

  std::map<ResourceName, ResourceState> resources_;
  std::map<EntryIdentity, EntryKey> entries_;
  std::size_t entry_count_ = 0;
};

}  // namespace brf

#endif  // BRF_INDEX_HPP
