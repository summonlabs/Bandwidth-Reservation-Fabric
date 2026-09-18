// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/index.hpp"

#include <algorithm>
#include <vector>

namespace brf {
namespace {

/// Saturation ceiling for index arithmetic (2^62). Admission keeps real values
/// far below it: a point can only hold reservations the coordinator admitted,
/// each bounded by the resource ceiling plus the policy overcommit allowance.
constexpr std::int64_t kIndexSaturation = 4611686018427387904LL;
constexpr std::int64_t kNoValue = INT64_MIN;

[[nodiscard]] std::int64_t saturating_add(std::int64_t a, std::int64_t b) noexcept {
  if (b > 0 && a > kIndexSaturation - b) return kIndexSaturation;
  if (b < 0 && a < -kIndexSaturation - b) return -kIndexSaturation;
  return a + b;
}

}  // namespace

const char* to_string(HolderKind kind) noexcept {
  switch (kind) {
    case HolderKind::kReservation: return "RESERVATION";
    case HolderKind::kHold: return "HOLD";
  }
  return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Dynamic segment tree: range add and range max over the timestamp domain.
// Nodes are allocated on demand, so memory tracks the number of distinct
// touched paths rather than the size of the timeline.
// ---------------------------------------------------------------------------
struct IntervalCapacityIndex::Impl {
  struct Node {
    std::int64_t max = 0;
    std::int64_t lazy = 0;
    std::uint32_t left = 0;
    std::uint32_t right = 0;
  };

  std::vector<Node> nodes;
  std::size_t live_intervals = 0;

  Impl() { nodes.emplace_back(); }

  [[nodiscard]] std::uint32_t make_node() {
    nodes.emplace_back();
    return static_cast<std::uint32_t>(nodes.size() - 1);
  }

  void reset() {
    nodes.clear();
    nodes.emplace_back();
  }

  void add(std::uint32_t index, std::int64_t lo, std::int64_t hi, std::int64_t ql, std::int64_t qr,
           std::int64_t delta) {
    if (qr <= lo || hi <= ql) return;
    if (ql <= lo && hi <= qr) {
      nodes[index].max = saturating_add(nodes[index].max, delta);
      nodes[index].lazy = saturating_add(nodes[index].lazy, delta);
      return;
    }
    const std::int64_t mid = lo + (hi - lo) / 2;
    // Node storage is a vector, so no reference may be held across a node
    // allocation: every access re-indexes after the vector may have grown.
    if (nodes[index].left == 0) nodes[index].left = make_node();
    if (nodes[index].right == 0) nodes[index].right = make_node();
    const std::uint32_t left = nodes[index].left;
    const std::uint32_t right = nodes[index].right;
    const std::int64_t carry = nodes[index].lazy;
    if (carry != 0) {
      nodes[left].max = saturating_add(nodes[left].max, carry);
      nodes[left].lazy = saturating_add(nodes[left].lazy, carry);
      nodes[right].max = saturating_add(nodes[right].max, carry);
      nodes[right].lazy = saturating_add(nodes[right].lazy, carry);
      nodes[index].lazy = 0;
    }
    add(left, lo, mid, ql, qr, delta);
    add(right, mid, hi, ql, qr, delta);
    nodes[index].max = std::max(nodes[left].max, nodes[right].max);
  }

  [[nodiscard]] std::int64_t query(std::uint32_t index, std::int64_t lo, std::int64_t hi, std::int64_t ql,
                                   std::int64_t qr, std::int64_t carry) const {
    if (qr <= lo || hi <= ql) return kNoValue;
    // An untouched subtree contributes nothing of its own, but any lazy value
    // accumulated above it still applies. Dropping the carry here would report
    // zero for intervals covered by an ancestor's pending range add.
    if (index == 0) return carry;
    const Node& node = nodes[index];
    if (ql <= lo && hi <= qr) {
      return saturating_add(carry, node.max);
    }
    const std::int64_t mid = lo + (hi - lo) / 2;
    const std::int64_t next_carry = saturating_add(carry, node.lazy);
    const std::int64_t left_max = query(node.left, lo, mid, ql, qr, next_carry);
    const std::int64_t right_max = query(node.right, mid, hi, ql, qr, next_carry);
    return std::max(left_max, right_max);
  }

  [[nodiscard]] std::int64_t query(std::int64_t lo, std::int64_t hi) const {
    if (nodes.size() <= 1) return 0;
    const std::int64_t value = query(1, 0, kMaxTimestampNs, lo, hi, 0);
    return value == kNoValue ? 0 : value;
  }

  [[nodiscard]] bool exceeds(std::uint32_t index, std::int64_t lo, std::int64_t hi, std::int64_t ql,
                             std::int64_t qr, std::int64_t carry, std::int64_t limit) const {
    if (qr <= lo || hi <= ql) return false;
    if (index == 0) return carry > limit;
    const Node& node = nodes[index];
    if (ql <= lo && hi <= qr) {
      return saturating_add(carry, node.max) > limit;
    }
    const std::int64_t mid = lo + (hi - lo) / 2;
    const std::int64_t next_carry = saturating_add(carry, node.lazy);
    return exceeds(node.left, lo, mid, ql, qr, next_carry, limit) ||
           exceeds(node.right, mid, hi, ql, qr, next_carry, limit);
  }
};

IntervalCapacityIndex::IntervalCapacityIndex() : impl_(std::make_unique<Impl>()) {
  (void)impl_->make_node();  // Root occupies index 1.
}
IntervalCapacityIndex::~IntervalCapacityIndex() = default;
IntervalCapacityIndex::IntervalCapacityIndex(IntervalCapacityIndex&&) noexcept = default;
IntervalCapacityIndex& IntervalCapacityIndex::operator=(IntervalCapacityIndex&&) noexcept = default;

void IntervalCapacityIndex::add(const Interval& interval, Bandwidth amount) noexcept {
  if (interval.empty() || amount.bps == 0) return;
  if (impl_->nodes.size() <= 1) (void)impl_->make_node();
  impl_->add(1, 0, kMaxTimestampNs, interval.start.ns, interval.end.ns, amount.bps);
  ++impl_->live_intervals;
}

void IntervalCapacityIndex::remove(const Interval& interval, Bandwidth amount) noexcept {
  if (interval.empty() || amount.bps == 0) return;
  if (impl_->nodes.size() <= 1) return;
  impl_->add(1, 0, kMaxTimestampNs, interval.start.ns, interval.end.ns, -amount.bps);
  if (impl_->live_intervals > 0) --impl_->live_intervals;
  if (impl_->live_intervals == 0) {
    impl_->reset();
  }
}

Bandwidth IntervalCapacityIndex::peak(const Interval& window) const noexcept {
  if (window.empty()) return Bandwidth{0};
  return Bandwidth{impl_->query(window.start.ns, window.end.ns)};
}

Bandwidth IntervalCapacityIndex::at(Timestamp instant) const noexcept {
  if (instant.ns < 0 || instant.ns >= kMaxTimestampNs) return Bandwidth{0};
  return Bandwidth{impl_->query(instant.ns, instant.ns + 1)};
}

bool IntervalCapacityIndex::exceeds(const Interval& window, Bandwidth limit) const noexcept {
  if (window.empty()) return false;
  if (impl_->nodes.size() <= 1) return false;
  return impl_->exceeds(1, 0, kMaxTimestampNs, window.start.ns, window.end.ns, 0, limit.bps);
}

std::size_t IntervalCapacityIndex::node_count() const noexcept { return impl_->nodes.size(); }

// ---------------------------------------------------------------------------
// Resource-keyed index
// ---------------------------------------------------------------------------
CapacityIndex::ResourceState* CapacityIndex::state_for(const ResourceName& resource) {
  auto it = resources_.find(resource);
  return it == resources_.end() ? nullptr : &it->second;
}

const CapacityIndex::ResourceState* CapacityIndex::state_for(const ResourceName& resource) const {
  auto it = resources_.find(resource);
  return it == resources_.end() ? nullptr : &it->second;
}

Status CapacityIndex::insert(const IndexEntry& entry) {
  if (entry.interval.empty()) {
    return make_error(ErrorCode::kInvalidInterval, "index entry has an empty interval");
  }
  if (entry.amount.bps <= 0) {
    return make_error(ErrorCode::kInvalidBandwidth, "index entry has a non-positive amount");
  }
  if (entry.resource.empty()) {
    return make_error(ErrorCode::kInvalidName, "index entry has an empty resource name");
  }
  const EntryIdentity identity{entry.kind, entry.id, entry.resource};
  if (entries_.find(identity) != entries_.end()) {
    return make_error(ErrorCode::kAlreadyExists, "index entry already exists for this holder and resource");
  }
  ResourceState& state = resources_[entry.resource];
  if (entry.kind == HolderKind::kReservation) {
    state.committed.add(entry.interval, entry.amount);
  } else {
    state.holds.add(entry.interval, entry.amount);
  }
  state.combined.add(entry.interval, entry.amount);
  state.by_start.emplace(entry.interval.start, entry);
  ++state.entry_count;
  ++entry_count_;
  entries_.emplace(identity, EntryKey{entry.interval.start});
  return {};
}

Status CapacityIndex::erase(HolderKind kind, const ReservationId& id, std::uint64_t holder_generation,
                            const ResourceName& resource) {
  const EntryIdentity identity{kind, id, resource};
  auto entry_it = entries_.find(identity);
  if (entry_it == entries_.end()) {
    return make_error(ErrorCode::kNotFound, "index entry does not exist");
  }
  ResourceState* state = state_for(resource);
  if (state == nullptr) {
    return make_error(ErrorCode::kInternal, "index bookkeeping is inconsistent");
  }
  auto range = state->by_start.equal_range(entry_it->second.start);
  bool removed = false;
  for (auto it = range.first; it != range.second; ++it) {
    if (it->second.id == id && it->second.holder_generation == holder_generation && it->second.kind == kind) {
      if (kind == HolderKind::kReservation) {
        state->committed.remove(it->second.interval, it->second.amount);
      } else {
        state->holds.remove(it->second.interval, it->second.amount);
      }
      state->combined.remove(it->second.interval, it->second.amount);
      state->by_start.erase(it);
      --state->entry_count;
      removed = true;
      break;
    }
  }
  if (!removed) {
    return make_error(ErrorCode::kInternal, "index entry vanished from the interval map");
  }
  entries_.erase(entry_it);
  if (entry_count_ > 0) --entry_count_;
  if (state->entry_count == 0) {
    resources_.erase(resource);
  }
  return {};
}

Status CapacityIndex::erase_all(HolderKind kind, const ReservationId& id,
                                std::uint64_t holder_generation) {
  // An identity owns at most one generation of indexed capacity, so erasing by
  // identity removes every resource entry that identity holds. The generation
  // is retained for diagnostics and for the mismatch report below.
  std::size_t removed = 0;
  std::size_t mismatched = 0;
  std::vector<ResourceName> touched;
  for (auto it = entries_.begin(); it != entries_.end();) {
    if (it->first.kind != kind || !(it->first.id == id)) {
      ++it;
      continue;
    }
    ResourceState* state = state_for(it->first.resource);
    if (state != nullptr) {
      touched.push_back(it->first.resource);
      auto range = state->by_start.equal_range(it->second.start);
      for (auto entry = range.first; entry != range.second; ++entry) {
        if (entry->second.kind != kind || !(entry->second.id == id)) continue;
        if (entry->second.holder_generation != holder_generation) ++mismatched;
        if (kind == HolderKind::kReservation) {
          state->committed.remove(entry->second.interval, entry->second.amount);
        } else {
          state->holds.remove(entry->second.interval, entry->second.amount);
        }
        state->combined.remove(entry->second.interval, entry->second.amount);
        state->by_start.erase(entry);
        if (state->entry_count > 0) --state->entry_count;
        ++removed;
        break;
      }
    }
    it = entries_.erase(it);
  }
  // Sweep for interval-map elements of this identity that have no bookkeeping
  // key (a state that can only arise from an interrupted repair). Leaving them
  // would double-count capacity and block nothing, so they are removed here.
  for (const ResourceName& resource : touched) {
    ResourceState* state = state_for(resource);
    if (state == nullptr) continue;
    for (auto it = state->by_start.begin(); it != state->by_start.end();) {
      if (it->second.kind != kind || !(it->second.id == id)) {
        ++it;
        continue;
      }
      if (kind == HolderKind::kReservation) {
        state->committed.remove(it->second.interval, it->second.amount);
      } else {
        state->holds.remove(it->second.interval, it->second.amount);
      }
      state->combined.remove(it->second.interval, it->second.amount);
      it = state->by_start.erase(it);
      if (state->entry_count > 0) --state->entry_count;
      ++removed;
    }
  }
  if (removed == 0) {
    return make_error(ErrorCode::kNotFound, "index entry does not exist");
  }
  if (removed > entry_count_) {
    entry_count_ = 0;
  } else {
    entry_count_ -= removed;
  }
  (void)mismatched;
  std::sort(touched.begin(), touched.end());
  touched.erase(std::unique(touched.begin(), touched.end()), touched.end());
  for (const ResourceName& resource : touched) {
    const ResourceState* state = state_for(resource);
    if (state != nullptr && state->entry_count == 0) {
      resources_.erase(resource);
    }
  }
  return {};
}

Status CapacityIndex::replace_all(HolderKind kind, const ReservationId& id, std::uint64_t holder_generation,
                                  const std::vector<IndexEntry>& entries) {
  Status erased = erase_all(kind, id, holder_generation);
  if (!erased && erased.code() != ErrorCode::kNotFound) {
    return erased;
  }
  for (const IndexEntry& entry : entries) {
    Status inserted = insert(entry);
    if (!inserted) return inserted;
  }
  return {};
}

bool CapacityIndex::contains(HolderKind kind, const ReservationId& id) const {
  for (const auto& pair : entries_) {
    if (pair.first.kind == kind && pair.first.id == id) return true;
  }
  return false;
}

std::vector<IndexEntry> CapacityIndex::find_all(HolderKind kind, const ReservationId& id) const {
  std::vector<IndexEntry> found;
  for (const auto& pair : entries_) {
    if (pair.first.kind != kind || !(pair.first.id == id)) continue;
    const ResourceState* state = state_for(pair.first.resource);
    if (state == nullptr) continue;
    auto range = state->by_start.equal_range(pair.second.start);
    for (auto it = range.first; it != range.second; ++it) {
      if (it->second.kind == kind && it->second.id == id) {
        found.push_back(it->second);
        break;
      }
    }
  }
  std::sort(found.begin(), found.end(), [](const IndexEntry& a, const IndexEntry& b) {
    return a.resource < b.resource;
  });
  return found;
}

Bandwidth CapacityIndex::peak_committed(const ResourceName& resource, const Interval& window) const noexcept {
  const ResourceState* state = state_for(resource);
  return state == nullptr ? Bandwidth{0} : state->committed.peak(window);
}

Bandwidth CapacityIndex::peak_holds(const ResourceName& resource, const Interval& window) const noexcept {
  const ResourceState* state = state_for(resource);
  return state == nullptr ? Bandwidth{0} : state->holds.peak(window);
}

Bandwidth CapacityIndex::peak_combined(const ResourceName& resource, const Interval& window) const noexcept {
  const ResourceState* state = state_for(resource);
  return state == nullptr ? Bandwidth{0} : state->combined.peak(window);
}

Bandwidth CapacityIndex::committed_at(const ResourceName& resource, Timestamp instant) const noexcept {
  const ResourceState* state = state_for(resource);
  return state == nullptr ? Bandwidth{0} : state->committed.at(instant);
}

std::vector<IndexEntry> CapacityIndex::overlapping(const ResourceName& resource, const Interval& window,
                                                   std::size_t output_limit, std::size_t scan_limit,
                                                   std::size_t* total_out, bool* truncated_out) const {
  std::vector<IndexEntry> out;
  if (total_out != nullptr) *total_out = 0;
  if (truncated_out != nullptr) *truncated_out = false;
  const ResourceState* state = state_for(resource);
  if (state == nullptr || window.empty()) return out;

  std::size_t scanned = 0;
  std::size_t matched = 0;
  bool hit_scan_limit = false;
  for (const auto& pair : state->by_start) {
    if (!(pair.first < window.end)) break;
    if (scanned >= scan_limit) {
      hit_scan_limit = true;
      break;
    }
    ++scanned;
    if (pair.second.interval.end <= window.start) continue;
    ++matched;
    if (out.size() < output_limit) {
      out.push_back(pair.second);
    }
  }
  std::sort(out.begin(), out.end(), [](const IndexEntry& a, const IndexEntry& b) {
    if (a.interval.start != b.interval.start) return a.interval.start < b.interval.start;
    if (a.interval.end != b.interval.end) return a.interval.end < b.interval.end;
    if (!(a.id == b.id)) return a.id < b.id;
    return a.resource < b.resource;
  });
  if (total_out != nullptr) *total_out = matched;
  if (truncated_out != nullptr) *truncated_out = hit_scan_limit || matched > out.size();
  return out;
}

std::vector<ChangePoint> CapacityIndex::timeline(const ResourceName& resource, const Interval& window,
                                                 std::size_t max_points, bool* truncated_out) const {
  std::vector<ChangePoint> points;
  if (truncated_out != nullptr) *truncated_out = false;
  const ResourceState* state = state_for(resource);
  if (state == nullptr || window.empty()) return points;

  std::vector<Timestamp> boundaries;
  boundaries.push_back(window.start);
  for (const auto& pair : state->by_start) {
    if (!(pair.first < window.end)) break;
    const Interval& interval = pair.second.interval;
    if (interval.end <= window.start) continue;
    boundaries.push_back(interval.start < window.start ? window.start : interval.start);
    boundaries.push_back(interval.end > window.end ? window.end : interval.end);
    if (boundaries.size() > (max_points + 2) * 2) {
      if (truncated_out != nullptr) *truncated_out = true;
      break;
    }
  }
  std::sort(boundaries.begin(), boundaries.end());
  boundaries.erase(std::unique(boundaries.begin(), boundaries.end()), boundaries.end());
  if (boundaries.size() > max_points + 1) {
    boundaries.resize(max_points + 1);
    if (truncated_out != nullptr) *truncated_out = true;
  }
  for (const Timestamp instant : boundaries) {
    if (instant < window.start || instant >= window.end) continue;
    ChangePoint point;
    point.at = instant;
    point.committed = state->committed.at(instant);
    point.holds = state->holds.at(instant);
    points.push_back(point);
  }
  return points;
}

std::vector<ResourceName> CapacityIndex::resource_names() const {
  std::vector<ResourceName> names;
  names.reserve(resources_.size());
  for (const auto& pair : resources_) {
    names.push_back(pair.first);
  }
  return names;
}

void CapacityIndex::clear() noexcept {
  resources_.clear();
  entries_.clear();
  entry_count_ = 0;
}

}  // namespace brf
