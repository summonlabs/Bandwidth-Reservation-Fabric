// Bandwidth Reservation Fabric - clock model and half-open interval semantics.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_TIME_HPP
#define BRF_TIME_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "brf/error.hpp"

namespace brf {

/// Absolute instant on the fabric timeline: nanoseconds since the Unix epoch,
/// UTC. Negative instants (pre-1970) are rejected everywhere.
struct Timestamp {
  std::int64_t ns = 0;

  friend constexpr bool operator==(Timestamp a, Timestamp b) noexcept { return a.ns == b.ns; }
  friend constexpr std::strong_ordering operator<=>(Timestamp a, Timestamp b) noexcept { return a.ns <=> b.ns; }
};

/// Signed span of nanoseconds. Durable spans are always positive.
struct Duration {
  std::int64_t ns = 0;

  friend constexpr bool operator==(Duration a, Duration b) noexcept { return a.ns == b.ns; }
  friend constexpr std::strong_ordering operator<=>(Duration a, Duration b) noexcept { return a.ns <=> b.ns; }
};

inline constexpr std::int64_t kNsPerSecond = 1000000000LL;
inline constexpr std::int64_t kNsPerMillisecond = 1000000LL;
inline constexpr std::int64_t kNsPerMinute = 60LL * kNsPerSecond;
inline constexpr std::int64_t kNsPerHour = 60LL * kNsPerMinute;
inline constexpr std::int64_t kNsPerDay = 24LL * kNsPerHour;

/// Hard ceiling on any single reservation span (100 years). Bounds interval
/// arithmetic and prevents absurd durations from reaching the index.
inline constexpr std::int64_t kMaxReservationSpanNs = 100LL * 366LL * kNsPerDay;

/// Upper bound of the fabric timeline: 2100-01-01T00:00:00Z. Bounding the
/// domain keeps every interval arithmetic result representable in int64
/// nanoseconds (the int64 nanosecond domain itself ends in 2262).
inline constexpr std::int64_t kMaxTimestampNs = 4102444800LL * kNsPerSecond;

/// Half-open interval [start, end). The runtime uses exactly one interval
/// convention: a reservation covering [s, e) occupies every instant t with
/// s <= t < e. Adjacent intervals never conflict.
struct Interval {
  Timestamp start;
  Timestamp end;

  [[nodiscard]] constexpr bool empty() const noexcept { return !(start < end); }
  [[nodiscard]] Result<std::int64_t> span_ns() const noexcept {
    if (end.ns <= start.ns) {
      return make_error(ErrorCode::kInvalidInterval, "interval end must be strictly after start");
    }
    if (start.ns < 0) {
      return make_error(ErrorCode::kInvalidInterval, "interval start must not be negative");
    }
    const std::int64_t span = end.ns - start.ns;
    if (span > kMaxReservationSpanNs) {
      return make_error(ErrorCode::kInvalidInterval, "interval span exceeds the maximum reservation span");
    }
    return span;
  }
  [[nodiscard]] constexpr bool overlaps(const Interval& other) const noexcept {
    return start < other.end && other.start < end;
  }
  [[nodiscard]] constexpr bool contains(const Interval& other) const noexcept {
    return start <= other.start && other.end <= end;
  }
  [[nodiscard]] constexpr bool contains(Timestamp t) const noexcept { return start <= t && t < end; }

  friend constexpr bool operator==(const Interval& a, const Interval& b) noexcept {
    return a.start == b.start && a.end == b.end;
  }
  friend constexpr std::strong_ordering operator<=>(const Interval& a, const Interval& b) noexcept {
    if (a.start != b.start) return a.start <=> b.start;
    return a.end <=> b.end;
  }
};

/// Structural validation of an interval. This is the only admission point for
/// caller-supplied windows.
[[nodiscard]] Result<void> validate_interval(const Interval& interval) noexcept;

/// Deterministic identity of a canonical window. Two intervals that are equal
/// under the half-open convention hash to the same IntervalId.
[[nodiscard]] std::string interval_id_hex(const Interval& interval);

/// Formats a timestamp as ISO-8601 UTC with nanosecond precision:
/// 1970-01-01T00:00:00.000000000Z. Never locale or timezone dependent.
[[nodiscard]] std::string format_timestamp(Timestamp ts);

/// Parses the canonical ISO-8601 UTC form above. Rejects local-time forms,
/// shortened precision, offsets, and out-of-range fields.
[[nodiscard]] Result<Timestamp> parse_timestamp(std::string_view text) noexcept;

[[nodiscard]] inline Result<Timestamp> add(Timestamp ts, Duration d) noexcept {
  if (d.ns < 0) {
    return make_error(ErrorCode::kInvalidInterval, "duration must not be negative");
  }
  if (ts.ns > kMaxTimestampNs - d.ns) {
    return make_error(ErrorCode::kOverflow, "timestamp addition overflows the fabric timeline");
  }
  return Timestamp{ts.ns + d.ns};
}

[[nodiscard]] inline Result<Timestamp> sub(Timestamp ts, Duration d) noexcept {
  if (d.ns < 0) {
    return make_error(ErrorCode::kInvalidInterval, "duration must not be negative");
  }
  if (ts.ns < d.ns) {
    return make_error(ErrorCode::kOverflow, "timestamp subtraction underflows the fabric timeline");
  }
  return Timestamp{ts.ns - d.ns};
}

/// Saturation-free difference: requires a <= b.
[[nodiscard]] inline Result<Duration> difference(Timestamp b, Timestamp a) noexcept {
  if (b < a) {
    return make_error(ErrorCode::kInvalidInterval, "difference requires an ordered pair of instants");
  }
  return Duration{b.ns - a.ns};
}

}  // namespace brf

#endif  // BRF_TIME_HPP
