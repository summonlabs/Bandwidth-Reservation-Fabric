// Bandwidth Reservation Fabric - explicit fixed-point bandwidth units.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_BANDWIDTH_HPP
#define BRF_BANDWIDTH_HPP

#include <cstdint>
#include <string>

#include "brf/error.hpp"

namespace brf {

/// Exact integer bits per second. Floating point is never used for capacity
/// accounting: closure is decided by integer comparison.
struct Bandwidth {
  std::int64_t bps = 0;

  friend constexpr bool operator==(Bandwidth a, Bandwidth b) noexcept { return a.bps == b.bps; }
  friend constexpr std::strong_ordering operator<=>(Bandwidth a, Bandwidth b) noexcept { return a.bps <=> b.bps; }
};

/// Largest bandwidth value the runtime accepts (1 Pbit/s). Bounds every
/// intermediate sum so closure checks cannot silently overflow.
inline constexpr std::int64_t kMaxBandwidthBps = 1000000000000000LL;

[[nodiscard]] inline Result<Bandwidth> make_bandwidth(std::int64_t bps) noexcept {
  if (bps <= 0) {
    return make_error(ErrorCode::kInvalidBandwidth, "bandwidth must be strictly positive");
  }
  if (bps > kMaxBandwidthBps) {
    return make_error(ErrorCode::kInvalidBandwidth, "bandwidth exceeds the maximum representable value");
  }
  return Bandwidth{bps};
}

/// Checked sum that refuses to wrap and refuses to exceed the ceiling.
[[nodiscard]] inline Result<Bandwidth> add(Bandwidth a, Bandwidth b) noexcept {
  if (a.bps < 0 || b.bps < 0) {
    return make_error(ErrorCode::kInvalidBandwidth, "bandwidth must not be negative");
  }
  if (a.bps > kMaxBandwidthBps - b.bps) {
    return make_error(ErrorCode::kOverflow, "bandwidth addition overflows the representable range");
  }
  return Bandwidth{a.bps + b.bps};
}

/// Checked difference. Returns kInvalidBandwidth when the result would be
/// negative, so callers must decide explicitly what a shortfall means.
[[nodiscard]] inline Result<Bandwidth> subtract(Bandwidth a, Bandwidth b) noexcept {
  if (b.bps > a.bps) {
    return make_error(ErrorCode::kInvalidBandwidth, "bandwidth subtraction would be negative");
  }
  return Bandwidth{a.bps - b.bps};
}

[[nodiscard]] inline constexpr Bandwidth saturating_add(Bandwidth a, Bandwidth b) noexcept {
  if (a.bps > kMaxBandwidthBps - b.bps) {
    return Bandwidth{kMaxBandwidthBps};
  }
  return Bandwidth{a.bps + b.bps};
}

[[nodiscard]] std::string format_bandwidth(Bandwidth bw);
[[nodiscard]] Result<Bandwidth> parse_bandwidth(std::string_view text) noexcept;

}  // namespace brf

#endif  // BRF_BANDWIDTH_HPP
