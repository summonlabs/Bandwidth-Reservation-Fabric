// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/bandwidth.hpp"

#include <array>
#include <cstdio>
#include <string>

#include "brf/identity.hpp"

namespace brf {
namespace {

struct Scale {
  char suffix;
  std::int64_t factor;
  const char* label;
};

constexpr std::array<Scale, 4> kScales{{{'T', 1000000000000LL, "Tbit/s"},
                                        {'G', 1000000000LL, "Gbit/s"},
                                        {'M', 1000000LL, "Mbit/s"},
                                        {'k', 1000LL, "kbit/s"}}};

}  // namespace

std::string format_bandwidth(Bandwidth bw) {
  if (bw.bps < 0) return "<invalid>";
  for (const Scale& scale : kScales) {
    if (bw.bps >= scale.factor) {
      const std::int64_t whole = bw.bps / scale.factor;
      const std::int64_t milli = (bw.bps % scale.factor) * 1000 / scale.factor;
      char buffer[64];
      const int written = std::snprintf(buffer, sizeof(buffer), "%lld.%03lld %s", static_cast<long long>(whole),
                                        static_cast<long long>(milli), scale.label);
      if (written > 0) {
        return std::string(buffer, static_cast<std::size_t>(written));
      }
      return "<invalid>";
    }
  }
  return to_decimal(static_cast<std::uint64_t>(bw.bps)) + " bit/s";
}

Result<Bandwidth> parse_bandwidth(std::string_view text) noexcept {
  if (text.empty()) {
    return make_error(ErrorCode::kInvalidBandwidth, "bandwidth field is empty");
  }
  std::int64_t factor = 1;
  const char last = text.back();
  bool has_suffix = false;
  for (const Scale& scale : kScales) {
    if (last == scale.suffix) {
      factor = scale.factor;
      has_suffix = true;
      break;
    }
  }
  const std::string_view digits = has_suffix ? text.substr(0, text.size() - 1) : text;
  Result<std::uint64_t> parsed = parse_uint64_decimal(digits);
  if (!parsed) {
    return parsed.error();
  }
  const std::uint64_t value = parsed.value();
  if (value > static_cast<std::uint64_t>(kMaxBandwidthBps)) {
    return make_error(ErrorCode::kInvalidBandwidth, "bandwidth exceeds the maximum representable value");
  }
  const std::uint64_t scaled = value * static_cast<std::uint64_t>(factor);
  if (scaled > static_cast<std::uint64_t>(kMaxBandwidthBps)) {
    return make_error(ErrorCode::kOverflow, "bandwidth scaling overflows the representable range");
  }
  return make_bandwidth(static_cast<std::int64_t>(scaled));
}

}  // namespace brf
