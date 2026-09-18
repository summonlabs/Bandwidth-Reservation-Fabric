// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/time.hpp"

#include <array>
#include <cstdio>

#include "brf/hash.hpp"

namespace brf {
namespace {

struct CivilDate {
  std::int64_t year = 1970;
  unsigned month = 1;
  unsigned day = 1;
};

/// Days-from-civil / civil-from-days (Howard Hinnant's algorithms), valid for
/// the whole proleptic Gregorian calendar. Deliberately free of <ctime> so the
/// runtime can never acquire local-timezone behaviour.
[[nodiscard]] constexpr std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) noexcept {
  y -= m <= 2 ? 1 : 0;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned month_shift = (m > 2U) ? (m - 3U) : (m + 9U);
  const unsigned doy = (153U * month_shift + 2U) / 5U + d - 1U;
  const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
  return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

[[nodiscard]] constexpr CivilDate civil_from_days(std::int64_t z) noexcept {
  z += 719468;
  const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(z - era * 146097);
  const unsigned yoe = (doe - doe / 1460U + doe / 36524U - doe / 146096U) / 365U;
  const std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
  const unsigned doy = doe - (365U * yoe + yoe / 4U - yoe / 100U);
  const unsigned mp = (5U * doy + 2U) / 153U;
  const unsigned d = doy - (153U * mp + 2U) / 5U + 1U;
  const unsigned m = (mp < 10U) ? (mp + 3U) : (mp - 9U);
  CivilDate out;
  out.year = y + (m <= 2U ? 1 : 0);
  out.month = m;
  out.day = d;
  return out;
}

[[nodiscard]] bool is_leap(std::int64_t year) noexcept {
  return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

[[nodiscard]] unsigned days_in_month(std::int64_t year, unsigned month) noexcept {
  constexpr std::array<unsigned, 12> kMonthDays{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (month < 1 || month > 12) return 0;
  if (month == 2 && is_leap(year)) return 29;
  return kMonthDays[month - 1];
}

[[nodiscard]] bool parse_fixed_digits(std::string_view text, std::size_t offset, std::size_t count,
                                      int* out) noexcept {
  if (offset + count > text.size()) return false;
  int value = 0;
  for (std::size_t i = 0; i < count; ++i) {
    const char ch = text[offset + i];
    if (ch < '0' || ch > '9') return false;
    value = value * 10 + (ch - '0');
  }
  *out = value;
  return true;
}

}  // namespace

Result<void> validate_interval(const Interval& interval) noexcept {
  if (interval.start.ns < 0) {
    return make_error(ErrorCode::kInvalidInterval, "interval start must not be negative");
  }
  if (interval.end.ns > kMaxTimestampNs) {
    return make_error(ErrorCode::kInvalidInterval, "interval end exceeds the maximum timestamp");
  }
  if (interval.end.ns <= interval.start.ns) {
    return make_error(ErrorCode::kInvalidInterval, "interval must be non-empty under [start, end) semantics");
  }
  const std::int64_t span = interval.end.ns - interval.start.ns;
  if (span > kMaxReservationSpanNs) {
    return make_error(ErrorCode::kInvalidInterval, "interval span exceeds the maximum reservation span");
  }
  return {};
}

std::string interval_id_hex(const Interval& interval) {
  std::array<std::uint8_t, 16> buffer{};
  const std::uint64_t start = static_cast<std::uint64_t>(interval.start.ns);
  const std::uint64_t end = static_cast<std::uint64_t>(interval.end.ns);
  for (std::size_t i = 0; i < 8; ++i) {
    buffer[i] = static_cast<std::uint8_t>((start >> (8 * (7 - i))) & 0xFFU);
    buffer[8 + i] = static_cast<std::uint8_t>((end >> (8 * (7 - i))) & 0xFFU);
  }
  return fingerprint128(buffer.data(), buffer.size()).to_hex();
}

std::string format_timestamp(Timestamp ts) {
  if (ts.ns < 0) return "<invalid>";
  const std::int64_t seconds = ts.ns / kNsPerSecond;
  const std::int64_t nanos = ts.ns % kNsPerSecond;
  const std::int64_t days = seconds / 86400;
  const std::int64_t second_of_day = seconds % 86400;
  const CivilDate date = civil_from_days(days);

  char buffer[40];
  const int written = std::snprintf(buffer, sizeof(buffer), "%04lld-%02u-%02uT%02lld:%02lld:%02lld.%09lldZ",
                                    static_cast<long long>(date.year), date.month, date.day,
                                    static_cast<long long>(second_of_day / 3600),
                                    static_cast<long long>((second_of_day % 3600) / 60),
                                    static_cast<long long>(second_of_day % 60),
                                    static_cast<long long>(nanos));
  if (written <= 0) return "<invalid>";
  return std::string(buffer, static_cast<std::size_t>(written));
}

Result<Timestamp> parse_timestamp(std::string_view text) noexcept {
  // Strict canonical form: YYYY-MM-DDTHH:MM:SS[.fffffffff]Z
  if (text.size() < 20) {
    return make_error(ErrorCode::kInvalidArgument, "timestamp is too short for the canonical form");
  }
  if (text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' || text[16] != ':') {
    return make_error(ErrorCode::kInvalidArgument, "timestamp does not match YYYY-MM-DDTHH:MM:SS(.f)Z");
  }
  int year = 0;
  int month = 0;
  int day = 0;
  int hour = 0;
  int minute = 0;
  int second = 0;
  if (!parse_fixed_digits(text, 0, 4, &year) || !parse_fixed_digits(text, 5, 2, &month) ||
      !parse_fixed_digits(text, 8, 2, &day) || !parse_fixed_digits(text, 11, 2, &hour) ||
      !parse_fixed_digits(text, 14, 2, &minute) || !parse_fixed_digits(text, 17, 2, &second)) {
    return make_error(ErrorCode::kInvalidArgument, "timestamp contains a non-digit field");
  }
  std::size_t cursor = 19;
  std::int64_t nanos = 0;
  if (cursor < text.size() && text[cursor] == '.') {
    ++cursor;
    std::size_t digits = 0;
    while (cursor < text.size() && text[cursor] >= '0' && text[cursor] <= '9') {
      if (digits >= 9) {
        return make_error(ErrorCode::kInvalidArgument, "timestamp has more than nine fractional digits");
      }
      nanos = nanos * 10 + (text[cursor] - '0');
      ++digits;
      ++cursor;
    }
    if (digits == 0) {
      return make_error(ErrorCode::kInvalidArgument, "timestamp fraction has no digits");
    }
    for (std::size_t i = digits; i < 9; ++i) {
      nanos *= 10;
    }
  }
  if (cursor >= text.size() || text[cursor] != 'Z' || cursor + 1 != text.size()) {
    return make_error(ErrorCode::kInvalidArgument, "timestamp must end with 'Z' (UTC) and no offset");
  }
  if (month < 1 || month > 12) {
    return make_error(ErrorCode::kInvalidArgument, "timestamp month is out of range");
  }
  if (day < 1 || static_cast<unsigned>(day) > days_in_month(year, static_cast<unsigned>(month))) {
    return make_error(ErrorCode::kInvalidArgument, "timestamp day is out of range");
  }
  if (hour > 23 || minute > 59 || second > 59) {
    return make_error(ErrorCode::kInvalidArgument, "timestamp time-of-day is out of range");
  }
  const std::int64_t days = days_from_civil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
  const std::int64_t seconds = days * 86400 + hour * 3600 + minute * 60 + second;
  if (seconds < 0) {
    return make_error(ErrorCode::kInvalidArgument, "timestamp precedes the Unix epoch");
  }
  const std::int64_t total = seconds * kNsPerSecond + nanos;
  if (total > kMaxTimestampNs) {
    return make_error(ErrorCode::kOverflow, "timestamp exceeds the supported domain");
  }
  return Timestamp{total};
}

}  // namespace brf
