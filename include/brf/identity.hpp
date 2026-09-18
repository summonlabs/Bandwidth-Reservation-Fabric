// Bandwidth Reservation Fabric - strongly typed identities and generations.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_IDENTITY_HPP
#define BRF_IDENTITY_HPP

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "brf/error.hpp"

namespace brf {

// ---------------------------------------------------------------------------
// 128-bit opaque identity (reservation, series, snapshot, attempt, publisher,
// boot, session). Ordering is byte-lexicographic so that every container in the
// runtime has one canonical, platform-independent order.
// ---------------------------------------------------------------------------
class Identity128 {
 public:
  static constexpr std::size_t kByteCount = 16;
  static constexpr std::size_t kHexLength = 32;

  constexpr Identity128() noexcept = default;

  [[nodiscard]] static Identity128 from_bytes(const std::array<std::uint8_t, kByteCount>& bytes) noexcept;
  [[nodiscard]] static Result<Identity128> from_hex(std::string_view hex) noexcept;

  /// Deterministically derives a child identity from a parent identity and a
  /// small label. Used for series members and derived interval identities so
  /// that identical canonical inputs yield identical identities.
  [[nodiscard]] static Identity128 derive(const Identity128& parent, std::uint64_t index) noexcept;

  [[nodiscard]] const std::array<std::uint8_t, kByteCount>& bytes() const noexcept { return bytes_; }
  [[nodiscard]] bool is_nil() const noexcept;
  [[nodiscard]] std::string to_hex() const;

  friend bool operator==(const Identity128& a, const Identity128& b) noexcept { return a.bytes_ == b.bytes_; }
  friend std::strong_ordering operator<=>(const Identity128& a, const Identity128& b) noexcept {
    return a.bytes_ <=> b.bytes_;
  }

 private:
  std::array<std::uint8_t, kByteCount> bytes_{};
};

// ---------------------------------------------------------------------------
// Strong monotonic counters. Each is a distinct type: passing an epoch where a
// generation is expected is a compile error, not a runtime surprise.
// ---------------------------------------------------------------------------
template <class Tag>
class Counter {
 public:
  using value_type = std::uint64_t;

  constexpr Counter() noexcept = default;
  explicit constexpr Counter(std::uint64_t v) noexcept : value_(v) {}

  [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }

  /// Returns the next counter value or an overflow error at the ceiling.
  [[nodiscard]] Result<Counter> next() const noexcept {
    if (value_ == kMax) {
      return make_error(ErrorCode::kOverflow, "counter exhausted");
    }
    return Counter(value_ + 1);
  }

  static constexpr std::uint64_t kMax = UINT64_MAX;

  friend constexpr bool operator==(Counter a, Counter b) noexcept { return a.value_ == b.value_; }
  friend constexpr std::strong_ordering operator<=>(Counter a, Counter b) noexcept { return a.value_ <=> b.value_; }

 private:
  std::uint64_t value_ = 0;
};

#define BRF_DEFINE_COUNTER(Name, TagName)     \
  struct TagName {};                          \
  using Name = Counter<TagName>

BRF_DEFINE_COUNTER(ReservationGeneration, ReservationGenerationTag);
BRF_DEFINE_COUNTER(ClaimantGeneration, ClaimantGenerationTag);
BRF_DEFINE_COUNTER(ResourceGeneration, ResourceGenerationTag);
BRF_DEFINE_COUNTER(PathAuthorityGeneration, PathAuthorityGenerationTag);
BRF_DEFINE_COUNTER(CapacitySnapshotGeneration, CapacitySnapshotGenerationTag);
BRF_DEFINE_COUNTER(PolicyGeneration, PolicyGenerationTag);
BRF_DEFINE_COUNTER(FabricEpoch, FabricEpochTag);
BRF_DEFINE_COUNTER(DurableSequence, DurableSequenceTag);
BRF_DEFINE_COUNTER(SeriesGeneration, SeriesGenerationTag);
BRF_DEFINE_COUNTER(SeriesIndex, SeriesIndexTag);
BRF_DEFINE_COUNTER(HoldGeneration, HoldGenerationTag);
BRF_DEFINE_COUNTER(SessionGeneration, SessionGenerationTag);

#undef BRF_DEFINE_COUNTER

// ---------------------------------------------------------------------------
// Identity-typed aliases. The wire/durable layers treat these as Identity128.
// ---------------------------------------------------------------------------
struct ReservationIdTag {};
struct ReservationSeriesIdTag {};
struct ClaimantIdTag {};
struct CapacitySnapshotIdTag {};
struct AttemptIdTag {};
struct PublisherIdTag {};
struct PublisherBootIdTag {};
struct SessionIdTag {};
struct HoldIdTag {};

using ReservationId = Identity128;
using ReservationSeriesId = Identity128;
using ClaimantId = Identity128;
using CapacitySnapshotId = Identity128;
using AttemptId = Identity128;
using PublisherId = Identity128;
using PublisherBootId = Identity128;
using SessionId = Identity128;
using HoldId = Identity128;

/// Parses a counter from its decimal spelling. Rejects empty strings, signs,
/// non-digits, and values that overflow std::uint64_t.
/// Fresh 128-bit identity from the operating system entropy source, mixed with
/// a process-local counter so two calls in the same nanosecond never collide.
[[nodiscard]] Identity128 random_identity() noexcept;

/// Formatted identity for logs and diagnostics: 8-4-4-4-12 groups.
[[nodiscard]] std::string format_identity(const Identity128& id);

[[nodiscard]] Result<std::uint64_t> parse_uint64_decimal(std::string_view text) noexcept;
[[nodiscard]] std::string to_decimal(std::uint64_t value);

template <class Tag>
[[nodiscard]] Result<Counter<Tag>> parse_counter(std::string_view text) noexcept {
  Result<std::uint64_t> parsed = parse_uint64_decimal(text);
  if (!parsed) {
    return parsed.error();
  }
  return Counter<Tag>(parsed.value());
}

template <class Tag>
[[nodiscard]] std::string to_string(Counter<Tag> counter) {
  return to_decimal(counter.value());
}

// ---------------------------------------------------------------------------
// Fixed-capacity validated name (resource / path / policy / failure domain).
// Names are part of durable state, so they are length-bounded, charset-checked,
// and rejected outright when they contain control characters, path separators,
// or non-ASCII bytes. Fixed capacity keeps encoding canonical and allocation
// free.
// ---------------------------------------------------------------------------
template <std::size_t Capacity>
class FixedName {
 public:
  static constexpr std::size_t kCapacity = Capacity;

  FixedName() noexcept = default;

  [[nodiscard]] static Result<FixedName> from_string(std::string_view text) noexcept {
    if (text.empty()) {
      return make_error(ErrorCode::kInvalidName, "name must not be empty");
    }
    if (text.size() > Capacity) {
      return make_error(ErrorCode::kInvalidName, "name exceeds capacity");
    }
    for (char ch : text) {
      const unsigned char raw = static_cast<unsigned char>(ch);
      const bool alpha = (raw >= 'A' && raw <= 'Z') || (raw >= 'a' && raw <= 'z');
      const bool digit = (raw >= '0' && raw <= '9');
      const bool punct = ch == '.' || ch == '_' || ch == '-' || ch == ':' || ch == '/' || ch == '@' || ch == '+';
      if (!alpha && !digit && !punct) {
        return make_error(ErrorCode::kInvalidName, "name contains an unsupported character");
      }
    }
    if (text.find("..") != std::string_view::npos) {
      return make_error(ErrorCode::kInvalidName, "name must not contain '..'");
    }
    FixedName out;
    out.size_ = static_cast<std::uint16_t>(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
      out.data_[i] = text[i];
    }
    return out;
  }

  [[nodiscard]] std::string_view view() const noexcept { return std::string_view(data_.data(), size_); }
  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
  [[nodiscard]] std::string str() const { return std::string(view()); }

  friend bool operator==(const FixedName& a, const FixedName& b) noexcept {
    return a.size_ == b.size_ && a.view() == b.view();
  }
  friend std::strong_ordering operator<=>(const FixedName& a, const FixedName& b) noexcept {
    return a.view() <=> b.view();
  }

 private:
  std::array<char, Capacity> data_{};
  std::uint16_t size_ = 0;
};

using ResourceName = FixedName<64>;
using PathName = FixedName<64>;
using PolicyName = FixedName<64>;
using FailureDomainName = FixedName<64>;
using ActorName = FixedName<48>;

}  // namespace brf

#endif  // BRF_IDENTITY_HPP
