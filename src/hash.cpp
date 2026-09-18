// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/hash.hpp"

#include <array>

namespace brf {
namespace {

constexpr std::uint64_t kFnvOffset = 1469598103934665603ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;
constexpr std::uint64_t kFnvOffsetLane2 = 14695981039346656037ULL;

[[nodiscard]] constexpr std::uint64_t fnv1a_impl(const std::uint8_t* data, std::size_t size,
                                                 std::uint64_t seed) noexcept {
  std::uint64_t state = seed;
  for (std::size_t i = 0; i < size; ++i) {
    state ^= static_cast<std::uint64_t>(data[i]);
    state *= kFnvPrime;
  }
  return state;
}

/// Reflected CRC-32C table, generated at compile time.
struct Crc32cTable {
  std::array<std::uint32_t, 256> values{};

  constexpr Crc32cTable() noexcept {
    constexpr std::uint32_t kPoly = 0x82F63B78U;  // reflected 0x1EDC6F41
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t crc = i;
      for (int bit = 0; bit < 8; ++bit) {
        crc = (crc & 1U) != 0U ? (crc >> 1) ^ kPoly : (crc >> 1);
      }
      values[i] = crc;
    }
  }
};

constexpr Crc32cTable kCrcTable{};

}  // namespace

std::uint64_t fnv1a_64(const void* data, std::size_t size) noexcept {
  return fnv1a_impl(static_cast<const std::uint8_t*>(data), size, kFnvOffset);
}

std::uint64_t fnv1a_64(std::string_view bytes) noexcept {
  return fnv1a_impl(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size(), kFnvOffset);
}

Identity128 fingerprint128(const void* data, std::size_t size) noexcept {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  const std::uint64_t lane1 = fnv1a_impl(bytes, size, kFnvOffset);
  const std::uint64_t lane2 = fnv1a_impl(bytes, size, kFnvOffsetLane2);
  std::array<std::uint8_t, Identity128::kByteCount> out{};
  for (std::size_t i = 0; i < 8; ++i) {
    out[i] = static_cast<std::uint8_t>((lane1 >> (8 * (7 - i))) & 0xFFU);
    out[8 + i] = static_cast<std::uint8_t>((lane2 >> (8 * (7 - i))) & 0xFFU);
  }
  return Identity128::from_bytes(out);
}

Identity128 fingerprint128(std::string_view bytes) noexcept {
  return fingerprint128(bytes.data(), bytes.size());
}

std::uint32_t crc32c(const void* data, std::size_t size) noexcept {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::uint32_t crc = 0xFFFFFFFFU;
  for (std::size_t i = 0; i < size; ++i) {
    crc = kCrcTable.values[(crc ^ bytes[i]) & 0xFFU] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFFU;
}

void Crc32cBuilder::update(const void* data, std::size_t size) noexcept {
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  std::uint32_t crc = state_;
  for (std::size_t i = 0; i < size; ++i) {
    crc = kCrcTable.values[(crc ^ bytes[i]) & 0xFFU] ^ (crc >> 8);
  }
  state_ = crc;
}

}  // namespace brf
