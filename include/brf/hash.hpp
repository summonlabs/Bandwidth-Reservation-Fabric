// Bandwidth Reservation Fabric - deterministic content fingerprinting and CRC.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_HASH_HPP
#define BRF_HASH_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "brf/identity.hpp"

namespace brf {

/// FNV-1a 64 over a byte range. Deterministic across platforms and builds; used
/// for request fingerprints and index seeding.
[[nodiscard]] std::uint64_t fnv1a_64(std::string_view bytes) noexcept;
[[nodiscard]] std::uint64_t fnv1a_64(const void* data, std::size_t size) noexcept;

/// 128-bit content fingerprint (two independent FNV-1a lanes). This is an
/// integrity and identity fingerprint, NOT a cryptographic digest: it detects
/// accidental divergence, not adversarial collision.
[[nodiscard]] Identity128 fingerprint128(std::string_view bytes) noexcept;
[[nodiscard]] Identity128 fingerprint128(const void* data, std::size_t size) noexcept;

/// CRC-32C (Castagnoli), reflected, polynomial 0x1EDC6F41. Used for durable
/// record and wire frame integrity.
[[nodiscard]] std::uint32_t crc32c(const void* data, std::size_t size) noexcept;

/// Incremental CRC-32C so streamed records can be checksummed without a
/// second copy of the payload.
class Crc32cBuilder {
 public:
  void update(const void* data, std::size_t size) noexcept;
  [[nodiscard]] std::uint32_t finish() const noexcept { return state_ ^ 0xFFFFFFFFU; }

 private:
  std::uint32_t state_ = 0xFFFFFFFFU;
};

}  // namespace brf

#endif  // BRF_HASH_HPP
