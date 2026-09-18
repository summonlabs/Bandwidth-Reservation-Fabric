// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/identity.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <random>

#include "brf/hash.hpp"

namespace brf {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

[[nodiscard]] int hex_value(char ch) noexcept {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

}  // namespace

Identity128 Identity128::from_bytes(const std::array<std::uint8_t, kByteCount>& bytes) noexcept {
  Identity128 id;
  id.bytes_ = bytes;
  return id;
}

Result<Identity128> Identity128::from_hex(std::string_view hex) noexcept {
  if (hex.size() != kHexLength) {
    return make_error(ErrorCode::kInvalidIdentity, "identity must be exactly 32 hexadecimal characters");
  }
  Identity128 id;
  for (std::size_t i = 0; i < kByteCount; ++i) {
    const int hi = hex_value(hex[2 * i]);
    const int lo = hex_value(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      return make_error(ErrorCode::kInvalidIdentity, "identity contains a non-hexadecimal character");
    }
    id.bytes_[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return id;
}

Identity128 random_identity() noexcept {
  static std::atomic<std::uint64_t> counter{0};
  const std::uint64_t sequence = counter.fetch_add(1);
  std::random_device device;
  std::array<std::uint8_t, 24> material{};
  for (std::size_t i = 0; i < 16; ++i) {
    material[i] = static_cast<std::uint8_t>(device() & 0xFFU);
  }
  const std::uint64_t stamp = static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  for (std::size_t i = 0; i < 8; ++i) {
    material[16 + i] = static_cast<std::uint8_t>(((stamp ^ (sequence * 0x9E3779B97F4A7C15ULL)) >>
                                                  (8 * i)) & 0xFFU);
  }
  return fingerprint128(material.data(), material.size());
}

std::string format_identity(const Identity128& id) {
  const std::string hex = id.to_hex();
  return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" + hex.substr(16, 4) +
         "-" + hex.substr(20, 12);
}

Identity128 Identity128::derive(const Identity128& parent, std::uint64_t index) noexcept {
  std::array<std::uint8_t, kByteCount + 8> buffer{};
  std::copy(parent.bytes_.begin(), parent.bytes_.end(), buffer.begin());
  for (std::size_t i = 0; i < 8; ++i) {
    buffer[kByteCount + i] = static_cast<std::uint8_t>((index >> (8 * (7 - i))) & 0xFFU);
  }
  return fingerprint128(buffer.data(), buffer.size());
}

bool Identity128::is_nil() const noexcept {
  for (std::uint8_t byte : bytes_) {
    if (byte != 0) return false;
  }
  return true;
}

std::string Identity128::to_hex() const {
  std::string out;
  out.resize(kHexLength);
  for (std::size_t i = 0; i < kByteCount; ++i) {
    out[2 * i] = kHexDigits[(bytes_[i] >> 4) & 0x0FU];
    out[2 * i + 1] = kHexDigits[bytes_[i] & 0x0FU];
  }
  return out;
}

Result<std::uint64_t> parse_uint64_decimal(std::string_view text) noexcept {
  if (text.empty()) {
    return make_error(ErrorCode::kInvalidArgument, "empty numeric field");
  }
  if (text.size() > 20) {
    return make_error(ErrorCode::kOverflow, "numeric field is too long");
  }
  std::uint64_t value = 0;
  for (char ch : text) {
    if (ch < '0' || ch > '9') {
      return make_error(ErrorCode::kInvalidArgument, "numeric field contains a non-digit character");
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');
    if (value > (UINT64_MAX - digit) / 10U) {
      return make_error(ErrorCode::kOverflow, "numeric field overflows 64 bits");
    }
    value = value * 10U + digit;
  }
  return value;
}

std::string to_decimal(std::uint64_t value) {
  if (value == 0) return "0";
  char buffer[20];
  std::size_t index = 0;
  while (value > 0) {
    buffer[index++] = static_cast<char>('0' + (value % 10U));
    value /= 10U;
  }
  std::string out;
  out.reserve(index);
  for (std::size_t i = index; i > 0; --i) {
    out.push_back(buffer[i - 1]);
  }
  return out;
}

}  // namespace brf
