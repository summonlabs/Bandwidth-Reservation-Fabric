// Bandwidth Reservation Fabric - canonical bounded binary encoding primitives.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_WIRE_HPP
#define BRF_WIRE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "brf/error.hpp"
#include "brf/identity.hpp"

namespace brf {

/// Encoding limits. Every decoder enforces these bounds: a hostile or corrupt
/// peer cannot make the runtime allocate unbounded memory.
inline constexpr std::size_t kMaxBlobBytes = 4u * 1024u * 1024u;
inline constexpr std::size_t kMaxTextBytes = 64u * 1024u;
inline constexpr std::size_t kMaxCollectionItems = 1u << 16;

/// Canonical little-endian writer. Encoding is byte-exact: identical values
/// always produce identical bytes, which is what makes fingerprints and durable
/// comparisons meaningful.
class Writer {
 public:
  Writer() = default;
  explicit Writer(std::size_t reserve) { buffer_.reserve(reserve); }

  void u8(std::uint8_t v) { buffer_.push_back(static_cast<char>(v)); }
  void u16(std::uint16_t v);
  void u32(std::uint32_t v);
  void u64(std::uint64_t v);
  void i64(std::int64_t v);
  void boolean(bool v) { u8(v ? 1U : 0U); }
  void raw(const void* data, std::size_t size);
  void fixed128(const Identity128& id) { raw(id.bytes().data(), Identity128::kByteCount); }
  void bytes(std::string_view data);
  void text(std::string_view data) { bytes(data); }
  void count(std::size_t n) { u32(static_cast<std::uint32_t>(n)); }

  [[nodiscard]] const std::string& buffer() const noexcept { return buffer_; }
  [[nodiscard]] std::string take() { return std::move(buffer_); }
  [[nodiscard]] std::size_t size() const noexcept { return buffer_.size(); }
  void clear() noexcept { buffer_.clear(); }

 private:
  std::string buffer_;
};

/// Bounds-checked reader. Every failure is an explicit error: no reader ever
/// reads past the end of the frame, and no length prefix is trusted.
class Reader {
 public:
  explicit Reader(std::string_view data) : data_(data) {}

  [[nodiscard]] Result<std::uint8_t> u8();
  [[nodiscard]] Result<std::uint16_t> u16();
  [[nodiscard]] Result<std::uint32_t> u32();
  [[nodiscard]] Result<std::uint64_t> u64();
  [[nodiscard]] Result<std::int64_t> i64();
  [[nodiscard]] Result<bool> boolean();
  [[nodiscard]] Result<std::string_view> raw(std::size_t size);
  [[nodiscard]] Result<Identity128> fixed128();
  [[nodiscard]] Result<std::string_view> bytes(std::size_t max_size);
  [[nodiscard]] Result<std::string_view> text(std::size_t max_size);
  /// Reads a length prefix and validates it against max_size and the remaining
  /// bytes without consuming them (used for framed sub-messages).
  [[nodiscard]] Result<std::uint32_t> peek_count(std::size_t max_size);

  [[nodiscard]] bool exhausted() const noexcept { return offset_ >= data_.size(); }
  [[nodiscard]] std::size_t remaining() const noexcept { return data_.size() - offset_; }
  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

 private:
  std::string_view data_;
  std::size_t offset_ = 0;
};

}  // namespace brf

#endif  // BRF_WIRE_HPP
