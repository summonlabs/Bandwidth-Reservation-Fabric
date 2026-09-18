// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/wire.hpp"

#include <cstring>

namespace brf {
namespace {

[[nodiscard]] Error truncated(std::string_view what) {
  return make_error(ErrorCode::kCorrupt, std::string("truncated encoding while reading ") + std::string(what));
}

}  // namespace

void Writer::u16(std::uint16_t v) {
  u8(static_cast<std::uint8_t>(v & 0xFFU));
  u8(static_cast<std::uint8_t>((v >> 8) & 0xFFU));
}

void Writer::u32(std::uint32_t v) {
  u16(static_cast<std::uint16_t>(v & 0xFFFFU));
  u16(static_cast<std::uint16_t>((v >> 16) & 0xFFFFU));
}

void Writer::u64(std::uint64_t v) {
  u32(static_cast<std::uint32_t>(v & 0xFFFFFFFFULL));
  u32(static_cast<std::uint32_t>((v >> 32) & 0xFFFFFFFFULL));
}

void Writer::i64(std::int64_t v) { u64(static_cast<std::uint64_t>(v)); }

void Writer::raw(const void* data, std::size_t size) {
  if (size == 0) return;
  buffer_.append(static_cast<const char*>(data), size);
}

void Writer::bytes(std::string_view data) {
  u32(static_cast<std::uint32_t>(data.size()));
  raw(data.data(), data.size());
}

Result<std::uint8_t> Reader::u8() {
  if (remaining() < 1) return truncated("u8");
  return static_cast<std::uint8_t>(data_[offset_++]);
}

Result<std::uint16_t> Reader::u16() {
  Result<std::uint8_t> lo = u8();
  if (!lo) return lo.error();
  Result<std::uint8_t> hi = u8();
  if (!hi) return hi.error();
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(lo.value()) |
                                    static_cast<std::uint16_t>(static_cast<std::uint16_t>(hi.value()) << 8));
}

Result<std::uint32_t> Reader::u32() {
  Result<std::uint16_t> lo = u16();
  if (!lo) return lo.error();
  Result<std::uint16_t> hi = u16();
  if (!hi) return hi.error();
  return static_cast<std::uint32_t>(static_cast<std::uint32_t>(lo.value()) |
                                    (static_cast<std::uint32_t>(hi.value()) << 16));
}

Result<std::uint64_t> Reader::u64() {
  Result<std::uint32_t> lo = u32();
  if (!lo) return lo.error();
  Result<std::uint32_t> hi = u32();
  if (!hi) return hi.error();
  return static_cast<std::uint64_t>(lo.value()) | (static_cast<std::uint64_t>(hi.value()) << 32);
}

Result<std::int64_t> Reader::i64() {
  Result<std::uint64_t> raw = u64();
  if (!raw) return raw.error();
  return static_cast<std::int64_t>(raw.value());
}

Result<bool> Reader::boolean() {
  Result<std::uint8_t> raw = u8();
  if (!raw) return raw.error();
  if (raw.value() > 1) {
    return make_error(ErrorCode::kCorrupt, "boolean field must be 0 or 1");
  }
  return raw.value() == 1;
}

Result<std::string_view> Reader::raw(std::size_t size) {
  if (remaining() < size) return truncated("byte range");
  std::string_view out = data_.substr(offset_, size);
  offset_ += size;
  return out;
}

Result<Identity128> Reader::fixed128() {
  Result<std::string_view> raw_bytes = raw(Identity128::kByteCount);
  if (!raw_bytes) return raw_bytes.error();
  std::array<std::uint8_t, Identity128::kByteCount> bytes{};
  for (std::size_t i = 0; i < Identity128::kByteCount; ++i) {
    bytes[i] = static_cast<std::uint8_t>(raw_bytes.value()[i]);
  }
  return Identity128::from_bytes(bytes);
}

Result<std::string_view> Reader::bytes(std::size_t max_size) {
  Result<std::uint32_t> length = u32();
  if (!length) return length.error();
  if (length.value() > max_size) {
    return make_error(ErrorCode::kResourceExhausted, "length-prefixed field exceeds its bound");
  }
  return raw(length.value());
}

Result<std::string_view> Reader::text(std::size_t max_size) { return bytes(max_size); }

Result<std::uint32_t> Reader::peek_count(std::size_t max_size) {
  Result<std::uint32_t> length = u32();
  if (!length) return length.error();
  if (length.value() > max_size) {
    return make_error(ErrorCode::kResourceExhausted, "collection length exceeds its bound");
  }
  return length;
}

}  // namespace brf
