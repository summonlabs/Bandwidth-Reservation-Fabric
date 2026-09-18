// Bandwidth Reservation Fabric - error taxonomy and Result<> carrier.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_ERROR_HPP
#define BRF_ERROR_HPP

#include <optional>
#include <string>
#include <utility>

namespace brf {

/// Closed error taxonomy. Every failure surfaced by the runtime maps to exactly
/// one of these codes; callers branch on the code, never on message text.
enum class ErrorCode : std::uint16_t {
  kOk = 0,
  kInvalidArgument,
  kInvalidInterval,
  kInvalidBandwidth,
  kInvalidIdentity,
  kInvalidName,
  kOverflow,
  kNotFound,
  kAlreadyExists,
  kGenerationMismatch,
  kStaleEpoch,
  kStaleGeneration,
  kFencedClaimant,
  kAuthorityRequired,
  kPolicyRejected,
  kInsufficientCapacity,
  kCapacityOvercommit,
  kIllegalTransition,
  kIdempotentReplay,
  kConflict,
  kCorrupt,
  kTornTail,
  kIo,
  kUnsupported,
  kResourceExhausted,
  kCancelled,
  kShuttingDown,
  kInternal,
};

/// Stable, human-readable spelling of an error code (never localized).
[[nodiscard]] const char* to_string(ErrorCode code) noexcept;

/// True when the code is a refusal caused by stale/aged authority rather than
/// by malformed input. Used by callers to decide between retry and repair.
[[nodiscard]] bool is_authority_refusal(ErrorCode code) noexcept;

struct Error {
  ErrorCode code = ErrorCode::kOk;
  std::string message;

  Error() = default;
  Error(ErrorCode c, std::string m) : code(c), message(std::move(m)) {}

  [[nodiscard]] bool ok() const noexcept { return code == ErrorCode::kOk; }
};

/// Minimal Result<T> carrier (the project targets C++20, so std::expected is
/// not available). A Result is either a value or an Error, never both.
template <class T>
class Result {
 public:
  Result(T value) : value_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Result(Error error) : error_(std::move(error)) {}      // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool has_value() const noexcept { return value_.has_value(); }
  explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] T& value() & { return *value_; }
  [[nodiscard]] const T& value() const& { return *value_; }
  [[nodiscard]] T&& value() && { return std::move(*value_); }

  [[nodiscard]] const Error& error() const noexcept { return error_; }
  [[nodiscard]] ErrorCode code() const noexcept { return error_.code; }

 private:
  std::optional<T> value_;
  Error error_;
};

/// Result<void> specialisation.
template <>
class Result<void> {
 public:
  Result() = default;
  Result(Error error) : error_(std::move(error)) {}  // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool has_value() const noexcept { return error_.ok(); }
  explicit operator bool() const noexcept { return has_value(); }
  [[nodiscard]] const Error& error() const noexcept { return error_; }
  [[nodiscard]] ErrorCode code() const noexcept { return error_.code; }

 private:
  Error error_;
};

using Status = Result<void>;

[[nodiscard]] inline Error make_error(ErrorCode code, std::string message) {
  return Error{code, std::move(message)};
}

}  // namespace brf

#endif  // BRF_ERROR_HPP
