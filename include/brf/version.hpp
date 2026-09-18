// Bandwidth Reservation Fabric - version and build identity.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_VERSION_HPP
#define BRF_VERSION_HPP

#include <cstdint>
#include <string>

namespace brf {

inline constexpr int kVersionMajor = 1;
inline constexpr int kVersionMinor = 0;
inline constexpr int kVersionPatch = 0;

/// Canonical library version string, e.g. "1.0.0".
[[nodiscard]] const char* version_string() noexcept;

/// Durable-state format version. Bumped only on incompatible on-disk change.
inline constexpr std::uint16_t kDurableFormatVersion = 1;

/// Wire protocol version for the coordinator transport.
inline constexpr std::uint16_t kWireProtocolVersion = 1;

}  // namespace brf

#endif  // BRF_VERSION_HPP
