// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/clock.hpp"

#include <chrono>

namespace brf {

SystemClock::SystemClock() noexcept {
  last_.store(now().ns);
}

Timestamp SystemClock::now() const noexcept {
  const auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
  const auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(since_epoch).count();
  std::int64_t current = static_cast<std::int64_t>(nanos);
  if (current < 0) current = 0;
  // Monotonic guard: a backwards step of the host clock must not make interval
  // arithmetic non-monotonic inside one process.
  std::int64_t observed = last_.load();
  while (current > observed) {
    if (last_.compare_exchange_weak(observed, current)) {
      break;
    }
  }
  return Timestamp{observed > current ? observed : current};
}

std::shared_ptr<IClock> make_system_clock() { return std::make_shared<SystemClock>(); }

}  // namespace brf
