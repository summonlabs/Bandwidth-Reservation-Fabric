// Bandwidth Reservation Fabric - injectable clock model.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_CLOCK_HPP
#define BRF_CLOCK_HPP

#include <atomic>
#include <cstdint>
#include <memory>

#include "brf/time.hpp"

namespace brf {

/// Wall-clock source. All activation, expiry, and recall-effect decisions read
/// time through this interface so tests can drive the fabric deterministically.
class IClock {
 public:
  IClock() = default;
  IClock(const IClock&) = delete;
  IClock& operator=(const IClock&) = delete;
  virtual ~IClock() = default;

  /// Current instant on the fabric timeline.
  [[nodiscard]] virtual Timestamp now() const noexcept = 0;
};

/// Reads the system UTC clock. Monotonicity is guarded: the reported instant
/// never moves backwards, which keeps interval ordering total even if the
/// host clock steps during a run.
class SystemClock final : public IClock {
 public:
  SystemClock() noexcept;
  [[nodiscard]] Timestamp now() const noexcept override;

 private:
  mutable std::atomic<std::int64_t> last_{0};
};

/// Test clock. Time advances only when the test says so.
class ManualClock final : public IClock {
 public:
  explicit ManualClock(Timestamp start) noexcept : now_(start.ns) {}
  [[nodiscard]] Timestamp now() const noexcept override { return Timestamp{now_.load()}; }
  void set(Timestamp ts) noexcept { now_.store(ts.ns); }
  void advance(Duration d) noexcept { now_.store(now_.load() + d.ns); }

 private:
  std::atomic<std::int64_t> now_;
};

[[nodiscard]] std::shared_ptr<IClock> make_system_clock();

}  // namespace brf

#endif  // BRF_CLOCK_HPP
