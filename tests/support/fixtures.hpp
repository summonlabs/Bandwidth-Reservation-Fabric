// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Shared fixtures: temporary durable stores, deterministic clocks, and canonical
// authority statements used across suites.
#ifndef BRF_TEST_FIXTURES_HPP
#define BRF_TEST_FIXTURES_HPP

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "brf/brf.hpp"
#include "support/test_harness.hpp"

namespace brf::test {

inline constexpr std::int64_t kSecond = 1000000000LL;
inline constexpr std::int64_t kMinute = 60LL * kSecond;
inline constexpr std::int64_t kHour = 60LL * kMinute;

/// Fixed base instant: 2026-01-01T00:00:00Z.
inline constexpr std::int64_t kBaseEpochNs = 1767225600LL * kSecond;

/// Owns a temporary directory that is removed on destruction.
class TempDir {
 public:
  TempDir() {
    const Identity128 tag = random_identity();
    path_ = std::filesystem::temp_directory_path() / ("brf-test-" + tag.to_hex().substr(0, 16));
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
    std::filesystem::create_directories(path_, ec);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  [[nodiscard]] std::string str() const { return path_.string(); }
  [[nodiscard]] const std::filesystem::path& path() const { return path_; }

 private:
  std::filesystem::path path_;
};

[[nodiscard]] inline ResourceName name_of(const char* text) {
  Result<ResourceName> parsed = ResourceName::from_string(text);
  if (!parsed) {
    std::abort();
  }
  return parsed.value();
}

[[nodiscard]] inline PathName path_of(const char* text) {
  Result<PathName> parsed = PathName::from_string(text);
  if (!parsed) {
    std::abort();
  }
  return parsed.value();
}

[[nodiscard]] inline PolicyName policy_of(const char* text) {
  Result<PolicyName> parsed = PolicyName::from_string(text);
  if (!parsed) {
    std::abort();
  }
  return parsed.value();
}

[[nodiscard]] inline ActorName actor_of(const char* text) {
  Result<ActorName> parsed = ActorName::from_string(text);
  if (!parsed) {
    std::abort();
  }
  return parsed.value();
}

[[nodiscard]] inline Interval window_of(std::int64_t start_ns, std::int64_t end_ns) {
  return Interval{Timestamp{start_ns}, Timestamp{end_ns}};
}

[[nodiscard]] inline ResourceCapacity capacity_of(const char* resource, std::int64_t bps,
                                                  std::uint64_t generation,
                                                  std::int64_t headroom = 0) {
  ResourceCapacity capacity;
  capacity.resource = name_of(resource);
  capacity.generation = ResourceGeneration(generation);
  capacity.reservable_capacity = Bandwidth{bps};
  capacity.protected_headroom = Bandwidth{headroom};
  capacity.failure_domain = FailureDomainName{};
  capacity.failure_domain_generation = FailureDomainGeneration(0);
  return capacity;
}

[[nodiscard]] inline CapacitySnapshot snapshot_of(std::vector<ResourceCapacity> resources,
                                                 std::uint64_t generation, FabricEpoch epoch) {
  CapacitySnapshot snapshot;
  snapshot.id = Identity128::derive(Identity128::from_hex("00112233445566778899aabbccddeeff").value(),
                                    generation);
  snapshot.generation = CapacitySnapshotGeneration(generation);
  snapshot.fabric_epoch = epoch;
  snapshot.complete = true;
  snapshot.resources = std::move(resources);
  return snapshot;
}

[[nodiscard]] inline PolicyRecord permissive_policy(const char* name, std::uint64_t generation = 1) {
  PolicyRecord policy = PolicyRegistry::strict_default(policy_of(name));
  policy.generation = PolicyGeneration(generation);
  policy.allow_recall_protected = true;
  policy.max_hold_ttl = Duration{5 * kSecond};
  policy.max_holds_per_session = 8;
  policy.max_hold_bandwidth = Bandwidth{100000000000LL};
  return policy;
}

[[nodiscard]] inline codec::RequestContext context_of(FabricEpoch epoch, const ClaimantId& claimant,
                                                      ClaimantGeneration claimant_generation,
                                                      const AttemptId& attempt,
                                                      const char* actor = "brf-test") {
  codec::RequestContext context;
  context.actor = actor_of(actor);
  context.publisher = Identity128::derive(claimant, 0x505542ULL);
  context.publisher_boot = Identity128::derive(claimant, 0x424F4F54ULL);
  context.session = Identity128::derive(claimant, 0x53455353ULL);
  context.attempt = attempt;
  context.claimant = claimant;
  context.claimant_generation = claimant_generation;
  context.asserted_epoch = epoch;
  context.reason = "test operation";
  return context;
}

/// A coordinator wired to a manual clock and a temporary store.
class Fixture {
 public:
  Fixture() : clock_(std::make_shared<ManualClock>(Timestamp{kBaseEpochNs})) {
    CoordinatorConfig config;
    config.store_directory = directory_.str();
    config.clock = clock_;
    config.boot_identity = Identity128::from_hex("0102030405060708090a0b0c0d0e0f10").value();
    Result<std::unique_ptr<ReservationCoordinator>> opened = ReservationCoordinator::open(config);
    if (!opened) {
      std::abort();
    }
    coordinator = std::move(opened.value());
  }

  /// Reopens the same durable directory, advancing the fabric epoch.
  void reopen(const Identity128& boot = Identity128::from_hex("1112131415161718191a1b1c1d1e1f20").value()) {
    coordinator.reset();
    CoordinatorConfig config;
    config.store_directory = directory_.str();
    config.clock = clock_;
    config.boot_identity = boot;
    Result<std::unique_ptr<ReservationCoordinator>> opened = ReservationCoordinator::open(config);
    if (!opened) {
      std::abort();
    }
    coordinator = std::move(opened.value());
  }

  [[nodiscard]] Timestamp now() const { return clock_->now(); }
  void advance(std::int64_t ns) { clock_->advance(Duration{ns}); }
  [[nodiscard]] FabricEpoch epoch() const { return coordinator->incarnation().epoch; }

  std::shared_ptr<ManualClock> clock_;
  TempDir directory_;
  std::unique_ptr<ReservationCoordinator> coordinator;
};

/// Canonical claimant identities used across suites.
[[nodiscard]] inline ClaimantId claimant_a() {
  return Identity128::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").value();
}
[[nodiscard]] inline ClaimantId claimant_b() {
  return Identity128::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").value();
}

/// Builds default terms for a single-resource reservation.
[[nodiscard]] inline ReservationTerms terms_of(const ClaimantId& claimant,
                                               ClaimantGeneration claimant_generation,
                                               const char* resource, std::int64_t amount_bps,
                                               Interval interval, const char* policy = "fabric-default",
                                               GuaranteeClass guarantee = GuaranteeClass::kGuaranteed) {
  ReservationTerms terms;
  terms.claimant = claimant;
  terms.claimant_generation = claimant_generation;
  terms.binding_kind = BindingKind::kResources;
  terms.resources.push_back(name_of(resource));
  terms.interval = interval;
  terms.amount = Bandwidth{amount_bps};
  terms.guarantee = guarantee;
  terms.policy = policy_of(policy);
  return terms;
}

/// Seeds a coordinator with one policy, one resource and (optionally) a path.
[[nodiscard]] inline Status seed_authority(ReservationCoordinator& coordinator, FabricEpoch epoch,
                                           const char* resource, std::int64_t capacity_bps,
                                           std::uint64_t resource_generation = 1,
                                           std::int64_t headroom = 0,
                                           const char* policy = "fabric-default") {
  codec::RequestContext context;
  context.actor = actor_of("brf-authority");
  context.publisher = Identity128::from_hex("aabbccddeeff00112233445566778899").value();
  context.publisher_boot = Identity128::from_hex("99887766554433221100ffeeddccbbaa").value();
  context.asserted_epoch = epoch;
  context.reason = "seed";
  Status policy_applied = coordinator.ingest_policy(permissive_policy(policy), context);
  if (!policy_applied) return policy_applied;
  return coordinator.ingest_capacity(
      snapshot_of({capacity_of(resource, capacity_bps, resource_generation, headroom)}, 1, epoch), {}, context);
}

}  // namespace brf::test

#endif  // BRF_TEST_FIXTURES_HPP
