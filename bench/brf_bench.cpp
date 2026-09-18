// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Synthetic population benchmark.
//
// HONESTY: every number below measures completed runtime work over a synthetic
// reservation population on this host. Nothing here is a physical-network,
// switch, NIC, or optical measurement, and none of it is a packet-scheduling
// result. The benchmark exists to expose how admission, query, and recovery
// cost scale with population size, overlap density, resource width, and
// amendment rate.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "brf/brf.hpp"

namespace {

using Clock = std::chrono::steady_clock;

struct Measurement {
  std::string label;
  std::uint64_t operations = 0;
  double elapsed_seconds = 0.0;
  std::uint64_t checksum = 0;

  [[nodiscard]] double per_second() const {
    return elapsed_seconds > 0.0 ? static_cast<double>(operations) / elapsed_seconds : 0.0;
  }
};

int g_failures = 0;

void report(const Measurement& measurement) {
  std::printf("%-46s ops=%-8llu seconds=%8.4f  ops/sec=%12.1f  checksum=%llu\n",
              measurement.label.c_str(), static_cast<unsigned long long>(measurement.operations),
              measurement.elapsed_seconds, measurement.per_second(),
              static_cast<unsigned long long>(measurement.checksum));
}

[[nodiscard]] brf::Identity128 seed_identity() {
  return brf::Identity128::from_hex("be11c0debe11c0debe11c0debe11c0de").value();
}

[[nodiscard]] brf::codec::RequestContext context_for(brf::FabricEpoch epoch, std::uint64_t index) {
  brf::codec::RequestContext context;
  context.actor = brf::ActorName::from_string("brf-bench").value();
  context.publisher = brf::Identity128::derive(seed_identity(), 0x505542ULL);
  context.publisher_boot = brf::Identity128::derive(seed_identity(), 0x424F4F54ULL);
  context.session = brf::Identity128::derive(seed_identity(), 0x53455353ULL);
  context.claimant = brf::Identity128::derive(seed_identity(), 0x434C4149ULL + index % 64);
  context.claimant_generation = brf::ClaimantGeneration(1);
  context.asserted_epoch = epoch;
  context.attempt = brf::Identity128::derive(seed_identity(), index + 1);
  context.reason = "benchmark";
  return context;
}

[[nodiscard]] brf::ResourceName name_of_index(std::size_t index) {
  return brf::ResourceName::from_string("bench-" + std::to_string(index)).value();
}

/// Owns a temporary store directory for the benchmark run.
class BenchDirectory {
 public:
  BenchDirectory() {
    path_ = std::filesystem::temp_directory_path() /
            ("brf-bench-" + brf::random_identity().to_hex().substr(0, 12));
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
    std::filesystem::create_directories(path_, ec);
  }
  ~BenchDirectory() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  [[nodiscard]] std::string str() const { return path_.string(); }

 private:
  std::filesystem::path path_;
};

[[nodiscard]] bool seed_store(brf::ReservationCoordinator& coordinator, brf::FabricEpoch epoch,
                              std::size_t resources, std::int64_t capacity) {
  brf::codec::RequestContext context = context_for(epoch, 0);
  context.actor = brf::ActorName::from_string("brf-authority").value();
  context.claimant = brf::ClaimantId{};
  brf::PolicyRecord policy =
      brf::PolicyRegistry::strict_default(brf::PolicyName::from_string("bench-policy").value());
  policy.allow_recall_protected = true;
  policy.max_preemption_victims = 8;
  if (!coordinator.ingest_policy(policy, context)) return false;
  brf::CapacitySnapshot snapshot;
  snapshot.id = brf::Identity128::derive(seed_identity(), 0x534E4150ULL);
  snapshot.generation = brf::CapacitySnapshotGeneration(1);
  snapshot.fabric_epoch = epoch;
  snapshot.complete = true;
  for (std::size_t index = 0; index < resources; ++index) {
    brf::ResourceCapacity entry;
    entry.resource = name_of_index(index);
    entry.generation = brf::ResourceGeneration(1);
    entry.reservable_capacity = brf::Bandwidth{capacity};
    snapshot.resources.push_back(entry);
  }
  return static_cast<bool>(coordinator.ingest_capacity(snapshot, {}, context));
}

[[nodiscard]] Measurement measure_commits(brf::ReservationCoordinator& coordinator, brf::FabricEpoch epoch,
                                          std::size_t resources, std::size_t population, std::int64_t amount,
                                          std::int64_t window_seconds, std::int64_t base_ns) {
  Measurement measurement;
  measurement.label = "commit " + std::to_string(population) + "x" + std::to_string(resources) +
                      "-resource@" + std::to_string(amount / 1000000) + "Mbit";
  const auto start = Clock::now();
  for (std::size_t index = 0; index < population; ++index) {
    brf::codec::RequestContext context = context_for(epoch, index + 1);
    brf::ReservationTerms terms;
    terms.claimant = context.claimant;
    terms.claimant_generation = context.claimant_generation;
    terms.resources.push_back(name_of_index(index % resources));
    if (resources > 1) {
      terms.resources.push_back(name_of_index((index + 1) % resources));
    }
    const std::int64_t offset = static_cast<std::int64_t>(index % 16) * window_seconds * brf::kNsPerSecond;
    terms.interval = brf::Interval{brf::Timestamp{base_ns + offset},
                                   brf::Timestamp{base_ns + offset + window_seconds * brf::kNsPerSecond}};
    terms.amount = brf::Bandwidth{amount};
    terms.policy = brf::PolicyName::from_string("bench-policy").value();
    brf::Result<brf::CommitResult> outcome = coordinator.create_reservation(context, terms, {}, false, {});
    if (outcome && outcome.value().report.outcome == brf::AdmissionOutcome::kCommittable) {
      ++measurement.operations;
      ++measurement.checksum;
    } else {
      ++g_failures;
      if (g_failures <= 3) {
        std::printf("  refusal: %s\n", outcome ? outcome.value().report.explanation.c_str()
                                              : outcome.error().message.c_str());
      }
    }
  }
  measurement.elapsed_seconds = std::chrono::duration<double>(Clock::now() - start).count();
  return measurement;
}

[[nodiscard]] Measurement measure_queries(brf::ReservationCoordinator& coordinator, std::size_t resources,
                                          std::size_t queries, std::int64_t window_seconds,
                                          std::int64_t base_ns) {
  Measurement measurement;
  measurement.label = "remaining-capacity query";
  const auto start = Clock::now();
  for (std::size_t index = 0; index < queries; ++index) {
    const std::int64_t offset =
        static_cast<std::int64_t>(index % 16) * window_seconds * brf::kNsPerSecond;
    brf::Result<std::vector<brf::RemainingCapacity>> remaining = coordinator.query_remaining(
        name_of_index(index % resources),
        brf::Interval{brf::Timestamp{base_ns + offset},
                      brf::Timestamp{base_ns + offset + window_seconds * brf::kNsPerSecond}});
    if (remaining && !remaining.value().empty()) {
      ++measurement.operations;
      measurement.checksum += static_cast<std::uint64_t>(remaining.value().front().remaining.bps);
    } else {
      ++g_failures;
    }
  }
  measurement.elapsed_seconds = std::chrono::duration<double>(Clock::now() - start).count();
  return measurement;
}

[[nodiscard]] Measurement measure_overlap_index(brf::CapacityIndex& index, std::size_t entries,
                                                std::int64_t base_ns) {
  Measurement measurement;
  measurement.label = "index insert+peak";
  const auto start = Clock::now();
  for (std::size_t step = 0; step < entries; ++step) {
    brf::IndexEntry entry;
    entry.kind = brf::HolderKind::kReservation;
    entry.id = brf::Identity128::derive(seed_identity(), 0x10000ULL + step);
    entry.holder_generation = 1;
    entry.resource = name_of_index(step % 8);
    const std::int64_t offset = static_cast<std::int64_t>(step % 512) * brf::kNsPerSecond;
    entry.interval = brf::Interval{brf::Timestamp{base_ns + offset},
                                   brf::Timestamp{base_ns + offset + 3600 * brf::kNsPerSecond}};
    entry.amount = brf::Bandwidth{1000000};
    if (!index.insert(entry)) {
      ++g_failures;
      continue;
    }
    const brf::Bandwidth peak = index.peak_combined(
        entry.resource,
        brf::Interval{brf::Timestamp{base_ns}, brf::Timestamp{base_ns + 86400 * brf::kNsPerSecond}});
    measurement.checksum += static_cast<std::uint64_t>(peak.bps);
    ++measurement.operations;
  }
  measurement.elapsed_seconds = std::chrono::duration<double>(Clock::now() - start).count();
  return measurement;
}

[[nodiscard]] Measurement measure_amendments(brf::ReservationCoordinator& coordinator,
                                             brf::FabricEpoch epoch, std::size_t amendments,
                                             std::vector<brf::ReservationId>* ids,
                                             std::vector<brf::ReservationGeneration>* generations,
                                             std::int64_t base_ns) {
  Measurement measurement;
  measurement.label = "amend";
  const auto start = Clock::now();
  for (std::size_t step = 0; step < amendments && !ids->empty(); ++step) {
    const std::size_t target = step % ids->size();
    const brf::ReservationId id = (*ids)[target];
    brf::codec::RequestContext context = context_for(epoch, 1'000'000 + step);
    brf::Result<brf::ReservationRecord> current =
        coordinator.get_reservation(id, brf::ReservationGeneration(0));
    if (!current) {
      ++g_failures;
      continue;
    }
    brf::ReservationTerms terms = current.value().terms;
    terms.amount = brf::Bandwidth{terms.amount.bps + 1000000};
    brf::Result<brf::AmendmentResult> outcome = coordinator.amend_reservation(
        context, current.value().id, current.value().generation, terms, false);
    if (outcome && outcome.value().report.outcome == brf::AdmissionOutcome::kCommittable) {
      (*generations)[target] = outcome.value().successor.generation;
      ++measurement.operations;
      ++measurement.checksum;
    } else {
      ++g_failures;
    }
  }
  (void)base_ns;
  measurement.elapsed_seconds = std::chrono::duration<double>(Clock::now() - start).count();
  return measurement;
}

[[nodiscard]] Measurement measure_recovery(const std::string& store, std::size_t expected,
                                           std::uint64_t* recovered_records) {
  Measurement measurement;
  measurement.label = "recovery (reopen durable store)";
  brf::CoordinatorConfig config;
  config.store_directory = store;
  const auto start = Clock::now();
  brf::RecoveryReport report;
  brf::Result<std::unique_ptr<brf::ReservationCoordinator>> reopened =
      brf::ReservationCoordinator::open(config, &report);
  measurement.elapsed_seconds = std::chrono::duration<double>(Clock::now() - start).count();
  if (!reopened) {
    ++g_failures;
    return measurement;
  }
  const brf::CoordinatorStats stats = reopened.value()->stats();
  measurement.operations = stats.tracked_reservations;
  measurement.checksum = report.records_replayed;
  *recovered_records = report.records_replayed;
  if (stats.tracked_reservations != expected) {
    std::printf("  warning: recovered %llu reservations, expected %zu\n",
                static_cast<unsigned long long>(stats.tracked_reservations), expected);
  }
  return measurement;
}

}  // namespace

int main(int argc, char** argv) {
  const std::size_t population =
      argc > 1 ? static_cast<std::size_t>(std::stoull(argv[1])) : 2000;
  const std::size_t resources = argc > 2 ? static_cast<std::size_t>(std::stoull(argv[2])) : 4;
  std::printf("Bandwidth Reservation Fabric %s - synthetic population benchmark\n",
              brf::version_string());
  std::printf("population=%zu resources=%zu (synthetic; not a physical-network measurement)\n",
              population, resources);

  // Synthetic windows start one hour after the current instant: the default
  // policy forbids a commitment that begins in the past.
  const std::int64_t base_ns = brf::SystemClock{}.now().ns + 3600LL * brf::kNsPerSecond;
  const std::int64_t capacity = 100000000000LL;

  BenchDirectory directory;
  brf::CoordinatorConfig config;
  config.store_directory = directory.str();
  config.clock = brf::make_system_clock();
  brf::Result<std::unique_ptr<brf::ReservationCoordinator>> opened =
      brf::ReservationCoordinator::open(config);
  if (!opened) {
    std::printf("failed to open coordinator: %s\n", opened.error().message.c_str());
    return 2;
  }
  std::unique_ptr<brf::ReservationCoordinator> coordinator = std::move(opened.value());
  const brf::FabricEpoch epoch = coordinator->incarnation().epoch;
  if (!seed_store(*coordinator, epoch, resources, capacity)) {
    std::printf("failed to seed authority\n");
    return 2;
  }

  const std::int64_t amount = capacity / (static_cast<std::int64_t>(population / 16) + 8);
  Measurement commits = measure_commits(*coordinator, epoch, resources, population, amount, 3600, base_ns);
  report(commits);
  Measurement queries = measure_queries(*coordinator, resources, population, 3600, base_ns);
  report(queries);

  std::vector<brf::ReservationId> ids;
  std::vector<brf::ReservationGeneration> generations;
  brf::Result<std::vector<brf::ReservationRecord>> tracked =
      coordinator->query_resource(name_of_index(0), brf::Interval{brf::Timestamp{0}, brf::Timestamp{brf::kMaxTimestampNs}},
                                  true);
  if (tracked) {
    for (const brf::ReservationRecord& record : tracked.value()) {
      if (record.state == brf::ReservationState::kCommitted ||
          record.state == brf::ReservationState::kActive) {
        ids.push_back(record.id);
        generations.push_back(record.generation);
      }
    }
  }
  Measurement amendments =
      measure_amendments(*coordinator, epoch, ids.empty() ? 0 : population / 4, &ids, &generations, base_ns);
  report(amendments);

  brf::CapacityIndex index;
  Measurement index_measurement = measure_overlap_index(index, population, base_ns);
  report(index_measurement);

  const std::vector<std::string> violations = coordinator->audit_invariants();
  std::printf("invariant audit: %s (%zu violation(s))\n", violations.empty() ? "clean" : "FAILED",
              violations.size());
  for (const std::string& violation : violations) {
    std::printf("  %s\n", violation.c_str());
  }
  brf::Status compacted = coordinator->compact();
  if (!compacted) {
    std::printf("compaction failed: %s\n", compacted.error().message.c_str());
    ++g_failures;
  }
  const brf::CoordinatorStats stats = coordinator->stats();
  const std::size_t expected = stats.tracked_reservations;
  const std::string store = directory.str();
  coordinator.reset();

  std::uint64_t recovered_records = 0;
  Measurement recovery = measure_recovery(store, expected, &recovered_records);
  report(recovery);
  std::printf("recovered durable records=%llu reservations=%llu\n",
              static_cast<unsigned long long>(recovered_records),
              static_cast<unsigned long long>(recovery.operations));
  std::printf("failures=%d\n", g_failures);
  return g_failures == 0 ? 0 : 1;
}
