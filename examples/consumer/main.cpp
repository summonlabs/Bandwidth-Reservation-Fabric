// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Example: an external consumer of the installed package. It links brf::brf,
// builds authority, commits a reservation, amends it, and inspects the result.
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "brf/brf.hpp"

int main() {
  const std::filesystem::path directory =
      std::filesystem::temp_directory_path() / ("brf-example-" + brf::random_identity().to_hex().substr(0, 12));
  std::error_code ec;
  std::filesystem::remove_all(directory, ec);

  brf::CoordinatorConfig config;
  config.store_directory = directory.string();
  config.clock = brf::make_system_clock();
  brf::Result<std::unique_ptr<brf::ReservationCoordinator>> opened =
      brf::ReservationCoordinator::open(config);
  if (!opened) {
    std::printf("open failed: %s\n", opened.error().message.c_str());
    return 1;
  }
  std::unique_ptr<brf::ReservationCoordinator> coordinator = std::move(opened.value());
  const brf::FabricEpoch epoch = coordinator->incarnation().epoch;
  std::printf("coordinator epoch %s boot %s\n", brf::to_string(epoch).c_str(),
              coordinator->incarnation().boot.to_hex().c_str());

  const brf::ClaimantId claimant =
      brf::Identity128::from_hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf").value();
  brf::codec::RequestContext authority;
  authority.actor = brf::ActorName::from_string("example-authority").value();
  authority.publisher = brf::Identity128::from_hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf").value();
  authority.publisher_boot = brf::Identity128::from_hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf").value();
  authority.asserted_epoch = epoch;

  const brf::PolicyName policy_name = brf::PolicyName::from_string("example-policy").value();
  brf::PolicyRecord policy = brf::PolicyRegistry::strict_default(policy_name);
  policy.allow_recall_protected = true;
  if (!coordinator->ingest_policy(policy, authority)) {
    std::printf("policy ingestion failed\n");
    return 1;
  }

  const brf::ResourceName resource = brf::ResourceName::from_string("edge-1").value();
  const std::int64_t capacity = 100000000000LL;  // 100 Gbit/s
  brf::CapacitySnapshot snapshot;
  snapshot.id = brf::Identity128::from_hex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf").value();
  snapshot.generation = brf::CapacitySnapshotGeneration(1);
  snapshot.fabric_epoch = epoch;
  snapshot.complete = true;
  brf::ResourceCapacity entry;
  entry.resource = resource;
  entry.generation = brf::ResourceGeneration(1);
  entry.reservable_capacity = brf::Bandwidth{capacity};
  entry.protected_headroom = brf::Bandwidth{capacity / 10};
  snapshot.resources.push_back(entry);
  if (!coordinator->ingest_capacity(snapshot, {}, authority)) {
    std::printf("capacity ingestion failed\n");
    return 1;
  }

  const brf::Timestamp now = coordinator->incarnation().epoch.value() == 0
                                 ? brf::make_system_clock()->now()
                                 : brf::make_system_clock()->now();
  const brf::Interval window{brf::Timestamp{now.ns + 60LL * brf::kNsPerSecond},
                             brf::Timestamp{now.ns + 3600LL * brf::kNsPerSecond}};

  brf::codec::RequestContext context;
  context.actor = brf::ActorName::from_string("example-consumer").value();
  context.publisher = brf::Identity128::from_hex("e0e1e2e3e4e5e6e7e8e9eaebecedeeef").value();
  context.publisher_boot = brf::Identity128::from_hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").value();
  context.session = brf::Identity128::from_hex("0102030405060708090a0b0c0d0e0f10").value();
  context.claimant = claimant;
  context.claimant_generation = brf::ClaimantGeneration(1);
  context.asserted_epoch = epoch;
  context.attempt = brf::Identity128::from_hex("1112131415161718191a1b1c1d1e1f20").value();
  context.reason = "example";

  brf::ReservationTerms terms;
  terms.claimant = claimant;
  terms.claimant_generation = brf::ClaimantGeneration(1);
  terms.resources.push_back(resource);
  terms.interval = window;
  terms.amount = brf::Bandwidth{20000000000LL};  // 20 Gbit/s
  terms.policy = policy_name;
  terms.guarantee = brf::GuaranteeClass::kGuaranteed;

  brf::Result<brf::CommitResult> committed = coordinator->create_reservation(context, terms, {}, false, {});
  if (!committed) {
    std::printf("commit failed: %s\n", committed.error().message.c_str());
    return 1;
  }
  if (committed.value().report.outcome != brf::AdmissionOutcome::kCommittable) {
    std::printf("admission refused: %s\n", committed.value().report.explanation.c_str());
    return 1;
  }
  std::printf("committed %s generation %s for %lld bit/s\n",
              committed.value().record.id.to_hex().c_str(),
              brf::to_string(committed.value().record.generation).c_str(),
              static_cast<long long>(committed.value().record.terms.amount.bps));

  brf::Result<std::vector<brf::RemainingCapacity>> remaining =
      coordinator->query_remaining(resource, window);
  if (remaining && !remaining.value().empty()) {
    std::printf("remaining capacity %lld bit/s of %lld bit/s\n",
                static_cast<long long>(remaining.value().front().remaining.bps),
                static_cast<long long>(remaining.value().front().committable_ceiling.bps));
  }

  context.attempt = brf::Identity128::from_hex("2122232425262728292a2b2c2d2e2f30").value();
  brf::ReservationTerms amended = terms;
  amended.amount = brf::Bandwidth{30000000000LL};
  brf::Result<brf::AmendmentResult> amended_result = coordinator->amend_reservation(
      context, committed.value().record.id, committed.value().record.generation, amended, false);
  if (!amended_result) {
    std::printf("amendment failed: %s\n", amended_result.error().message.c_str());
    return 1;
  }
  std::printf("amended to generation %s\n",
              brf::to_string(amended_result.value().successor.generation).c_str());

  const std::vector<std::string> violations = coordinator->audit_invariants();
  std::printf("invariant audit: %s\n", violations.empty() ? "clean" : "violated");
  for (const std::string& violation : violations) {
    std::printf("  %s\n", violation.c_str());
  }

  coordinator->begin_shutdown();
  std::filesystem::remove_all(directory, ec);
  return violations.empty() ? 0 : 1;
}
