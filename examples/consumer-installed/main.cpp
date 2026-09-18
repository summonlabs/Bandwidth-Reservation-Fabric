// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Independent downstream consumer: this project is NOT part of the BRF build
// tree. It is configured on its own against an installed brf package with
// find_package(brf 1.0 REQUIRED), which is how a real consumer would use it.
#include <cstdio>
#include <filesystem>
#include <memory>

#include "brf/brf.hpp"

int main(int argc, char** argv) {
  const std::filesystem::path directory =
      argc > 1 ? std::filesystem::path(argv[1])
               : std::filesystem::temp_directory_path() /
                     ("brf-consumer-" + brf::random_identity().to_hex().substr(0, 12));

  brf::CoordinatorConfig config;
  config.store_directory = directory.string();
  config.clock = brf::make_system_clock();
  brf::Result<std::unique_ptr<brf::ReservationCoordinator>> opened =
      brf::ReservationCoordinator::open(config);
  if (!opened) {
    std::printf("CONSUMER FAIL open: %s\n", opened.error().message.c_str());
    return 1;
  }
  std::unique_ptr<brf::ReservationCoordinator> coordinator = std::move(opened.value());

  brf::codec::RequestContext context;
  context.actor = brf::ActorName::from_string("downstream-consumer").value();
  context.publisher = brf::Identity128::from_hex("00112233445566778899aabbccddeeff").value();
  context.publisher_boot = brf::Identity128::from_hex("ffeeddccbbaa99887766554433221100").value();
  context.asserted_epoch = coordinator->incarnation().epoch;
  context.attempt = brf::Identity128::from_hex("0123456789abcdef0123456789abcdef").value();
  context.claimant = brf::ClaimantId{};

  brf::PolicyRecord policy =
      brf::PolicyRegistry::strict_default(brf::PolicyName::from_string("consumer-policy").value());
  if (!coordinator->ingest_policy(policy, context)) {
    std::printf("CONSUMER FAIL policy\n");
    return 1;
  }

  brf::CapacitySnapshot snapshot;
  snapshot.id = brf::Identity128::from_hex("abcdefabcdefabcdefabcdefabcdefab").value();
  snapshot.generation = brf::CapacitySnapshotGeneration(1);
  snapshot.fabric_epoch = context.asserted_epoch;
  snapshot.complete = true;
  brf::ResourceCapacity entry;
  entry.resource = brf::ResourceName::from_string("consumer-link").value();
  entry.generation = brf::ResourceGeneration(1);
  entry.reservable_capacity = brf::Bandwidth{10000000000LL};
  snapshot.resources.push_back(entry);
  if (!coordinator->ingest_capacity(snapshot, {}, context)) {
    std::printf("CONSUMER FAIL capacity\n");
    return 1;
  }

  const brf::Timestamp now = brf::SystemClock{}.now();
  brf::ReservationTerms terms;
  terms.claimant = brf::Identity128::from_hex("11111111111111111111111111111111").value();
  terms.claimant_generation = brf::ClaimantGeneration(1);
  terms.resources.push_back(entry.resource);
  terms.interval = brf::Interval{brf::Timestamp{now.ns + 60LL * brf::kNsPerSecond},
                                 brf::Timestamp{now.ns + 600LL * brf::kNsPerSecond}};
  terms.amount = brf::Bandwidth{2000000000LL};
  terms.policy = brf::PolicyName::from_string("consumer-policy").value();

  brf::codec::RequestContext commit_context = context;
  commit_context.claimant = terms.claimant;
  commit_context.claimant_generation = terms.claimant_generation;
  commit_context.attempt = brf::Identity128::from_hex("22222222222222222222222222222222").value();
  brf::Result<brf::CommitResult> committed =
      coordinator->create_reservation(commit_context, terms, {}, false, {});
  if (!committed || committed.value().report.outcome != brf::AdmissionOutcome::kCommittable) {
    std::printf("CONSUMER FAIL commit\n");
    return 1;
  }
  const std::vector<std::string> violations = coordinator->audit_invariants();
  std::printf("CONSUMER OK version=%s epoch=%s reservation=%s generation=%s audit=%s\n",
              brf::version_string(), brf::to_string(commit_context.asserted_epoch).c_str(),
              committed.value().record.id.to_hex().c_str(),
              brf::to_string(committed.value().record.generation).c_str(),
              violations.empty() ? "clean" : "violated");
  coordinator->begin_shutdown();
  std::error_code ec;
  std::filesystem::remove_all(directory, ec);
  return violations.empty() ? 0 : 1;
}
