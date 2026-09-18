// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Durable store proofs: versioned records, integrity checks, torn-tail repair,
// corruption refusal, snapshot + rotation.
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "brf/brf.hpp"
#include "support/fixtures.hpp"
#include "support/test_harness.hpp"

using namespace brf;  // NOLINT(google-build-using-namespace)
using namespace brf::test;

namespace {

[[nodiscard]] std::string record_payload(std::uint64_t value) {
  Writer writer(32);
  writer.u64(value);
  return writer.take();
}

[[nodiscard]] std::string read_file(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, const std::string& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

[[nodiscard]] Store::Options options_for(const TempDir& directory) {
  Store::Options options;
  options.directory = directory.str();
  return options;
}

}  // namespace

BRF_TEST(store, append_recover_round_trip) {
  TempDir directory;
  {
    Result<std::unique_ptr<Store>> store = Store::open(options_for(directory), nullptr);
    BRF_REQUIRE(store.has_value());
    for (std::uint64_t i = 0; i < 5; ++i) {
      Result<DurableSequence> sequence =
          store.value()->append(RecordKind::kFabricBoot, record_payload(i));
      BRF_REQUIRE(sequence.has_value());
      BRF_CHECK_EQ(sequence.value().value(), i + 1);
    }
    BRF_CHECK_OK(store.value()->close());
  }
  RecoveryReport report;
  Result<std::unique_ptr<Store>> reopened = Store::open(options_for(directory), &report);
  BRF_REQUIRE(reopened.has_value());
  BRF_CHECK_EQ(reopened.value()->records().size(), std::size_t{5});
  BRF_CHECK_EQ(reopened.value()->last_sequence(), std::uint64_t{5});
  BRF_CHECK(!report.torn_tail_truncated);
  BRF_CHECK_EQ(report.records_replayed, std::uint64_t{5});
  for (std::size_t i = 0; i < 5; ++i) {
    BRF_CHECK_EQ(reopened.value()->records()[i].sequence.value(), i + 1);
    BRF_CHECK_EQ(reopened.value()->records()[i].payload, record_payload(i));
  }
}

BRF_TEST(store, torn_tail_is_repaired_not_guessed) {
  TempDir directory;
  {
    Result<std::unique_ptr<Store>> store = Store::open(options_for(directory), nullptr);
    BRF_REQUIRE(store.has_value());
    for (std::uint64_t i = 0; i < 3; ++i) {
      BRF_CHECK_OK(store.value()->append(RecordKind::kFabricBoot, record_payload(i)));
    }
    BRF_CHECK_OK(store.value()->close());
  }
  const std::string journal_path = directory.str() + "/fabric.brfjournal";
  const std::string original = read_file(journal_path);
  // Simulate a crash in the middle of writing the fourth record.
  write_file(journal_path, original + std::string(9, 'Z'));
  RecoveryReport report;
  Result<std::unique_ptr<Store>> reopened = Store::open(options_for(directory), &report);
  BRF_REQUIRE(reopened.has_value());
  BRF_CHECK(report.torn_tail_truncated);
  BRF_CHECK_EQ(reopened.value()->records().size(), std::size_t{3});
  BRF_CHECK_OK(reopened.value()->close());
  BRF_CHECK_EQ(read_file(journal_path).size(), original.size());

  // The repaired journal accepts new records with the next sequence number.
  Result<std::unique_ptr<Store>> again = Store::open(options_for(directory), nullptr);
  BRF_REQUIRE(again.has_value());
  Result<DurableSequence> appended = again.value()->append(RecordKind::kFabricBoot, record_payload(3));
  BRF_REQUIRE(appended.has_value());
  BRF_CHECK_EQ(appended.value().value(), std::uint64_t{4});
}

BRF_TEST(store, mid_file_corruption_is_refused) {
  TempDir directory;
  {
    Result<std::unique_ptr<Store>> store = Store::open(options_for(directory), nullptr);
    BRF_REQUIRE(store.has_value());
    for (std::uint64_t i = 0; i < 4; ++i) {
      BRF_CHECK_OK(store.value()->append(RecordKind::kFabricBoot, record_payload(i)));
    }
    BRF_CHECK_OK(store.value()->close());
  }
  const std::string journal_path = directory.str() + "/fabric.brfjournal";
  std::string bytes = read_file(journal_path);
  BRF_REQUIRE(bytes.size() > 60);
  bytes[40] = static_cast<char>(bytes[40] ^ 0x5A);
  write_file(journal_path, bytes);
  RecoveryReport report;
  Result<std::unique_ptr<Store>> reopened = Store::open(options_for(directory), &report);
  BRF_CHECK(!reopened.has_value());
  BRF_CHECK_EQ(reopened.error().code, ErrorCode::kCorrupt);
}

BRF_TEST(store, non_monotonic_sequence_is_refused) {
  TempDir directory;
  {
    Result<std::unique_ptr<Store>> store = Store::open(options_for(directory), nullptr);
    BRF_REQUIRE(store.has_value());
    BRF_CHECK_OK(store.value()->append(RecordKind::kFabricBoot, record_payload(1)));
    BRF_CHECK_OK(store.value()->close());
  }
  const std::string journal_path = directory.str() + "/fabric.brfjournal";
  // Duplicate the first record verbatim: same sequence number twice.
  const std::string first = read_file(journal_path);
  write_file(journal_path, first + first);
  Result<std::unique_ptr<Store>> reopened = Store::open(options_for(directory), nullptr);
  BRF_CHECK(!reopened.has_value());
  BRF_CHECK_EQ(reopened.error().code, ErrorCode::kCorrupt);
}

BRF_TEST(store, snapshot_survives_rotation_and_replay_is_suffix_only) {
  TempDir directory;
  {
    Result<std::unique_ptr<Store>> store = Store::open(options_for(directory), nullptr);
    BRF_REQUIRE(store.has_value());
    for (std::uint64_t i = 0; i < 3; ++i) {
      BRF_CHECK_OK(store.value()->append(RecordKind::kFabricBoot, record_payload(i)));
    }
    Result<DurableSequence> snapshot = store.value()->write_snapshot("SNAPSHOT-STATE");
    BRF_REQUIRE(snapshot.has_value());
    BRF_CHECK_EQ(snapshot.value().value(), std::uint64_t{3});
    BRF_CHECK_OK(store.value()->rotate_journal());
    BRF_CHECK_OK(store.value()->append(RecordKind::kFabricBoot, record_payload(99)));
    BRF_CHECK_OK(store.value()->close());
  }
  RecoveryReport report;
  Result<std::unique_ptr<Store>> reopened = Store::open(options_for(directory), &report);
  BRF_REQUIRE(reopened.has_value());
  BRF_CHECK(report.snapshot_loaded);
  BRF_CHECK_EQ(reopened.value()->snapshot_payload(), std::string("SNAPSHOT-STATE"));
  BRF_CHECK_EQ(reopened.value()->records().size(), std::size_t{1});
  BRF_CHECK_EQ(reopened.value()->records().front().sequence.value(), std::uint64_t{4});
  BRF_CHECK_EQ(reopened.value()->last_sequence(), std::uint64_t{4});
}

BRF_TEST(store, corrupt_snapshot_is_refused) {
  TempDir directory;
  {
    Result<std::unique_ptr<Store>> store = Store::open(options_for(directory), nullptr);
    BRF_REQUIRE(store.has_value());
    BRF_CHECK_OK(store.value()->append(RecordKind::kFabricBoot, record_payload(1)));
    BRF_REQUIRE(store.value()->write_snapshot("PAYLOAD").has_value());
    BRF_CHECK_OK(store.value()->close());
  }
  const std::string snapshot_path = directory.str() + "/fabric.brfsnap";
  std::string bytes = read_file(snapshot_path);
  BRF_REQUIRE(!bytes.empty());
  bytes.back() = static_cast<char>(bytes.back() ^ 0xFF);
  write_file(snapshot_path, bytes);
  Result<std::unique_ptr<Store>> reopened = Store::open(options_for(directory), nullptr);
  BRF_CHECK(!reopened.has_value());
  BRF_CHECK_EQ(reopened.error().code, ErrorCode::kCorrupt);
}

BRF_TEST(store, oversized_record_is_refused) {
  TempDir directory;
  Result<std::unique_ptr<Store>> store = Store::open(options_for(directory), nullptr);
  BRF_REQUIRE(store.has_value());
  Store::Options small = options_for(directory);
  small.max_record_payload = 64;
  TempDir other;
  Result<std::unique_ptr<Store>> bounded = Store::open(small, nullptr);
  BRF_REQUIRE(bounded.has_value());
  const std::string big(65, 'x');
  Result<DurableSequence> appended = bounded.value()->append(RecordKind::kFabricBoot, big);
  BRF_CHECK(!appended.has_value());
  BRF_CHECK_EQ(appended.error().code, ErrorCode::kResourceExhausted);
  BRF_CHECK(bounded.value()->append(RecordKind::kFabricBoot, std::string(64, 'x')));
}

BRF_TEST(store, journal_validation_helpers_report_defects) {
  TempDir directory;
  const std::string journal_path = directory.str() + "/fabric.brfjournal";
  BRF_CHECK(!read_journal_file(journal_path, 1024, nullptr).has_value());
  {
    Result<std::unique_ptr<Store>> store = Store::open(options_for(directory), nullptr);
    BRF_REQUIRE(store.has_value());
    BRF_CHECK_OK(store.value()->append(RecordKind::kPolicyRecord, record_payload(7)));
    BRF_CHECK_OK(store.value()->close());
  }
  RecoveryReport report;
  Result<std::vector<JournalRecord>> records = read_journal_file(journal_path, 1024, &report);
  BRF_REQUIRE(records.has_value());
  BRF_CHECK_EQ(records.value().size(), std::size_t{1});
  BRF_CHECK(records.value().front().kind == RecordKind::kPolicyRecord);
  BRF_CHECK_EQ(report.last_sequence, std::uint64_t{1});
  BRF_CHECK(!read_snapshot_file(directory.str() + "/fabric.brfsnap", nullptr).has_value());
}

