// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// brf-inspect: reads durable state without a coordinator. Read-only: the store
// is opened through the reader helpers, never through append paths, so an
// inspection cannot mutate the fabric it is inspecting.
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "brf/brf.hpp"

namespace {

struct Counts {
  std::map<std::string, std::uint64_t> by_kind;
  std::uint64_t records = 0;
  std::uint64_t bytes = 0;
};

void usage() {
  std::printf(
      "brf-inspect --store <dir> [--records] [--reservations] [--max <n>]\n"
      "  Verifies durable integrity (snapshot seal, record checksums, sequence\n"
      "  monotonicity) and prints a bounded summary of the durable state.\n");
}

[[nodiscard]] std::string argument_value(int argc, char** argv, const char* name,
                                         const std::string& fallback = {}) {
  for (int i = 1; i + 1 < argc; ++i) {
    if (std::strcmp(argv[i], name) == 0) return argv[i + 1];
  }
  return fallback;
}

[[nodiscard]] bool has_flag(int argc, char** argv, const char* name) {
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], name) == 0) return true;
  }
  return false;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc <= 1 || has_flag(argc, argv, "--help")) {
    usage();
    return argc <= 1 ? 1 : 0;
  }
  const std::string directory = argument_value(argc, argv, "--store");
  if (directory.empty()) {
    usage();
    return 1;
  }
  const std::size_t limit = static_cast<std::size_t>(std::stoull(argument_value(argc, argv, "--max", "32")));
  int problems = 0;

  brf::RecoveryReport snapshot_report;
  brf::Result<std::string> snapshot =
      brf::read_snapshot_file(directory + "/fabric.brfsnap", &snapshot_report);
  if (!snapshot && snapshot.code() != brf::ErrorCode::kNotFound) {
    std::printf("SNAPSHOT INVALID %s\n", snapshot.error().message.c_str());
    ++problems;
  } else if (snapshot) {
    std::printf("SNAPSHOT ok sequence=%llu bytes=%zu\n",
                static_cast<unsigned long long>(snapshot_report.snapshot_sequence),
                snapshot.value().size());
  } else {
    std::printf("SNAPSHOT absent\n");
  }

  brf::RecoveryReport journal_report;
  brf::Result<std::vector<brf::JournalRecord>> records =
      brf::read_journal_file(directory + "/fabric.brfjournal", 4u * 1024u * 1024u, &journal_report);
  if (!records) {
    std::printf("JOURNAL INVALID %s\n", records.error().message.c_str());
    return 2;
  }
  std::printf("JOURNAL ok records=%zu last_sequence=%llu torn_tail=%d truncated_bytes=%llu\n",
              records.value().size(), static_cast<unsigned long long>(journal_report.last_sequence),
              journal_report.torn_tail_truncated ? 1 : 0,
              static_cast<unsigned long long>(journal_report.truncated_bytes));

  Counts counts;
  std::vector<brf::codec::DurableRecord> decoded;
  bool print_records = has_flag(argc, argv, "--records");
  for (const brf::JournalRecord& record : records.value()) {
    brf::codec::DurableRecord durable;
    brf::Status status = brf::codec::decode_record(record.payload, record.kind, durable);
    if (!status) {
      std::printf("RECORD %llu INVALID %s\n", static_cast<unsigned long long>(record.sequence.value()),
                  status.error().message.c_str());
      ++problems;
      continue;
    }
    ++counts.by_kind[brf::to_string(record.kind)];
    ++counts.records;
    counts.bytes += record.payload.size();
    decoded.push_back(durable);
    if (print_records && decoded.size() <= limit) {
      std::printf("RECORD sequence=%llu kind=%s\n",
                  static_cast<unsigned long long>(record.sequence.value()),
                  brf::to_string(record.kind));
    }
  }
  for (const auto& pair : counts.by_kind) {
    std::printf("KIND %s %llu\n", pair.first.c_str(), static_cast<unsigned long long>(pair.second));
  }

  if (has_flag(argc, argv, "--reservations")) {
    std::size_t shown = 0;
    for (const brf::codec::DurableRecord& record : decoded) {
      if (record.kind != brf::RecordKind::kReservationCommit &&
          record.kind != brf::RecordKind::kReservationAmend) {
        continue;
      }
      if (shown++ >= limit) {
        std::printf("RESERVATIONS truncated at %zu\n", limit);
        break;
      }
      const brf::ReservationRecord& reservation = record.reservation.record;
      std::printf("RESERVATION sequence=%s id=%s generation=%s state=%s applicability=%s amount=%lld\n",
                  brf::to_string(reservation.sequence).c_str(), reservation.id.to_hex().c_str(),
                  brf::to_string(reservation.generation).c_str(), brf::to_string(reservation.state),
                  brf::to_string(reservation.applicability),
                  static_cast<long long>(reservation.terms.amount.bps));
    }
  }

  std::printf("SUMMARY records=%llu payload_bytes=%llu problems=%d\n",
              static_cast<unsigned long long>(counts.records),
              static_cast<unsigned long long>(counts.bytes), problems);
  return problems == 0 ? 0 : 2;
}
