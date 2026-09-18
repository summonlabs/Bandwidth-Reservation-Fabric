// Bandwidth Reservation Fabric - durable journal and snapshot storage.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_STORE_HPP
#define BRF_STORE_HPP

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "brf/error.hpp"
#include "brf/identity.hpp"
#include "brf/time.hpp"

namespace brf {

/// Durable record categories. The number is part of the on-disk format.
enum class RecordKind : std::uint16_t {
  kFabricBoot = 1,             ///< Coordinator incarnation and epoch advance.
  kCapacitySnapshot = 2,       ///< Authoritative capacity ingestion.
  kPathSnapshot = 3,           ///< Authoritative path authority ingestion.
  kPolicyRecord = 4,           ///< Policy ingestion.
  kReservationCommit = 5,      ///< New durable reservation (first generation).
  kReservationAmend = 6,       ///< Supersession edge plus successor record.
  kReservationSeries = 7,      ///< Series grouping record.
  kReservationState = 8,       ///< Lifecycle transition.
  kReservationApplicability = 9,  ///< Revalidation requirement / staleness.
  kAttemptOutcome = 10,        ///< Idempotency record for an attempt.
  kOvercommit = 11,            ///< Emergency overcommit detection/resolution.
  kRetire = 12,                ///< Archival retirement of terminal records.
  kFence = 13,                 ///< Durable boot/session/claimant fencing record.
  kClaimantRegistration = 14,  ///< Claimant generation registration.
};

[[nodiscard]] const char* to_string(RecordKind kind) noexcept;
[[nodiscard]] Result<RecordKind> parse_record_kind(std::uint16_t value) noexcept;

/// One recovered journal record.
struct JournalRecord {
  RecordKind kind = RecordKind::kFabricBoot;
  DurableSequence sequence;
  std::string payload;
  std::uint64_t file_offset = 0;
};

/// Recovery diagnostics, exposed for inspection tooling and tests.
struct RecoveryReport {
  bool snapshot_loaded = false;
  bool torn_tail_truncated = false;
  std::uint64_t truncated_bytes = 0;
  std::uint64_t snapshot_sequence = 0;
  std::uint64_t records_replayed = 0;
  std::uint64_t records_skipped = 0;
  std::uint64_t last_sequence = 0;
  FabricEpoch recovered_epoch;
  std::string detail;
};

/// Crash-safe append-only store.
///
/// Layout inside the directory:
///   fabric.brfsnap   sealed snapshot (magic, version, sequence, payload, CRC)
///   fabric.brfjournal append-only records: header + CRC + payload
///
/// Durability contract: ::append() returns only after the record bytes have
/// been handed to the operating system and flushed to stable storage. A durable
/// mutation is never acknowledged before its record is durable.
class Store {
 public:
  struct Options {
    std::string directory;
    /// Reject records whose payload exceeds this bound.
    std::size_t max_record_payload = 4u * 1024u * 1024u;
    /// Snapshot payload bound.
    std::size_t max_snapshot_payload = 256u * 1024u * 1024u;
    /// Journal growth that triggers a compaction hint.
    std::uint64_t compact_threshold_bytes = 8u * 1024u * 1024u;
    /// When false, append() skips the flush-to-stable-storage step. Tests use
    /// this to inject torn writes; production paths never do.
    bool sync_on_append = true;
  };

  static Result<std::unique_ptr<Store>> open(const Options& options, RecoveryReport* report_out);

  /// Appends one record with the next durable sequence number and flushes.
  [[nodiscard]] Result<DurableSequence> append(RecordKind kind, std::string_view payload);

  /// Serialises all recovered records with sequence greater than
  /// skip_at_or_below, for deterministic rebuild.
  [[nodiscard]] const std::vector<JournalRecord>& records() const noexcept { return records_; }

  [[nodiscard]] Result<DurableSequence> write_snapshot(std::string_view payload);
  /// Rotates the journal after a successful snapshot.
  [[nodiscard]] Status rotate_journal();

  [[nodiscard]] std::uint64_t last_sequence() const noexcept { return last_sequence_.value(); }
  [[nodiscard]] std::uint64_t snapshot_sequence() const noexcept { return snapshot_sequence_.value(); }
  [[nodiscard]] std::uint64_t journal_bytes() const noexcept { return journal_bytes_; }
  [[nodiscard]] std::string_view snapshot_payload() const noexcept { return snapshot_payload_; }
  [[nodiscard]] const RecoveryReport& recovery_report() const noexcept { return report_; }
  [[nodiscard]] const std::string& snapshot_path() const noexcept { return snapshot_path_; }
  [[nodiscard]] const std::string& journal_path() const noexcept { return journal_path_; }
  [[nodiscard]] bool should_compact() const noexcept { return journal_bytes_ >= options_.compact_threshold_bytes; }

  /// Forces buffered data to stable storage. Used before shutdown.
  [[nodiscard]] Status flush();
  [[nodiscard]] Status close();

  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;
  ~Store();

 private:
  Store();
  struct Impl;
  std::unique_ptr<Impl> impl_;
  Options options_;
  std::vector<JournalRecord> records_;
  DurableSequence last_sequence_;
  DurableSequence snapshot_sequence_;
  std::uint64_t journal_bytes_ = 0;
  std::string snapshot_payload_;
  RecoveryReport report_;
  std::string snapshot_path_;
  std::string journal_path_;

  friend class StoreAccess;
};

/// Reads a snapshot file without opening a store (inspection tooling).
[[nodiscard]] Result<std::string> read_snapshot_file(const std::string& path, RecoveryReport* report_out);

/// Validates a journal file end to end, reporting the first structural defect.
[[nodiscard]] Result<std::vector<JournalRecord>> read_journal_file(const std::string& path,
                                                                   std::size_t max_payload,
                                                                   RecoveryReport* report_out);

}  // namespace brf

#endif  // BRF_STORE_HPP
