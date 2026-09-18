// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "brf/store.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "brf/hash.hpp"
#include "brf/version.hpp"
#include "brf/wire.hpp"

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace brf {
namespace {

constexpr char kJournalMagic[4] = {'B', 'R', 'F', 'J'};
constexpr char kSnapshotMagic[4] = {'B', 'R', 'F', 'S'};
constexpr std::size_t kJournalHeaderBytes = 22;   // magic + length + sequence + kind + crc
constexpr std::size_t kSnapshotHeaderBytes = 32;  // magic + version + reserved + seq + payload len + crcs
constexpr std::size_t kSnapshotFooterBytes = 8;   // seal magic + crc
constexpr char kSnapshotSeal[4] = {'S', 'E', 'A', 'L'};
constexpr std::string_view kStoreIdFile = "fabric.brfstore";
constexpr std::string_view kSnapshotFileName = "fabric.brfsnap";
constexpr std::string_view kJournalFileName = "fabric.brfjournal";

void put_u16(std::string& out, std::uint16_t v) {
  out.push_back(static_cast<char>(v & 0xFFU));
  out.push_back(static_cast<char>((v >> 8) & 0xFFU));
}

void put_u32(std::string& out, std::uint32_t v) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<char>((v >> (8 * i)) & 0xFFU));
  }
}

void put_u64(std::string& out, std::uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<char>((v >> (8 * i)) & 0xFFU));
  }
}

[[nodiscard]] std::uint16_t get_u16(const char* data) {
  return static_cast<std::uint16_t>(static_cast<unsigned char>(data[0]) |
                                    (static_cast<unsigned char>(data[1]) << 8));
}

[[nodiscard]] std::uint32_t get_u32(const char* data) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(static_cast<unsigned char>(data[i])) << (8 * i);
  }
  return value;
}

[[nodiscard]] std::uint64_t get_u64(const char* data) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(static_cast<unsigned char>(data[i])) << (8 * i);
  }
  return value;
}

/// Flushes stdio buffers and then the operating system's cache. A durable
/// mutation is not acknowledged before this returns.
[[nodiscard]] Status sync_file(std::FILE* file) {
  if (std::fflush(file) != 0) {
    return make_error(ErrorCode::kIo, "failed to flush durable state");
  }
#ifdef _WIN32
  if (_commit(_fileno(file)) != 0) {
    return make_error(ErrorCode::kIo, "failed to flush durable state to stable storage");
  }
#else
  if (::fsync(::fileno(file)) != 0) {
    return make_error(ErrorCode::kIo, "failed to flush durable state to stable storage");
  }
#endif
  return {};
}

[[nodiscard]] Status replace_file(const std::string& source, const std::string& destination) {
#ifdef _WIN32
  if (::MoveFileExA(source.c_str(), destination.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
    return make_error(ErrorCode::kIo, "failed to atomically replace the snapshot file");
  }
  return {};
#else
  if (::rename(source.c_str(), destination.c_str()) != 0) {
    return make_error(ErrorCode::kIo, "failed to atomically replace the snapshot file");
  }
  return {};
#endif
}

[[nodiscard]] Result<std::string> read_all(const std::string& path, std::size_t max_bytes) {
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return make_error(ErrorCode::kNotFound, "file does not exist: " + path);
  }
  std::fseek(file, 0, SEEK_END);
  const long size = std::ftell(file);
  std::fseek(file, 0, SEEK_SET);
  if (size < 0) {
    std::fclose(file);
    return make_error(ErrorCode::kIo, "failed to size file: " + path);
  }
  if (static_cast<std::size_t>(size) > max_bytes) {
    std::fclose(file);
    return make_error(ErrorCode::kResourceExhausted, "file exceeds the supported size: " + path);
  }
  std::string buffer(static_cast<std::size_t>(size), '\0');
  if (!buffer.empty()) {
    const std::size_t read = std::fread(buffer.data(), 1, buffer.size(), file);
    if (read != buffer.size()) {
      std::fclose(file);
      return make_error(ErrorCode::kIo, "failed to read file: " + path);
    }
  }
  std::fclose(file);
  return buffer;
}

[[nodiscard]] Status write_all(const std::string& path, std::string_view bytes) {
  std::FILE* file = std::fopen(path.c_str(), "wb");
  if (file == nullptr) {
    return make_error(ErrorCode::kIo, "failed to create file: " + path);
  }
  if (!bytes.empty()) {
    const std::size_t written = std::fwrite(bytes.data(), 1, bytes.size(), file);
    if (written != bytes.size()) {
      std::fclose(file);
      return make_error(ErrorCode::kIo, "short write to file: " + path);
    }
  }
  Status sync = sync_file(file);
  std::fclose(file);
  if (!sync) return sync;
  return {};
}

}  // namespace

const char* to_string(RecordKind kind) noexcept {
  switch (kind) {
    case RecordKind::kFabricBoot: return "FABRIC_BOOT";
    case RecordKind::kCapacitySnapshot: return "CAPACITY_SNAPSHOT";
    case RecordKind::kPathSnapshot: return "PATH_SNAPSHOT";
    case RecordKind::kPolicyRecord: return "POLICY_RECORD";
    case RecordKind::kReservationCommit: return "RESERVATION_COMMIT";
    case RecordKind::kReservationAmend: return "RESERVATION_AMEND";
    case RecordKind::kReservationSeries: return "RESERVATION_SERIES";
    case RecordKind::kReservationState: return "RESERVATION_STATE";
    case RecordKind::kReservationApplicability: return "RESERVATION_APPLICABILITY";
    case RecordKind::kAttemptOutcome: return "ATTEMPT_OUTCOME";
    case RecordKind::kOvercommit: return "OVERCOMMIT";
    case RecordKind::kRetire: return "RETIRE";
    case RecordKind::kFence: return "FENCE";
    case RecordKind::kClaimantRegistration: return "CLAIMANT_REGISTRATION";
  }
  return "UNKNOWN";
}

Result<RecordKind> parse_record_kind(std::uint16_t value) noexcept {
  if (value < 1 || value > 14) {
    return make_error(ErrorCode::kInvalidArgument, "unknown durable record kind");
  }
  return static_cast<RecordKind>(value);
}

struct Store::Impl {
  std::FILE* journal = nullptr;
  std::string directory;
};

Store::Store() : impl_(std::make_unique<Impl>()) {}

Store::~Store() { (void)close(); }

Result<std::unique_ptr<Store>> Store::open(const Options& options, RecoveryReport* report_out) {
  if (options.directory.empty()) {
    return make_error(ErrorCode::kInvalidArgument, "store directory must be specified");
  }
  auto store = std::unique_ptr<Store>(new Store());
  store->options_ = options;
  store->impl_->directory = options.directory;
  store->snapshot_path_ = options.directory + "/" + std::string(kSnapshotFileName);
  store->journal_path_ = options.directory + "/" + std::string(kJournalFileName);

  std::error_code ec;
  std::filesystem::create_directories(options.directory, ec);
  if (ec) {
    return make_error(ErrorCode::kIo, "failed to create the store directory: " + ec.message());
  }

  // Stable store identity. Created once; never silently regenerated, because
  // the identity is part of every boot record.
  const std::string store_id_path = options.directory + "/" + std::string(kStoreIdFile);
  if (!std::filesystem::exists(store_id_path, ec)) {
    std::string fresh = std::to_string(static_cast<unsigned long long>(
                            static_cast<unsigned long long>(std::chrono::steady_clock::now().time_since_epoch().count()))) +
                        "|" + std::to_string(static_cast<unsigned long long>(
                                      std::hash<std::string>{}(store_id_path)));
    // Derive a 128-bit identity from process-independent material.
    Identity128 id = fingerprint128(fresh);
    Status written = write_all(store_id_path, id.to_hex() + "\n");
    if (!written) return written.error();
    store->report_.detail = "store identity created";
  } else {
    Result<std::string> existing = read_all(store_id_path, 128);
    if (!existing) return existing.error();
    std::string_view text = existing.value();
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
      text.remove_suffix(1);
    }
    Result<Identity128> parsed = Identity128::from_hex(text);
    if (!parsed) {
      return make_error(ErrorCode::kCorrupt, "store identity file is corrupt");
    }
    store->report_.detail = "store identity reused";
  }

  // Snapshot first: it defines the floor sequence for journal replay.
  RecoveryReport snapshot_report;
  Result<std::string> snapshot = read_snapshot_file(store->snapshot_path_, &snapshot_report);
  if (snapshot) {
    store->snapshot_payload_ = snapshot.value();
    store->snapshot_sequence_ = DurableSequence(snapshot_report.snapshot_sequence);
    store->report_.snapshot_loaded = true;
    store->report_.snapshot_sequence = snapshot_report.snapshot_sequence;
  } else if (snapshot.code() != ErrorCode::kNotFound) {
    return snapshot.error();
  }

  RecoveryReport journal_report;
  Result<std::vector<JournalRecord>> records =
      read_journal_file(store->journal_path_, options.max_record_payload, &journal_report);
  if (!records) {
    if (records.code() != ErrorCode::kNotFound) {
      return records.error();
    }
  } else {
    store->records_ = records.value();
  }

  // A torn tail is repaired by truncating to the last complete record. A
  // mid-file defect is refusal, never silent repair.
  if (journal_report.torn_tail_truncated) {
    const std::uint64_t last_good = store->records_.empty() ? 0 : store->records_.back().file_offset;
    std::uint64_t truncate_at = 0;
    if (store->records_.empty()) {
      truncate_at = 0;
    } else {
      const JournalRecord& last = store->records_.back();
      truncate_at = last.file_offset + kJournalHeaderBytes + last.payload.size();
    }
    std::error_code size_ec;
    std::filesystem::resize_file(store->journal_path_, truncate_at, size_ec);
    if (size_ec) {
      return make_error(ErrorCode::kIo, "failed to truncate a torn journal tail: " + size_ec.message());
    }
    (void)last_good;
    store->report_.torn_tail_truncated = true;
    store->report_.truncated_bytes = journal_report.truncated_bytes;
  }

  // Drop records the snapshot already accounts for, then establish the durable
  // sequence floor.
  std::vector<JournalRecord> effective;
  effective.reserve(store->records_.size());
  const std::uint64_t floor = store->snapshot_sequence_.value();
  for (const JournalRecord& record : store->records_) {
    if (record.sequence.value() <= floor) {
      ++store->report_.records_skipped;
      continue;
    }
    effective.push_back(record);
  }
  store->records_ = effective.empty() && floor > 0 ? std::vector<JournalRecord>{} : effective;

  std::uint64_t last_seq = floor;
  for (const JournalRecord& record : store->records_) {
    last_seq = record.sequence.value();
  }
  store->last_sequence_ = DurableSequence(last_seq);
  store->report_.records_replayed = store->records_.size();
  store->report_.last_sequence = last_seq;
  store->report_.detail = journal_report.detail;

  std::uint64_t journal_bytes = 0;
  std::error_code size_ec;
  if (std::filesystem::exists(store->journal_path_, size_ec)) {
    journal_bytes = std::filesystem::file_size(store->journal_path_, size_ec);
    if (size_ec) journal_bytes = 0;
  }
  store->journal_bytes_ = journal_bytes;

  store->impl_->journal = std::fopen(store->journal_path_.c_str(), "ab");
  if (store->impl_->journal == nullptr) {
    return make_error(ErrorCode::kIo, "failed to open the journal for append");
  }
  if (report_out != nullptr) {
    *report_out = store->report_;
  }
  return store;
}

Result<DurableSequence> Store::append(RecordKind kind, std::string_view payload) {
  if (impl_->journal == nullptr) {
    return make_error(ErrorCode::kIo, "journal is not open");
  }
  if (payload.size() > options_.max_record_payload) {
    return make_error(ErrorCode::kResourceExhausted, "durable record exceeds the payload bound");
  }
  const std::uint64_t next = last_sequence_.value() + 1;
  std::string header;
  header.reserve(kJournalHeaderBytes);
  header.append(kJournalMagic, 4);
  put_u32(header, static_cast<std::uint32_t>(kJournalHeaderBytes + payload.size()));
  put_u64(header, next);
  put_u16(header, static_cast<std::uint16_t>(kind));
  put_u32(header, crc32c(payload.data(), payload.size()));

  if (std::fwrite(header.data(), 1, header.size(), impl_->journal) != header.size()) {
    return make_error(ErrorCode::kIo, "failed to append a durable record header");
  }
  if (!payload.empty() &&
      std::fwrite(payload.data(), 1, payload.size(), impl_->journal) != payload.size()) {
    return make_error(ErrorCode::kIo, "failed to append a durable record payload");
  }
  if (options_.sync_on_append) {
    Status synced = sync_file(impl_->journal);
    if (!synced) return synced.error();
  } else if (std::fflush(impl_->journal) != 0) {
    return make_error(ErrorCode::kIo, "failed to flush the journal stream");
  }
  journal_bytes_ += header.size() + payload.size();
  last_sequence_ = DurableSequence(next);

  JournalRecord record;
  record.kind = kind;
  record.sequence = DurableSequence(next);
  record.payload.assign(payload.data(), payload.size());
  record.file_offset = journal_bytes_ - (header.size() + payload.size());
  records_.push_back(std::move(record));
  return DurableSequence(next);
}

Result<DurableSequence> Store::write_snapshot(std::string_view payload) {
  if (payload.size() > options_.max_snapshot_payload) {
    return make_error(ErrorCode::kResourceExhausted, "snapshot exceeds the payload bound");
  }
  std::string file;
  file.reserve(kSnapshotHeaderBytes + payload.size() + kSnapshotFooterBytes);
  file.append(kSnapshotMagic, 4);
  put_u16(file, kDurableFormatVersion);
  put_u16(file, 0);
  put_u64(file, last_sequence_.value());
  put_u64(file, payload.size());
  put_u32(file, crc32c(payload.data(), payload.size()));
  put_u32(file, 0);  // header CRC placeholder
  const std::uint32_t header_crc = crc32c(file.data(), file.size() - 4);
  for (int i = 0; i < 4; ++i) {
    file[file.size() - 4 + static_cast<std::size_t>(i)] =
        static_cast<char>((header_crc >> (8 * i)) & 0xFFU);
  }
  file.append(payload.data(), payload.size());
  file.append(kSnapshotSeal, 4);
  // The seal checksum covers everything written so far: header, payload and the
  // seal magic. The trailing checksum itself is of course excluded.
  put_u32(file, crc32c(file.data(), file.size()));

  const std::string temporary = snapshot_path_ + ".tmp";
  Status written = write_all(temporary, file);
  if (!written) return written.error();
  Status replaced = replace_file(temporary, snapshot_path_);
  if (!replaced) return replaced.error();
  snapshot_sequence_ = last_sequence_;
  snapshot_payload_.assign(payload.data(), payload.size());
  return snapshot_sequence_;
}

Status Store::rotate_journal() {
  if (impl_->journal != nullptr) {
    Status synced = sync_file(impl_->journal);
    if (!synced) return synced;
    std::fclose(impl_->journal);
    impl_->journal = nullptr;
  }
  std::error_code ec;
  std::filesystem::remove(journal_path_, ec);
  impl_->journal = std::fopen(journal_path_.c_str(), "ab");
  if (impl_->journal == nullptr) {
    return make_error(ErrorCode::kIo, "failed to recreate the journal after rotation");
  }
  journal_bytes_ = 0;
  records_.clear();
  return {};
}

Status Store::flush() {
  if (impl_->journal == nullptr) return {};
  return sync_file(impl_->journal);
}

Status Store::close() {
  if (impl_ == nullptr || impl_->journal == nullptr) return {};
  Status synced = sync_file(impl_->journal);
  std::fclose(impl_->journal);
  impl_->journal = nullptr;
  return synced;
}

Result<std::string> read_snapshot_file(const std::string& path, RecoveryReport* report_out) {
  Result<std::string> raw = read_all(path, 256u * 1024u * 1024u);
  if (!raw) return raw.error();
  const std::string& file = raw.value();
  if (file.size() < kSnapshotHeaderBytes + kSnapshotFooterBytes) {
    return make_error(ErrorCode::kCorrupt, "snapshot file is too small to be valid");
  }
  if (std::memcmp(file.data(), kSnapshotMagic, 4) != 0) {
    return make_error(ErrorCode::kCorrupt, "snapshot magic is invalid");
  }
  const std::uint16_t version = get_u16(file.data() + 4);
  if (version != kDurableFormatVersion) {
    return make_error(ErrorCode::kUnsupported, "snapshot format version is not supported");
  }
  const std::uint64_t sequence = get_u64(file.data() + 8);
  const std::uint64_t payload_length = get_u64(file.data() + 16);
  const std::uint32_t payload_crc = get_u32(file.data() + 24);
  const std::uint32_t header_crc = get_u32(file.data() + 28);
  if (header_crc != crc32c(file.data(), 28)) {
    return make_error(ErrorCode::kCorrupt, "snapshot header checksum mismatch");
  }
  if (payload_length > file.size() - kSnapshotHeaderBytes - kSnapshotFooterBytes) {
    return make_error(ErrorCode::kCorrupt, "snapshot payload length exceeds the file size");
  }
  const std::size_t expected_size = kSnapshotHeaderBytes + static_cast<std::size_t>(payload_length) +
                                    kSnapshotFooterBytes;
  if (file.size() != expected_size) {
    return make_error(ErrorCode::kCorrupt, "snapshot size does not match its declared payload length");
  }
  const char* payload = file.data() + kSnapshotHeaderBytes;
  if (crc32c(payload, static_cast<std::size_t>(payload_length)) != payload_crc) {
    return make_error(ErrorCode::kCorrupt, "snapshot payload checksum mismatch");
  }
  const char* footer = payload + payload_length;
  if (std::memcmp(footer, kSnapshotSeal, 4) != 0) {
    return make_error(ErrorCode::kCorrupt, "snapshot seal is missing");
  }
  const std::uint32_t seal_crc = get_u32(footer + 4);
  if (seal_crc != crc32c(file.data(), file.size() - 4)) {
    return make_error(ErrorCode::kCorrupt, "snapshot seal checksum mismatch");
  }
  if (report_out != nullptr) {
    report_out->snapshot_loaded = true;
    report_out->snapshot_sequence = sequence;
  }
  return std::string(payload, static_cast<std::size_t>(payload_length));
}

Result<std::vector<JournalRecord>> read_journal_file(const std::string& path, std::size_t max_payload,
                                                     RecoveryReport* report_out) {
  Result<std::string> raw = read_all(path, 1024u * 1024u * 1024u);
  if (!raw) return raw.error();
  const std::string& file = raw.value();
  std::vector<JournalRecord> records;
  std::size_t offset = 0;
  std::uint64_t last_sequence = 0;
  bool have_sequence = false;
  while (offset < file.size()) {
    const std::size_t remaining = file.size() - offset;
    if (remaining < kJournalHeaderBytes) {
      if (report_out != nullptr) {
        report_out->torn_tail_truncated = true;
        report_out->truncated_bytes = remaining;
        report_out->detail = "journal ends with a partial record header";
      }
      break;
    }
    if (std::memcmp(file.data() + offset, kJournalMagic, 4) != 0) {
      // The header is complete but its magic is wrong: this is corruption, not
      // a torn tail, and the store refuses to start rather than guess.
      return make_error(ErrorCode::kCorrupt,
                        "journal contains an invalid record magic at offset " + std::to_string(offset));
    }
    const std::uint32_t length = get_u32(file.data() + offset + 4);
    const std::uint64_t sequence = get_u64(file.data() + offset + 8);
    const std::uint16_t kind_value = get_u16(file.data() + offset + 16);
    const std::uint32_t payload_crc = get_u32(file.data() + offset + 18);
    if (length < kJournalHeaderBytes) {
      return make_error(ErrorCode::kCorrupt, "journal record declares an impossible length");
    }
    const std::size_t payload_size = length - kJournalHeaderBytes;
    if (payload_size > max_payload) {
      return make_error(ErrorCode::kResourceExhausted, "journal record payload exceeds the bound");
    }
    if (remaining < length) {
      if (report_out != nullptr) {
        report_out->torn_tail_truncated = true;
        report_out->truncated_bytes = remaining;
        report_out->detail = "journal ends with a truncated record body";
      }
      break;
    }
    const char* payload = file.data() + offset + kJournalHeaderBytes;
    if (crc32c(payload, payload_size) != payload_crc) {
      return make_error(ErrorCode::kCorrupt,
                        "journal record checksum mismatch at offset " + std::to_string(offset));
    }
    if (have_sequence && sequence <= last_sequence) {
      return make_error(ErrorCode::kCorrupt, "journal sequence numbers are not strictly increasing");
    }
    have_sequence = true;
    last_sequence = sequence;
    Result<RecordKind> kind = parse_record_kind(kind_value);
    if (!kind) {
      return make_error(ErrorCode::kCorrupt, "journal record declares an unknown kind");
    }
    JournalRecord record;
    record.kind = kind.value();
    record.sequence = DurableSequence(sequence);
    record.payload.assign(payload, payload_size);
    record.file_offset = offset;
    records.push_back(std::move(record));
    offset += length;
  }
  if (report_out != nullptr) {
    report_out->records_replayed = records.size();
    report_out->last_sequence = last_sequence;
  }
  return records;
}

}  // namespace brf
