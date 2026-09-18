// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Coordinator core: boot/recovery, authority ingestion, persistence, shutdown.
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "brf/hash.hpp"
#include "brf/version.hpp"
#include "coordinator_impl.hpp"

namespace brf {
namespace {

constexpr std::string_view kStoreIdFileName = "fabric.brfstore";

[[nodiscard]] Error admission_error(AdmissionOutcome outcome, const std::string& explanation) {
  return make_error(outcome_to_error_code(outcome), explanation);
}

[[nodiscard]] Result<Identity128> read_store_identity(const std::string& directory) {
  const std::string path = directory + "/" + std::string(kStoreIdFileName);
  std::ifstream stream(path);
  if (!stream.good()) {
    return make_error(ErrorCode::kNotFound, "store identity file is missing");
  }
  std::string text;
  std::getline(stream, text);
  while (!text.empty() && (text.back() == '\r' || text.back() == '\n')) {
    text.pop_back();
  }
  return Identity128::from_hex(text);
}

}  // namespace

// ---------------------------------------------------------------------------
// Boot and recovery
// ---------------------------------------------------------------------------
ReservationCoordinator::ReservationCoordinator() = default;
ReservationCoordinator::~ReservationCoordinator() = default;

Result<std::unique_ptr<ReservationCoordinator>> ReservationCoordinator::open(const CoordinatorConfig& config,
                                                                            RecoveryReport* report_out) {
  if (config.store_directory.empty()) {
    return make_error(ErrorCode::kInvalidArgument, "a durable store directory is required");
  }
  if (config.max_live_reservations == 0 || config.max_attempts == 0) {
    return make_error(ErrorCode::kInvalidArgument, "coordinator bounds must be non-zero");
  }
  auto coordinator = std::unique_ptr<ReservationCoordinator>(new ReservationCoordinator());
  auto impl = std::make_unique<Impl>();
  impl->config = config;
  impl->clock = config.clock != nullptr ? config.clock : make_system_clock();

  Store::Options options;
  options.directory = config.store_directory;
  RecoveryReport report;
  Result<std::unique_ptr<Store>> store = Store::open(options, &report);
  if (!store) {
    return store.error();
  }
  impl->store = std::move(store.value());
  impl->recovery = report;

  Result<Identity128> store_id = read_store_identity(config.store_directory);
  if (!store_id) {
    return make_error(ErrorCode::kCorrupt, "durable store identity could not be read");
  }
  impl->store_id = store_id.value();
  impl->incarnation.store = store_id.value();

  // Snapshot first: it is the compacted prefix of the record stream.
  if (!impl->store->snapshot_payload().empty()) {
    codec::SnapshotState state;
    Reader reader(impl->store->snapshot_payload());
    Status decoded = codec::decode(reader, state);
    if (!decoded) {
      return make_error(ErrorCode::kCorrupt, "snapshot payload could not be decoded: " + decoded.error().message);
    }
    if (!reader.exhausted()) {
      return make_error(ErrorCode::kCorrupt, "snapshot payload has trailing bytes");
    }
    impl->apply_snapshot_locked(state);
  }

  for (const JournalRecord& record : impl->store->records()) {
    codec::DurableRecord durable;
    Status decoded = codec::decode_record(record.payload, record.kind, durable);
    if (!decoded) {
      return make_error(ErrorCode::kCorrupt,
                        "durable record at sequence " + to_string(record.sequence) +
                            " could not be decoded: " + decoded.error().message);
    }
    Status applied = impl->apply_replay_locked(durable);
    if (!applied) {
      return make_error(applied.code(),
                        "durable record at sequence " + to_string(record.sequence) +
                            " could not be applied: " + applied.error().message);
    }
  }

  impl->rebuild_queues_locked();
  Status rebuilt = impl->rebuild_index_locked();
  if (!rebuilt) {
    return rebuilt.error();
  }

  // Advance the fabric epoch. Every restart is a new coordinator incarnation,
  // and every request that asserts the previous epoch is refused from here on.
  const std::uint64_t next_epoch = impl->incarnation.epoch.value() + 1;
  if (impl->incarnation.epoch.value() == UINT64_MAX) {
    return make_error(ErrorCode::kOverflow, "fabric epoch is exhausted");
  }
  Identity128 boot = config.boot_identity;
  if (boot.is_nil()) {
    boot = random_identity();
  }
  const Timestamp now = impl->now_locked();
  codec::DurableRecord boot_record;
  boot_record.kind = RecordKind::kFabricBoot;
  boot_record.epoch.epoch = FabricEpoch(next_epoch);
  boot_record.epoch.coordinator_boot = boot;
  boot_record.epoch.at = now;
  Result<DurableSequence> appended = impl->append_locked(boot_record);
  if (!appended) {
    return appended.error();
  }
  impl->incarnation.epoch = FabricEpoch(next_epoch);
  impl->incarnation.boot = boot;
  impl->incarnation.sequence = DurableSequence(impl->store->last_sequence());
  impl->recovery.recovered_epoch = FabricEpoch(next_epoch);
  impl->recovery.last_sequence = impl->store->last_sequence();

  // Reconcile elapsed intervals from durable timestamps: liveness is not
  // restored, but committed facts are, and time kept moving while we were down.
  Status reconciled = impl->reconcile_locked(now);
  if (!reconciled) {
    return reconciled.error();
  }
  Status refreshed = impl->refresh_applicability_locked(now, /*auto_revalidate=*/true);
  if (!refreshed) {
    return refreshed.error();
  }
  Status history = impl->release_terminal_history_locked(now);
  if (!history) {
    return history.error();
  }

  coordinator->impl_ = std::move(impl);
  if (report_out != nullptr) {
    *report_out = coordinator->impl_->recovery;
  }
  return coordinator;
}

Status ReservationCoordinator::Impl::validate_context_locked(const codec::RequestContext& context,
                                                             bool require_attempt) {
  if (stopping.load()) {
    return make_error(ErrorCode::kShuttingDown, "coordinator is shutting down");
  }
  if (context.asserted_epoch != incarnation.epoch) {
    return make_error(ErrorCode::kStaleEpoch,
                      "request asserts fabric epoch " + to_string(context.asserted_epoch) +
                          " but this incarnation is epoch " + to_string(incarnation.epoch));
  }
  if (context.publisher.is_nil()) {
    return make_error(ErrorCode::kInvalidIdentity, "request must carry a publisher identity");
  }
  if (require_attempt && context.attempt.is_nil()) {
    return make_error(ErrorCode::kInvalidIdentity,
                      "authority-bearing requests must carry an attempt identity");
  }
  if (!context.publisher_boot.is_nil()) {
    auto boot = fenced_boots.find(context.publisher_boot);
    if (boot != fenced_boots.end()) {
      return make_error(ErrorCode::kFencedClaimant,
                        "publisher boot is fenced: " + sanitize_reason(boot->second.reason));
    }
  }
  if (!context.claimant.is_nil()) {
    auto claimant = fenced_claimants.find(context.claimant);
    if (claimant != fenced_claimants.end()) {
      return make_error(ErrorCode::kFencedClaimant,
                        "claimant is fenced: " + sanitize_reason(claimant->second.reason));
    }
  }
  return {};
}

Result<DurableSequence> ReservationCoordinator::Impl::append_locked(codec::DurableRecord& record) {
  const std::string payload = codec::encode_record(record);
  Result<DurableSequence> appended = store->append(record.kind, payload);
  if (!appended) {
    return appended.error();
  }
  ++stats.durable_records;
  incarnation.sequence = appended.value();
  return appended.value();
}

Provenance ReservationCoordinator::Impl::make_provenance_locked(const codec::RequestContext& context,
                                                               DurableSequence sequence,
                                                               Timestamp at) const {
  Provenance provenance;
  provenance.actor = context.actor;
  provenance.publisher = context.publisher;
  provenance.publisher_boot = context.publisher_boot;
  provenance.session = context.session;
  provenance.attempt = context.attempt;
  provenance.fabric_epoch = incarnation.epoch;
  provenance.coordinator_boot = incarnation.boot;
  provenance.recorded_at = at;
  provenance.sequence = sequence;
  provenance.reason = sanitize_reason(context.reason);
  return provenance;
}

Status ReservationCoordinator::Impl::ensure_claimant_locked(const ClaimantId& claimant,
                                                            ClaimantGeneration generation, Timestamp now) {
  if (claimant.is_nil()) {
    return make_error(ErrorCode::kInvalidIdentity, "claimant identity must not be nil");
  }
  auto it = claimants.find(claimant);
  if (it == claimants.end()) {
    codec::DurableRecord record;
    record.kind = RecordKind::kClaimantRegistration;
    record.claimant.claimant = claimant;
    record.claimant.generation = generation;
    record.claimant.at = now;
    Result<DurableSequence> appended = append_locked(record);
    if (!appended) return appended.error();
    claimants.emplace(claimant, generation);
    return {};
  }
  if (generation < it->second) {
    return make_error(ErrorCode::kFencedClaimant,
                      "claimant generation " + to_string(generation) +
                          " is stale; the registered generation is " + to_string(it->second));
  }
  if (generation > it->second) {
    codec::DurableRecord record;
    record.kind = RecordKind::kClaimantRegistration;
    record.claimant.claimant = claimant;
    record.claimant.generation = generation;
    record.claimant.at = now;
    Result<DurableSequence> appended = append_locked(record);
    if (!appended) return appended.error();
    it->second = generation;
    fence_holds_for_claimant_locked(claimant, generation, "claimant generation advanced");
  }
  return {};
}

const PolicyRecord& ReservationCoordinator::Impl::policy_for_locked(const PolicyName& name,
                                                                   std::string* note) {
  const PolicyRecord* found = policies.current(name);
  if (found != nullptr) {
    return *found;
  }
  if (note != nullptr) {
    *note = "policy '" + name.str() + "' is not registered; the strict built-in policy applies";
  }
  fallback_policy = PolicyRegistry::strict_default(name);
  return fallback_policy;
}

Status ReservationCoordinator::Impl::release_hold_locked(const HoldId& id, const std::string& reason,
                                                         bool fenced) {
  auto it = holds.find(id);
  if (it == holds.end()) {
    return make_error(ErrorCode::kNotFound, "hold does not exist");
  }
  codec::HoldRecord& hold = it->second;
  if (hold.released) {
    return {};
  }
  hold.released = true;
  hold.released_at = now_locked();
  hold.release_reason = sanitize_reason(reason);
  if (index.contains(HolderKind::kHold, id)) {
    Status erased = index.erase_all(HolderKind::kHold, id, hold.generation.value());
    (void)erased;
  }
  if (fenced) {
    ++stats.fenced_holds;
  }
  released_holds.push_back(id);
  while (released_holds.size() > 4096) {
    released_holds.pop_front();
  }
  return {};
}

void ReservationCoordinator::Impl::fence_holds_for_claimant_locked(const ClaimantId& claimant,
                                                                  ClaimantGeneration generation,
                                                                  const std::string& reason) {
  std::vector<HoldId> victims;
  for (const auto& pair : holds) {
    if (pair.second.released) continue;
    if (pair.second.claimant == claimant && pair.second.claimant_generation < generation) {
      victims.push_back(pair.first);
    }
  }
  for (const HoldId& id : victims) {
    Status released = release_hold_locked(id, reason, true);
    (void)released;
  }
}

void ReservationCoordinator::Impl::fence_holds_for_boot_locked(const PublisherBootId& boot,
                                                               const std::string& reason) {
  std::vector<HoldId> victims;
  for (const auto& pair : holds) {
    if (!pair.second.released && pair.second.boot == boot) victims.push_back(pair.first);
  }
  for (const HoldId& id : victims) {
    Status released = release_hold_locked(id, reason, true);
    (void)released;
  }
}

void ReservationCoordinator::Impl::fence_holds_for_session_locked(const SessionId& session,
                                                                  const std::string& reason) {
  std::vector<HoldId> victims;
  for (const auto& pair : holds) {
    if (!pair.second.released && pair.second.session == session) victims.push_back(pair.first);
  }
  for (const HoldId& id : victims) {
    Status released = release_hold_locked(id, reason, true);
    (void)released;
  }
}

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------
Status ReservationCoordinator::Impl::apply_replay_locked(const codec::DurableRecord& record) {
  switch (record.kind) {
    case RecordKind::kFabricBoot: {
      if (record.epoch.epoch > incarnation.epoch) {
        incarnation.epoch = record.epoch.epoch;
      }
      return {};
    }
    case RecordKind::kCapacitySnapshot: {
      const CapacitySnapshot& snapshot = record.capacity.snapshot;
      for (const ResourceCapacity& capacity : snapshot.resources) {
        Result<bool> applied = ledger.apply(capacity, snapshot.id, snapshot.ingested_at);
        if (!applied) return applied.error();
      }
      for (const ResourceName& name : record.capacity.withdrawals) {
        Status withdrawn = ledger.withdraw(name, snapshot.ingested_at);
        if (!withdrawn && withdrawn.code() != ErrorCode::kNotFound) return withdrawn;
      }
      last_capacity_snapshot = snapshot.id;
      last_capacity_generation = snapshot.generation;
      return {};
    }
    case RecordKind::kPathSnapshot: {
      const PathAuthoritySnapshot& snapshot = record.path;
      for (const PathAuthority& path : snapshot.paths) {
        Result<bool> applied = paths.apply(path, snapshot.id, snapshot.ingested_at);
        if (!applied) return applied.error();
      }
      last_path_snapshot = snapshot.id;
      last_path_generation = snapshot.generation;
      return {};
    }
    case RecordKind::kPolicyRecord: {
      Result<bool> applied = policies.apply(record.policy);
      if (!applied) return applied.error();
      return {};
    }
    case RecordKind::kReservationCommit:
    case RecordKind::kReservationAmend:
    case RecordKind::kReservationSeries: {
      const codec::ReservationMutation& mutation = record.reservation;
      if (mutation.supersede_record) {
        ReservationRecord* predecessor =
            find_record_locked(mutation.record.predecessor, mutation.record.predecessor_generation);
        if (predecessor != nullptr) {
          Provenance provenance = predecessor->last_provenance;
          set_state_locked(*predecessor, ReservationState::kSuperseded, mutation.record.committed_at,
                           "superseded by a later generation", provenance);
          // A superseded generation stops consuming capacity, so its time-queue
          // entries must go with it.
          sync_queues_locked(*predecessor);
        } else {
          return make_error(ErrorCode::kCorrupt, "supersession references an unknown predecessor");
        }
      }
      if (mutation.has_edge) {
        edges.push_back(mutation.edge);
      }
      register_record_locked(mutation.record);
      sync_queues_locked(mutation.record);
      for (const ReservationRecord& member : mutation.members) {
        register_record_locked(member);
        sync_queues_locked(member);
      }
      if (mutation.has_series) {
        const detail::SeriesKey key{mutation.series.id, mutation.series.generation};
        series_records[key] = mutation.series;
        auto current = current_series.find(mutation.series.id);
        if (current == current_series.end() || mutation.series.generation > current->second) {
          current_series[mutation.series.id] = mutation.series.generation;
        }
      }
      for (const codec::StateMutation& companion : mutation.companions) {
        ReservationRecord* target = find_record_locked(companion.id, companion.generation);
        if (target == nullptr) {
          return make_error(ErrorCode::kCorrupt, "companion mutation references an unknown reservation");
        }
        set_state_locked(*target, companion.to_state, companion.at, companion.reason, companion.provenance);
        sync_queues_locked(*target);
      }
      if (mutation.has_attempt) {
        detail::AttemptRecord attempt;
        attempt.attempt = mutation.attempt.attempt;
        attempt.fingerprint = mutation.attempt.fingerprint;
        attempt.outcome = mutation.attempt.outcome;
        attempt.reservation = mutation.attempt.reservation;
        attempt.generation = mutation.attempt.generation;
        attempt.sequence = mutation.attempt.result_sequence;
        attempt.claimant = mutation.attempt.claimant;
        attempt.at = mutation.attempt.at;
        remember_attempt_locked(attempt);
      }
      return {};
    }
    case RecordKind::kReservationState: {
      ReservationRecord* target = find_record_locked(record.state.id, record.state.generation);
      if (target == nullptr) {
        return make_error(ErrorCode::kCorrupt, "state mutation references an unknown reservation");
      }
      if (record.state.recall_effective_at.ns > 0) {
        target->recall_effective_at = record.state.recall_effective_at;
      }
      set_state_locked(*target, record.state.to_state, record.state.at, record.state.reason,
                       record.state.provenance);
      sync_queues_locked(*target);
      if (record.state.has_attempt) {
        detail::AttemptRecord attempt;
        attempt.attempt = record.state.attempt.attempt;
        attempt.fingerprint = record.state.attempt.fingerprint;
        attempt.outcome = record.state.attempt.outcome;
        attempt.reservation = record.state.attempt.reservation;
        attempt.generation = record.state.attempt.generation;
        attempt.sequence = record.state.attempt.result_sequence;
        attempt.claimant = record.state.attempt.claimant;
        attempt.at = record.state.attempt.at;
        remember_attempt_locked(attempt);
      }
      return {};
    }
    case RecordKind::kReservationApplicability: {
      ReservationRecord* target = find_record_locked(record.applicability.id, record.applicability.generation);
      if (target == nullptr) {
        return make_error(ErrorCode::kCorrupt, "applicability mutation references an unknown reservation");
      }
      target->applicability = record.applicability.applicability;
      target->applicability_reason = record.applicability.reason;
      target->state_changed_at = record.applicability.at;
      return {};  // Queues are rebuilt from the record set after replay.
    }
    case RecordKind::kAttemptOutcome: {
      detail::AttemptRecord attempt;
      attempt.attempt = record.attempt.attempt;
      attempt.fingerprint = record.attempt.fingerprint;
      attempt.outcome = record.attempt.outcome;
      attempt.reservation = record.attempt.reservation;
      attempt.generation = record.attempt.generation;
      attempt.sequence = record.attempt.result_sequence;
      attempt.claimant = record.attempt.claimant;
      attempt.at = record.attempt.at;
      remember_attempt_locked(attempt);
      return {};
    }
    case RecordKind::kFence: {
      detail::FenceRecord fence;
      fence.claimant = record.fence.claimant;
      fence.claimant_generation = record.fence.claimant_generation;
      fence.boot = record.fence.boot;
      fence.session = record.fence.session;
      fence.at = record.fence.at;
      fence.reason = record.fence.reason;
      fence.claimant_wide = record.fence.claimant_wide;
      if (fence.claimant_wide && !fence.claimant.is_nil()) {
        fenced_claimants[fence.claimant] = fence;
      }
      if (!fence.boot.is_nil()) {
        fenced_boots[fence.boot] = fence;
      }
      return {};
    }
    case RecordKind::kClaimantRegistration: {
      auto it = claimants.find(record.claimant.claimant);
      if (it == claimants.end() || record.claimant.generation > it->second) {
        claimants[record.claimant.claimant] = record.claimant.generation;
      }
      return {};
    }
    case RecordKind::kOvercommit: {
      detail::OvercommitState state;
      state.mutation = record.overcommit;
      state.resolved = record.overcommit.resolved;
      overcommit[record.overcommit.resource] = state;
      return {};
    }
    case RecordKind::kRetire: {
      for (std::size_t i = 0; i < record.retire.ids.size(); ++i) {
        const detail::ReservationKey key{record.retire.ids[i], record.retire.generations[i]};
        auto it = records.find(key);
        if (it == records.end()) continue;
        retired[key.id] = it->second;
        if (history_count > 0) --history_count;
        records.erase(it);
      }
      return {};
    }
  }
  return make_error(ErrorCode::kUnsupported, "unsupported durable record kind during replay");
}

// ---------------------------------------------------------------------------
// Snapshot state
// ---------------------------------------------------------------------------
codec::SnapshotState ReservationCoordinator::Impl::snapshot_state_locked() const {
  codec::SnapshotState state;
  state.epoch = incarnation.epoch;
  state.coordinator_boot = incarnation.boot;
  state.sequence = DurableSequence(store->last_sequence());
  for (const ResourceName& name : ledger.resource_names()) {
    const CapacityLedger::Entry* entry = ledger.find(name);
    codec::SnapshotCapacityEntry item;
    item.capacity = entry->capacity;
    item.snapshot = entry->snapshot;
    item.ingested_at = entry->ingested_at;
    item.withdrawn = entry->withdrawn;
    item.withdrawn_at = entry->withdrawn_at;
    item.prior_generations = entry->prior_generations;
    state.capacity.push_back(std::move(item));
  }
  for (const PathName& name : paths.path_names()) {
    const PathAuthorityTable::Entry* entry = paths.find(name);
    codec::SnapshotPathEntry item;
    item.path = entry->path;
    item.snapshot = entry->snapshot;
    item.ingested_at = entry->ingested_at;
    item.retired = entry->retired;
    item.prior_generations = entry->prior_generations;
    state.paths.push_back(std::move(item));
  }
  for (const PolicyName& name : policies.policy_names()) {
    const PolicyRegistry::Entry* entry = policies.find(name);
    codec::SnapshotPolicyEntry item;
    item.record = entry->record;
    item.ingested_at = entry->ingested_at;
    item.prior_generations = entry->prior_generations;
    state.policies.push_back(std::move(item));
  }
  for (const auto& pair : records) {
    state.reservations.push_back(pair.second);
  }
  for (const auto& pair : series_records) {
    state.series.push_back(pair.second);
  }
  state.edges = edges;
  for (const auto& pair : attempts) {
    codec::AttemptMutation mutation;
    mutation.attempt = pair.second.attempt;
    mutation.fingerprint = pair.second.fingerprint;
    mutation.outcome = pair.second.outcome;
    mutation.reservation = pair.second.reservation;
    mutation.generation = pair.second.generation;
    mutation.result_sequence = pair.second.sequence;
    mutation.claimant = pair.second.claimant;
    mutation.at = pair.second.at;
    state.attempts.push_back(std::move(mutation));
  }
  for (const auto& pair : fenced_boots) {
    codec::FenceMutation mutation;
    mutation.claimant = pair.second.claimant;
    mutation.claimant_generation = pair.second.claimant_generation;
    mutation.boot = pair.second.boot;
    mutation.session = pair.second.session;
    mutation.at = pair.second.at;
    mutation.reason = pair.second.reason;
    mutation.claimant_wide = pair.second.claimant_wide;
    state.fences.push_back(std::move(mutation));
  }
  for (const auto& pair : claimants) {
    codec::ClaimantMutation mutation;
    mutation.claimant = pair.first;
    mutation.generation = pair.second;
    state.claimants.push_back(mutation);
  }
  for (const auto& pair : overcommit) {
    state.overcommits.push_back(pair.second.mutation);
  }
  for (const auto& pair : retired) {
    state.retired.push_back(pair.second);
  }
  return state;
}

void ReservationCoordinator::Impl::apply_snapshot_locked(const codec::SnapshotState& state) {
  ledger.clear();
  paths.clear();
  policies.clear();
  Timestamp best_time{0};
  for (const codec::SnapshotCapacityEntry& item : state.capacity) {
    CapacityLedger::Entry entry;
    entry.capacity = item.capacity;
    entry.snapshot = item.snapshot;
    entry.ingested_at = item.ingested_at;
    entry.withdrawn = item.withdrawn;
    entry.withdrawn_at = item.withdrawn_at;
    entry.prior_generations = item.prior_generations;
    ledger.inject(std::move(entry));
    if (!(item.ingested_at < best_time)) {
      best_time = item.ingested_at;
      last_capacity_snapshot = item.snapshot;
      // The snapshot-level generation is a coarse idempotency guard; the
      // per-resource generation checks in CapacityLedger are authoritative and
      // are fully restored, so this may safely restart from zero.
      last_capacity_generation = CapacitySnapshotGeneration(0);
    }
  }
  for (const codec::SnapshotPathEntry& item : state.paths) {
    PathAuthorityTable::Entry entry;
    entry.path = item.path;
    entry.snapshot = item.snapshot;
    entry.ingested_at = item.ingested_at;
    entry.retired = item.retired;
    entry.prior_generations = item.prior_generations;
    paths.inject(std::move(entry));
    last_path_snapshot = item.snapshot;
  }
  for (const codec::SnapshotPolicyEntry& item : state.policies) {
    PolicyRegistry::Entry entry;
    entry.record = item.record;
    entry.ingested_at = item.ingested_at;
    entry.prior_generations = item.prior_generations;
    policies.inject(std::move(entry));
  }
  incarnation.epoch = state.epoch;
  for (const ReservationRecord& record : state.reservations) {
    register_record_locked(record);
    sync_queues_locked(record);
  }
  for (const ReservationSeries& series : state.series) {
    const detail::SeriesKey key{series.id, series.generation};
    series_records[key] = series;
    auto current = current_series.find(series.id);
    if (current == current_series.end() || series.generation > current->second) {
      current_series[series.id] = series.generation;
    }
  }
  edges = state.edges;
  for (const codec::AttemptMutation& mutation : state.attempts) {
    detail::AttemptRecord record;
    record.attempt = mutation.attempt;
    record.fingerprint = mutation.fingerprint;
    record.outcome = mutation.outcome;
    record.reservation = mutation.reservation;
    record.generation = mutation.generation;
    record.sequence = mutation.result_sequence;
    record.claimant = mutation.claimant;
    record.at = mutation.at;
    remember_attempt_locked(record);
  }
  for (const codec::FenceMutation& mutation : state.fences) {
    detail::FenceRecord record;
    record.claimant = mutation.claimant;
    record.claimant_generation = mutation.claimant_generation;
    record.boot = mutation.boot;
    record.session = mutation.session;
    record.at = mutation.at;
    record.reason = mutation.reason;
    record.claimant_wide = mutation.claimant_wide;
    if (record.claimant_wide && !record.claimant.is_nil()) {
      fenced_claimants[record.claimant] = record;
    }
    if (!record.boot.is_nil()) {
      fenced_boots[record.boot] = record;
    }
  }
  for (const codec::ClaimantMutation& mutation : state.claimants) {
    auto it = claimants.find(mutation.claimant);
    if (it == claimants.end() || mutation.generation > it->second) {
      claimants[mutation.claimant] = mutation.generation;
    }
  }
  for (const codec::OvercommitMutation& mutation : state.overcommits) {
    detail::OvercommitState entry;
    entry.mutation = mutation;
    entry.resolved = mutation.resolved;
    overcommit[mutation.resource] = entry;
  }
  for (const ReservationRecord& record : state.retired) {
    retired[record.id] = record;
    register_record_locked(record);
  }
}

Status ReservationCoordinator::Impl::compact_locked() {
  codec::SnapshotState state = snapshot_state_locked();
  Writer writer(1024);
  codec::encode(writer, state);
  std::string payload = writer.take();
  Result<DurableSequence> written = store->write_snapshot(payload);
  if (!written) return written.error();
  Status rotated = store->rotate_journal();
  if (!rotated) return rotated;
  stats.snapshot_sequence = store->snapshot_sequence();
  return {};
}

// ---------------------------------------------------------------------------
// Authority ingestion
// ---------------------------------------------------------------------------
Status ReservationCoordinator::Impl::ingest_capacity_locked(const CapacitySnapshot& snapshot,
                                                           const std::vector<ResourceName>& withdrawals,
                                                           const codec::RequestContext& context) {
  const Timestamp now = now_locked();
  Status valid = validate_context_locked(context, /*require_attempt=*/false);
  if (!valid) return valid;
  if (snapshot.id.is_nil()) {
    return make_error(ErrorCode::kInvalidIdentity, "capacity snapshot must carry an identity");
  }
  if (snapshot.generation.value() == 0) {
    return make_error(ErrorCode::kInvalidArgument, "capacity snapshot generation must be non-zero");
  }
  if (snapshot.fabric_epoch.value() != 0 && snapshot.fabric_epoch != incarnation.epoch) {
    return make_error(ErrorCode::kStaleEpoch, "capacity snapshot was produced for a different fabric epoch");
  }
  if (snapshot.resources.size() > kMaxResourcesPerSnapshot) {
    return make_error(ErrorCode::kResourceExhausted, "capacity snapshot exceeds the resource bound");
  }
  if (snapshot.generation <= last_capacity_generation && !last_capacity_snapshot.is_nil()) {
    if (snapshot.id == last_capacity_snapshot) {
      return {};  // Idempotent re-ingestion of the snapshot already applied.
    }
    return make_error(ErrorCode::kStaleGeneration, "capacity snapshot generation went backwards");
  }
  std::vector<ResourceName> names;
  for (const ResourceCapacity& capacity : snapshot.resources) {
    names.push_back(capacity.resource);
  }
  std::vector<ResourceName> sorted = names;
  std::sort(sorted.begin(), sorted.end());
  if (std::adjacent_find(sorted.begin(), sorted.end()) != sorted.end()) {
    return make_error(ErrorCode::kConflict, "capacity snapshot names the same resource twice");
  }

  std::vector<ResourceCapacity> applied;
  std::vector<ResourceName> advanced;
  std::vector<ResourceName> withdrawn;
  for (const ResourceCapacity& capacity : snapshot.resources) {
    const CapacityLedger::Entry* previous = ledger.find(capacity.resource);
    const ResourceGeneration before = previous == nullptr ? ResourceGeneration(0) : previous->capacity.generation;
    Result<bool> changed = ledger.apply(capacity, snapshot.id, now);
    if (!changed) {
      return changed.error();
    }
    if (changed.value()) {
      applied.push_back(capacity);
      advanced.push_back(capacity.resource);
      if (before.value() != 0 && capacity.generation > before) {
        ++stats.generation_advances;
      }
    }
  }
  for (const ResourceName& name : withdrawals) {
    Status removed = ledger.withdraw(name, now);
    if (!removed) {
      if (removed.code() == ErrorCode::kNotFound) continue;
      return removed;
    }
    withdrawn.push_back(name);
  }
  if (applied.empty() && withdrawn.empty()) {
    last_capacity_snapshot = snapshot.id;
    last_capacity_generation = snapshot.generation;
    return {};  // Idempotent: nothing authoritative changed, nothing to record.
  }

  codec::DurableRecord record;
  record.kind = RecordKind::kCapacitySnapshot;
  record.capacity.snapshot = snapshot;
  record.capacity.snapshot.ingested_at = now;
  record.capacity.withdrawals = withdrawn;
  Result<DurableSequence> appended = append_locked(record);
  if (!appended) return appended.error();
  last_capacity_snapshot = snapshot.id;
  last_capacity_generation = snapshot.generation;
  ++stats.capacity_ingestions;

  // Any reservation bound to a generation that just moved is no longer evidence
  // of authority. It is marked, never silently re-pointed.
  Status refreshed = refresh_applicability_locked(now, /*auto_revalidate=*/true);
  if (!refreshed) return refreshed;
  // Holds are transient authority: a generation change or a withdrawal fences
  // them outright rather than carrying them onto the new generation.
  {
    std::vector<HoldId> victims;
    for (const auto& pair : holds) {
      if (pair.second.released) continue;
      for (const ResourceName& resource : pair.second.resources) {
        if (std::find(advanced.begin(), advanced.end(), resource) != advanced.end() ||
            std::find(withdrawn.begin(), withdrawn.end(), resource) != withdrawn.end()) {
          victims.push_back(pair.first);
          break;
        }
      }
    }
    for (const HoldId& id : victims) {
      Status released = release_hold_locked(id, "resource generation changed under a provisional hold", true);
      (void)released;
    }
  }
  for (const ResourceCapacity& capacity : applied) {
    Status detected = detect_overcommit_locked(capacity.resource, now);
    if (!detected) return detected;
  }
  for (const ResourceName& name : withdrawn) {
    Status detected = detect_overcommit_locked(name, now);
    if (!detected) return detected;
  }
  Status history = release_terminal_history_locked(now);
  if (!history) return history;
  return {};
}

}  // namespace brf
