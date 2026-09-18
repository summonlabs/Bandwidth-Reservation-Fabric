// Bandwidth Reservation Fabric - canonical codecs for domain and durable types.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_CODEC_HPP
#define BRF_CODEC_HPP

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "brf/authority.hpp"
#include "brf/capacity.hpp"
#include "brf/index.hpp"
#include "brf/outcome.hpp"
#include "brf/policy.hpp"
#include "brf/reservation.hpp"
#include "brf/store.hpp"
#include "brf/wire.hpp"

namespace brf::codec {

// --- generic helpers --------------------------------------------------------
template <std::size_t N>
void encode(Writer& w, const FixedName<N>& v) {
  w.text(v.view());
}

template <std::size_t N>
[[nodiscard]] Status decode(Reader& r, FixedName<N>& v) {
  Result<std::string_view> raw = r.text(N);
  if (!raw) return raw.error();
  if (raw.value().empty()) {
    // An absent optional name is legal in the durable/wire model; the domain
    // layer decides which names are actually required.
    v = FixedName<N>{};
    return {};
  }
  Result<FixedName<N>> parsed = FixedName<N>::from_string(raw.value());
  if (!parsed) return parsed.error();
  v = parsed.value();
  return {};
}

template <class Tag>
void encode(Writer& w, Counter<Tag> v) {
  w.u64(v.value());
}

template <class Tag>
[[nodiscard]] Status decode(Reader& r, Counter<Tag>& v) {
  Result<std::uint64_t> raw = r.u64();
  if (!raw) return raw.error();
  v = Counter<Tag>(raw.value());
  return {};
}

void encode(Writer& w, const std::optional<Bandwidth>& v);
[[nodiscard]] Status decode(Reader& r, std::optional<Bandwidth>& v);
void encode(Writer& w, BindingKind v);
[[nodiscard]] Status decode(Reader& r, BindingKind& v);
void encode(Writer& w, GuaranteeClass v);
[[nodiscard]] Status decode(Reader& r, GuaranteeClass& v);
void encode(Writer& w, ReservationState v);
[[nodiscard]] Status decode(Reader& r, ReservationState& v);
void encode(Writer& w, Applicability v);
[[nodiscard]] Status decode(Reader& r, Applicability& v);
void encode(Writer& w, ApplicabilityReason v);
[[nodiscard]] Status decode(Reader& r, ApplicabilityReason& v);
void encode(Writer& w, AdmissionOutcome v);
[[nodiscard]] Status decode(Reader& r, AdmissionOutcome& v);
void encode(Writer& w, ErrorCode v);
[[nodiscard]] Status decode(Reader& r, ErrorCode& v);
void encode(Writer& w, RecordKind v);
[[nodiscard]] Status decode(Reader& r, RecordKind& v);
void encode(Writer& w, HolderKind v);
[[nodiscard]] Status decode(Reader& r, HolderKind& v);

// --- primitives -------------------------------------------------------------
void encode(Writer& w, const Identity128& v);
[[nodiscard]] Status decode(Reader& r, Identity128& v);
void encode(Writer& w, const Interval& v);
[[nodiscard]] Status decode(Reader& r, Interval& v);
void encode(Writer& w, const Bandwidth& v);
[[nodiscard]] Status decode(Reader& r, Bandwidth& v);
void encode(Writer& w, const Duration& v);
[[nodiscard]] Status decode(Reader& r, Duration& v);
void encode(Writer& w, const Timestamp& v);
[[nodiscard]] Status decode(Reader& r, Timestamp& v);

// --- identity and authority -------------------------------------------------
void encode(Writer& w, const ResourceRef& v);
[[nodiscard]] Status decode(Reader& r, ResourceRef& v);
void encode(Writer& w, const FailureDomainRef& v);
[[nodiscard]] Status decode(Reader& r, FailureDomainRef& v);
void encode(Writer& w, const AuthorityVector& v);
[[nodiscard]] Status decode(Reader& r, AuthorityVector& v);
void encode(Writer& w, const Provenance& v);
[[nodiscard]] Status decode(Reader& r, Provenance& v);

// --- capacity ---------------------------------------------------------------
void encode(Writer& w, const MaintenanceWindow& v);
[[nodiscard]] Status decode(Reader& r, MaintenanceWindow& v);
void encode(Writer& w, const ResourceCapacity& v);
[[nodiscard]] Status decode(Reader& r, ResourceCapacity& v);
void encode(Writer& w, const CapacitySnapshot& v);
[[nodiscard]] Status decode(Reader& r, CapacitySnapshot& v);
void encode(Writer& w, const PathAuthority& v);
[[nodiscard]] Status decode(Reader& r, PathAuthority& v);
void encode(Writer& w, const PathAuthoritySnapshot& v);
[[nodiscard]] Status decode(Reader& r, PathAuthoritySnapshot& v);

// --- policy -----------------------------------------------------------------
void encode(Writer& w, const PolicyRecord& v);
[[nodiscard]] Status decode(Reader& r, PolicyRecord& v);

// --- reservation ------------------------------------------------------------
void encode(Writer& w, const RecurrenceSpec& v);
[[nodiscard]] Status decode(Reader& r, RecurrenceSpec& v);
void encode(Writer& w, const ReservationTerms& v);
[[nodiscard]] Status decode(Reader& r, ReservationTerms& v);
void encode(Writer& w, const ReservationRecord& v);
[[nodiscard]] Status decode(Reader& r, ReservationRecord& v);
void encode(Writer& w, const SupersessionEdge& v);
[[nodiscard]] Status decode(Reader& r, SupersessionEdge& v);
void encode(Writer& w, const ReservationSeries& v);
[[nodiscard]] Status decode(Reader& r, ReservationSeries& v);

// --- holds ------------------------------------------------------------------
/// Provisional hold. Holds are deliberately NOT durable: they bind transient
/// session/boot authority and vanish on restart, so they live only here and in
/// the coordinator's in-memory registry.
struct HoldRecord {
  HoldId id;
  HoldGeneration generation;
  ClaimantId claimant;
  ClaimantGeneration claimant_generation;
  SessionId session;
  PublisherBootId boot;
  FabricEpoch epoch;
  BindingKind binding_kind = BindingKind::kResources;
  std::vector<ResourceName> resources;
  PathName path;
  PathAuthorityGeneration path_generation;
  Interval interval;
  Bandwidth amount{0};
  GuaranteeClass guarantee = GuaranteeClass::kGuaranteed;
  Timestamp created_at;
  Timestamp expires_at;
  bool released = false;
  Timestamp released_at;
  std::string release_reason;
};
void encode(Writer& w, const HoldRecord& v);
[[nodiscard]] Status decode(Reader& r, HoldRecord& v);

// --- request context --------------------------------------------------------
/// Identity and epoch assertions attached to every authority-bearing request.
struct RequestContext {
  ActorName actor;
  PublisherId publisher;
  PublisherBootId publisher_boot;
  SessionId session;
  AttemptId attempt;
  ClaimantId claimant;
  ClaimantGeneration claimant_generation;
  /// Epoch the caller believes is current. The coordinator refuses anything
  /// that is not exactly its own epoch.
  FabricEpoch asserted_epoch;
  std::string reason;
};
void encode(Writer& w, const RequestContext& v);
[[nodiscard]] Status decode(Reader& r, RequestContext& v);

// --- durable payloads -------------------------------------------------------
/// Idempotency record for exactly one attempt. Stored inside the same durable
/// record as the mutation it describes, so "the attempt happened" and "the
/// mutation is durable" can never disagree after a crash.
struct AttemptMutation {
  AttemptId attempt;
  Identity128 fingerprint;
  AdmissionOutcome outcome = AdmissionOutcome::kInvalidRequest;
  ReservationId reservation;
  ReservationGeneration generation;
  DurableSequence result_sequence;
  Identity128 claimant;
  Timestamp at;
};
void encode(Writer& w, const AttemptMutation& v);
[[nodiscard]] Status decode(Reader& r, AttemptMutation& v);

struct StateMutation {
  ReservationId id;
  ReservationGeneration generation;
  ReservationState from_state = ReservationState::kDeclared;
  ReservationState to_state = ReservationState::kDeclared;
  Timestamp at;
  std::string reason;
  Provenance provenance;
  Timestamp recall_effective_at;
  bool has_attempt = false;
  AttemptMutation attempt;
};
void encode(Writer& w, const StateMutation& v);
[[nodiscard]] Status decode(Reader& r, StateMutation& v);

struct ReservationMutation {
  ReservationRecord record;
  bool has_series = false;
  ReservationSeries series;
  std::vector<ReservationRecord> members;
  bool has_edge = false;
  SupersessionEdge edge;
  bool supersede_record = false;  ///< True when record replaces a prior generation.
  /// State transitions committed atomically with this reservation, used by
  /// preemption (victims are recalled in the same durable record as the
  /// reservation that displaces them). Either all of it is durable or none.
  std::vector<StateMutation> companions;
  bool has_attempt = false;
  AttemptMutation attempt;
};
void encode(Writer& w, const ReservationMutation& v);
[[nodiscard]] Status decode(Reader& r, ReservationMutation& v);

struct ApplicabilityMutation {
  ReservationId id;
  ReservationGeneration generation;
  Applicability applicability = Applicability::kCurrent;
  ApplicabilityReason reason = ApplicabilityReason::kCurrent;
  Timestamp at;
};
void encode(Writer& w, const ApplicabilityMutation& v);
[[nodiscard]] Status decode(Reader& r, ApplicabilityMutation& v);

struct EpochMutation {
  FabricEpoch epoch;
  Identity128 coordinator_boot;
  Timestamp at;
};
void encode(Writer& w, const EpochMutation& v);
[[nodiscard]] Status decode(Reader& r, EpochMutation& v);

struct FenceMutation {
  ClaimantId claimant;
  ClaimantGeneration claimant_generation;
  PublisherBootId boot;
  SessionId session;
  Timestamp at;
  std::string reason;
  bool claimant_wide = false;
};
void encode(Writer& w, const FenceMutation& v);
[[nodiscard]] Status decode(Reader& r, FenceMutation& v);

struct ClaimantMutation {
  ClaimantId claimant;
  ClaimantGeneration generation;
  Timestamp at;
};
void encode(Writer& w, const ClaimantMutation& v);
[[nodiscard]] Status decode(Reader& r, ClaimantMutation& v);

struct OvercommitMutation {
  ResourceName resource;
  ResourceGeneration generation;
  Bandwidth committed_peak{0};
  Bandwidth ceiling{0};
  Interval window;
  Timestamp at;
  bool resolved = false;
};
void encode(Writer& w, const OvercommitMutation& v);
[[nodiscard]] Status decode(Reader& r, OvercommitMutation& v);

struct RetireMutation {
  std::vector<ReservationId> ids;
  std::vector<ReservationGeneration> generations;
  Timestamp at;
};
void encode(Writer& w, const RetireMutation& v);
[[nodiscard]] Status decode(Reader& r, RetireMutation& v);

struct CapacityMutation {
  CapacitySnapshot snapshot;
  /// Resources explicitly withdrawn by this record (complete snapshots).
  std::vector<ResourceName> withdrawals;
};
void encode(Writer& w, const CapacityMutation& v);
[[nodiscard]] Status decode(Reader& r, CapacityMutation& v);

/// Union carrier for one durable record. Exactly one member is meaningful,
/// selected by kind.
struct DurableRecord {
  RecordKind kind = RecordKind::kFabricBoot;
  ReservationMutation reservation;
  StateMutation state;
  ApplicabilityMutation applicability;
  AttemptMutation attempt;
  EpochMutation epoch;
  FenceMutation fence;
  ClaimantMutation claimant;
  OvercommitMutation overcommit;
  RetireMutation retire;
  CapacityMutation capacity;
  PathAuthoritySnapshot path;
  PolicyRecord policy;
};

void encode(Writer& w, const DurableRecord& v);
[[nodiscard]] Status decode(Reader& r, DurableRecord& v);

// --- snapshot state ---------------------------------------------------------
struct SnapshotCapacityEntry {
  ResourceCapacity capacity;
  CapacitySnapshotId snapshot;
  Timestamp ingested_at;
  bool withdrawn = false;
  Timestamp withdrawn_at;
  std::vector<ResourceGeneration> prior_generations;
};
struct SnapshotPathEntry {
  PathAuthority path;
  CapacitySnapshotId snapshot;
  Timestamp ingested_at;
  bool retired = false;
  std::vector<PathAuthorityGeneration> prior_generations;
};
struct SnapshotPolicyEntry {
  PolicyRecord record;
  Timestamp ingested_at;
  std::vector<PolicyGeneration> prior_generations;
};

/// Complete durable state. A snapshot is a pure function of the record stream
/// that produced it, so snapshot-then-replay and replay-only recovery converge.
struct SnapshotState {
  FabricEpoch epoch;
  Identity128 coordinator_boot;
  DurableSequence sequence;
  std::vector<SnapshotCapacityEntry> capacity;
  std::vector<SnapshotPathEntry> paths;
  std::vector<SnapshotPolicyEntry> policies;
  std::vector<ReservationRecord> reservations;
  std::vector<ReservationSeries> series;
  std::vector<SupersessionEdge> edges;
  std::vector<AttemptMutation> attempts;
  std::vector<FenceMutation> fences;
  std::vector<ClaimantMutation> claimants;
  std::vector<OvercommitMutation> overcommits;
  std::vector<ReservationRecord> retired;
};
void encode(Writer& w, const SnapshotState& v);
[[nodiscard]] Status decode(Reader& r, SnapshotState& v);

// --- reports and results ----------------------------------------------------
void encode(Writer& w, const CapabilityDelta& v);
[[nodiscard]] Status decode(Reader& r, CapabilityDelta& v);
void encode(Writer& w, const ConflictEntry& v);
[[nodiscard]] Status decode(Reader& r, ConflictEntry& v);
void encode(Writer& w, const ConflictSet& v);
[[nodiscard]] Status decode(Reader& r, ConflictSet& v);
void encode(Writer& w, const AdmissionReport& v);
[[nodiscard]] Status decode(Reader& r, AdmissionReport& v);
void encode(Writer& w, const CommitResult& v);
[[nodiscard]] Status decode(Reader& r, CommitResult& v);
void encode(Writer& w, const AmendmentResult& v);
[[nodiscard]] Status decode(Reader& r, AmendmentResult& v);
void encode(Writer& w, const LifecycleResult& v);
[[nodiscard]] Status decode(Reader& r, LifecycleResult& v);
void encode(Writer& w, const AttemptReconciliation& v);
[[nodiscard]] Status decode(Reader& r, AttemptReconciliation& v);
void encode(Writer& w, const RemainingCapacity& v);
[[nodiscard]] Status decode(Reader& r, RemainingCapacity& v);
void encode(Writer& w, const ChangePoint& v);
[[nodiscard]] Status decode(Reader& r, ChangePoint& v);
void encode(Writer& w, const CapacityTimeline& v);
[[nodiscard]] Status decode(Reader& r, CapacityTimeline& v);
void encode(Writer& w, const LineageView& v);
[[nodiscard]] Status decode(Reader& r, LineageView& v);
void encode(Writer& w, const OvercommitReport& v);
[[nodiscard]] Status decode(Reader& r, OvercommitReport& v);
void encode(Writer& w, const CoordinatorStats& v);
[[nodiscard]] Status decode(Reader& r, CoordinatorStats& v);
void encode(Writer& w, const IndexEntry& v);
[[nodiscard]] Status decode(Reader& r, IndexEntry& v);
void encode(Writer& w, const ResourceCapacity& v);
[[nodiscard]] Status decode(Reader& r, ResourceCapacity& v);
void encode(Writer& w, const RecoveryReport& v);
[[nodiscard]] Status decode(Reader& r, RecoveryReport& v);

// --- journal envelope -------------------------------------------------------
/// Wraps a durable payload with the kind/version that produced it, so a record
/// read back from disk can be rejected rather than misread when formats move.
[[nodiscard]] std::string encode_record(const DurableRecord& record);
[[nodiscard]] Status decode_record(std::string_view payload, RecordKind kind, DurableRecord& record);

// --- sequence helpers -------------------------------------------------------
// Defined after every element codec so unqualified lookup resolves the full
// overload set at instantiation time.
inline void encode_list(Writer& w, const std::vector<std::string>& items) {
  w.count(items.size());
  for (const std::string& item : items) {
    w.text(item);
  }
}

template <class T>
void encode_list(Writer& w, const std::vector<T>& items) {
  w.count(items.size());
  for (const T& item : items) {
    encode(w, item);
  }
}

/// Decodes a sequence bounded by kMaxCollectionItems. The bound is enforced
/// before allocation, so a hostile length prefix cannot exhaust memory.
template <class T>
[[nodiscard]] Status decode_list(Reader& r, std::vector<T>& items) {
  Result<std::uint32_t> count = r.u32();
  if (!count) return count.error();
  if (count.value() > kMaxCollectionItems) {
    return make_error(ErrorCode::kResourceExhausted, "encoded collection exceeds the item bound");
  }
  items.clear();
  items.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    T item{};
    Status decoded = decode(r, item);
    if (!decoded) return decoded;
    items.push_back(std::move(item));
  }
  return {};
}

template <>
[[nodiscard]] inline Status decode_list<std::string>(Reader& r, std::vector<std::string>& items) {
  Result<std::uint32_t> count = r.u32();
  if (!count) return count.error();
  if (count.value() > kMaxCollectionItems) {
    return make_error(ErrorCode::kResourceExhausted, "encoded collection exceeds the item bound");
  }
  items.clear();
  items.reserve(count.value());
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    Result<std::string_view> raw = r.text(kMaxTextBytes);
    if (!raw) return raw.error();
    items.emplace_back(raw.value().data(), raw.value().size());
  }
  return {};
}

}  // namespace brf::codec

#endif  // BRF_CODEC_HPP
