// Bandwidth Reservation Fabric - coordinator wire protocol.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#ifndef BRF_PROTOCOL_HPP
#define BRF_PROTOCOL_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "brf/codec.hpp"
#include "brf/error.hpp"
#include "brf/outcome.hpp"
#include "brf/version.hpp"
#include "brf/wire.hpp"

namespace brf::protocol {

/// Frame limits. A peer that exceeds them is refused, not accommodated.
inline constexpr std::size_t kMaxFrameBytes = 1u * 1024u * 1024u;
inline constexpr std::uint32_t kFrameMagic = 0x46524231u;  // 'BRF1'

enum class MessageType : std::uint16_t {
  kHello = 1,
  kHelloAck = 2,

  kIngestCapacity = 10,
  kIngestPathAuthority = 11,
  kIngestPolicy = 12,
  kRegisterClaimant = 13,
  kFence = 14,

  kValidate = 20,
  kCommit = 21,
  kAmend = 22,
  kRelease = 23,
  kRecall = 24,
  kRevoke = 25,
  kRevalidate = 26,
  kReconcileAttempt = 27,
  kReconcileLifecycle = 28,

  kGetReservation = 30,
  kQueryClaimant = 31,
  kQueryResource = 32,
  kQueryCommitted = 33,
  kQueryRemaining = 34,
  kExplainConflicts = 35,
  kTimeline = 36,
  kLineage = 37,
  kOvercommitReport = 38,
  kStats = 39,
  kDurableReplay = 40,

  kHoldAcquire = 50,
  kHoldRelease = 51,
  kHoldQuery = 52,
  kSessionRelease = 53,

  kShutdown = 60,

  kOk = 100,
  kError = 101,
};

[[nodiscard]] const char* to_string(MessageType type) noexcept;

struct Frame {
  MessageType type = MessageType::kError;
  std::string payload;
};

/// Frame layout: magic | total_length | crc32c | message_type | payload.
/// total_length includes the 16-byte header, so a decoder can validate the
/// declared size against the received bytes before allocating anything.
inline constexpr std::size_t kFrameHeaderBytes = 16;

[[nodiscard]] std::string encode_frame(MessageType type, std::string_view payload);
[[nodiscard]] Result<Frame> decode_frame(std::string_view bytes);

// --- payloads ---------------------------------------------------------------

struct HelloRequest {
  std::uint16_t protocol_version = kWireProtocolVersion;
  Identity128 client;
  std::string client_name;
};
struct HelloResponse {
  std::uint16_t protocol_version = kWireProtocolVersion;
  FabricEpoch epoch;
  Identity128 coordinator_boot;
  Identity128 store;
  std::uint32_t max_frame_bytes = static_cast<std::uint32_t>(kMaxFrameBytes);
  bool durable_writable = true;
};

struct CapacityIngestRequest {
  codec::RequestContext context;
  CapacitySnapshot snapshot;
  std::vector<ResourceName> withdrawals;
};
struct PathIngestRequest {
  codec::RequestContext context;
  PathAuthoritySnapshot snapshot;
};
struct PolicyIngestRequest {
  codec::RequestContext context;
  PolicyRecord record;
};
struct ClaimantRegistrationRequest {
  codec::RequestContext context;
  ClaimantId claimant;
  ClaimantGeneration generation;
};
struct FenceRequest {
  codec::RequestContext context;
  ClaimantId claimant;
  ClaimantGeneration claimant_generation;
  PublisherBootId boot;
  SessionId session;
  bool claimant_wide = false;
};

struct ReservationCreateRequest {
  codec::RequestContext context;
  ReservationTerms terms;
  ReservationId requested_id;
  bool dry_run = false;
  std::vector<HoldId> consume_holds;
};
struct AmendmentRequest {
  codec::RequestContext context;
  ReservationId target;
  ReservationGeneration target_generation;
  ReservationTerms terms;
  bool dry_run = false;
};
struct ReservationRefRequest {
  codec::RequestContext context;
  ReservationId id;
  ReservationGeneration generation;
};
struct RecallRequest {
  codec::RequestContext context;
  ReservationId id;
  ReservationGeneration generation;
  Timestamp effective_at;
  Duration grace;
  bool force = false;
};
struct RevalidateRequest {
  codec::RequestContext context;
  ReservationId id;
  ReservationGeneration generation;
  bool mark_stale = false;
};
struct AttemptRequest {
  codec::RequestContext context;
  AttemptId attempt;
};
struct LifecycleReconcileRequest {
  codec::RequestContext context;
  bool fence_dead_holds = true;
};

struct QueryRequest {
  codec::RequestContext context;
  ResourceName resource;
  Interval window;
  Bandwidth amount{0};
  bool include_terminal = false;
};
struct ClaimantQueryRequest {
  codec::RequestContext context;
  ClaimantId claimant;
  bool include_terminal = false;
};
struct LineageRequest {
  codec::RequestContext context;
  ReservationId id;
  ReservationGeneration generation;
};
struct HoldAcquireRequest {
  codec::RequestContext context;
  ReservationTerms terms;
  Timestamp expires_at;
};
struct HoldReleaseRequest {
  codec::RequestContext context;
  HoldId id;
  HoldGeneration generation;
};

struct StatusResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  std::string message;
  ReservationId reservation;
  ReservationGeneration generation;
  DurableSequence sequence;
};
struct CommitResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  std::string message;
  CommitResult result;
};
struct AmendmentResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  std::string message;
  AmendmentResult result;
};
struct LifecycleResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  std::string message;
  LifecycleResult result;
};
struct ReservationResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  std::string message;
  bool found = false;
  ReservationRecord record;
};
struct ReservationListResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  std::string message;
  std::vector<ReservationRecord> records;
  bool truncated = false;
};
struct RemainingResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  std::string message;
  std::vector<RemainingCapacity> resources;
};
struct ReportResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  AdmissionReport report;
};
struct TimelineResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  CapacityTimeline timeline;
};
struct LineageResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  LineageView lineage;
};
struct ReconciliationResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  AttemptReconciliation reconciliation;
};
struct OvercommitResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  OvercommitReport report;
};
struct StatsResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  CoordinatorStats stats;
  RecoveryReport recovery;
};
struct HoldResponse {
  AdmissionOutcome outcome = AdmissionOutcome::kCommittable;
  std::string message;
  codec::HoldRecord hold;
};
struct ErrorResponse {
  ErrorCode code = ErrorCode::kInternal;
  AdmissionOutcome outcome = AdmissionOutcome::kInvalidRequest;
  std::string message;
};

// --- payload codecs ---------------------------------------------------------
void encode(Writer& w, const HelloRequest& v);
[[nodiscard]] Status decode(Reader& r, HelloRequest& v);
void encode(Writer& w, const HelloResponse& v);
[[nodiscard]] Status decode(Reader& r, HelloResponse& v);
void encode(Writer& w, const CapacityIngestRequest& v);
[[nodiscard]] Status decode(Reader& r, CapacityIngestRequest& v);
void encode(Writer& w, const PathIngestRequest& v);
[[nodiscard]] Status decode(Reader& r, PathIngestRequest& v);
void encode(Writer& w, const PolicyIngestRequest& v);
[[nodiscard]] Status decode(Reader& r, PolicyIngestRequest& v);
void encode(Writer& w, const ClaimantRegistrationRequest& v);
[[nodiscard]] Status decode(Reader& r, ClaimantRegistrationRequest& v);
void encode(Writer& w, const FenceRequest& v);
[[nodiscard]] Status decode(Reader& r, FenceRequest& v);
void encode(Writer& w, const ReservationCreateRequest& v);
[[nodiscard]] Status decode(Reader& r, ReservationCreateRequest& v);
void encode(Writer& w, const AmendmentRequest& v);
[[nodiscard]] Status decode(Reader& r, AmendmentRequest& v);
void encode(Writer& w, const ReservationRefRequest& v);
[[nodiscard]] Status decode(Reader& r, ReservationRefRequest& v);
void encode(Writer& w, const RecallRequest& v);
[[nodiscard]] Status decode(Reader& r, RecallRequest& v);
void encode(Writer& w, const RevalidateRequest& v);
[[nodiscard]] Status decode(Reader& r, RevalidateRequest& v);
void encode(Writer& w, const AttemptRequest& v);
[[nodiscard]] Status decode(Reader& r, AttemptRequest& v);
void encode(Writer& w, const LifecycleReconcileRequest& v);
[[nodiscard]] Status decode(Reader& r, LifecycleReconcileRequest& v);
void encode(Writer& w, const QueryRequest& v);
[[nodiscard]] Status decode(Reader& r, QueryRequest& v);
void encode(Writer& w, const ClaimantQueryRequest& v);
[[nodiscard]] Status decode(Reader& r, ClaimantQueryRequest& v);
void encode(Writer& w, const LineageRequest& v);
[[nodiscard]] Status decode(Reader& r, LineageRequest& v);
void encode(Writer& w, const HoldAcquireRequest& v);
[[nodiscard]] Status decode(Reader& r, HoldAcquireRequest& v);
void encode(Writer& w, const HoldReleaseRequest& v);
[[nodiscard]] Status decode(Reader& r, HoldReleaseRequest& v);
void encode(Writer& w, const StatusResponse& v);
[[nodiscard]] Status decode(Reader& r, StatusResponse& v);
void encode(Writer& w, const CommitResponse& v);
[[nodiscard]] Status decode(Reader& r, CommitResponse& v);
void encode(Writer& w, const AmendmentResponse& v);
[[nodiscard]] Status decode(Reader& r, AmendmentResponse& v);
void encode(Writer& w, const LifecycleResponse& v);
[[nodiscard]] Status decode(Reader& r, LifecycleResponse& v);
void encode(Writer& w, const ReservationResponse& v);
[[nodiscard]] Status decode(Reader& r, ReservationResponse& v);
void encode(Writer& w, const ReservationListResponse& v);
[[nodiscard]] Status decode(Reader& r, ReservationListResponse& v);
void encode(Writer& w, const RemainingResponse& v);
[[nodiscard]] Status decode(Reader& r, RemainingResponse& v);
void encode(Writer& w, const ReportResponse& v);
[[nodiscard]] Status decode(Reader& r, ReportResponse& v);
void encode(Writer& w, const TimelineResponse& v);
[[nodiscard]] Status decode(Reader& r, TimelineResponse& v);
void encode(Writer& w, const LineageResponse& v);
[[nodiscard]] Status decode(Reader& r, LineageResponse& v);
void encode(Writer& w, const ReconciliationResponse& v);
[[nodiscard]] Status decode(Reader& r, ReconciliationResponse& v);
void encode(Writer& w, const OvercommitResponse& v);
[[nodiscard]] Status decode(Reader& r, OvercommitResponse& v);
void encode(Writer& w, const StatsResponse& v);
[[nodiscard]] Status decode(Reader& r, StatsResponse& v);
void encode(Writer& w, const HoldResponse& v);
[[nodiscard]] Status decode(Reader& r, HoldResponse& v);
void encode(Writer& w, const ErrorResponse& v);
[[nodiscard]] Status decode(Reader& r, ErrorResponse& v);

}  // namespace brf::protocol

#endif  // BRF_PROTOCOL_HPP
