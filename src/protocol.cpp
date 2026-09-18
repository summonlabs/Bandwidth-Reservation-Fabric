// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Wire protocol: framing plus canonical codecs for every request and response.
#include "brf/protocol.hpp"

#include "brf/hash.hpp"

namespace brf::protocol {
namespace {

template <class T>
void encode_payload(Writer& w, const T& value) {
  encode(w, value);
}

[[nodiscard]] Status read_message(Reader& r, std::string& out, std::size_t max_size) {
  Result<std::string_view> raw = r.text(max_size);
  if (!raw) return raw.error();
  out.assign(raw.value().data(), raw.value().size());
  return {};
}

}  // namespace

const char* to_string(MessageType type) noexcept {
  switch (type) {
    case MessageType::kHello: return "HELLO";
    case MessageType::kHelloAck: return "HELLO_ACK";
    case MessageType::kIngestCapacity: return "INGEST_CAPACITY";
    case MessageType::kIngestPathAuthority: return "INGEST_PATH_AUTHORITY";
    case MessageType::kIngestPolicy: return "INGEST_POLICY";
    case MessageType::kRegisterClaimant: return "REGISTER_CLAIMANT";
    case MessageType::kFence: return "FENCE";
    case MessageType::kValidate: return "VALIDATE";
    case MessageType::kCommit: return "COMMIT";
    case MessageType::kAmend: return "AMEND";
    case MessageType::kRelease: return "RELEASE";
    case MessageType::kRecall: return "RECALL";
    case MessageType::kRevoke: return "REVOKE";
    case MessageType::kRevalidate: return "REVALIDATE";
    case MessageType::kReconcileAttempt: return "RECONCILE_ATTEMPT";
    case MessageType::kReconcileLifecycle: return "RECONCILE_LIFECYCLE";
    case MessageType::kGetReservation: return "GET_RESERVATION";
    case MessageType::kQueryClaimant: return "QUERY_CLAIMANT";
    case MessageType::kQueryResource: return "QUERY_RESOURCE";
    case MessageType::kQueryCommitted: return "QUERY_COMMITTED";
    case MessageType::kQueryRemaining: return "QUERY_REMAINING";
    case MessageType::kExplainConflicts: return "EXPLAIN_CONFLICTS";
    case MessageType::kTimeline: return "TIMELINE";
    case MessageType::kLineage: return "LINEAGE";
    case MessageType::kOvercommitReport: return "OVERCOMMIT_REPORT";
    case MessageType::kStats: return "STATS";
    case MessageType::kDurableReplay: return "DURABLE_REPLAY";
    case MessageType::kHoldAcquire: return "HOLD_ACQUIRE";
    case MessageType::kHoldRelease: return "HOLD_RELEASE";
    case MessageType::kHoldQuery: return "HOLD_QUERY";
    case MessageType::kSessionRelease: return "SESSION_RELEASE";
    case MessageType::kShutdown: return "SHUTDOWN";
    case MessageType::kOk: return "OK";
    case MessageType::kError: return "ERROR";
  }
  return "UNKNOWN";
}

std::string encode_frame(MessageType type, std::string_view payload) {
  Writer writer(kFrameHeaderBytes + payload.size());
  writer.u32(kFrameMagic);
  writer.u32(static_cast<std::uint32_t>(kFrameHeaderBytes + payload.size()));
  writer.u32(crc32c(payload.data(), payload.size()));
  writer.u16(static_cast<std::uint16_t>(type));
  writer.u16(kWireProtocolVersion);
  writer.raw(payload.data(), payload.size());
  return writer.take();
}

Result<Frame> decode_frame(std::string_view bytes) {
  if (bytes.size() < kFrameHeaderBytes) {
    return make_error(ErrorCode::kCorrupt, "frame is shorter than its header");
  }
  Reader reader(bytes);
  Result<std::uint32_t> magic = reader.u32();
  if (!magic) return magic.error();
  if (magic.value() != kFrameMagic) {
    return make_error(ErrorCode::kCorrupt, "frame magic is invalid");
  }
  Result<std::uint32_t> length = reader.u32();
  if (!length) return length.error();
  if (length.value() != bytes.size()) {
    return make_error(ErrorCode::kCorrupt, "frame length does not match the received bytes");
  }
  Result<std::uint32_t> checksum = reader.u32();
  if (!checksum) return checksum.error();
  Result<std::uint16_t> type = reader.u16();
  if (!type) return type.error();
  Result<std::uint16_t> version = reader.u16();
  if (!version) return version.error();
  if (version.value() != kWireProtocolVersion) {
    return make_error(ErrorCode::kUnsupported, "frame protocol version is not supported");
  }
  const std::string_view payload = bytes.substr(kFrameHeaderBytes);
  if (crc32c(payload.data(), payload.size()) != checksum.value()) {
    return make_error(ErrorCode::kCorrupt, "frame checksum mismatch");
  }
  // Unknown message types are refused rather than silently ignored.
  if (type.value() < 1 || type.value() > static_cast<std::uint16_t>(MessageType::kError)) {
    return make_error(ErrorCode::kUnsupported, "frame declares an unknown message type");
  }
  Frame frame;
  frame.type = static_cast<MessageType>(type.value());
  frame.payload.assign(payload.data(), payload.size());
  return frame;
}

// --- codecs -----------------------------------------------------------------
void encode(Writer& w, const HelloRequest& v) {
  w.u16(v.protocol_version);
  w.fixed128(v.client);
  w.text(v.client_name);
}
Status decode(Reader& r, HelloRequest& v) {
  Result<std::uint16_t> version = r.u16();
  if (!version) return version.error();
  v.protocol_version = version.value();
  Result<Identity128> client = r.fixed128();
  if (!client) return client.error();
  v.client = client.value();
  return read_message(r, v.client_name, 128);
}

void encode(Writer& w, const HelloResponse& v) {
  w.u16(v.protocol_version);
  codec::encode(w, v.epoch);
  w.fixed128(v.coordinator_boot);
  w.fixed128(v.store);
  w.u32(v.max_frame_bytes);
  w.boolean(v.durable_writable);
}
Status decode(Reader& r, HelloResponse& v) {
  Result<std::uint16_t> version = r.u16();
  if (!version) return version.error();
  v.protocol_version = version.value();
  Status s = codec::decode(r, v.epoch);
  if (!s) return s;
  Result<Identity128> boot = r.fixed128();
  if (!boot) return boot.error();
  v.coordinator_boot = boot.value();
  Result<Identity128> store = r.fixed128();
  if (!store) return store.error();
  v.store = store.value();
  Result<std::uint32_t> bound = r.u32();
  if (!bound) return bound.error();
  v.max_frame_bytes = bound.value();
  Result<bool> writable = r.boolean();
  if (!writable) return writable.error();
  v.durable_writable = writable.value();
  return {};
}

void encode(Writer& w, const CapacityIngestRequest& v) {
  codec::encode(w, v.context);
  codec::encode(w, v.snapshot);
  codec::encode_list(w, v.withdrawals);
}
Status decode(Reader& r, CapacityIngestRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  s = codec::decode(r, v.snapshot);
  if (!s) return s;
  return codec::decode_list(r, v.withdrawals);
}

void encode(Writer& w, const PathIngestRequest& v) {
  codec::encode(w, v.context);
  codec::encode(w, v.snapshot);
}
Status decode(Reader& r, PathIngestRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  return codec::decode(r, v.snapshot);
}

void encode(Writer& w, const PolicyIngestRequest& v) {
  codec::encode(w, v.context);
  codec::encode(w, v.record);
}
Status decode(Reader& r, PolicyIngestRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  return codec::decode(r, v.record);
}

void encode(Writer& w, const ClaimantRegistrationRequest& v) {
  codec::encode(w, v.context);
  w.fixed128(v.claimant);
  codec::encode(w, v.generation);
}
Status decode(Reader& r, ClaimantRegistrationRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  return codec::decode(r, v.generation);
}

void encode(Writer& w, const FenceRequest& v) {
  codec::encode(w, v.context);
  w.fixed128(v.claimant);
  codec::encode(w, v.claimant_generation);
  w.fixed128(v.boot);
  w.fixed128(v.session);
  w.boolean(v.claimant_wide);
}
Status decode(Reader& r, FenceRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  s = codec::decode(r, v.claimant_generation);
  if (!s) return s;
  Result<Identity128> boot = r.fixed128();
  if (!boot) return boot.error();
  v.boot = boot.value();
  Result<Identity128> session = r.fixed128();
  if (!session) return session.error();
  v.session = session.value();
  Result<bool> wide = r.boolean();
  if (!wide) return wide.error();
  v.claimant_wide = wide.value();
  return {};
}

void encode(Writer& w, const ReservationCreateRequest& v) {
  codec::encode(w, v.context);
  codec::encode(w, v.terms);
  w.fixed128(v.requested_id);
  w.boolean(v.dry_run);
  w.count(v.consume_holds.size());
  for (const HoldId& hold : v.consume_holds) {
    w.fixed128(hold);
  }
}
Status decode(Reader& r, ReservationCreateRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  s = codec::decode(r, v.terms);
  if (!s) return s;
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.requested_id = id.value();
  Result<bool> dry = r.boolean();
  if (!dry) return dry.error();
  v.dry_run = dry.value();
  Result<std::uint32_t> count = r.u32();
  if (!count) return count.error();
  if (count.value() > 64) {
    return make_error(ErrorCode::kResourceExhausted, "too many holds named for consumption");
  }
  v.consume_holds.clear();
  for (std::uint32_t i = 0; i < count.value(); ++i) {
    Result<Identity128> hold = r.fixed128();
    if (!hold) return hold.error();
    v.consume_holds.push_back(hold.value());
  }
  return {};
}

void encode(Writer& w, const AmendmentRequest& v) {
  codec::encode(w, v.context);
  w.fixed128(v.target);
  codec::encode(w, v.target_generation);
  codec::encode(w, v.terms);
  w.boolean(v.dry_run);
}
Status decode(Reader& r, AmendmentRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<Identity128> target = r.fixed128();
  if (!target) return target.error();
  v.target = target.value();
  s = codec::decode(r, v.target_generation);
  if (!s) return s;
  s = codec::decode(r, v.terms);
  if (!s) return s;
  Result<bool> dry = r.boolean();
  if (!dry) return dry.error();
  v.dry_run = dry.value();
  return {};
}

void encode(Writer& w, const ReservationRefRequest& v) {
  codec::encode(w, v.context);
  w.fixed128(v.id);
  codec::encode(w, v.generation);
}
Status decode(Reader& r, ReservationRefRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  return codec::decode(r, v.generation);
}

void encode(Writer& w, const RecallRequest& v) {
  codec::encode(w, v.context);
  w.fixed128(v.id);
  codec::encode(w, v.generation);
  codec::encode(w, v.effective_at);
  codec::encode(w, v.grace);
  w.boolean(v.force);
}
Status decode(Reader& r, RecallRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  s = codec::decode(r, v.generation);
  if (!s) return s;
  s = codec::decode(r, v.effective_at);
  if (!s) return s;
  s = codec::decode(r, v.grace);
  if (!s) return s;
  Result<bool> force = r.boolean();
  if (!force) return force.error();
  v.force = force.value();
  return {};
}

void encode(Writer& w, const RevalidateRequest& v) {
  codec::encode(w, v.context);
  w.fixed128(v.id);
  codec::encode(w, v.generation);
  w.boolean(v.mark_stale);
}
Status decode(Reader& r, RevalidateRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  s = codec::decode(r, v.generation);
  if (!s) return s;
  Result<bool> mark = r.boolean();
  if (!mark) return mark.error();
  v.mark_stale = mark.value();
  return {};
}

void encode(Writer& w, const AttemptRequest& v) {
  codec::encode(w, v.context);
  w.fixed128(v.attempt);
}
Status decode(Reader& r, AttemptRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<Identity128> attempt = r.fixed128();
  if (!attempt) return attempt.error();
  v.attempt = attempt.value();
  return {};
}

void encode(Writer& w, const LifecycleReconcileRequest& v) {
  codec::encode(w, v.context);
  w.boolean(v.fence_dead_holds);
}
Status decode(Reader& r, LifecycleReconcileRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<bool> fence = r.boolean();
  if (!fence) return fence.error();
  v.fence_dead_holds = fence.value();
  return {};
}

void encode(Writer& w, const QueryRequest& v) {
  codec::encode(w, v.context);
  codec::encode(w, v.resource);
  codec::encode(w, v.window);
  codec::encode(w, v.amount);
  w.boolean(v.include_terminal);
}
Status decode(Reader& r, QueryRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  s = codec::decode(r, v.resource);
  if (!s) return s;
  s = codec::decode(r, v.window);
  if (!s) return s;
  s = codec::decode(r, v.amount);
  if (!s) return s;
  Result<bool> terminal = r.boolean();
  if (!terminal) return terminal.error();
  v.include_terminal = terminal.value();
  return {};
}

void encode(Writer& w, const ClaimantQueryRequest& v) {
  codec::encode(w, v.context);
  w.fixed128(v.claimant);
  w.boolean(v.include_terminal);
}
Status decode(Reader& r, ClaimantQueryRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<Identity128> claimant = r.fixed128();
  if (!claimant) return claimant.error();
  v.claimant = claimant.value();
  Result<bool> terminal = r.boolean();
  if (!terminal) return terminal.error();
  v.include_terminal = terminal.value();
  return {};
}

void encode(Writer& w, const LineageRequest& v) {
  codec::encode(w, v.context);
  w.fixed128(v.id);
  codec::encode(w, v.generation);
}
Status decode(Reader& r, LineageRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  return codec::decode(r, v.generation);
}

void encode(Writer& w, const HoldAcquireRequest& v) {
  codec::encode(w, v.context);
  codec::encode(w, v.terms);
  codec::encode(w, v.expires_at);
}
Status decode(Reader& r, HoldAcquireRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  s = codec::decode(r, v.terms);
  if (!s) return s;
  return codec::decode(r, v.expires_at);
}

void encode(Writer& w, const HoldReleaseRequest& v) {
  codec::encode(w, v.context);
  w.fixed128(v.id);
  codec::encode(w, v.generation);
}
Status decode(Reader& r, HoldReleaseRequest& v) {
  Status s = codec::decode(r, v.context);
  if (!s) return s;
  Result<Identity128> id = r.fixed128();
  if (!id) return id.error();
  v.id = id.value();
  return codec::decode(r, v.generation);
}

void encode(Writer& w, const StatusResponse& v) {
  codec::encode(w, v.outcome);
  w.text(v.message);
  w.fixed128(v.reservation);
  codec::encode(w, v.generation);
  codec::encode(w, v.sequence);
}
Status decode(Reader& r, StatusResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  s = read_message(r, v.message, kMaxTextBytes);
  if (!s) return s;
  Result<Identity128> reservation = r.fixed128();
  if (!reservation) return reservation.error();
  v.reservation = reservation.value();
  s = codec::decode(r, v.generation);
  if (!s) return s;
  return codec::decode(r, v.sequence);
}

void encode(Writer& w, const CommitResponse& v) {
  codec::encode(w, v.outcome);
  w.text(v.message);
  codec::encode(w, v.result);
}
Status decode(Reader& r, CommitResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  s = read_message(r, v.message, kMaxTextBytes);
  if (!s) return s;
  return codec::decode(r, v.result);
}

void encode(Writer& w, const AmendmentResponse& v) {
  codec::encode(w, v.outcome);
  w.text(v.message);
  codec::encode(w, v.result);
}
Status decode(Reader& r, AmendmentResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  s = read_message(r, v.message, kMaxTextBytes);
  if (!s) return s;
  return codec::decode(r, v.result);
}

void encode(Writer& w, const LifecycleResponse& v) {
  codec::encode(w, v.outcome);
  w.text(v.message);
  codec::encode(w, v.result);
}
Status decode(Reader& r, LifecycleResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  s = read_message(r, v.message, kMaxTextBytes);
  if (!s) return s;
  return codec::decode(r, v.result);
}

void encode(Writer& w, const ReservationResponse& v) {
  codec::encode(w, v.outcome);
  w.text(v.message);
  w.boolean(v.found);
  codec::encode(w, v.record);
}
Status decode(Reader& r, ReservationResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  s = read_message(r, v.message, kMaxTextBytes);
  if (!s) return s;
  Result<bool> found = r.boolean();
  if (!found) return found.error();
  v.found = found.value();
  return codec::decode(r, v.record);
}

void encode(Writer& w, const ReservationListResponse& v) {
  codec::encode(w, v.outcome);
  w.text(v.message);
  codec::encode_list(w, v.records);
  w.boolean(v.truncated);
}
Status decode(Reader& r, ReservationListResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  s = read_message(r, v.message, kMaxTextBytes);
  if (!s) return s;
  s = codec::decode_list(r, v.records);
  if (!s) return s;
  Result<bool> truncated = r.boolean();
  if (!truncated) return truncated.error();
  v.truncated = truncated.value();
  return {};
}

void encode(Writer& w, const RemainingResponse& v) {
  codec::encode(w, v.outcome);
  w.text(v.message);
  codec::encode_list(w, v.resources);
}
Status decode(Reader& r, RemainingResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  s = read_message(r, v.message, kMaxTextBytes);
  if (!s) return s;
  return codec::decode_list(r, v.resources);
}

void encode(Writer& w, const ReportResponse& v) {
  codec::encode(w, v.outcome);
  codec::encode(w, v.report);
}
Status decode(Reader& r, ReportResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  return codec::decode(r, v.report);
}

void encode(Writer& w, const TimelineResponse& v) {
  codec::encode(w, v.outcome);
  codec::encode(w, v.timeline);
}
Status decode(Reader& r, TimelineResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  return codec::decode(r, v.timeline);
}

void encode(Writer& w, const LineageResponse& v) {
  codec::encode(w, v.outcome);
  codec::encode(w, v.lineage);
}
Status decode(Reader& r, LineageResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  return codec::decode(r, v.lineage);
}

void encode(Writer& w, const ReconciliationResponse& v) {
  codec::encode(w, v.outcome);
  codec::encode(w, v.reconciliation);
}
Status decode(Reader& r, ReconciliationResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  return codec::decode(r, v.reconciliation);
}

void encode(Writer& w, const OvercommitResponse& v) {
  codec::encode(w, v.outcome);
  codec::encode(w, v.report);
}
Status decode(Reader& r, OvercommitResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  return codec::decode(r, v.report);
}

void encode(Writer& w, const StatsResponse& v) {
  codec::encode(w, v.outcome);
  codec::encode(w, v.stats);
  codec::encode(w, v.recovery);
}
Status decode(Reader& r, StatsResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  s = codec::decode(r, v.stats);
  if (!s) return s;
  return codec::decode(r, v.recovery);
}

void encode(Writer& w, const HoldResponse& v) {
  codec::encode(w, v.outcome);
  w.text(v.message);
  codec::encode(w, v.hold);
}
Status decode(Reader& r, HoldResponse& v) {
  Status s = codec::decode(r, v.outcome);
  if (!s) return s;
  s = read_message(r, v.message, kMaxTextBytes);
  if (!s) return s;
  return codec::decode(r, v.hold);
}

void encode(Writer& w, const ErrorResponse& v) {
  codec::encode(w, v.code);
  codec::encode(w, v.outcome);
  w.text(v.message);
}
Status decode(Reader& r, ErrorResponse& v) {
  Status s = codec::decode(r, v.code);
  if (!s) return s;
  s = codec::decode(r, v.outcome);
  if (!s) return s;
  return read_message(r, v.message, kMaxTextBytes);
}

}  // namespace brf::protocol
