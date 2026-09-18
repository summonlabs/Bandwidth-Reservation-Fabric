// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// brf-coordinator: serves the reservation fabric over real TCP.
//
// Every request is answered from the authoritative core. A durable commit is
// flushed to stable storage before its response frame is written, so a client
// that loses the reply reconciles by attempt identity instead of guessing.
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "brf/brf.hpp"

namespace {

using brf::Result;
using brf::Status;

struct ServerOptions {
  std::string store_directory;
  std::uint16_t port = 0;
  std::string port_file;
  std::string epoch_file;
  std::size_t max_connections = 32;
};

[[nodiscard]] brf::protocol::StatusResponse status_of(brf::AdmissionOutcome outcome,
                                                      const std::string& message) {
  brf::protocol::StatusResponse response;
  response.outcome = outcome;
  response.message = message;
  return response;
}

[[nodiscard]] Status send_error(brf::TcpSocket& socket, brf::ErrorCode code,
                                brf::AdmissionOutcome outcome, const std::string& message) {
  brf::protocol::ErrorResponse response;
  response.code = code;
  response.outcome = outcome;
  response.message = message;
  brf::Writer writer(256);
  brf::protocol::encode(writer, response);
  return socket.write_frame(brf::protocol::MessageType::kError, writer.buffer());
}

template <class Response>
[[nodiscard]] Status send_response(brf::TcpSocket& socket, brf::protocol::MessageType type,
                                   const Response& response) {
  brf::Writer writer(512);
  brf::protocol::encode(writer, response);
  return socket.write_frame(type, writer.buffer());
}

[[nodiscard]] Status read_payload(const brf::protocol::Frame& frame, brf::Reader& reader) {
  if (frame.payload.empty()) {
    return brf::make_error(brf::ErrorCode::kInvalidArgument, "request payload is empty");
  }
  reader = brf::Reader(frame.payload);
  return {};
}

class Session {
 public:
  Session(brf::ReservationCoordinator& coordinator, brf::TcpSocket socket)
      : coordinator_(coordinator), socket_(std::move(socket)) {}

  [[nodiscard]] Status serve() {
    for (;;) {
      Result<brf::protocol::Frame> frame = socket_.read_frame(brf::protocol::kMaxFrameBytes);
      if (!frame) {
        // A closed peer, a malformed frame, or a checksum failure all end the
        // session; the durable state is unaffected either way.
        return {};
      }
      if (frame.value().type == brf::protocol::MessageType::kShutdown) {
        shutdown_requested_ = true;
        brf::protocol::StatusResponse response =
            status_of(brf::AdmissionOutcome::kCommittable, "shutdown accepted");
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      Status handled = dispatch(frame.value());
      if (!handled) return handled;
      if (stop_) return {};
    }
  }

  [[nodiscard]] bool shutdown_requested() const noexcept { return shutdown_requested_; }
  void stop() noexcept { stop_ = true; }
  void close() noexcept { socket_.close(); }

 private:
  [[nodiscard]] Status dispatch(const brf::protocol::Frame& frame) {
    brf::Reader reader(frame.payload);
    switch (frame.type) {
      case brf::protocol::MessageType::kHello: {
        brf::protocol::HelloRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        brf::protocol::HelloResponse response;
        const brf::CoordinatorIncarnation incarnation = coordinator_.incarnation();
        response.epoch = incarnation.epoch;
        response.coordinator_boot = incarnation.boot;
        response.store = incarnation.store;
        response.durable_writable = true;
        return send_response(socket_, brf::protocol::MessageType::kHelloAck, response);
      }
      case brf::protocol::MessageType::kIngestCapacity: {
        brf::protocol::CapacityIngestRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Status ingested = coordinator_.ingest_capacity(request.snapshot, request.withdrawals, request.context);
        if (!ingested) {
          return send_error(socket_, ingested.code(), brf::AdmissionOutcome::kInvalidRequest,
                            ingested.error().message);
        }
        return send_response(socket_, brf::protocol::MessageType::kOk,
                             status_of(brf::AdmissionOutcome::kCommittable, "capacity ingested"));
      }
      case brf::protocol::MessageType::kIngestPathAuthority: {
        brf::protocol::PathIngestRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Status ingested = coordinator_.ingest_paths(request.snapshot, request.context);
        if (!ingested) {
          return send_error(socket_, ingested.code(), brf::AdmissionOutcome::kInvalidRequest,
                            ingested.error().message);
        }
        return send_response(socket_, brf::protocol::MessageType::kOk,
                             status_of(brf::AdmissionOutcome::kCommittable, "path authority ingested"));
      }
      case brf::protocol::MessageType::kIngestPolicy: {
        brf::protocol::PolicyIngestRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Status ingested = coordinator_.ingest_policy(request.record, request.context);
        if (!ingested) {
          return send_error(socket_, ingested.code(), brf::AdmissionOutcome::kInvalidRequest,
                            ingested.error().message);
        }
        return send_response(socket_, brf::protocol::MessageType::kOk,
                             status_of(brf::AdmissionOutcome::kCommittable, "policy ingested"));
      }
      case brf::protocol::MessageType::kRegisterClaimant: {
        brf::protocol::ClaimantRegistrationRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Status registered =
            coordinator_.register_claimant(request.claimant, request.generation, request.context);
        if (!registered) {
          return send_error(socket_, registered.code(), brf::AdmissionOutcome::kInvalidRequest,
                            registered.error().message);
        }
        return send_response(socket_, brf::protocol::MessageType::kOk,
                             status_of(brf::AdmissionOutcome::kCommittable, "claimant registered"));
      }
      case brf::protocol::MessageType::kFence: {
        brf::protocol::FenceRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Status fenced = coordinator_.fence(request.context, request.claimant, request.claimant_generation,
                                           request.boot, request.session, request.claimant_wide);
        if (!fenced) {
          return send_error(socket_, fenced.code(), brf::AdmissionOutcome::kInvalidRequest,
                            fenced.error().message);
        }
        return send_response(socket_, brf::protocol::MessageType::kOk,
                             status_of(brf::AdmissionOutcome::kCommittable, "fence recorded"));
      }
      case brf::protocol::MessageType::kValidate:
      case brf::protocol::MessageType::kCommit: {
        brf::protocol::ReservationCreateRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        const bool dry_run = frame.type == brf::protocol::MessageType::kValidate || request.dry_run;
        Result<brf::CommitResult> outcome = coordinator_.create_reservation(
            request.context, request.terms, request.requested_id, dry_run, request.consume_holds);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::CommitResponse response;
        response.outcome = outcome.value().report.outcome;
        response.message = outcome.value().report.explanation;
        response.result = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kAmend: {
        brf::protocol::AmendmentRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::AmendmentResult> outcome = coordinator_.amend_reservation(
            request.context, request.target, request.target_generation, request.terms, request.dry_run);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::AmendmentResponse response;
        response.outcome = outcome.value().report.outcome;
        response.message = outcome.value().report.explanation;
        response.result = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kRelease:
      case brf::protocol::MessageType::kRevoke: {
        brf::protocol::ReservationRefRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::LifecycleResult> outcome =
            frame.type == brf::protocol::MessageType::kRelease
                ? coordinator_.release_reservation(request.context, request.id, request.generation)
                : coordinator_.revoke_reservation(request.context, request.id, request.generation);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::LifecycleResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.message = outcome.value().record.state_reason;
        response.result = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kRecall: {
        brf::protocol::RecallRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::LifecycleResult> outcome = coordinator_.recall_reservation(
            request.context, request.id, request.generation, request.effective_at, request.grace,
            request.force);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::LifecycleResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.message = outcome.value().record.state_reason;
        response.result = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kRevalidate: {
        brf::protocol::RevalidateRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::LifecycleResult> outcome = coordinator_.revalidate_reservation(
            request.context, request.id, request.generation, request.mark_stale);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::LifecycleResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.message = "revalidated";
        response.result = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kReconcileAttempt: {
        brf::protocol::AttemptRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::AttemptReconciliation> outcome =
            coordinator_.reconcile_attempt(request.context, request.attempt);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::ReconciliationResponse response;
        response.outcome = outcome.value().committed ? brf::AdmissionOutcome::kCommittable
                                                     : brf::AdmissionOutcome::kInvalidRequest;
        response.reconciliation = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kReconcileLifecycle: {
        brf::protocol::LifecycleReconcileRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::LifecycleResult> outcome = coordinator_.reconcile_lifecycle(request.context);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::LifecycleResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.message = "lifecycle reconciled";
        response.result = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kGetReservation: {
        brf::protocol::ReservationRefRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::ReservationRecord> outcome =
            coordinator_.get_reservation(request.id, request.generation);
        brf::protocol::ReservationResponse response;
        if (!outcome) {
          response.outcome = brf::AdmissionOutcome::kInvalidRequest;
          response.message = outcome.error().message;
          response.found = false;
        } else {
          response.outcome = brf::AdmissionOutcome::kCommittable;
          response.message = outcome.value().state_reason;
          response.found = true;
          response.record = outcome.value();
        }
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kQueryClaimant: {
        brf::protocol::ClaimantQueryRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<std::vector<brf::ReservationRecord>> outcome =
            coordinator_.query_claimant(request.claimant, request.include_terminal);
        brf::protocol::ReservationListResponse response;
        if (!outcome) {
          response.outcome = brf::AdmissionOutcome::kInvalidRequest;
          response.message = outcome.error().message;
        } else {
          response.outcome = brf::AdmissionOutcome::kCommittable;
          response.records = outcome.value();
        }
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kQueryResource:
      case brf::protocol::MessageType::kQueryCommitted: {
        brf::protocol::QueryRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<std::vector<brf::ReservationRecord>> outcome = coordinator_.query_resource(
            request.resource, request.window, request.include_terminal);
        brf::protocol::ReservationListResponse response;
        if (!outcome) {
          response.outcome = brf::AdmissionOutcome::kInvalidRequest;
          response.message = outcome.error().message;
        } else {
          response.outcome = brf::AdmissionOutcome::kCommittable;
          response.records = outcome.value();
        }
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kQueryRemaining: {
        brf::protocol::QueryRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<std::vector<brf::RemainingCapacity>> outcome =
            coordinator_.query_remaining(request.resource, request.window);
        brf::protocol::RemainingResponse response;
        if (!outcome) {
          response.outcome = brf::AdmissionOutcome::kInvalidRequest;
          response.message = outcome.error().message;
        } else {
          response.outcome = brf::AdmissionOutcome::kCommittable;
          response.resources = outcome.value();
        }
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kExplainConflicts: {
        brf::protocol::ReservationCreateRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::AdmissionReport> outcome =
            coordinator_.explain_conflicts(request.terms, request.requested_id);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::ReportResponse response;
        response.outcome = outcome.value().outcome;
        response.report = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kTimeline: {
        brf::protocol::QueryRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::CapacityTimeline> outcome =
            coordinator_.query_timeline(request.resource, request.window, 64);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::TimelineResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.timeline = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kLineage: {
        brf::protocol::LineageRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::LineageView> outcome = coordinator_.query_lineage(request.id, request.generation);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::LineageResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.lineage = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kOvercommitReport: {
        brf::protocol::OvercommitResponse response;
        Result<brf::OvercommitReport> outcome = coordinator_.overcommit_report();
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.report = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kStats: {
        brf::protocol::StatsResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.stats = coordinator_.stats();
        response.recovery = coordinator_.recovery_report();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kDurableReplay: {
        brf::protocol::StatsResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.stats = coordinator_.stats();
        response.recovery = coordinator_.recovery_report();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kHoldAcquire: {
        brf::protocol::HoldAcquireRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::codec::HoldRecord> outcome =
            coordinator_.acquire_hold(request.context, request.terms, request.expires_at);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::HoldResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.message = "hold acquired";
        response.hold = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kHoldRelease: {
        brf::protocol::HoldReleaseRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Result<brf::codec::HoldRecord> outcome =
            coordinator_.release_hold(request.context, request.id, request.generation);
        if (!outcome) {
          return send_error(socket_, outcome.error().code, brf::AdmissionOutcome::kInvalidRequest,
                            outcome.error().message);
        }
        brf::protocol::HoldResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.message = "hold released";
        response.hold = outcome.value();
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kHoldQuery: {
        brf::protocol::HoldResponse response;
        response.outcome = brf::AdmissionOutcome::kCommittable;
        response.message = "holds";
        return send_response(socket_, brf::protocol::MessageType::kOk, response);
      }
      case brf::protocol::MessageType::kSessionRelease: {
        brf::protocol::LifecycleReconcileRequest request;
        Status decoded = brf::protocol::decode(reader, request);
        if (!decoded) return send_error(socket_, decoded.code(), brf::AdmissionOutcome::kInvalidRequest,
                                        decoded.error().message);
        Status released = coordinator_.release_session(request.context);
        if (!released) {
          return send_error(socket_, released.code(), brf::AdmissionOutcome::kInvalidRequest,
                            released.error().message);
        }
        return send_response(socket_, brf::protocol::MessageType::kOk,
                             status_of(brf::AdmissionOutcome::kCommittable, "session released"));
      }
      default:
        return send_error(socket_, brf::ErrorCode::kUnsupported, brf::AdmissionOutcome::kUnsupported,
                          std::string("unsupported message type: ") + brf::protocol::to_string(frame.type));
    }
  }

  brf::ReservationCoordinator& coordinator_;
  brf::TcpSocket socket_;
  bool shutdown_requested_ = false;
  bool stop_ = false;
};

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

void write_file(const std::string& path, const std::string& text) {
  if (path.empty()) return;
  std::FILE* file = std::fopen(path.c_str(), "wb");
  if (file == nullptr) return;
  std::fwrite(text.data(), 1, text.size(), file);
  std::fclose(file);
}

}  // namespace

int main(int argc, char** argv) {
  if (has_flag(argc, argv, "--help")) {
    std::printf(
        "brf-coordinator --store <dir> [--port <n>] [--port-file <path>] [--epoch-file <path>]\n"
        "  Serves the Bandwidth Reservation Fabric over loopback TCP.\n"
        "  Port 0 selects an ephemeral port, reported on stdout as LISTENING <port>.\n");
    return 0;
  }
  ServerOptions options;
  options.store_directory = argument_value(argc, argv, "--store", "brf-store");
  const std::string port_text = argument_value(argc, argv, "--port", "0");
  options.port = static_cast<std::uint16_t>(std::stoi(port_text));
  options.port_file = argument_value(argc, argv, "--port-file");
  options.epoch_file = argument_value(argc, argv, "--epoch-file");

  brf::CoordinatorConfig config;
  config.store_directory = options.store_directory;
  brf::RecoveryReport report;
  Result<std::unique_ptr<brf::ReservationCoordinator>> opened =
      brf::ReservationCoordinator::open(config, &report);
  if (!opened) {
    std::fprintf(stderr, "brf-coordinator: failed to open the store: %s\n",
                 opened.error().message.c_str());
    return 2;
  }
  std::unique_ptr<brf::ReservationCoordinator> coordinator = std::move(opened.value());

  Result<brf::TcpListener> listener = brf::TcpListener::bind_loopback(options.port);
  if (!listener) {
    std::fprintf(stderr, "brf-coordinator: bind failed: %s\n", listener.error().message.c_str());
    return 2;
  }
  const brf::CoordinatorIncarnation incarnation = coordinator->incarnation();
  std::printf("LISTENING %u\n", static_cast<unsigned>(listener.value().port()));
  std::printf("EPOCH %s\n", brf::to_string(incarnation.epoch).c_str());
  std::printf("BOOT %s\n", incarnation.boot.to_hex().c_str());
  std::printf("STORE %s\n", incarnation.store.to_hex().c_str());
  std::printf("RECOVERED torn_tail=%d records=%llu snapshot=%d\n",
              report.torn_tail_truncated ? 1 : 0,
              static_cast<unsigned long long>(report.records_replayed),
              report.snapshot_loaded ? 1 : 0);
  std::fflush(stdout);
  write_file(options.port_file, std::to_string(static_cast<unsigned>(listener.value().port())));
  write_file(options.epoch_file, brf::to_string(incarnation.epoch));

  std::mutex sessions_mutex;
  std::vector<std::shared_ptr<Session>> sessions;
  std::vector<std::thread> workers;
  std::atomic<bool> stop{false};
  std::atomic<bool> shutdown_requested{false};

  while (!stop.load()) {
    Result<brf::TcpSocket> socket = listener.value().accept();
    if (!socket) {
      break;  // The listener was closed: shutdown.
    }
    auto session = std::make_shared<Session>(*coordinator, std::move(socket.value()));
    {
      std::lock_guard<std::mutex> guard(sessions_mutex);
      sessions.push_back(session);
    }
    workers.emplace_back([session, &stop, &shutdown_requested]() {
      Status served = session->serve();
      (void)served;
      if (session->shutdown_requested()) {
        shutdown_requested.store(true);
        stop.store(true);
      }
      session->close();
    });
    if (shutdown_requested.load()) {
      break;
    }
  }

  listener.value().close();
  {
    std::lock_guard<std::mutex> guard(sessions_mutex);
    for (const std::shared_ptr<Session>& session : sessions) {
      session->stop();
      session->close();
    }
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  coordinator->begin_shutdown();
  Status flushed = coordinator->flush();
  (void)flushed;
  std::printf("STOPPED\n");
  std::fflush(stdout);
  brf::transport_shutdown();
  return 0;
}