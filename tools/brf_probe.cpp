// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// brf-probe: a real client of the reservation fabric. Used by the multiprocess
// proofs and by operators. Identities are derived deterministically from --seed
// and printed, so a supervisor can fence exactly the incarnation it killed.
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "brf/brf.hpp"

namespace {

using brf::Result;
using brf::Status;

struct Options {
  std::uint16_t port = 0;
  std::uint64_t seed = 1;
  std::string command;
  std::vector<std::pair<std::string, std::string>> arguments;
};

[[nodiscard]] std::string argument(const Options& options, const char* name,
                                   const std::string& fallback = {}) {
  for (const auto& pair : options.arguments) {
    if (pair.first == name) return pair.second;
  }
  return fallback;
}

[[nodiscard]] bool has_argument(const Options& options, const char* name) {
  for (const auto& pair : options.arguments) {
    if (pair.first == name) return true;
  }
  return false;
}

[[nodiscard]] Result<std::int64_t> parse_amount(const std::string& text) {
  Result<brf::Bandwidth> parsed = brf::parse_bandwidth(text);
  if (!parsed) return parsed.error();
  return parsed.value().bps;
}

/// Parses a bandwidth field that may legitimately be zero (headroom).
[[nodiscard]] Result<std::int64_t> parse_zeroable_bandwidth(const std::string& text) {
  Result<std::uint64_t> parsed = brf::parse_uint64_decimal(text);
  if (!parsed) return parsed.error();
  if (parsed.value() > static_cast<std::uint64_t>(brf::kMaxBandwidthBps)) {
    return brf::make_error(brf::ErrorCode::kInvalidBandwidth, "value exceeds the representable range");
  }
  return static_cast<std::int64_t>(parsed.value());
}

[[nodiscard]] Result<brf::Timestamp> parse_instant(const std::string& text) {
  if (!text.empty() && text[0] == '+') {
    Result<std::uint64_t> seconds = brf::parse_uint64_decimal(text.substr(1));
    if (!seconds) return seconds.error();
    const brf::Timestamp now = brf::SystemClock{}.now();
    return brf::Timestamp{now.ns + static_cast<std::int64_t>(seconds.value()) * brf::kNsPerSecond};
  }
  return brf::parse_timestamp(text);
}

[[nodiscard]] brf::Identity128 seed_identity(std::uint64_t seed) {
  return brf::Identity128::derive(brf::Identity128::from_hex("5eed5eed5eed5eed5eed5eed5eed5eed").value(), seed);
}

[[nodiscard]] brf::codec::RequestContext make_context(const Options& options, brf::FabricEpoch epoch,
                                                      const std::string& claimant_text,
                                                      const std::string& attempt_text) {
  const brf::Identity128 seed_id = seed_identity(options.seed);
  brf::codec::RequestContext context;
  context.actor = brf::ActorName::from_string("brf-probe").value();
  context.publisher = brf::Identity128::derive(seed_id, 0x505542ULL);
  context.publisher_boot = brf::Identity128::derive(seed_id, 0x424F4F54ULL);
  context.session = brf::Identity128::derive(seed_id, 0x53455353ULL);
  context.claimant = claimant_text.empty() ? brf::Identity128::derive(seed_id, 0x434C4149ULL)
                                           : brf::Identity128::from_hex(claimant_text).value();
  context.claimant_generation = brf::ClaimantGeneration(1);
  context.asserted_epoch = epoch;
  const std::string asserted = argument(options, "--epoch");
  if (!asserted.empty()) {
    // A caller may assert an epoch explicitly. This is how a stale-epoch replay
    // is produced in the multiprocess proofs.
    context.asserted_epoch = brf::FabricEpoch(std::stoull(asserted));
  }
  context.attempt = attempt_text.empty()
                        ? brf::Identity128::derive(seed_id, 0x41545445ULL)
                        : brf::Identity128::from_hex(attempt_text).value();
  context.reason = "brf-probe";
  return context;
}

void print_identity(const Options& options) {
  const brf::Identity128 seed_id = seed_identity(options.seed);
  std::printf("BOOT %s\n", brf::Identity128::derive(seed_id, 0x424F4F54ULL).to_hex().c_str());
  std::printf("SESSION %s\n", brf::Identity128::derive(seed_id, 0x53455353ULL).to_hex().c_str());
  std::printf("CLAIMANT %s\n", brf::Identity128::derive(seed_id, 0x434C4149ULL).to_hex().c_str());
}

[[nodiscard]] int fail(const std::string& message) {
  std::printf("ERR %s\n", message.c_str());
  std::fflush(stdout);
  return 1;
}

[[nodiscard]] Result<brf::TcpSocket> connect(const Options& options) {
  Status ready = brf::transport_init();
  if (!ready) return ready.error();
  return brf::connect_loopback(options.port);
}

[[nodiscard]] Result<brf::protocol::Frame> request(brf::TcpSocket& socket,
                                                   brf::protocol::MessageType type,
                                                   const std::string& payload) {
  Status sent = socket.write_frame(type, payload);
  if (!sent) return sent.error();
  return socket.read_frame(brf::protocol::kMaxFrameBytes);
}

[[nodiscard]] Result<brf::protocol::HelloResponse> hello(brf::TcpSocket& socket) {
  brf::protocol::HelloRequest hello_request;
  hello_request.client = brf::random_identity();
  hello_request.client_name = "brf-probe";
  brf::Writer writer(64);
  brf::protocol::encode(writer, hello_request);
  Result<brf::protocol::Frame> frame =
      request(socket, brf::protocol::MessageType::kHello, writer.take());
  if (!frame) return frame.error();
  if (frame.value().type != brf::protocol::MessageType::kHelloAck) {
    return brf::make_error(brf::ErrorCode::kInternal, "coordinator refused the handshake");
  }
  brf::Reader reader(frame.value().payload);
  brf::protocol::HelloResponse response;
  Status decoded = brf::protocol::decode(reader, response);
  if (!decoded) return decoded.error();
  return response;
}

[[nodiscard]] int report_error(const brf::protocol::Frame& frame) {
  brf::Reader reader(frame.payload);
  brf::protocol::ErrorResponse response;
  Status decoded = brf::protocol::decode(reader, response);
  if (!decoded) return fail("undecodable error frame");
  return fail(std::string(brf::to_string(response.code)) + " " + response.message);
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string token = argv[i];
    if (token == "--help") {
      std::printf(
          "brf-probe --port <n> --seed <n> <command> [--key value ...]\n"
          "commands: hello, seed, commit, commit-then-hang, remaining, reconcile, release, hold,\n"
          "          fence-session, stats, pause\n");
      return 0;
    }
    if (token == "--port" && i + 1 < argc) {
      options.port = static_cast<std::uint16_t>(std::stoi(argv[++i]));
      continue;
    }
    if (token == "--seed" && i + 1 < argc) {
      options.seed = static_cast<std::uint64_t>(std::stoull(argv[++i]));
      continue;
    }
    if (token.size() > 2 && token[0] == '-' && token[1] == '-') {
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        options.arguments.emplace_back(token, argv[++i]);
      } else {
        options.arguments.emplace_back(token, "1");
      }
      continue;
    }
    if (options.command.empty()) {
      options.command = token;
      continue;
    }
    return fail("unexpected argument: " + token);
  }
  if (options.port == 0 || options.command.empty()) {
    return fail("--port and a command are required");
  }
  print_identity(options);

  Result<brf::TcpSocket> socket = connect(options);
  if (!socket) return fail("connect failed: " + socket.error().message);
  Result<brf::protocol::HelloResponse> greeting = hello(socket.value());
  if (!greeting) return fail("handshake failed: " + greeting.error().message);
  const brf::FabricEpoch epoch = greeting.value().epoch;
  std::printf("EPOCH %s\n", brf::to_string(epoch).c_str());
  std::printf("COORDINATOR %s\n", greeting.value().coordinator_boot.to_hex().c_str());

  if (options.command == "hello") {
    std::printf("OK hello\n");
    return 0;
  }

  if (options.command == "seed") {
    const std::string resource = argument(options, "--resource", "r1");
    Result<std::int64_t> capacity = parse_amount(argument(options, "--capacity", "100000000000"));
    if (!capacity) return fail("bad capacity: " + capacity.error().message);
    Result<std::int64_t> headroom = parse_zeroable_bandwidth(argument(options, "--headroom", "0"));
    if (!headroom) return fail("bad headroom: " + headroom.error().message);
    const std::string policy_name = argument(options, "--policy", "fabric-default");
    const std::string generation_text = argument(options, "--generation", "1");

    brf::codec::RequestContext context = make_context(options, epoch, {}, {});
    context.actor = brf::ActorName::from_string("brf-authority").value();
    context.claimant = brf::ClaimantId{};
    brf::PolicyRecord policy = brf::PolicyRegistry::strict_default(brf::PolicyName::from_string(policy_name).value());
    policy.generation = brf::PolicyGeneration(std::stoull(generation_text));
    policy.allow_recall_protected = true;
    policy.max_hold_ttl = brf::Duration{
        std::stoll(argument(options, "--max-hold-ttl-seconds", "5")) * brf::kNsPerSecond};
    policy.max_holds_per_session = 8;
    policy.max_hold_bandwidth = brf::Bandwidth{100000000000LL};
    brf::Writer policy_writer(512);
    brf::protocol::PolicyIngestRequest policy_request;
    policy_request.context = context;
    policy_request.record = policy;
    brf::protocol::encode(policy_writer, policy_request);
    Result<brf::protocol::Frame> policy_frame = request(
        socket.value(), brf::protocol::MessageType::kIngestPolicy, policy_writer.take());
    if (!policy_frame) return fail("policy request failed: " + policy_frame.error().message);
    if (policy_frame.value().type == brf::protocol::MessageType::kError) {
      return report_error(policy_frame.value());
    }

    brf::CapacitySnapshot snapshot;
    snapshot.id = brf::Identity128::derive(seed_identity(options.seed), 0x534E4150ULL);
    snapshot.generation = brf::CapacitySnapshotGeneration(std::stoull(generation_text));
    snapshot.fabric_epoch = epoch;
    snapshot.complete = true;
    brf::ResourceCapacity entry;
    entry.resource = brf::ResourceName::from_string(resource).value();
    entry.generation = brf::ResourceGeneration(0);
    // The resource generation is the requested capacity generation; a fresh
    // probe therefore always declares the next authoritative statement.
    entry.generation = brf::ResourceGeneration(std::stoull(argument(options, "--resource-generation", generation_text)));
    entry.reservable_capacity = brf::Bandwidth{capacity.value()};
    entry.protected_headroom = brf::Bandwidth{headroom.value()};
    snapshot.resources.push_back(entry);

    brf::protocol::CapacityIngestRequest ingest;
    ingest.context = context;
    ingest.snapshot = snapshot;
    for (const std::string& withdrawn : std::vector<std::string>{}) {
      (void)withdrawn;
    }
    if (has_argument(options, "--withdraw")) {
      const std::string name = argument(options, "--withdraw");
      ingest.withdrawals.push_back(brf::ResourceName::from_string(name).value());
    }
    brf::Writer writer(512);
    brf::protocol::encode(writer, ingest);
    Result<brf::protocol::Frame> frame =
        request(socket.value(), brf::protocol::MessageType::kIngestCapacity, writer.take());
    if (!frame) return fail("capacity request failed: " + frame.error().message);
    if (frame.value().type == brf::protocol::MessageType::kError) {
      return report_error(frame.value());
    }
    std::printf("OK seed resource=%s capacity=%lld generation=%s\n", resource.c_str(),
                static_cast<long long>(capacity.value()), generation_text.c_str());
    return 0;
  }

  if (options.command == "commit" || options.command == "commit-then-hang") {
    const std::string resource = argument(options, "--resource", "r1");
    Result<std::int64_t> amount = parse_amount(argument(options, "--amount", "1000000000"));
    if (!amount) return fail("bad amount: " + amount.error().message);
    Result<brf::Timestamp> start = parse_instant(argument(options, "--start", "+60"));
    if (!start) return fail("bad start: " + start.error().message);
    Result<brf::Timestamp> end = parse_instant(argument(options, "--end", "+3600"));
    if (!end) return fail("bad end: " + end.error().message);

    brf::codec::RequestContext context =
        make_context(options, epoch, argument(options, "--claimant"), argument(options, "--attempt"));
    brf::ReservationTerms terms;
    terms.claimant = context.claimant;
    terms.claimant_generation = context.claimant_generation;
    terms.binding_kind = brf::BindingKind::kResources;
    terms.resources.push_back(brf::ResourceName::from_string(resource).value());
    terms.interval = brf::Interval{start.value(), end.value()};
    terms.amount = brf::Bandwidth{amount.value()};
    terms.policy = brf::PolicyName::from_string(argument(options, "--policy", "fabric-default")).value();
    if (has_argument(options, "--guarantee")) {
      Result<brf::GuaranteeClass> parsed =
          brf::parse_guarantee_class(argument(options, "--guarantee"));
      if (!parsed) return fail("bad guarantee class");
      terms.guarantee = parsed.value();
    }
    brf::protocol::ReservationCreateRequest create;
    create.context = context;
    create.terms = terms;
    if (has_argument(options, "--id")) {
      create.requested_id = brf::Identity128::from_hex(argument(options, "--id")).value();
    }
    brf::Writer writer(512);
    brf::protocol::encode(writer, create);
    Result<brf::protocol::Frame> frame =
        request(socket.value(), brf::protocol::MessageType::kCommit, writer.take());
    if (!frame) return fail("commit request failed: " + frame.error().message);
    if (frame.value().type == brf::protocol::MessageType::kError) {
      return report_error(frame.value());
    }
    brf::Reader reader(frame.value().payload);
    brf::protocol::CommitResponse response;
    Status decoded = brf::protocol::decode(reader, response);
    if (!decoded) return fail("undecodable commit response");
    if (options.command == "commit-then-hang") {
      // The durable commit has been acknowledged by the coordinator, but the
      // caller of this process never learns the outcome: it is killed here.
      // Reconciliation by attempt identity is the only correct recovery.
      std::printf("DURABLE outcome=%s id=%s generation=%s\n", brf::to_string(response.outcome),
                  response.result.record.id.to_hex().c_str(),
                  brf::to_string(response.result.record.generation).c_str());
      std::fflush(stdout);
      std::this_thread::sleep_for(std::chrono::hours(1));
      return 0;
    }
    std::printf("OK commit outcome=%s id=%s generation=%s state=%s amount=%lld reply=%s\n",
                brf::to_string(response.outcome), response.result.record.id.to_hex().c_str(),
                brf::to_string(response.result.record.generation).c_str(),
                brf::to_string(response.result.record.state),
                static_cast<long long>(response.result.record.terms.amount.bps),
                response.result.replayed ? "replayed" : "fresh");
    return response.result.report.outcome == brf::AdmissionOutcome::kCommittable ? 0 : 3;
  }

  if (options.command == "remaining") {
    const std::string resource = argument(options, "--resource", "r1");
    Result<brf::Timestamp> start = parse_instant(argument(options, "--start", "+0"));
    if (!start) return fail("bad start: " + start.error().message);
    Result<brf::Timestamp> end = parse_instant(argument(options, "--end", "+86400"));
    if (!end) return fail("bad end: " + end.error().message);
    brf::protocol::QueryRequest query;
    query.context = make_context(options, epoch, {}, {});
    query.resource = brf::ResourceName::from_string(resource).value();
    query.window = brf::Interval{start.value(), end.value()};
    brf::Writer writer(256);
    brf::protocol::encode(writer, query);
    Result<brf::protocol::Frame> frame =
        request(socket.value(), brf::protocol::MessageType::kQueryRemaining, writer.take());
    if (!frame) return fail("query failed: " + frame.error().message);
    if (frame.value().type == brf::protocol::MessageType::kError) {
      return report_error(frame.value());
    }
    brf::Reader reader(frame.value().payload);
    brf::protocol::RemainingResponse response;
    Status decoded = brf::protocol::decode(reader, response);
    if (!decoded) return fail("undecodable remaining response");
    for (const brf::RemainingCapacity& entry : response.resources) {
      std::printf("OK remaining resource=%s generation=%s ceiling=%lld committed=%lld holds=%lld "
                  "remaining=%lld emergency=%d\n",
                  entry.resource.str().c_str(), brf::to_string(entry.generation).c_str(),
                  static_cast<long long>(entry.committable_ceiling.bps),
                  static_cast<long long>(entry.committed_peak.bps),
                  static_cast<long long>(entry.holds_peak.bps),
                  static_cast<long long>(entry.remaining.bps), entry.overcommit_emergency ? 1 : 0);
    }
    return 0;
  }

  if (options.command == "reconcile") {
    brf::protocol::AttemptRequest attempt_request;
    attempt_request.context = make_context(options, epoch, {}, {});
    if (has_argument(options, "--attempt")) {
      attempt_request.attempt = brf::Identity128::from_hex(argument(options, "--attempt")).value();
    } else {
      attempt_request.attempt = attempt_request.context.attempt;
    }
    brf::Writer writer(128);
    brf::protocol::encode(writer, attempt_request);
    Result<brf::protocol::Frame> frame =
        request(socket.value(), brf::protocol::MessageType::kReconcileAttempt, writer.take());
    if (!frame) return fail("reconcile failed: " + frame.error().message);
    if (frame.value().type == brf::protocol::MessageType::kError) {
      return report_error(frame.value());
    }
    brf::Reader reader(frame.value().payload);
    brf::protocol::ReconciliationResponse response;
    Status decoded = brf::protocol::decode(reader, response);
    if (!decoded) return fail("undecodable reconciliation response");
    std::printf("OK reconcile known=%d committed=%d outcome=%s id=%s generation=%s note=%s\n",
                response.reconciliation.known ? 1 : 0, response.reconciliation.committed ? 1 : 0,
                brf::to_string(response.reconciliation.outcome),
                response.reconciliation.reservation.to_hex().c_str(),
                brf::to_string(response.reconciliation.generation).c_str(),
                response.reconciliation.note.c_str());
    return 0;
  }

  if (options.command == "release") {
    brf::protocol::ReservationRefRequest reference;
    reference.context = make_context(options, epoch, {}, {});
    reference.id = brf::Identity128::from_hex(argument(options, "--id")).value();
    reference.generation = brf::ReservationGeneration(std::stoull(argument(options, "--generation", "1")));
    brf::Writer writer(256);
    brf::protocol::encode(writer, reference);
    Result<brf::protocol::Frame> frame =
        request(socket.value(), brf::protocol::MessageType::kRelease, writer.take());
    if (!frame) return fail("release failed: " + frame.error().message);
    if (frame.value().type == brf::protocol::MessageType::kError) {
      return report_error(frame.value());
    }
    brf::Reader reader(frame.value().payload);
    brf::protocol::LifecycleResponse response;
    Status decoded = brf::protocol::decode(reader, response);
    if (!decoded) return fail("undecodable release response");
    std::printf("OK release state=%s replayed=%d\n", brf::to_string(response.result.record.state),
                response.result.replayed ? 1 : 0);
    return 0;
  }

  if (options.command == "hold") {
    brf::protocol::HoldAcquireRequest hold;
    hold.context = make_context(options, epoch, {}, {});
    const std::string resource = argument(options, "--resource", "r1");
    Result<std::int64_t> amount = parse_amount(argument(options, "--amount", "1000000000"));
    if (!amount) return fail("bad amount: " + amount.error().message);
    Result<brf::Timestamp> start = parse_instant(argument(options, "--start", "+60"));
    if (!start) return fail("bad start: " + start.error().message);
    Result<brf::Timestamp> end = parse_instant(argument(options, "--end", "+3600"));
    if (!end) return fail("bad end: " + end.error().message);
    hold.terms.claimant = hold.context.claimant;
    hold.terms.claimant_generation = hold.context.claimant_generation;
    hold.terms.resources.push_back(brf::ResourceName::from_string(resource).value());
    hold.terms.interval = brf::Interval{start.value(), end.value()};
    hold.terms.amount = brf::Bandwidth{amount.value()};
    hold.terms.policy = brf::PolicyName::from_string("fabric-default").value();
    hold.expires_at = brf::Timestamp{brf::SystemClock{}.now().ns +
                                     std::stoll(argument(options, "--ttl-seconds", "5")) * brf::kNsPerSecond};
    brf::Writer writer(512);
    brf::protocol::encode(writer, hold);
    Result<brf::protocol::Frame> frame =
        request(socket.value(), brf::protocol::MessageType::kHoldAcquire, writer.take());
    if (!frame) return fail("hold failed: " + frame.error().message);
    if (frame.value().type == brf::protocol::MessageType::kError) {
      return report_error(frame.value());
    }
    brf::Reader reader(frame.value().payload);
    brf::protocol::HoldResponse response;
    Status decoded = brf::protocol::decode(reader, response);
    if (!decoded) return fail("undecodable hold response");
    std::printf("OK hold id=%s generation=%s\n", response.hold.id.to_hex().c_str(),
                brf::to_string(response.hold.generation).c_str());
    return 0;
  }

  if (options.command == "fence-session") {
    brf::protocol::FenceRequest fence;
    fence.context = make_context(options, epoch, {}, {});
    fence.context.actor = brf::ActorName::from_string("brf-operator").value();
    fence.boot = brf::Identity128::from_hex(argument(options, "--boot")).value();
    fence.session = brf::Identity128::from_hex(argument(options, "--session")).value();
    fence.claimant_wide = has_argument(options, "--claimant-wide");
    brf::Writer writer(256);
    brf::protocol::encode(writer, fence);
    Result<brf::protocol::Frame> frame =
        request(socket.value(), brf::protocol::MessageType::kFence, writer.take());
    if (!frame) return fail("fence failed: " + frame.error().message);
    if (frame.value().type == brf::protocol::MessageType::kError) {
      return report_error(frame.value());
    }
    std::printf("OK fence boot=%s session=%s\n", fence.boot.to_hex().c_str(),
                fence.session.to_hex().c_str());
    return 0;
  }

  if (options.command == "session-release") {
    brf::protocol::LifecycleReconcileRequest release_request;
    release_request.context = make_context(options, epoch, {}, {});
    brf::Writer writer(128);
    brf::protocol::encode(writer, release_request);
    Result<brf::protocol::Frame> frame =
        request(socket.value(), brf::protocol::MessageType::kSessionRelease, writer.take());
    if (!frame) return fail("session release failed: " + frame.error().message);
    if (frame.value().type == brf::protocol::MessageType::kError) {
      return report_error(frame.value());
    }
    std::printf("OK session-release\n");
    return 0;
  }

  if (options.command == "stats") {
    brf::Writer writer(8);
    writer.u8(0);
    Result<brf::protocol::Frame> frame =
        request(socket.value(), brf::protocol::MessageType::kStats, writer.take());
    if (!frame) return fail("stats failed: " + frame.error().message);
    if (frame.value().type == brf::protocol::MessageType::kError) {
      return report_error(frame.value());
    }
    brf::Reader reader(frame.value().payload);
    brf::protocol::StatsResponse response;
    Status decoded = brf::protocol::decode(reader, response);
    if (!decoded) return fail("undecodable stats response");
    std::printf("OK stats epoch=%s commits=%llu rejections=%llu replayed=%llu releases=%llu "
                "expiries=%llu records=%llu tracked=%llu holds=%llu\n",
                brf::to_string(response.stats.epoch).c_str(),
                static_cast<unsigned long long>(response.stats.commits),
                static_cast<unsigned long long>(response.stats.commit_rejections),
                static_cast<unsigned long long>(response.stats.replayed_attempts),
                static_cast<unsigned long long>(response.stats.releases),
                static_cast<unsigned long long>(response.stats.expiries),
                static_cast<unsigned long long>(response.stats.durable_records),
                static_cast<unsigned long long>(response.stats.tracked_reservations),
                static_cast<unsigned long long>(response.stats.live_holds));
    return 0;
  }

  if (options.command == "pause") {
    // Stay connected and idle so a supervisor can kill this incarnation while
    // its session authority is live.
    std::printf("OK pause\n");
    std::fflush(stdout);
    std::this_thread::sleep_for(std::chrono::hours(1));
    return 0;
  }

  return fail("unknown command: " + options.command);
}
