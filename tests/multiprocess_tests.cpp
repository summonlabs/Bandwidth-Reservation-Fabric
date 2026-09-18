// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Multiprocess proofs. Every test here uses real OS processes and real TCP
// frames: a coordinator process, probe processes, and hard kills.
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "brf/brf.hpp"
#include "support/fixtures.hpp"
#include "support/process.hpp"
#include "support/test_harness.hpp"

using namespace brf;  // NOLINT(google-build-using-namespace)
using namespace brf::test;

namespace {

constexpr std::int64_t kGbit = 1000000000LL;

[[nodiscard]] std::string coordinator_path() { return std::string(BRF_COORDINATOR_EXECUTABLE); }
[[nodiscard]] std::string probe_path() { return std::string(BRF_PROBE_EXECUTABLE); }

struct ProbeOutput {
  std::vector<std::string> lines;
  std::string boot;
  std::string session;
  std::string claimant;
  std::string epoch;
  int exit_code = 0;
  bool started = false;
};

[[nodiscard]] std::string field_of(const std::vector<std::string>& lines, const std::string& key) {
  for (const std::string& line : lines) {
    if (line.rfind(key + " ", 0) == 0) {
      return line.substr(key.size() + 1);
    }
  }
  return {};
}

[[nodiscard]] std::string value_of(const std::vector<std::string>& lines, const std::string& key) {
  for (const std::string& line : lines) {
    std::size_t position = line.find(key + "=");
    if (position == std::string::npos) continue;
    position += key.size() + 1;
    std::size_t end = line.find(' ', position);
    return line.substr(position, end == std::string::npos ? std::string::npos : end - position);
  }
  return {};
}

/// Runs a probe to completion and returns everything it printed.
[[nodiscard]] ProbeOutput run_probe(std::uint16_t port, std::uint64_t seed,
                                    const std::vector<std::string>& arguments) {
  ProbeOutput output;
  std::vector<std::string> full = {"--port", std::to_string(port), "--seed", std::to_string(seed)};
  full.insert(full.end(), arguments.begin(), arguments.end());
  Result<ChildProcess> child = ChildProcess::spawn(probe_path(), full);
  if (!child) {
    report_note("spawn failed: " + child.error().message);
    return output;
  }
  output.started = true;
  for (;;) {
    Result<std::string> line = child.value().read_line();
    if (!line) break;
    output.lines.push_back(line.value());
  }
  output.exit_code = child.value().wait();
  output.boot = field_of(output.lines, "BOOT");
  output.session = field_of(output.lines, "SESSION");
  output.claimant = field_of(output.lines, "CLAIMANT");
  output.epoch = field_of(output.lines, "EPOCH");
  return output;
}

/// A live coordinator process with its ephemeral port and epoch.
struct CoordinatorProcess {
  ChildProcess process;
  std::uint16_t port = 0;
  std::string epoch;
  std::string boot;
  bool started = false;
};

[[nodiscard]] CoordinatorProcess start_coordinator(const std::string& store) {
  CoordinatorProcess coordinator;
  Result<ChildProcess> child =
      ChildProcess::spawn(coordinator_path(), {"--store", store, "--port", "0"});
  if (!child) {
    report_note("coordinator spawn failed: " + child.error().message);
    return coordinator;
  }
  coordinator.process = std::move(child.value());
  coordinator.started = true;
  for (;;) {
    Result<std::string> line = coordinator.process.read_line();
    if (!line) break;
    if (line.value().rfind("LISTENING ", 0) == 0) {
      coordinator.port = static_cast<std::uint16_t>(std::stoi(line.value().substr(10)));
    } else if (line.value().rfind("EPOCH ", 0) == 0) {
      coordinator.epoch = line.value().substr(6);
    } else if (line.value().rfind("BOOT ", 0) == 0) {
      coordinator.boot = line.value().substr(5);
    }
    if (!coordinator.epoch.empty() && !coordinator.boot.empty() && coordinator.port != 0) break;
  }
  return coordinator;
}

/// Seeds one resource and a policy through the wire protocol.
[[nodiscard]] bool seed_via_probe(std::uint16_t port, std::uint64_t seed, const char* resource,
                                  std::int64_t capacity_bps, std::uint64_t generation = 1,
                                  std::int64_t hold_ttl_seconds = 5) {
  const ProbeOutput output = run_probe(
      port, seed,
      {"seed", "--resource", resource, "--capacity", std::to_string(capacity_bps),
       "--resource-generation", std::to_string(generation), "--max-hold-ttl-seconds",
       std::to_string(hold_ttl_seconds)});
  return output.exit_code == 0 && !output.lines.empty() &&
         output.lines.back().rfind("OK ", 0) == 0;
}

}  // namespace

BRF_TEST(multiprocess, coordinator_restart_preserves_commitments_and_advances_epoch) {
  TempDir directory;
  CoordinatorProcess coordinator = start_coordinator(directory.str());
  BRF_REQUIRE(coordinator.started);
  BRF_REQUIRE(coordinator.port != 0);
  const std::string first_epoch = coordinator.epoch;
  BRF_CHECK(!first_epoch.empty());
  BRF_REQUIRE(seed_via_probe(coordinator.port, 1, "r1", 100 * kGbit));

  const ProbeOutput commit =
      run_probe(coordinator.port, 1,
                {"commit", "--resource", "r1", "--amount", std::to_string(40 * kGbit), "--start", "+60",
                 "--end", "+7200", "--attempt",
                 Identity128::from_hex("11111111111111111111111111111111").value().to_hex()});
  BRF_REQUIRE(!commit.lines.empty());
  const std::string reservation_id = value_of(commit.lines, "id");
  BRF_CHECK_EQ(commit.exit_code, 0);
  BRF_CHECK(!reservation_id.empty());

  // Hard-kill the coordinator: no graceful shutdown, no flush, no notification.
  coordinator.process.kill();
  const int killed = coordinator.process.wait();
  (void)killed;

  CoordinatorProcess restarted = start_coordinator(directory.str());
  BRF_REQUIRE(restarted.started);
  BRF_CHECK(restarted.port != 0);
  BRF_CHECK(!(restarted.epoch == first_epoch));
  BRF_CHECK(std::stoull(restarted.epoch) > std::stoull(first_epoch));
  BRF_CHECK(!(restarted.boot == coordinator.boot));

  // The durable commitment survived restart at the same identity.
  const ProbeOutput remaining =
      run_probe(restarted.port, 1, {"remaining", "--resource", "r1", "--start", "+60", "--end", "+7200"});
  BRF_REQUIRE(!remaining.lines.empty());
  BRF_CHECK_EQ(remaining.exit_code, 0);
  BRF_CHECK_EQ(std::stoll(value_of(remaining.lines, "remaining")), 60 * kGbit);
  BRF_CHECK_EQ(std::stoll(value_of(remaining.lines, "committed")), 40 * kGbit);

  // A request that asserts the previous epoch is refused outright.
  const ProbeOutput stale =
      run_probe(restarted.port, 1,
                {"commit", "--resource", "r1", "--amount", std::to_string(kGbit), "--start", "+60",
                 "--end", "+7200", "--epoch", first_epoch});
  BRF_CHECK_EQ(stale.exit_code, 1);
  const std::string stale_line = stale.lines.empty() ? std::string() : stale.lines.back();
  BRF_CHECK(stale_line.find("STALE_EPOCH") != std::string::npos);

  // The durable attempt record survived, so an ambiguous reply is resolvable.
  const ProbeOutput reconciled =
      run_probe(restarted.port, 1,
                {"reconcile", "--attempt",
                 Identity128::from_hex("11111111111111111111111111111111").value().to_hex()});
  BRF_CHECK_EQ(reconciled.exit_code, 0);
  BRF_CHECK_EQ(value_of(reconciled.lines, "known"), std::string("1"));
  BRF_CHECK_EQ(value_of(reconciled.lines, "committed"), std::string("1"));
  BRF_CHECK_EQ(value_of(reconciled.lines, "id"), reservation_id);

  restarted.process.kill();
  (void)restarted.process.wait();
}

BRF_TEST(multiprocess, client_killed_after_commit_is_reconciled_by_attempt_identity) {
  TempDir directory;
  CoordinatorProcess coordinator = start_coordinator(directory.str());
  BRF_REQUIRE(coordinator.started);
  BRF_REQUIRE(seed_via_probe(coordinator.port, 2, "r1", 100 * kGbit));

  const std::string attempt = Identity128::from_hex("22222222222222222222222222222222").value().to_hex();
  Result<ChildProcess> probe = ChildProcess::spawn(
      probe_path(), {"--port", std::to_string(coordinator.port), "--seed", "2", "commit-then-hang",
                     "--resource", "r1", "--amount", std::to_string(30 * kGbit), "--start", "+60",
                     "--end", "+7200", "--attempt", attempt});
  BRF_REQUIRE(probe.has_value());
  // The child reports the durable commit and then dies without telling its
  // caller anything further: exactly the ambiguous-reply situation.
  std::string committed_line;
  for (;;) {
    Result<std::string> line = probe.value().read_line();
    BRF_REQUIRE(line.has_value());
    if (line.value().rfind("DURABLE ", 0) == 0) {
      committed_line = line.value();
      break;
    }
  }
  BRF_CHECK(!committed_line.empty());
  probe.value().kill();
  const int exit_code = probe.value().wait();
  (void)exit_code;

  const ProbeOutput reconciled =
      run_probe(coordinator.port, 3, {"reconcile", "--attempt", attempt});
  BRF_CHECK_EQ(reconciled.exit_code, 0);
  BRF_CHECK_EQ(value_of(reconciled.lines, "known"), std::string("1"));
  BRF_CHECK_EQ(value_of(reconciled.lines, "committed"), std::string("1"));

  // The commitment exists exactly once: a retry of the same attempt replays.
  const ProbeOutput remaining =
      run_probe(coordinator.port, 3, {"remaining", "--resource", "r1", "--start", "+60", "--end", "+7200"});
  BRF_CHECK_EQ(std::stoll(value_of(remaining.lines, "committed")), 30 * kGbit);

  coordinator.process.kill();
  (void)coordinator.process.wait();
}

BRF_TEST(multiprocess, dead_publisher_holds_are_fenced_by_its_incarnation) {
  TempDir directory;
  CoordinatorProcess coordinator = start_coordinator(directory.str());
  BRF_REQUIRE(coordinator.started);
  BRF_REQUIRE(seed_via_probe(coordinator.port, 4, "r1", 100 * kGbit, 1, 900));

  // Probe 4 acquires a provisional hold and exits without releasing it.
  const ProbeOutput hold =
      run_probe(coordinator.port, 4,
                {"hold", "--resource", "r1", "--amount", std::to_string(40 * kGbit), "--start", "+60",
                 "--end", "+3600", "--ttl-seconds", "600"});
  BRF_REQUIRE(!hold.lines.empty());
  BRF_CHECK_EQ(hold.exit_code, 0);
  BRF_CHECK(!hold.boot.empty());
  BRF_CHECK(!hold.session.empty());

  const ProbeOutput during =
      run_probe(coordinator.port, 5, {"remaining", "--resource", "r1", "--start", "+60", "--end", "+3600"});
  BRF_CHECK_EQ(std::stoll(value_of(during.lines, "holds")), 40 * kGbit);
  BRF_CHECK_EQ(std::stoll(value_of(during.lines, "remaining")), 60 * kGbit);

  // The supervisor declares that incarnation dead; its transient authority is
  // fenced and the capacity returns immediately.
  const ProbeOutput fenced =
      run_probe(coordinator.port, 6, {"fence-session", "--boot", hold.boot, "--session", hold.session});
  BRF_CHECK_EQ(fenced.exit_code, 0);
  const ProbeOutput after =
      run_probe(coordinator.port, 5, {"remaining", "--resource", "r1", "--start", "+60", "--end", "+3600"});
  BRF_CHECK_EQ(std::stoll(value_of(after.lines, "holds")), 0);
  BRF_CHECK_EQ(std::stoll(value_of(after.lines, "remaining")), 100 * kGbit);

  // A later request replayed from the fenced boot is refused.
  const ProbeOutput replayed =
      run_probe(coordinator.port, 4,
                {"commit", "--resource", "r1", "--amount", std::to_string(kGbit), "--start", "+60",
                 "--end", "+3600"});
  BRF_CHECK_EQ(replayed.exit_code, 1);
  BRF_CHECK(replayed.lines.back().find("CLAIMANT_FENCED") != std::string::npos);

  coordinator.process.kill();
  (void)coordinator.process.wait();
}

BRF_TEST(multiprocess, durable_state_survives_a_kill_during_live_traffic) {
  TempDir directory;
  CoordinatorProcess coordinator = start_coordinator(directory.str());
  BRF_REQUIRE(coordinator.started);
  BRF_REQUIRE(seed_via_probe(coordinator.port, 7, "r1", 100 * kGbit, 1, 900));

  // Two committed reservations plus one provisional hold, then a hard kill with
  // live client authority outstanding.
  for (std::uint64_t index = 0; index < 2; ++index) {
    const ProbeOutput commit = run_probe(
        coordinator.port, 7 + index,
        {"commit", "--resource", "r1", "--amount", std::to_string(20 * kGbit), "--start", "+60",
         "--end", "+7200", "--attempt",
         Identity128::derive(Identity128::from_hex("33333333333333333333333333333333").value(), index)
             .to_hex()});
    BRF_REQUIRE(!commit.lines.empty());
    BRF_CHECK_EQ(commit.exit_code, 0);
  }
  const ProbeOutput hold =
      run_probe(coordinator.port, 9,
                {"hold", "--resource", "r1", "--amount", std::to_string(10 * kGbit), "--start", "+60",
                 "--end", "+7200", "--ttl-seconds", "600"});
  BRF_REQUIRE(!hold.lines.empty());
  BRF_CHECK_EQ(hold.exit_code, 0);

  coordinator.process.kill();
  (void)coordinator.process.wait();

  CoordinatorProcess restarted = start_coordinator(directory.str());
  BRF_REQUIRE(restarted.started);
  const ProbeOutput after =
      run_probe(restarted.port, 10, {"remaining", "--resource", "r1", "--start", "+60", "--end", "+7200"});
  BRF_REQUIRE(!after.lines.empty());
  // Both durable commitments survive; the transient hold does not.
  BRF_CHECK_EQ(std::stoll(value_of(after.lines, "committed")), 40 * kGbit);
  BRF_CHECK_EQ(std::stoll(value_of(after.lines, "holds")), 0);
  BRF_CHECK_EQ(std::stoll(value_of(after.lines, "remaining")), 60 * kGbit);

  restarted.process.kill();
  (void)restarted.process.wait();
}

BRF_TEST(multiprocess, malformed_frames_do_not_disturb_durable_state) {
  TempDir directory;
  CoordinatorProcess coordinator = start_coordinator(directory.str());
  BRF_REQUIRE(coordinator.started);
  BRF_REQUIRE(seed_via_probe(coordinator.port, 11, "r1", 100 * kGbit));
  const ProbeOutput commit =
      run_probe(coordinator.port, 11,
                {"commit", "--resource", "r1", "--amount", std::to_string(25 * kGbit), "--start", "+60",
                 "--end", "+7200", "--attempt",
                 Identity128::from_hex("44444444444444444444444444444444").value().to_hex()});
  BRF_REQUIRE(!commit.lines.empty());
  BRF_CHECK_EQ(commit.exit_code, 0);

  // Raw garbage on a real connection: wrong magic, truncated header, and a valid
  // header with a corrupted payload checksum.
  {
    Result<TcpSocket> socket = connect_loopback(coordinator.port);
    BRF_REQUIRE(socket.has_value());
    const std::string garbage = "not-a-frame-at-all";
    BRF_CHECK_OK(socket.value().write_bytes(garbage));
    socket.value().close();
  }
  {
    Result<TcpSocket> socket = connect_loopback(coordinator.port);
    BRF_REQUIRE(socket.has_value());
    const std::string truncated(7, '\x01');
    BRF_CHECK_OK(socket.value().write_bytes(truncated));
    socket.value().close();
  }
  {
    Result<TcpSocket> socket = connect_loopback(coordinator.port);
    BRF_REQUIRE(socket.has_value());
    brf::protocol::HelloRequest request;
    request.client = Identity128::from_hex("55555555555555555555555555555555").value();
    request.client_name = "malformed";
    brf::Writer writer(64);
    brf::protocol::encode(writer, request);
    std::string frame = brf::protocol::encode_frame(brf::protocol::MessageType::kHello, writer.buffer());
    frame[frame.size() - 1] = static_cast<char>(frame[frame.size() - 1] ^ 0x5A);
    BRF_CHECK_OK(socket.value().write_bytes(frame));
    socket.value().close();
  }

  // The coordinator is still serving and the commitment is intact.
  const ProbeOutput remaining =
      run_probe(coordinator.port, 12, {"remaining", "--resource", "r1", "--start", "+60", "--end", "+7200"});
  BRF_REQUIRE(!remaining.lines.empty());
  BRF_CHECK_EQ(remaining.exit_code, 0);
  BRF_CHECK_EQ(std::stoll(value_of(remaining.lines, "committed")), 25 * kGbit);

  coordinator.process.kill();
  (void)coordinator.process.wait();
}
