// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Real OS process control for the multiprocess proofs. Thread-only substitutes
// do not prove multiprocess behaviour, so these helpers spawn actual child
// processes, capture their output, and can hard-kill them.
#ifndef BRF_TEST_PROCESS_HPP
#define BRF_TEST_PROCESS_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "brf/error.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace brf::test {

/// A child process with piped stdout+stderr.
class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess() { shutdown(); }
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ChildProcess(ChildProcess&& other) noexcept { adopt(std::move(other)); }
  ChildProcess& operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
      shutdown();
      adopt(std::move(other));
    }
    return *this;
  }

  /// Spawns an executable with arguments. The child's stdout and stderr are
  /// merged into one pipe.
  [[nodiscard]] static Result<ChildProcess> spawn(const std::string& executable,
                                                  const std::vector<std::string>& arguments);

  /// Reads one line from the child, blocking until one is available. Returns an
  /// error when the child closed its output.
  [[nodiscard]] Result<std::string> read_line();

  /// Hard-kills the child (TerminateProcess / SIGKILL). This is what "the
  /// publisher died" means for the fabric.
  void kill();

  /// Waits for termination and returns the exit code. Blocking, never timed.
  int wait();

  [[nodiscard]] bool alive();

  void close_output();

  [[nodiscard]] std::uint64_t pid() const noexcept { return pid_; }

 private:
  void adopt(ChildProcess&& other) noexcept;
  void shutdown() noexcept;

#ifdef _WIN32
  void* process_ = nullptr;
  void* output_ = nullptr;
#else
  int output_ = -1;
  int pid_ = -1;
  bool reaped_ = false;
#endif
  std::uint64_t pid_ = 0;
  std::string buffer_;
};

}  // namespace brf::test

#endif  // BRF_TEST_PROCESS_HPP
