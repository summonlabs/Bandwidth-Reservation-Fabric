// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "support/process.hpp"

#include <cstring>

#ifdef _WIN32
#include <cstdio>
#else
#include <csignal>
#include <cstdio>
#include <cstdlib>
#endif

namespace brf::test {
namespace {

[[nodiscard]] std::string quote_argument(const std::string& value) {
  if (value.find_first_of(" \t\"") == std::string::npos) {
    return value;
  }
  std::string quoted = "\"";
  for (char ch : value) {
    if (ch == '"') quoted.push_back('\\');
    quoted.push_back(ch);
  }
  quoted.push_back('"');
  return quoted;
}

}  // namespace

#ifdef _WIN32

Result<ChildProcess> ChildProcess::spawn(const std::string& executable,
                                         const std::vector<std::string>& arguments) {
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.bInheritHandle = TRUE;

  HANDLE read_handle = nullptr;
  HANDLE write_handle = nullptr;
  if (::CreatePipe(&read_handle, &write_handle, &attributes, 0) == 0) {
    return make_error(ErrorCode::kIo, "CreatePipe failed");
  }
  ::SetHandleInformation(read_handle, HANDLE_FLAG_INHERIT, 0);

  std::string command_line = quote_argument(executable);
  for (const std::string& argument : arguments) {
    command_line.push_back(' ');
    command_line += quote_argument(argument);
  }

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = write_handle;
  startup.hStdError = write_handle;
  startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
  PROCESS_INFORMATION information{};

  std::vector<char> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back('\0');
  const BOOL created = ::CreateProcessA(executable.c_str(), mutable_command.data(), nullptr, nullptr,
                                        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                                        &information);
  ::CloseHandle(write_handle);
  if (created == 0) {
    ::CloseHandle(read_handle);
    return make_error(ErrorCode::kIo, "CreateProcess failed with error " +
                                          std::to_string(::GetLastError()));
  }
  ::CloseHandle(information.hThread);
  ChildProcess child;
  child.process_ = information.hProcess;
  child.output_ = read_handle;
  child.pid_ = static_cast<std::uint64_t>(information.dwProcessId);
  return child;
}

Result<std::string> ChildProcess::read_line() {
  if (output_ == nullptr) {
    return make_error(ErrorCode::kCancelled, "child output is closed");
  }
  HANDLE handle = static_cast<HANDLE>(output_);
  for (;;) {
    const std::size_t newline = buffer_.find('\n');
    if (newline != std::string::npos) {
      std::string line = buffer_.substr(0, newline);
      buffer_.erase(0, newline + 1);
      while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) {
        line.pop_back();
      }
      return line;
    }
    char chunk = 0;
    DWORD read = 0;
    if (::ReadFile(handle, &chunk, 1, &read, nullptr) == 0 || read == 0) {
      close_output();
      return make_error(ErrorCode::kCancelled, "child closed its output");
    }
    buffer_.push_back(chunk);
  }
}

void ChildProcess::kill() {
  if (process_ != nullptr) {
    ::TerminateProcess(static_cast<HANDLE>(process_), 9);
  }
}

int ChildProcess::wait() {
  if (process_ == nullptr) return -1;
  ::WaitForSingleObject(static_cast<HANDLE>(process_), INFINITE);
  DWORD code = 0;
  ::GetExitCodeProcess(static_cast<HANDLE>(process_), &code);
  ::CloseHandle(static_cast<HANDLE>(process_));
  process_ = nullptr;
  return static_cast<int>(code);
}

bool ChildProcess::alive() {
  if (process_ == nullptr) return false;
  DWORD code = 0;
  if (::GetExitCodeProcess(static_cast<HANDLE>(process_), &code) == 0) return false;
  return code == STILL_ACTIVE;
}

void ChildProcess::close_output() {
  if (output_ != nullptr) {
    ::CloseHandle(static_cast<HANDLE>(output_));
    output_ = nullptr;
  }
}

void ChildProcess::adopt(ChildProcess&& other) noexcept {
  process_ = other.process_;
  output_ = other.output_;
  pid_ = other.pid_;
  buffer_ = std::move(other.buffer_);
  other.process_ = nullptr;
  other.output_ = nullptr;
  other.pid_ = 0;
}

void ChildProcess::shutdown() noexcept {
  close_output();
  if (process_ != nullptr) {
    ::TerminateProcess(static_cast<HANDLE>(process_), 9);
    ::WaitForSingleObject(static_cast<HANDLE>(process_), INFINITE);
    ::CloseHandle(static_cast<HANDLE>(process_));
    process_ = nullptr;
  }
}

#else  // POSIX

Result<ChildProcess> ChildProcess::spawn(const std::string& executable,
                                         const std::vector<std::string>& arguments) {
  int descriptors[2];
  if (::pipe(descriptors) != 0) {
    return make_error(ErrorCode::kIo, "pipe failed");
  }
  const pid_t pid = ::fork();
  if (pid < 0) {
    ::close(descriptors[0]);
    ::close(descriptors[1]);
    return make_error(ErrorCode::kIo, "fork failed");
  }
  if (pid == 0) {
    ::close(descriptors[0]);
    ::dup2(descriptors[1], STDOUT_FILENO);
    ::dup2(descriptors[1], STDERR_FILENO);
    ::close(descriptors[1]);
    std::vector<char*> argv;
    argv.push_back(const_cast<char*>(executable.c_str()));
    for (const std::string& argument : arguments) {
      argv.push_back(const_cast<char*>(argument.c_str()));
    }
    argv.push_back(nullptr);
    ::execv(executable.c_str(), argv.data());
    ::_exit(127);
  }
  ::close(descriptors[1]);
  ChildProcess child;
  child.output_ = descriptors[0];
  child.pid_ = static_cast<std::uint64_t>(pid);
  return child;
}

Result<std::string> ChildProcess::read_line() {
  if (output_ < 0) {
    return make_error(ErrorCode::kCancelled, "child output is closed");
  }
  for (;;) {
    const std::size_t newline = buffer_.find('\n');
    if (newline != std::string::npos) {
      std::string line = buffer_.substr(0, newline);
      buffer_.erase(0, newline + 1);
      return line;
    }
    char chunk = 0;
    const ssize_t read = ::read(output_, &chunk, 1);
    if (read <= 0) {
      close_output();
      return make_error(ErrorCode::kCancelled, "child closed its output");
    }
    buffer_.push_back(chunk);
  }
}

void ChildProcess::kill() {
  if (pid_ > 0) {
    ::kill(static_cast<pid_t>(pid_), SIGKILL);
  }
}

int ChildProcess::wait() {
  if (pid_ <= 0) return -1;
  int status = 0;
  ::waitpid(static_cast<pid_t>(pid_), &status, 0);
  reaped_ = true;
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  return -1;
}

bool ChildProcess::alive() {
  if (pid_ <= 0 || reaped_) return false;
  int status = 0;
  const pid_t result = ::waitpid(static_cast<pid_t>(pid_), &status, WNOHANG);
  if (result == 0) return true;
  reaped_ = true;
  return false;
}

void ChildProcess::close_output() {
  if (output_ >= 0) {
    ::close(output_);
    output_ = -1;
  }
}

void ChildProcess::adopt(ChildProcess&& other) noexcept {
  output_ = other.output_;
  pid_ = other.pid_;
  reaped_ = other.reaped_;
  buffer_ = std::move(other.buffer_);
  other.output_ = -1;
  other.pid_ = -1;
}

void ChildProcess::shutdown() noexcept {
  close_output();
  if (pid_ > 0 && !reaped_) {
    ::kill(static_cast<pid_t>(pid_), SIGKILL);
    int status = 0;
    ::waitpid(static_cast<pid_t>(pid_), &status, 0);
    reaped_ = true;
  }
}

#endif

}  // namespace brf::test
