// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "support/test_harness.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace brf::test {
namespace {

std::vector<std::string>& failures() {
  static std::vector<std::string> instance;
  return instance;
}

}  // namespace

std::vector<TestCase>& registry() {
  static std::vector<TestCase> instance;
  return instance;
}

Registrar::Registrar(const char* suite, const char* name, TestFn fn) {
  registry().push_back(TestCase{suite, name, fn});
}

void report_failure(const char* file, int line, const std::string& message) {
  std::string text = std::string(file) + ":" + std::to_string(line) + ": " + message;
  failures().push_back(text);
  std::fprintf(stderr, "  FAIL %s\n", text.c_str());
}

void report_note(const std::string& message) { std::fprintf(stdout, "  note %s\n", message.c_str()); }

int run_all(int argc, char** argv) {
  // Unbuffered output: if a test crashes, the progress log survives.
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  std::string filter;
  bool list_only = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
      filter = argv[++i];
    } else if (std::strcmp(argv[i], "--list") == 0) {
      list_only = true;
    }
  }
  std::vector<TestCase>& tests = registry();
  if (list_only) {
    for (const TestCase& test : tests) {
      std::printf("%s.%s\n", test.suite.c_str(), test.name.c_str());
    }
    return 0;
  }
  std::size_t executed = 0;
  std::size_t failed = 0;
  for (const TestCase& test : tests) {
    const std::string full = test.suite + "." + test.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) continue;
    const std::size_t before = failures().size();
    std::printf("[ RUN  ] %s\n", full.c_str());
    test.fn();
    ++executed;
    if (failures().size() != before) {
      ++failed;
      std::printf("[ FAIL ] %s\n", full.c_str());
    } else {
      std::printf("[  OK  ] %s\n", full.c_str());
    }
  }
  std::printf("\n%zu test(s) executed, %zu failed, %zu failed check(s)\n", executed, failed,
              failures().size());
  return failed == 0 ? 0 : 1;
}

}  // namespace brf::test

int main(int argc, char** argv) { return ::brf::test::run_all(argc, argv); }
