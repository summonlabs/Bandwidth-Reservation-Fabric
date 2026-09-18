// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Minimal deterministic test harness. No timeouts, no retries: a test that
// hangs is a defect and is left to hang so the deadlock stays visible.
#ifndef BRF_TEST_HARNESS_HPP
#define BRF_TEST_HARNESS_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

namespace brf::test {

using TestFn = void (*)();

struct TestCase {
  std::string suite;
  std::string name;
  TestFn fn = nullptr;
};

std::vector<TestCase>& registry();

struct Registrar {
  Registrar(const char* suite, const char* name, TestFn fn);
};

void report_failure(const char* file, int line, const std::string& message);
void report_note(const std::string& message);

/// Runs every registered test (optionally filtered) and returns the exit code.
int run_all(int argc, char** argv);

template <class T>
[[nodiscard]] std::string to_text(const T& value) {
  if constexpr (std::is_same_v<T, std::string>) {
    return value;
  } else if constexpr (std::is_same_v<T, std::string_view>) {
    return std::string(value);
  } else if constexpr (std::is_same_v<T, const char*> || std::is_same_v<T, char*>) {
    return value == nullptr ? std::string("<null>") : std::string(value);
  } else if constexpr (std::is_same_v<T, bool>) {
    return value ? std::string("true") : std::string("false");
  } else if constexpr (std::is_enum_v<T>) {
    return std::to_string(static_cast<long long>(value));
  } else if constexpr (std::is_arithmetic_v<T>) {
    return std::to_string(value);
  } else {
    return std::string("<value>");
  }
}

}  // namespace brf::test

#define BRF_TEST(suite_name, test_name)                                          \
  static void suite_name##_##test_name();                                        \
  static const ::brf::test::Registrar brf_registrar_##suite_name##_##test_name(  \
      #suite_name, #test_name, &suite_name##_##test_name);                       \
  static void suite_name##_##test_name()

#define BRF_REQUIRE(condition)                                                              \
  do {                                                                                      \
    if (!(condition)) {                                                                     \
      ::brf::test::report_failure(__FILE__, __LINE__, "requirement failed: " #condition);    \
      return;                                                                               \
    }                                                                                       \
  } while (false)

#define BRF_CHECK(condition)                                                                \
  do {                                                                                      \
    if (!(condition)) {                                                                     \
      ::brf::test::report_failure(__FILE__, __LINE__, "check failed: " #condition);          \
    }                                                                                       \
  } while (false)

#define BRF_CHECK_EQ(actual, expected)                                                       \
  do {                                                                                       \
    const auto& brf_actual_value = (actual);                                                 \
    const auto& brf_expected_value = (expected);                                             \
    if (!(brf_actual_value == brf_expected_value)) {                                         \
      ::brf::test::report_failure(                                                           \
          __FILE__, __LINE__,                                                                \
          std::string("expected " #actual " == " #expected " but got ") +                    \
              ::brf::test::to_text(brf_actual_value) + " vs " +                              \
              ::brf::test::to_text(brf_expected_value));                                     \
    }                                                                                        \
  } while (false)

#define BRF_CHECK_OK(expression)                                                              \
  do {                                                                                        \
    const auto& brf_status_value = (expression);                                              \
    if (!brf_status_value) {                                                                  \
      ::brf::test::report_failure(                                                            \
          __FILE__, __LINE__,                                                                 \
          std::string("expected success from " #expression " but got error: ") +              \
              brf_status_value.error().message);                                              \
    }                                                                                         \
  } while (false)

#define BRF_REQUIRE_OK(expression)                                                            \
  do {                                                                                        \
    const auto& brf_status_value = (expression);                                              \
    if (!brf_status_value) {                                                                  \
      ::brf::test::report_failure(                                                            \
          __FILE__, __LINE__,                                                                 \
          std::string("expected success from " #expression " but got error: ") +              \
              brf_status_value.error().message);                                              \
      return;                                                                                 \
    }                                                                                         \
  } while (false)

#endif  // BRF_TEST_HARNESS_HPP
