# Test suites. No timeouts are configured anywhere: a hanging test is a defect
# to diagnose, never something to terminate and call passing.
set(BRF_TEST_SUPPORT support/test_harness.cpp)

function(brf_add_test target)
  add_executable(${target} ${ARGN} ${BRF_TEST_SUPPORT})
  target_include_directories(${target} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/support)
  target_link_libraries(${target} PRIVATE brf Threads::Threads)
  brf_apply_warnings(${target})
  if(WIN32)
    target_link_libraries(${target} PRIVATE ws2_32)
  endif()
  add_test(NAME ${target} COMMAND ${target})
endfunction()

brf_add_test(brf_core_tests core_tests.cpp)
brf_add_test(brf_store_tests store_tests.cpp)
brf_add_test(brf_coordinator_tests coordinator_tests.cpp)
brf_add_test(brf_property_tests property_tests.cpp)
brf_add_test(brf_adversarial_tests adversarial_tests.cpp)
brf_add_test(brf_concurrency_tests concurrency_tests.cpp)
brf_add_test(brf_runtime_checks_tests runtime_checks_tests.cpp)

# The multiprocess suite needs the built tools and real OS processes.
add_executable(brf_multiprocess_tests multiprocess_tests.cpp support/process.cpp ${BRF_TEST_SUPPORT})
target_include_directories(brf_multiprocess_tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/support)
target_link_libraries(brf_multiprocess_tests PRIVATE brf Threads::Threads)
target_compile_definitions(brf_multiprocess_tests PRIVATE
  BRF_COORDINATOR_EXECUTABLE="$<TARGET_FILE:brf-coordinator>"
  BRF_PROBE_EXECUTABLE="$<TARGET_FILE:brf-probe>")
brf_apply_warnings(brf_multiprocess_tests)
if(WIN32)
  target_link_libraries(brf_multiprocess_tests PRIVATE ws2_32)
endif()
add_dependencies(brf_multiprocess_tests brf-coordinator brf-probe)
add_test(NAME brf_multiprocess_tests COMMAND brf_multiprocess_tests)
