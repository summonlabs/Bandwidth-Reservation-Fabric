cmake_minimum_required(VERSION 3.20)

project(BandwidthReservationFabric
  VERSION 1.0.0
  DESCRIPTION "Generation-bound bandwidth reservation runtime"
  HOMEPAGE_URL "https://github.com/summonlabs/Bandwidth-Reservation-Fabric"
  LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(BRF_BUILD_TOOLS "Build brf-coordinator, brf-probe, brf-inspect" ON)
option(BRF_BUILD_TESTS "Build the test, property, race, adversarial and multiprocess suites" ON)
option(BRF_BUILD_BENCHMARKS "Build the synthetic population benchmark" ON)
option(BRF_BUILD_EXAMPLES "Build example consumers" ON)
option(BRF_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)
option(BRF_ENABLE_ASAN "Enable AddressSanitizer/UBSan on toolchains that support it" OFF)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(BRF_IS_TOP_LEVEL ON)
else()
  set(BRF_IS_TOP_LEVEL OFF)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Warning profile: strict, first-party only
# ---------------------------------------------------------------------------
# Applied directly to first-party targets so that nothing leaks into the
# exported package interface.
function(brf_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /Zc:preprocessor)
    # The runtime uses the C stdio API deliberately for explicit durability
    # control (fflush plus FlushFileBuffers/fsync semantics).
    target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    if(BRF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(BRF_ENABLE_ASAN)
      target_compile_options(${target} PRIVATE /fsanitize=address)
    endif()
  else()
    target_compile_options(${target} PRIVATE
      -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
      -Wnon-virtual-dtor -Woverloaded-virtual -Wnull-dereference)
    if(BRF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(BRF_ENABLE_ASAN)
      target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(BRF_SOURCES
  src/authority.cpp
  src/coordinator_admission.cpp
  src/bandwidth.cpp
  src/capacity.cpp
  src/clock.cpp
  src/codec.cpp
  src/coordinator_core.cpp
  src/coordinator_lifecycle.cpp
  src/coordinator_ops.cpp
  src/coordinator_overcommit.cpp
  src/coordinator_query.cpp
  src/coordinator_records.cpp
  src/error.cpp
  src/hash.cpp
  src/identity.cpp
  src/index.cpp
  src/outcome.cpp
  src/policy.cpp
  src/protocol.cpp
  src/reservation.cpp
  src/store.cpp
  src/time.cpp
  src/transport.cpp
  src/version.cpp
  src/wire.cpp)

add_library(brf STATIC ${BRF_SOURCES})
add_library(brf::brf ALIAS brf)
target_compile_features(brf PUBLIC cxx_std_20)
target_include_directories(brf
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
brf_apply_warnings(brf)
target_link_libraries(brf PRIVATE Threads::Threads)
if(WIN32)
  target_link_libraries(brf PRIVATE ws2_32)
endif()
set_target_properties(brf PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON
  CXX_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------
install(TARGETS brf EXPORT brfTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT brfTargets
  FILE brfTargets.cmake
  NAMESPACE brf::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/brf)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/brfConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/brfConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/brf)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/brfConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/brfConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/brfConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/brf)

# ---------------------------------------------------------------------------
# Tools, tests, benchmarks, examples
# ---------------------------------------------------------------------------
if(BRF_BUILD_TOOLS)
  add_subdirectory(tools)
endif()
if(BRF_BUILD_BENCHMARKS)
  add_subdirectory(bench)
endif()
if(BRF_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(BRF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
