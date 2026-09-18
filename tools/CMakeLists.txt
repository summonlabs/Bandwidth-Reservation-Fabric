# Operator-facing tools. Each one exercises the real runtime: the coordinator
# serves the durable core over TCP, the probe drives it as a client, and the
# inspector reads durable state without a coordinator.
add_executable(brf-coordinator brf_coordinator.cpp)
target_link_libraries(brf-coordinator PRIVATE brf Threads::Threads)
brf_apply_warnings(brf-coordinator)

add_executable(brf-probe brf_probe.cpp)
target_link_libraries(brf-probe PRIVATE brf Threads::Threads)
brf_apply_warnings(brf-probe)

add_executable(brf-inspect brf_inspect.cpp)
target_link_libraries(brf-inspect PRIVATE brf Threads::Threads)
brf_apply_warnings(brf-inspect)

if(WIN32)
  target_link_libraries(brf-coordinator PRIVATE ws2_32)
  target_link_libraries(brf-probe PRIVATE ws2_32)
  target_link_libraries(brf-inspect PRIVATE ws2_32)
endif()

install(TARGETS brf-coordinator brf-probe brf-inspect RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
