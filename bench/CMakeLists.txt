# Synthetic population benchmark. It measures completed runtime work only.
add_executable(brf-bench brf_bench.cpp)
target_link_libraries(brf-bench PRIVATE brf Threads::Threads)
brf_apply_warnings(brf-bench)
if(WIN32)
  target_link_libraries(brf-bench PRIVATE ws2_32)
endif()
