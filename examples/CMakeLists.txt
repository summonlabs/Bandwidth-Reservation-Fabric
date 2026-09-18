# In-tree example consumer. The installed-package consumer lives in
# examples/consumer-installed and is built by the release validation script.
add_executable(brf-example-consumer consumer/main.cpp)
target_link_libraries(brf-example-consumer PRIVATE brf::brf Threads::Threads)
brf_apply_warnings(brf-example-consumer)
if(WIN32)
  target_link_libraries(brf-example-consumer PRIVATE ws2_32)
endif()
