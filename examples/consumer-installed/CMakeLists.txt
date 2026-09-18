cmake_minimum_required(VERSION 3.20)
project(brf_downstream_consumer LANGUAGES CXX)

# Independent downstream consumer: configured against an installed brf package.
find_package(brf 1.0 REQUIRED)

add_executable(downstream-consumer main.cpp)
target_compile_features(downstream-consumer PRIVATE cxx_std_20)
target_link_libraries(downstream-consumer PRIVATE brf::brf)
find_package(Threads REQUIRED)
target_link_libraries(downstream-consumer PRIVATE Threads::Threads)
if(WIN32)
  target_link_libraries(downstream-consumer PRIVATE ws2_32)
endif()
