cmake_minimum_required(VERSION 3.16)
project(aar_golden_native_host LANGUAGES CXX)

add_executable(
    golden_native_test
    native_test.cpp
    ../app/src/main/cpp/payload_stats.cpp
)

target_include_directories(
    golden_native_test
    PRIVATE ../app/src/main/cpp
)

target_compile_features(golden_native_test PRIVATE cxx_std_17)
target_compile_options(golden_native_test PRIVATE -Wall -Wextra -Wpedantic)
