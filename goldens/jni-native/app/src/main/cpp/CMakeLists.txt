cmake_minimum_required(VERSION 3.22.1)
project(aar_golden_jni LANGUAGES CXX)

add_library(
    aar_golden_jni
    SHARED
    payload_stats.cpp
    jni_bridge.cpp
)

target_include_directories(aar_golden_jni PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(aar_golden_jni PRIVATE cxx_std_17)
target_compile_options(aar_golden_jni PRIVATE -Wall -Wextra -Wpedantic)
