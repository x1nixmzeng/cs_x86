cmake_minimum_required (VERSION 3.8)

# Suppress extra stuff from generated solution
set(CMAKE_SUPPRESS_REGENERATION true)

# set capstone options
set(CAPSTONE_BUILD_STATIC OFF CACHE BOOL "...")
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "...")
add_subdirectory("${PROJECT_SOURCE_DIR}/third_party/capstone")

add_subdirectory("${PROJECT_SOURCE_DIR}/cs_x86")

add_subdirectory("${PROJECT_SOURCE_DIR}/Tests.cs_x86")
