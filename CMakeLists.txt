cmake_minimum_required (VERSION 3.8)
project(cs_x86)

# Suppress extra stuff from generated solution
set(CMAKE_SUPPRESS_REGENERATION true)

# set capstone options
set(CAPSTONE_BUILD_STATIC OFF CACHE BOOL "...")
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "...")
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/third_party/capstone")

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/cs_x86")

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Tests.cs_x86")
