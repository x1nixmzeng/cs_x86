cmake_minimum_required (VERSION 3.8)
project(cs_x86)

# Suppress extra stuff from generated solution
set(CMAKE_SUPPRESS_REGENERATION true)

# Output all binary files into one folder
if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
 set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${cs_x86_BINARY_DIR}/bin")
endif()

# setup capstone options
set(CAPSTONE_BUILD_STATIC OFF CACHE BOOL "..." FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "..." FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "..." FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "..." FORCE)

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/third_party/capstone")

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/cs_x86")

add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/Tests.cs_x86")

# copy source files to install path
install(TARGETS capstone-shared RUNTIME DESTINATION .)
install(TARGETS cs_x86 RUNTIME DESTINATION .)
