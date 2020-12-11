cmake_minimum_required (VERSION 3.8)
project(Tests_cs_x86 LANGUAGES CSharp)

# Suppress extra stuff from generated solution
set(CMAKE_SUPPRESS_REGENERATION true)

# Output all binary files into one folder
if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
 set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${Tests_cs_x86_BINARY_DIR}/bin")
endif()

include(CSharpUtilities)

file (GLOB_RECURSE SOURCES
 "*.cs"
 "App.config"
)

csharp_set_windows_forms_properties("Properties/AssemblyInfo.cs")

source_group(TREE ${CMAKE_CURRENT_LIST_DIR} FILES ${SOURCES})

add_executable(Tests_cs_x86 ${SOURCES})
set_target_properties(Tests_cs_x86 PROPERTIES 
 VS_DOTNET_REFERENCES
 "Microsoft.CSharp;System;System.Core;System.Xml;System.Xml.Linq;System.Data;System.Data.DataSetExtensions;System.Net.Http"
)

set_property(TARGET Tests_cs_x86 PROPERTY DOTNET_TARGET_FRAMEWORK_VERSION "v4.5")

target_link_libraries(Tests_cs_x86 PUBLIC cs_x86)

# mark as unit test - see https://cmake.org/cmake/help/latest/prop_tgt/VS_GLOBAL_PROJECT_TYPES.html
set_target_properties(Tests_cs_x86 PROPERTIES VS_GLOBAL_PROJECT_TYPES "{3AC096D0-A1C2-E12C-1390-A8335801FDAB};{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}")
