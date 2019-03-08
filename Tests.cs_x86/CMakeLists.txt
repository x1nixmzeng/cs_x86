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
