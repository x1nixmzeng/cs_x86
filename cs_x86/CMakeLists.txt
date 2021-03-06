cmake_minimum_required (VERSION 3.8)
project(cs_x86 LANGUAGES CSharp)

# Suppress extra stuff from generated solution
set(CMAKE_SUPPRESS_REGENERATION true)

# Output all binary files into one folder
if(NOT DEFINED CMAKE_RUNTIME_OUTPUT_DIRECTORY)
 set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${cs_x86_BINARY_DIR}/bin")
endif()

include(CSharpUtilities)

file (GLOB SOURCES
 "Properties/AssemblyInfo.cs"
 "Capstone.cs"
 "CapstoneAPI.cs"
 "CapstoneStructs.cs"
 "CapstoneTypes.cs"
 "CapstoneWrapper.cs"
)

csharp_set_windows_forms_properties("Properties/AssemblyInfo.cs")

source_group(TREE ${CMAKE_CURRENT_LIST_DIR} FILES ${SOURCES})

add_library(cs_x86 SHARED ${SOURCES})

set_target_properties(cs_x86 PROPERTIES 
 VS_DOTNET_REFERENCES
 "Microsoft.CSharp;System;System.Core;System.Xml;System.Xml.Linq;System.Data"
)

set_property(TARGET cs_x86 PROPERTY DOTNET_TARGET_FRAMEWORK_VERSION "v4.5")

target_link_libraries(cs_x86 PUBLIC capstone-shared)
