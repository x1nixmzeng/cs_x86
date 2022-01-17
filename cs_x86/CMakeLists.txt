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

if (NOT DOTNET_TARGET_FRAMEWORK_VERSION)
 set(DOTNET_TARGET_FRAMEWORK_VERSION "v4.5")
endif()

set_target_properties(cs_x86 PROPERTIES 
 VS_DOTNET_REFERENCES
 "Microsoft.CSharp;System;System.Core;System.Xml;System.Xml.Linq;System.Data"

 DOTNET_TARGET_FRAMEWORK_VERSION ${DOTNET_TARGET_FRAMEWORK_VERSION}
)


target_link_libraries(cs_x86 PUBLIC capstone-shared)

# copy cs_x86 binary file to install path
install(TARGETS cs_x86 RUNTIME DESTINATION bin)
# copy capstone module binary without other misc files
install(PROGRAMS $<TARGET_FILE_DIR:cs_x86>/${CMAKE_SHARED_LIBRARY_PREFIX}capstone${CMAKE_SHARED_LIBRARY_SUFFIX} DESTINATION bin)
