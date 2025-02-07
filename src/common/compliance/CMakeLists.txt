# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

project(compliance)

add_library(compliance OBJECT
    Compliance.cpp
    audits.cpp)

target_compile_options(compliance PRIVATE -Wno-psabi)

target_link_libraries(compliance PRIVATE
    logging
    commonutils
    parsonlib
    base64)

#add_library(compliance INTERFACE)
set_target_properties(compliance PROPERTIES LINKER_LANGUAGE CXX)
#set_target_properties(compliance_lib PROPERTIES LINKER_LANGUAGE CXX)

#set_property(TARGET compliance PROPERTY INTERFACE_LINK_LIBRARIES
#      -Wl,--whole-archive,$<TARGET_FILE:compliance_lib>,--no-whole-archive)
      target_include_directories(compliance INTERFACE
      ${CMAKE_CURRENT_SOURCE_DIR}
      ${PLATFORM_INC_DIR})
