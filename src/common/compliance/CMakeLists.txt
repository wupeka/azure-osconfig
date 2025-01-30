# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

project(compliance_mc_iface)

FILE(GLOB PROCEDURES procedures/*.cpp)
add_library(compliance_mc_iface OBJECT
    Compliance.cpp
    ProcedureMap.cpp
    ${PROCEDURES}
)

add_custom_command(
        OUTPUT ProcedureMap.cpp
        COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/gen_procedures_map.py ${CMAKE_CURRENT_SOURCE_DIR}/procedures/
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen_procedures_map.py ${PROCEDURES}
        VERBATIM)

target_compile_options(compliance_mc_iface PRIVATE -Wno-psabi)

target_link_libraries(compliance_mc_iface PRIVATE
    logging
    commonutils
    parsonlib
    base64
    )

set_target_properties(compliance_mc_iface PROPERTIES LINKER_LANGUAGE CXX)
target_include_directories(compliance_mc_iface INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PLATFORM_INC_DIR})
