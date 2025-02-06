# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

project(compliancelib)

FILE(GLOB PROCEDURES procedures/*.cpp)

add_library(compliancelib STATIC
    ComplianceInterface.cpp
    ComplianceEngine.cpp
    Procedure.cpp
    JSON.cpp
    Evaluator.cpp
    ProcedureMap.cpp
    ${PROCEDURES}
    )

set_property(TARGET compliancelib PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(compliancelib PRIVATE
    logging
    commonutils
    parsonlib
    asb
    base64)
target_include_directories(compliancelib PUBLIC
    ${MODULES_INC_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_command(
    OUTPUT ProcedureMap.cpp
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/gen_procedures_map.py ${CMAKE_CURRENT_SOURCE_DIR}/procedures/
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen_procedures_map.py ${PROCEDURES}
    VERBATIM)
