# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_compile_options("-Wall;-Wextra;-Wunused;-Werror;-Wformat;-Wformat-security;-Wno-unused-result")
add_link_options("LINKER:-z,defs")

add_subdirectory(ssh)
add_subdirectory(asb)
add_subdirectory(compliance)
