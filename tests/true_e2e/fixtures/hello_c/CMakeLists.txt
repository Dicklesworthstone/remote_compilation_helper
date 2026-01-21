# RCH E2E Test Fixture - C Hello World CMake Configuration
#
# Build with: cmake -B build && cmake --build build
# Or: mkdir build && cd build && cmake .. && make

cmake_minimum_required(VERSION 3.16)
project(hello_c VERSION 0.1.0 LANGUAGES C)

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Werror -pedantic)
endif()

# Create the hello library
add_library(hello STATIC hello.c hello.h)
target_include_directories(hello PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Create the main executable
add_executable(hello_app main.c)
target_link_libraries(hello_app PRIVATE hello)

# Simple test
enable_testing()
add_test(NAME hello_runs COMMAND hello_app)
set_tests_properties(hello_runs PROPERTIES
    PASS_REGULAR_EXPRESSION "Hello from rch test fixture!")
