cmake_minimum_required(VERSION 3.10)

project(learn_from_xuanyuan)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/output")

include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(tshark_demo_main
    src/main.cpp
    src/loguru.cpp
    src/utils.cpp
    src/xdb_bench.cc
    src/xdb_search.cc
)

target_link_libraries(tshark_demo_main pthread dl)