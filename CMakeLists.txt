cmake_minimum_required(VERSION 3.10)

project(learn_from_xuanyuan VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/output")

# 启用测试
enable_testing()

include_directories(${CMAKE_SOURCE_DIR}/include)

# 创建库文件
set(LIB_SOURCES
    src/loguru.cpp
    src/utils.cpp
    src/tsharkManager.cpp
    src/xdb_bench.cc
    src/xdb_search.cc
)

add_library(tshark_lib STATIC ${LIB_SOURCES})
target_link_libraries(tshark_lib pthread dl)

# 主可执行文件
add_executable(tshark_demo_main src/main.cpp)
target_link_libraries(tshark_demo_main tshark_lib)

# 添加测试子目录
add_subdirectory(tests)