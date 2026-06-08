cmake_minimum_required(VERSION 3.24)

project(knmon_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(knmon-common INTERFACE)
target_include_directories(knmon-common INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/knmon-common/include
)

add_library(knmon-core STATIC
    knmon-core/src/Controller.cpp
)
target_include_directories(knmon-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/knmon-core/include
)
target_link_libraries(knmon-core PUBLIC knmon-common)
target_compile_definitions(knmon-core PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

add_library(knmon-collector-core STATIC
    knmon-collector/src/Collector.cpp
)
target_include_directories(knmon-collector-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/knmon-collector/include
)
target_link_libraries(knmon-collector-core PUBLIC knmon-common)

add_executable(knmon-collector
    knmon-collector/src/main.cpp
)
target_link_libraries(knmon-collector PRIVATE knmon-core knmon-collector-core)
target_compile_definitions(knmon-collector PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

add_executable(knmon-native-helper
    knmon-native-helper/src/main.cpp
)
target_link_libraries(knmon-native-helper PRIVATE knmon-core)
target_compile_definitions(knmon-native-helper PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

add_library(knmon-agent64 SHARED
    knmon-agent64/src/AgentMain.cpp
)
target_compile_definitions(knmon-agent64 PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

add_executable(knmon-sample-fileio
    ../samples/targets/fileio-sample/src/main.cpp
)
target_link_libraries(knmon-sample-fileio PRIVATE ntdll)
target_compile_definitions(knmon-sample-fileio PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
