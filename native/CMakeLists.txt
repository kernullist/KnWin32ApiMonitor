cmake_minimum_required(VERSION 3.24)

project(knmon_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(knmon-common INTERFACE)
target_include_directories(knmon-common INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/knmon-common/include
)

add_library(knmon-collector-core STATIC
    knmon-collector/src/Collector.cpp
    knmon-collector/src/SharedTransportReader.cpp
    knmon-collector/src/ThreadedSharedTransportReader.cpp
)
target_include_directories(knmon-collector-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/knmon-collector/include
)
target_link_libraries(knmon-collector-core PUBLIC knmon-common)
target_compile_definitions(knmon-collector-core PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

add_library(knmon-core STATIC
    knmon-core/src/Controller.cpp
)
target_include_directories(knmon-core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/knmon-core/include
)
target_link_libraries(knmon-core
    PUBLIC knmon-common
    PRIVATE knmon-collector-core
)
target_compile_definitions(knmon-core PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

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
target_link_libraries(knmon-native-helper PRIVATE knmon-core bcrypt winsqlite3)
target_compile_definitions(knmon-native-helper PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

set(KNMON_AGENT_SOURCE
    knmon-agent64/src/AgentMain.cpp
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_library(knmon-agent64 SHARED
        ${KNMON_AGENT_SOURCE}
    )
    target_compile_definitions(knmon-agent64 PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        KNMON_AGENT_ARCHITECTURE="x64"
        KNMON_AGENT_DLL_NAME="knmon-agent64.dll"
        KNMON_AGENT_HELLO_MESSAGE="KNMon x64 agent loaded by controlled early-bird APC"
    )
    target_link_libraries(knmon-agent64 PRIVATE knmon-common)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    add_library(knmon-agent32 SHARED
        ${KNMON_AGENT_SOURCE}
    )
    target_compile_definitions(knmon-agent32 PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        KNMON_AGENT_ARCHITECTURE="x86"
        KNMON_AGENT_DLL_NAME="knmon-agent32.dll"
        KNMON_AGENT_HELLO_MESSAGE="KNMon x86 agent loaded by controlled early-bird APC"
    )
    target_link_libraries(knmon-agent32 PRIVATE knmon-common)
else()
    message(FATAL_ERROR "Unsupported pointer size for KNMon agent build.")
endif()

add_executable(knmon-sample-fileio
    ../samples/targets/fileio-sample/src/main.cpp
)
target_link_libraries(knmon-sample-fileio PRIVATE ntdll ws2_32)
target_link_libraries(knmon-sample-fileio PRIVATE advapi32)
target_link_libraries(knmon-sample-fileio PRIVATE rpcrt4)
target_link_libraries(knmon-sample-fileio PRIVATE bcrypt)
target_link_libraries(knmon-sample-fileio PRIVATE crypt32)
target_link_libraries(knmon-sample-fileio PRIVATE winhttp)
target_link_libraries(knmon-sample-fileio PRIVATE wininet)
target_link_libraries(knmon-sample-fileio PRIVATE user32)
target_link_libraries(knmon-sample-fileio PRIVATE gdi32)
target_link_libraries(knmon-sample-fileio PRIVATE psapi)
target_link_libraries(knmon-sample-fileio PRIVATE version)
target_link_libraries(knmon-sample-fileio PRIVATE shell32)
target_link_libraries(knmon-sample-fileio PRIVATE ole32)
target_link_libraries(knmon-sample-fileio PRIVATE oleaut32)
target_link_libraries(knmon-sample-fileio PRIVATE secur32)
target_link_libraries(knmon-sample-fileio PRIVATE dnsapi)
target_link_libraries(knmon-sample-fileio PRIVATE setupapi)
target_link_libraries(knmon-sample-fileio PRIVATE userenv)
target_link_libraries(knmon-sample-fileio PRIVATE iphlpapi)
target_link_libraries(knmon-sample-fileio PRIVATE shlwapi)
target_link_libraries(knmon-sample-fileio PRIVATE wintrust)
target_link_libraries(knmon-sample-fileio PRIVATE runtimeobject)
target_link_libraries(knmon-sample-fileio PRIVATE dbghelp)
target_compile_definitions(knmon-sample-fileio PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

add_library(knmon-dynamic-probe SHARED
    ../samples/targets/dynamic-probe/src/main.cpp
)
target_compile_definitions(knmon-dynamic-probe PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
