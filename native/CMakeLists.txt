cmake_minimum_required(VERSION 3.24)

project(knmon_native LANGUAGES CXX)

if(WIN32)
    enable_language(RC)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(KNMON_VERSION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../VERSION")
if(EXISTS "${KNMON_VERSION_FILE}")
    file(READ "${KNMON_VERSION_FILE}" KNMON_VERSION_STRING)
    string(STRIP "${KNMON_VERSION_STRING}" KNMON_VERSION_STRING)
else()
    set(KNMON_VERSION_STRING "0.1.0.0")
endif()

if(NOT KNMON_VERSION_STRING MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    message(FATAL_ERROR "VERSION must use MAJOR.MINOR.PATCH.BUILD numeric format.")
endif()

set(KNMON_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(KNMON_VERSION_MINOR "${CMAKE_MATCH_2}")
set(KNMON_VERSION_PATCH "${CMAKE_MATCH_3}")
set(KNMON_VERSION_BUILD "${CMAKE_MATCH_4}")
set(KNMON_VERSION_COMMA "${KNMON_VERSION_MAJOR},${KNMON_VERSION_MINOR},${KNMON_VERSION_PATCH},${KNMON_VERSION_BUILD}")
set(KNMON_COMPANY_NAME "kernullist")
set(KNMON_PRODUCT_NAME "KN Win32 API Monitor")
set(KNMON_COPYRIGHT "Copyright (C) 2026 kernullist")

function(knmon_add_version_resource target file_description original_filename file_type)
    if(WIN32)
        set(KNMON_RESOURCE_FILE_DESCRIPTION "${file_description}")
        set(KNMON_RESOURCE_INTERNAL_NAME "${target}")
        set(KNMON_RESOURCE_ORIGINAL_FILENAME "${original_filename}")
        set(KNMON_RESOURCE_FILE_TYPE "${file_type}")
        set(resource_path "${CMAKE_CURRENT_BINARY_DIR}/version/${target}.rc")
        configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/version.rc.in"
            "${resource_path}"
            @ONLY
        )
        target_sources(${target} PRIVATE "${resource_path}")
    endif()
endfunction()

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

file(GLOB KNMON_COMMON_GENERATED_METADATA_PARAMETER_SOURCES CONFIGURE_DEPENDS
    knmon-common/src/GeneratedApiMetadataParametersChunk*.cpp
)

add_library(knmon-core STATIC
    knmon-core/src/Controller.cpp
    knmon-common/src/GeneratedApiMetadata.cpp
    ${KNMON_COMMON_GENERATED_METADATA_PARAMETER_SOURCES}
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
knmon_add_version_resource(knmon-collector "KN Win32 API Monitor Collector" "knmon-collector.exe" "0x1L")

add_executable(knmon-native-helper
    knmon-native-helper/src/main.cpp
)
target_link_libraries(knmon-native-helper PRIVATE knmon-core bcrypt winsqlite3)
target_compile_definitions(knmon-native-helper PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
knmon_add_version_resource(knmon-native-helper "KN Win32 API Monitor Native Helper" "knmon-native-helper.exe" "0x1L")

set(KNMON_AGENT_SOURCE
    knmon-agent64/src/AgentMain.cpp
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    file(GLOB KNMON_AGENT_GENERATED_HOOK_SOURCES CONFIGURE_DEPENDS
        knmon-agent64/src/GeneratedAgentHooksChunk*.cpp
    )
    add_library(knmon-agent64 SHARED
        ${KNMON_AGENT_SOURCE}
        knmon-common/src/GeneratedApiMetadata.cpp
        ${KNMON_COMMON_GENERATED_METADATA_PARAMETER_SOURCES}
        ${KNMON_AGENT_GENERATED_HOOK_SOURCES}
    )
    target_compile_definitions(knmon-agent64 PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        KNMON_AGENT_ARCHITECTURE="x64"
        KNMON_AGENT_DLL_NAME="knmon-agent64.dll"
        KNMON_AGENT_HELLO_MESSAGE="KNMon x64 agent loaded by controlled early-bird APC"
    )
    target_link_libraries(knmon-agent64 PRIVATE knmon-common)
    knmon_add_version_resource(knmon-agent64 "KN Win32 API Monitor x64 Agent" "knmon-agent64.dll" "0x2L")
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
    knmon_add_version_resource(knmon-agent32 "KN Win32 API Monitor x86 Agent" "knmon-agent32.dll" "0x2L")
else()
    message(FATAL_ERROR "Unsupported pointer size for KNMon agent build.")
endif()

function(knmon_link_sample_probe_libraries target)
    target_link_libraries(${target} PRIVATE ntdll ws2_32)
    target_link_libraries(${target} PRIVATE advapi32)
    target_link_libraries(${target} PRIVATE rpcrt4)
    target_link_libraries(${target} PRIVATE bcrypt)
    target_link_libraries(${target} PRIVATE crypt32)
    target_link_libraries(${target} PRIVATE winhttp)
    target_link_libraries(${target} PRIVATE wininet)
    target_link_libraries(${target} PRIVATE user32)
    target_link_libraries(${target} PRIVATE gdi32)
    target_link_libraries(${target} PRIVATE comdlg32)
    target_link_libraries(${target} PRIVATE dwmapi)
    target_link_libraries(${target} PRIVATE msacm32)
    target_link_libraries(${target} PRIVATE winmm)
    target_link_libraries(${target} PRIVATE uxtheme)
    target_link_libraries(${target} PRIVATE comctl32)
    target_link_libraries(${target} PRIVATE d3d9)
    target_link_libraries(${target} PRIVATE opengl32)
    target_link_libraries(${target} PRIVATE glu32)
    target_link_libraries(${target} PRIVATE gdiplus)
    target_link_libraries(${target} PRIVATE dxgi)
    target_link_libraries(${target} PRIVATE magnification)
    target_link_libraries(${target} PRIVATE msi)
    target_link_libraries(${target} PRIVATE odbc32)
    target_link_libraries(${target} PRIVATE snmpapi)
    target_link_libraries(${target} PRIVATE wldap32)
    target_link_libraries(${target} PRIVATE advpack)
    target_link_libraries(${target} PRIVATE dciman32)
    target_link_libraries(${target} PRIVATE dhcpcsvc6)
    target_link_libraries(${target} PRIVATE fwpuclnt)
    target_link_libraries(${target} PRIVATE propsys)
    target_link_libraries(${target} PRIVATE urlmon)
    target_link_libraries(${target} PRIVATE cfgmgr32)
    target_link_libraries(${target} PRIVATE imm32)
    target_link_libraries(${target} PRIVATE uiautomationcore)
    target_link_libraries(${target} PRIVATE wscapi)
    target_link_libraries(${target} PRIVATE msrating)
    target_link_libraries(${target} PRIVATE dhcpsapi)
    target_link_libraries(${target} PRIVATE wsnmp32)
    target_link_libraries(${target} PRIVATE psapi)
    target_link_libraries(${target} PRIVATE version)
    target_link_libraries(${target} PRIVATE shell32)
    target_link_libraries(${target} PRIVATE ole32)
    target_link_libraries(${target} PRIVATE oleaut32)
    target_link_libraries(${target} PRIVATE secur32)
    target_link_libraries(${target} PRIVATE dnsapi)
    target_link_libraries(${target} PRIVATE setupapi)
    target_link_libraries(${target} PRIVATE userenv)
    target_link_libraries(${target} PRIVATE iphlpapi)
    target_link_libraries(${target} PRIVATE netapi32)
    target_link_libraries(${target} PRIVATE shlwapi)
    target_link_libraries(${target} PRIVATE wintrust)
    target_link_libraries(${target} PRIVATE runtimeobject)
    target_link_libraries(${target} PRIVATE dbghelp)
    target_link_libraries(${target} PRIVATE webservices)
endfunction()

add_executable(knmon-sample-fileio
    ../samples/targets/fileio-sample/src/main.cpp
)
knmon_link_sample_probe_libraries(knmon-sample-fileio)
target_compile_definitions(knmon-sample-fileio PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
knmon_add_version_resource(knmon-sample-fileio "KN Win32 API Monitor Sample File I/O Target" "knmon-sample-fileio.exe" "0x1L")

add_executable(knmon-api-exerciser
    ../samples/targets/fileio-sample/src/main.cpp
)
knmon_link_sample_probe_libraries(knmon-api-exerciser)
target_compile_definitions(knmon-api-exerciser PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    KNMON_SAMPLE_PROGRAM_NAME="knmon-api-exerciser"
    KNMON_API_EXERCISER_DEFAULT_LOOP=1
)
knmon_add_version_resource(knmon-api-exerciser "KN Win32 API Monitor API Exerciser Target" "knmon-api-exerciser.exe" "0x1L")

add_library(knmon-dynamic-probe SHARED
    ../samples/targets/dynamic-probe/src/main.cpp
)
target_compile_definitions(knmon-dynamic-probe PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
knmon_add_version_resource(knmon-dynamic-probe "KN Win32 API Monitor Dynamic Probe" "knmon-dynamic-probe.dll" "0x2L")
