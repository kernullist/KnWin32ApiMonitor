cmake_minimum_required(VERSION 3.24)

project(knmon_native LANGUAGES C CXX)

include(CTest)

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

add_subdirectory(third-party/zstd)
add_library(knmon-session-codec STATIC knmon-common/src/SessionCodec.cpp)
target_link_libraries(knmon-session-codec PUBLIC knmon-common PRIVATE knmon-zstd)

add_library(knmon-ipc-security STATIC knmon-common/src/IpcSecurity.cpp)
target_link_libraries(knmon-ipc-security PUBLIC knmon-common PRIVATE advapi32 bcrypt)
target_compile_definitions(knmon-ipc-security PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

add_library(knmon-transport-support STATIC knmon-common/src/TransportWriter.cpp)
target_link_libraries(knmon-transport-support PUBLIC knmon-common)
target_compile_definitions(knmon-transport-support PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
if(MSVC)
    target_compile_options(knmon-transport-support PRIVATE /EHsc)
endif()

file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/third-party/nlohmann/json.hpp" KNMON_JSON_SHA256)
if(NOT KNMON_JSON_SHA256 STREQUAL "aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63")
    message(FATAL_ERROR "Pinned JSON dependency hash mismatch.")
endif()
file(SHA256 "${CMAKE_CURRENT_SOURCE_DIR}/third-party/nlohmann/LICENSE.MIT" KNMON_JSON_LICENSE_SHA256)
if(NOT KNMON_JSON_LICENSE_SHA256 STREQUAL "46a65cffd1ea955132d95a8dd921640714a8d6b537d2e4e482d31145ae95b603")
    message(FATAL_ERROR "Pinned JSON license hash mismatch.")
endif()
add_library(knmon-json STATIC knmon-common/src/BoundedJson.cpp)
target_link_libraries(knmon-json PUBLIC knmon-common)
target_include_directories(knmon-json SYSTEM PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/third-party")

if(BUILD_TESTING)
    add_executable(knmon-capture-history-test tests/CaptureHistoryTest.cpp)
    target_link_libraries(knmon-capture-history-test PRIVATE knmon-common)
    add_test(NAME capture-history COMMAND knmon-capture-history-test)
    add_executable(knmon-session-codec-test tests/SessionCodecTest.cpp)
    target_link_libraries(knmon-session-codec-test PRIVATE knmon-session-codec)
    add_test(NAME session-codec COMMAND knmon-session-codec-test)
    set_tests_properties(session-codec PROPERTIES TIMEOUT 20)
    add_executable(knmon-ipc-security-test tests/IpcSecurityTest.cpp)
    target_link_libraries(knmon-ipc-security-test PRIVATE knmon-ipc-security knmon-json advapi32)
    target_compile_definitions(knmon-ipc-security-test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    add_test(NAME ipc-security COMMAND knmon-ipc-security-test)
    set_tests_properties(ipc-security PROPERTIES TIMEOUT 20)
    add_executable(knmon-bounded-json-test tests/BoundedJsonTest.cpp)
    target_link_libraries(knmon-bounded-json-test PRIVATE knmon-json)
    target_include_directories(knmon-bounded-json-test SYSTEM PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/third-party")
    add_test(NAME bounded-json COMMAND knmon-bounded-json-test)
    set_tests_properties(bounded-json PROPERTIES TIMEOUT 15)
    add_executable(knmon-runtime-support-test tests/RuntimeSupportTest.cpp)
    target_link_libraries(knmon-runtime-support-test PRIVATE knmon-common knmon-core)
    add_test(NAME runtime-support COMMAND knmon-runtime-support-test)
    add_executable(knmon-transport-security-test tests/TransportSecurityTest.cpp)
    target_link_libraries(knmon-transport-security-test PRIVATE knmon-collector-core)
    target_compile_definitions(knmon-transport-security-test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    add_test(NAME transport-security COMMAND knmon-transport-security-test)
    add_executable(knmon-transport-writer-test tests/TransportWriterTest.cpp)
    target_link_libraries(knmon-transport-writer-test PRIVATE knmon-collector-core knmon-transport-support)
    target_compile_definitions(knmon-transport-writer-test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    add_test(NAME transport-writer COMMAND knmon-transport-writer-test)
    set_tests_properties(transport-writer PROPERTIES TIMEOUT 30)
    add_executable(knmon-session-lease-test tests/SessionLeaseTest.cpp)
    target_link_libraries(knmon-session-lease-test PRIVATE knmon-transport-support knmon-collector-core)
    target_compile_definitions(knmon-session-lease-test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(knmon-session-lease-test PRIVATE /EHa)
    endif()
    add_test(NAME session-lease COMMAND knmon-session-lease-test)
    set_tests_properties(session-lease PROPERTIES TIMEOUT 30)
    add_executable(knmon-transport-tamper-target tests/TransportTamperTarget.cpp)
    target_link_libraries(knmon-transport-tamper-target PRIVATE knmon-common)
    target_compile_definitions(knmon-transport-tamper-target PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

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
    PUBLIC knmon-common knmon-json knmon-ipc-security
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
target_link_libraries(knmon-native-helper PRIVATE knmon-core knmon-session-codec bcrypt winsqlite3)
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
    target_link_libraries(knmon-agent64 PRIVATE knmon-common knmon-transport-support knmon-ipc-security)
    if(MSVC)
        target_compile_options(knmon-agent64 PRIVATE /EHa)
    endif()
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
    target_link_libraries(knmon-agent32 PRIVATE knmon-common knmon-transport-support knmon-ipc-security)
    if(MSVC)
        target_compile_options(knmon-agent32 PRIVATE /EHa)
    endif()
    knmon_add_version_resource(knmon-agent32 "KN Win32 API Monitor x86 Agent" "knmon-agent32.dll" "0x2L")
else()
    message(FATAL_ERROR "Unsupported pointer size for KNMon agent build.")
endif()

if(BUILD_TESTING)
    add_library(knmon-lifecycle-test-agent SHARED ${KNMON_AGENT_SOURCE})
    target_link_libraries(knmon-lifecycle-test-agent PRIVATE knmon-common knmon-core knmon-transport-support)
    target_compile_definitions(knmon-lifecycle-test-agent PRIVATE
        WIN32_LEAN_AND_MEAN NOMINMAX KNMON_LIFECYCLE_TESTING
    )
    if(MSVC)
        target_compile_options(knmon-lifecycle-test-agent PRIVATE /EHa)
    endif()
    add_executable(knmon-lifecycle-exit-target tests/LifecycleExitTarget.cpp)
    target_compile_definitions(knmon-lifecycle-exit-target PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    add_test(NAME lifecycle-process-exit COMMAND knmon-lifecycle-exit-target $<TARGET_FILE:knmon-lifecycle-test-agent>)
    set_tests_properties(lifecycle-process-exit PROPERTIES TIMEOUT 10)
    add_test(NAME lifecycle-stop-reserved COMMAND knmon-lifecycle-exit-target $<TARGET_FILE:knmon-lifecycle-test-agent> reserved)
    add_test(NAME lifecycle-stop-commit COMMAND knmon-lifecycle-exit-target $<TARGET_FILE:knmon-lifecycle-test-agent> commit)
    set_tests_properties(lifecycle-stop-reserved lifecycle-stop-commit PROPERTIES TIMEOUT 20)
    add_executable(knmon-capture-semantics-test tests/CaptureSemanticsTest.cpp)
    add_executable(knmon-abi-differential-test tests/AbiDifferentialTest.cpp)
    add_executable(knmon-typed-abi-target samples/TypedAbiTarget.cpp)
    add_executable(knmon-comparison-target samples/ComparisonTarget.cpp)
    target_link_libraries(knmon-comparison-target PRIVATE advapi32 psapi)
    target_compile_definitions(knmon-comparison-target PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    add_executable(knmon-etw-corpus-reader samples/EtwCorpusReader.cpp)
    target_link_libraries(knmon-etw-corpus-reader PRIVATE advapi32)
    target_compile_definitions(knmon-etw-corpus-reader PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(knmon-typed-abi-target PRIVATE oleaut32 d2d1 user32)
    target_compile_definitions(knmon-typed-abi-target PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_compile_definitions(knmon-abi-differential-test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    add_test(NAME abi-differential COMMAND knmon-abi-differential-test $<TARGET_FILE:knmon-lifecycle-test-agent>)
    set_tests_properties(abi-differential PROPERTIES TIMEOUT 30)
    target_link_libraries(knmon-capture-semantics-test PRIVATE knmon-core ws2_32)
    target_compile_definitions(knmon-capture-semantics-test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(knmon-capture-semantics-test PRIVATE /EHa)
    endif()
    add_test(NAME capture-semantics COMMAND knmon-capture-semantics-test $<TARGET_FILE:knmon-lifecycle-test-agent>)
    set_tests_properties(capture-semantics PROPERTIES TIMEOUT 20)
    add_test(NAME capture-delayed-collector COMMAND knmon-capture-semantics-test $<TARGET_FILE:knmon-lifecycle-test-agent> --capture)
    set_tests_properties(capture-delayed-collector PROPERTIES TIMEOUT 25)
    add_test(NAME capture-stream-retention COMMAND knmon-capture-semantics-test $<TARGET_FILE:knmon-lifecycle-test-agent> --retention)
    add_test(NAME capture-consumer-failure COMMAND knmon-capture-semantics-test $<TARGET_FILE:knmon-lifecycle-test-agent> --consumer-failure)
    set_tests_properties(capture-stream-retention capture-consumer-failure PROPERTIES TIMEOUT 40)
    add_executable(knmon-module-lifecycle-test tests/ModuleLifecycleTest.cpp)
    target_link_libraries(knmon-module-lifecycle-test PRIVATE knmon-common)
    target_compile_definitions(knmon-module-lifecycle-test PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    add_library(knmon-module-probe-a SHARED tests/ModuleProbe.cpp)
    add_library(knmon-module-probe-b SHARED tests/ModuleProbe.cpp)
    add_library(knmon-module-delay-probe SHARED tests/ModuleProbe.cpp)
    target_compile_definitions(knmon-module-delay-probe PRIVATE KNMON_DELAY_PROBE)
    target_link_libraries(knmon-module-delay-probe PRIVATE version delayimp)
    target_link_options(knmon-module-delay-probe PRIVATE /DELAYLOAD:version.dll /DELAY:UNLOAD)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(KNMON_TWIN_EXPORT "timeGetTime=_timeGetTime@0 @141\nTwinAlias=_timeGetTime@0 @142")
    else()
        set(KNMON_TWIN_EXPORT "timeGetTime @141\nTwinAlias=timeGetTime @142")
    endif()
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/module-twin.def" "LIBRARY winmm\nEXPORTS\n${KNMON_TWIN_EXPORT}\n")
    foreach(variant a b)
        add_library(knmon-module-twin-${variant} SHARED tests/ModuleTwin.cpp "${CMAKE_CURRENT_BINARY_DIR}/module-twin.def")
        target_compile_definitions(knmon-module-twin-${variant} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
        set_target_properties(knmon-module-twin-${variant} PROPERTIES OUTPUT_NAME winmm
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/module-twin-${variant}"
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/module-twin-${variant}")
    endforeach()
    target_compile_definitions(knmon-module-twin-a PRIVATE KNMON_TWIN_VALUE=111)
    target_compile_definitions(knmon-module-twin-b PRIVATE KNMON_TWIN_VALUE=222)
    add_test(NAME module-lifecycle COMMAND knmon-module-lifecycle-test $<TARGET_FILE:knmon-lifecycle-test-agent>
        $<TARGET_FILE:knmon-module-probe-a> $<TARGET_FILE:knmon-module-probe-b> $<TARGET_FILE:knmon-module-delay-probe>
        $<TARGET_FILE:knmon-module-twin-a> $<TARGET_FILE:knmon-module-twin-b>)
    set_tests_properties(module-lifecycle PROPERTIES TIMEOUT 35)
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
