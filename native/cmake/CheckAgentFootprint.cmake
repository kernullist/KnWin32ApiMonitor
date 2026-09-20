if(NOT EXISTS "${AGENT_PATH}" OR NOT EXISTS "${LINKER}")
    message(FATAL_ERROR "Agent and MSVC linker paths are required.")
endif()

# The full host catalog must not be linked into the injected agent.
file(SIZE "${AGENT_PATH}" agent_size)
if(agent_size GREATER 8388608)
    message(FATAL_ERROR "Injected agent exceeds the 8 MiB on-disk budget: ${agent_size} bytes.")
endif()

execute_process(COMMAND "${LINKER}" /dump /exports "${AGENT_PATH}"
    RESULT_VARIABLE export_status OUTPUT_VARIABLE exports ERROR_VARIABLE export_error TIMEOUT 15)
if(NOT export_status STREQUAL "0")
    message(FATAL_ERROR "Agent export inspection failed: ${export_status} ${export_error}")
endif()

foreach(entry KnMonAgentInitialize KnMonAgentQueryState KnMonAgentStop KnMonAgentVersion)
    if(NOT exports MATCHES "[\r\n][ \t]+[0-9]+[ \t]+[0-9A-Fa-f]+[ \t]+[0-9A-Fa-f]+[ \t]+${entry}([ \t\r\n]|$)")
        message(FATAL_ERROR "Agent control export is missing: ${entry}")
    endif()
endforeach()
if(exports MATCHES "[ \t](KnMonInvokeGenerated|KnMonTest)")
    message(FATAL_ERROR "Production agent exposes a disabled dispatcher or test entry point.")
endif()
message(STATUS "Agent footprint and control exports passed: ${agent_size} bytes.")
