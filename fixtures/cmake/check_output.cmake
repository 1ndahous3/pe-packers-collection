if(NOT DEFINED PROGRAM OR NOT DEFINED EXPECTED)
    message(FATAL_ERROR "PROGRAM and EXPECTED are required.")
endif()
if(DEFINED ARGUMENT)
    execute_process(COMMAND "${PROGRAM}" "${ARGUMENT}"
        WORKING_DIRECTORY "${WORKING_DIRECTORY}"
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error
        TIMEOUT 10)
else()
    execute_process(COMMAND "${PROGRAM}"
        RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error
        TIMEOUT 10)
endif()
string(REPLACE "\r\n" "\n" output "${output}")
if(NOT result STREQUAL "0" OR NOT output STREQUAL "${EXPECTED}\n"
        OR NOT error STREQUAL "")
    message(FATAL_ERROR
        "Unexpected behavior: exit=${result}, stdout=[${output}], stderr=[${error}]")
endif()
