cmake_minimum_required(VERSION 3.24)
project(pe_fixtures VERSION 1.0 LANGUAGES C)

if(NOT WIN32 OR NOT CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    message(FATAL_ERROR "These baseline fixtures require Windows and MSVC.")
endif()
if(CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
    set(PE_ARCH x86)
    # LINK adds the leading underscore to x86 /ENTRY symbols.
    set(EXE_ENTRY "FixtureEntry@0")
    set(DLL_ENTRY "FixtureDllEntry@12")
    set(DLL_CALLBACK_SYMBOL "_RunFixture@16")
    set(DLL_WAIT_SYMBOL "_WaitFixture@16")
elseif(CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
    set(PE_ARCH amd64)
    set(EXE_ENTRY FixtureEntry)
    set(DLL_ENTRY FixtureDllEntry)
    set(DLL_CALLBACK_SYMBOL RunFixture)
    set(DLL_WAIT_SYMBOL WaitFixture)
else()
    message(FATAL_ERROR "Use a Visual Studio generator with -A Win32 or -A x64.")
endif()

# One simple configuration; do not introduce CRT startup or LTO.
set(CMAKE_CONFIGURATION_TYPES Release CACHE STRING "Fixture configuration" FORCE)
set(CMAKE_C_FLAGS_RELEASE "/Od /Ob0 /DNDEBUG")
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION FALSE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>")

add_executable(basic_exe src/basic_exe.c src/secrets.c)
set_target_properties(basic_exe PROPERTIES OUTPUT_NAME basic)
configure_file(src/basic_dll.def.in basic_dll.def @ONLY)
add_library(basic_dll SHARED src/basic_dll.c src/secrets.c
    "${CMAKE_CURRENT_BINARY_DIR}/basic_dll.def")
set_target_properties(basic_dll PROPERTIES OUTPUT_NAME basic PREFIX "")

foreach(target basic_exe basic_dll)
    target_compile_features(${target} PRIVATE c_std_11)
    target_compile_options(${target} PRIVATE /W4 /WX /utf-8 /GS- /Zl /Oi-)
    target_link_options(${target} PRIVATE
        /NODEFAULTLIB /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /FIXED:NO
        /MANIFEST:NO /OPT:NOREF /OPT:NOICF /MERGE:.markx=.text /IGNORE:4254)
    # LNK4254 is expected when merging the binary data marker into a code section.
    # The manifest validates the final section and its RX permissions.
    target_link_libraries(${target} PRIVATE kernel32)
endforeach()
target_link_options(basic_exe PRIVATE "/ENTRY:${EXE_ENTRY}" /SUBSYSTEM:CONSOLE)
target_link_options(basic_dll PRIVATE "/ENTRY:${DLL_ENTRY}")

# Use the system loader matching the DLL architecture, including from WOW64 hosts.
if(PE_ARCH STREQUAL "x86")
    set(RUNDLL32 "$ENV{WINDIR}/SysWOW64/rundll32.exe")
elseif(EXISTS "$ENV{WINDIR}/Sysnative/rundll32.exe")
    set(RUNDLL32 "$ENV{WINDIR}/Sysnative/rundll32.exe")
else()
    set(RUNDLL32 "$ENV{WINDIR}/System32/rundll32.exe")
endif()
if(NOT EXISTS "${RUNDLL32}")
    message(FATAL_ERROR "A Windows x64 host with both rundll32 architectures is required.")
endif()

find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)

enable_testing()
add_test(NAME basic_exe_output COMMAND "${CMAKE_COMMAND}"
    "-DPROGRAM=$<TARGET_FILE:basic_exe>"
    "-DEXPECTED=pe-fixture:basic-exe:ok"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_output.cmake")
add_test(NAME basic_dll_rundll32 COMMAND "${CMAKE_COMMAND}"
    "-DPROGRAM=${RUNDLL32}"
    "-DARGUMENT=./$<TARGET_FILE_NAME:basic_dll>,RunFixture"
    "-DWORKING_DIRECTORY=$<TARGET_FILE_DIR:basic_dll>"
    "-DEXPECTED=pe-fixture:basic-dll:ok"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_output.cmake")
add_test(NAME basic_exe_wait COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_wait.py"
    --program "$<TARGET_FILE:basic_exe>" --argument=--wait
    --expected pe-fixture:basic-exe:ok)
add_test(NAME basic_dll_wait COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_wait.py"
    --program "${RUNDLL32}"
    "--argument=./$<TARGET_FILE_NAME:basic_dll>,WaitFixture"
    --working-directory "$<TARGET_FILE_DIR:basic_dll>"
    --expected pe-fixture:basic-dll:ok)
add_test(NAME basic_exe_wait_exact_argument COMMAND "${CMAKE_COMMAND}"
    "-DPROGRAM=$<TARGET_FILE:basic_exe>" -DARGUMENT=--wait-extra
    "-DWORKING_DIRECTORY=$<TARGET_FILE_DIR:basic_exe>"
    "-DEXPECTED=pe-fixture:basic-exe:ok"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_output.cmake")
set_tests_properties(basic_exe_output basic_dll_rundll32 basic_exe_wait
    basic_dll_wait basic_exe_wait_exact_argument PROPERTIES TIMEOUT 15)

string(REGEX MATCH "/MSVC/([^/]+)/" compiler_toolset_path "${CMAKE_C_COMPILER}")
set(PE_TOOLSET_VERSION "${CMAKE_MATCH_1}")
configure_file(cmake/build-info.json.in build-info.json @ONLY)
install(TARGETS basic_exe basic_dll
    RUNTIME DESTINATION "${PE_ARCH}"
    LIBRARY DESTINATION "${PE_ARCH}"
    ARCHIVE DESTINATION "${PE_ARCH}/link")
install(FILES "${CMAKE_BINARY_DIR}/build-info.json" DESTINATION "${PE_ARCH}")
