cmake_minimum_required(VERSION 3.24)
project(crinkler_fixture LANGUAGES C)
if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "This Crinkler adapter requires MSVC and -A Win32.")
endif()
if(NOT EXISTS "${CRINKLER}" OR NOT EXISTS "${SDK_LIB_DIR}/kernel32.lib")
    message(FATAL_ERROR "Set CRINKLER and SDK_LIB_DIR (Windows SDK um/x86).")
endif()
set(CMAKE_CONFIGURATION_TYPES Release CACHE STRING "Configuration" FORCE)
set(CMAKE_C_FLAGS_RELEASE "/Od /Ob0 /DNDEBUG")
set(FIXTURE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/../../../fixtures/src")
add_library(fixture_objects OBJECT
    "${FIXTURE_SOURCE}/basic_exe.c" "${FIXTURE_SOURCE}/secrets.c")
target_compile_features(fixture_objects PRIVATE c_std_11)
target_compile_options(fixture_objects PRIVATE /W4 /WX /utf-8 /GS- /Zl /Oi-)
add_executable(baseline $<TARGET_OBJECTS:fixture_objects>)
target_link_options(baseline PRIVATE /NODEFAULTLIB /INCREMENTAL:NO
    /DYNAMICBASE /NXCOMPAT /FIXED:NO /MANIFEST:NO /OPT:NOREF /OPT:NOICF
    /MERGE:.markx=.text /IGNORE:4254 /ENTRY:FixtureEntry@0 /SUBSYSTEM:CONSOLE)
target_link_libraries(baseline PRIVATE kernel32)
add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/packed.exe"
    COMMAND "${CRINKLER}" "/OUT:${CMAKE_BINARY_DIR}/packed.exe"
        /ENTRY:FixtureEntry /NODEFAULTLIB /SUBSYSTEM:CONSOLE
        /COMPMODE:FAST /HASHSIZE:32
        $<TARGET_OBJECTS:fixture_objects>
        "${SDK_LIB_DIR}/kernel32.lib" "${SDK_LIB_DIR}/user32.lib"
    DEPENDS fixture_objects $<TARGET_OBJECTS:fixture_objects> "${CRINKLER}"
    COMMAND_EXPAND_LISTS VERBATIM)
add_custom_target(packed ALL DEPENDS "${CMAKE_BINARY_DIR}/packed.exe")
