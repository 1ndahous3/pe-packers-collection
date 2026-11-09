cmake_minimum_required(VERSION 3.24)
project(evb_bundle LANGUAGES C)
if(NOT MSVC)
    message(FATAL_ERROR "Use MSVC for this bundle fixture.")
endif()
set(CMAKE_CONFIGURATION_TYPES Release CACHE STRING "Configuration" FORCE)
set(CMAKE_C_FLAGS_RELEASE "/Od /Ob0 /DNDEBUG")
set(FIXTURE_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/../../../fixtures/src")
# Reuse the tested bundle entry instead of copying its source.
add_executable(bundle "${CMAKE_CURRENT_SOURCE_DIR}/../../molebox/bundle/bundle.c"
    "${FIXTURE_SOURCE}/basic_exe.c" "${FIXTURE_SOURCE}/secrets.c")
target_compile_features(bundle PRIVATE c_std_11)
target_compile_options(bundle PRIVATE /W4 /WX /utf-8 /GS- /Zl /Oi-)
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(BUNDLE_ENTRY "BundleEntry@0")
else()
    set(BUNDLE_ENTRY "BundleEntry")
endif()
target_link_options(bundle PRIVATE /NODEFAULTLIB /INCREMENTAL:NO
    /DYNAMICBASE /NXCOMPAT /FIXED:NO /MANIFEST:NO /OPT:NOREF /OPT:NOICF
    /MERGE:.markx=.text /IGNORE:4254 /ENTRY:${BUNDLE_ENTRY} /SUBSYSTEM:CONSOLE)
target_link_libraries(bundle PRIVATE kernel32)
