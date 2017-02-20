cmake_minimum_required(VERSION 2.8.8)

project(bindy)

# Detect correct C++11 flag
if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL Windows)
    include(CheckCXXCompilerFlag)
    CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
    CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
    if (COMPILER_SUPPORTS_CXX11)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
    elseif (COMPILER_SUPPORTS_CXX0X)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
    else ()
        message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
    endif ()
endif ()

if (${CMAKE_SYSTEM_NAME} STREQUAL Windows AND ${CMAKE_SYSTEM_VERSION} EQUAL 6.1)
    # HACK: Make cryptopp replace missing (till Windows 8) GetOverlappedResultEx() on Windows7 with somehting compatible
    add_definitions(-D_WIN32_WINNT=0x0601)
endif ()

if (${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD OR ${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif ()

include_directories(vendor)

option(BINDY_BUILD_SHARED "Build bindy as shared library" ON)
option(BINDY_BUILD_STATIC "Build bindy as static library" OFF)
option(BINDY_BUILD_EXAMPLE "Build exmaple client/server application" OFF)

# Configure sqlite
add_definitions(-DSQLITE_ENABLE_COLUMN_METADATA)

# Configure cryptopp
option(BUILD_STATIC "" ON)
option(BUILD_SHARED "" OFF)
option(BUILD_TESTING "" OFF)
option(BUILD_DOCUMENTATION "" OFF)
# Workadround for "shlib-with-non-pic-code" linter error on linux x86 due to ASM code
option(DISABLE_ASM "" ON)
add_subdirectory(vendor/cryptopp)
set_property(TARGET cryptopp-static PROPERTY POSITION_INDEPENDENT_CODE ON)


set(SOURCES
        bindy.cpp
        tinythread.cpp
        vendor/sole/sole.cpp
        vendor/sqlite/sqlite3.c
        )

if (BINDY_BUILD_SHARED)
    add_library(bindy SHARED ${SOURCES})
    set_target_properties(bindy PROPERTIES COMPILE_DEFINITIONS "BINDY_EXPORTS")
    target_link_libraries(bindy LINK_PRIVATE cryptopp-static)
endif ()

if (BINDY_BUILD_STATIC OR BINDY_BUILD_EXMAPLE)
    add_library(bindy-static STATIC ${SOURCES})
    target_link_libraries(bindy-static LINK_PRIVATE cryptopp-static)
endif ()


if (${CMAKE_SYSTEM_NAME} STREQUAL Linux OR ${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
    # librt is not static part of glibc in many Linux distros
    if (BINDY_BUILD_SHARED)
        target_link_libraries(bindy LINK_PRIVATE rt pthread)
    endif ()

    if (BINDY_BUILD_STATIC)
        target_link_libraries(bindy-static LINK_PRIVATE rt pthread)
    endif ()
endif ()

if (BINDY_BUILD_EXAMPLE)
    add_executable(bindy-main client-server.cpp)
    if (BINDY_BUILD_SHARED)
        target_link_libraries(bindy-main LINK_PRIVATE bindy)
    elseif (BINDY_BUILD_STATIC)
        target_link_libraries(bindy-main LINK_PRIVATE bindy-static)
    else ()
        message(FATAL_ERROR "You can't build example without building the library!")
    endif ()
    if (${CMAKE_SYSTEM_NAME} STREQUAL Linux)
        # When both CXX and C used, compilation fails without -ldl flag on Linux systems
        target_link_libraries(bindy-main LINK_PRIVATE dl)
    endif ()
endif ()