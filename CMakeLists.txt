CMAKE_MINIMUM_REQUIRED(VERSION 2.8.9)

PROJECT(bindy)

OPTION(BUILD_SHARED_LIBS "Build shared libraries" ON)
OPTION(BUILD_EXAMPLE "Build exmaple client/server application" OFF)

IF(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
    # It is required to build a rpath framework
    CMAKE_POLICY(SET CMP0042 NEW)
ENDIF()

# Detect correct C++11 flag
IF(NOT ${CMAKE_SYSTEM_NAME} STREQUAL Windows)
    INCLUDE(CheckCXXCompilerFlag)
    CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
    CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
    IF(COMPILER_SUPPORTS_CXX11)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
    ELSEIF(COMPILER_SUPPORTS_CXX0X)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
    ELSE()
        MESSAGE(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
    ENDIF()
ENDIF()

IF(${CMAKE_SYSTEM_NAME} STREQUAL Windows AND ${CMAKE_SYSTEM_VERSION} EQUAL 6.1)
    # HACK: Make cryptopp replace missing (till Windows 8) GetOverlappedResultEx() on Windows7 with somehting compatible
    ADD_DEFINITIONS(-D_WIN32_WINNT=0x0601)
ENDIF()

IF(${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD OR ${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
ENDIF()

# Configure sqlite
ADD_DEFINITIONS(-DSQLITE_ENABLE_COLUMN_METADATA)
ADD_DEFINITIONS(-DSQLITE_OMIT_LOAD_EXTENSION)

# generate config.h
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/bindy-config.h.in ${CMAKE_CURRENT_BINARY_DIR}/bindy-config.h)

# Determine existence of specific tcp flags
INCLUDE(CheckSymbolExists)
CHECK_SYMBOL_EXISTS(TCP_KEEPINTVL netinet/tcp.h HAVE_TCP_KEEPINTVL)
CHECK_SYMBOL_EXISTS(TCP_KEEPIDLE netinet/tcp.h HAVE_TCP_KEEPIDLE)
CHECK_SYMBOL_EXISTS(TCP_KEEPCNT netinet/tcp.h HAVE_TCP_KEEPCNT)

SET(SOURCES
        bindy.cpp
        tinythread.cpp
        vendor/sole/sole.cpp
        vendor/sqlite/sqlite3.c
        )

INCLUDE_DIRECTORIES(vendor)
ADD_LIBRARY(bindy ${SOURCES})
IF(BUILD_SHARED_LIBS)
    SET_TARGET_PROPERTIES(bindy PROPERTIES COMPILE_DEFINITIONS "BINDY_EXPORTS")
ENDIF()
# set fPIC for static and shared libs
SET(CMAKE_POSITION_INDEPENDENT_CODE ON)

FUNCTION(CONFIGURE_CRYPTOPP)
    # Unconditionally configure cryptopp in separate scope
    SET(BUILD_STATIC ON CACHE INTERNAL "")
    SET(BUILD_SHARED OFF CACHE INTERNAL "")
    SET(BUILD_TESTING OFF CACHE INTERNAL "")
    SET(BUILD_DOCUMENTATION OFF CACHE INTERNAL "")
    SET(DISABLE_ASM OFF CACHE INTERNAL "")
    SET(DISABLE_SSSE3 OFF CACHE INTERNAL "")
    SET(DISABLE_AESNI OFF CACHE INTERNAL "")
    SET(CRYPTOPP_DATA_DIR CACHE INTERNAL "")
    ADD_SUBDIRECTORY(vendor/cryptopp)
ENDFUNCTION()

CONFIGURE_CRYPTOPP()
TARGET_LINK_LIBRARIES(bindy LINK_PRIVATE cryptopp-static)

IF(${CMAKE_SYSTEM_NAME} STREQUAL Linux OR ${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
    # librt is not static part of glibc in many Linux distros
    TARGET_LINK_LIBRARIES(bindy LINK_PRIVATE rt pthread)
ENDIF()

IF(BUILD_EXAMPLE)
    ADD_EXECUTABLE(bindy-main client-server.cpp)
    TARGET_LINK_LIBRARIES(bindy-main LINK_PRIVATE bindy)
    IF(${CMAKE_SYSTEM_NAME} STREQUAL Linux)
        # When both CXX and C used, compilation fails without -ldl flag on Linux systems
        TARGET_LINK_LIBRARIES(bindy-main LINK_PRIVATE dl)
    ENDIF()
ENDIF()
