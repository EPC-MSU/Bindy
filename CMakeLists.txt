cmake_minimum_required(VERSION 2.8)


project(bindy)

if(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
	# It is required to build a rpath framework
	cmake_policy(SET CMP0042 NEW)
endif()
if(NO_RPATH_PACKAGING)
	set(CMAKE_SKIP_RPATH TRUE)
endif()

# Detect correct C++11 flag
if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL Windows)
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
if(COMPILER_SUPPORTS_CXX11)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif(COMPILER_SUPPORTS_CXX0X)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
else()
	message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()
endif()


# Find crypto++ library. Hinted path is CRYPTOPP_PATH
# Set CRYPTOPP_SHARED_LIBRARY to any value to use shared library
if(CRYPTOPP_SHARED_LIBRARY)
	set(CRYPTOPP_SHARED cryptopp)
endif()

find_path(CRYPTOPP_INCLUDE_DIR aes.h
	PATH_SUFFIXES cryptopp
	PATHS
	/usr/local/include/
	/usr/include/
	${CRYPTOPP_PATH}/include/
	${CRYPTOPP_PATH}/
	${CRYPTOPP_PATH_INCLUDE}
	)

find_library(CRYPTOPP_LIBRARY
	NAMES ${CRYPTOPP_SHARED} libcryptopp.a cryptlib.lib
	PATH_SUFFIXES lib64 lib
	PATHS
	/usr/local
	/usr
	${CRYPTOPP_PATH}/lib
	${CRYPTOPP_PATH}/
	)

if(${CMAKE_SYSTEM_NAME} STREQUAL Linux)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
endif()
if(${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -pthread")
endif()
if(${CMAKE_SYSTEM_NAME} STREQUAL Darwin)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL Linux OR ${CMAKE_SYSTEM_NAME} STREQUAL FreeBSD)
    # When both CXX and C used, compilation fails without -ldl flag
    # librt is used by sole on some platforms
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lrt -ldl")
endif()


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSQLITE_ENABLE_COLUMN_METADATA")

# creates variables CRYPTOPP_FOUND, CRYPTOPP_LIBRARY and CRYPTOPP_INCLUDE_DIR
include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CRYPTOPP DEFAULT_MSG CRYPTOPP_INCLUDE_DIR CRYPTOPP_LIBRARY)
mark_as_advanced(CRYPTOPP_INCLUDE_DIR CRYPTOPP_LIBRARY)

if(NOT CRYPTOPP_FOUND)
	message(FATAL_ERROR "Please set CRYPTOPP_PATH and/or CRYPTOPP_PATH_INCLUDE for custom crypto++ location")
endif()

include_directories(${CRYPTOPP_INCLUDE_DIR})
include_directories("vendor")

add_library(bindy SHARED bindy.cpp tinythread.cpp vendor/sole/sole.cpp vendor/sqlite/sqlite3.c)
target_link_libraries(bindy ${CRYPTOPP_LIBRARY})
if(${CMAKE_SYSTEM_NAME} STREQUAL Windows)
	target_link_libraries(bindy ws2_32)
endif()

add_executable(bindy-main client-server.cpp)
target_link_libraries(bindy-main bindy)
