cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 11)

project(btdht)

set(SOURCE_FILES
        libbtutils/src/bench-json.h
        libbtutils/src/bencoding.cpp
        libbtutils/src/bencoding.h
        libbtutils/src/bencparser.cpp
        libbtutils/src/bencparser.h
        libbtutils/src/bitfield.cpp
        libbtutils/src/bitfield.h
        libbtutils/src/bloom_filter.cpp
        libbtutils/src/bloom_filter.h
        libbtutils/src/DecodeEncodedString.cpp
        libbtutils/src/DecodeEncodedString.h
        libbtutils/src/endian_utils.h
        libbtutils/src/enumtype.h
        libbtutils/src/get_microseconds.cpp
        libbtutils/src/get_microseconds.h
        libbtutils/src/inet_ntop.cpp
        libbtutils/src/inet_ntop.h
        libbtutils/src/interlock.cpp
        libbtutils/src/interlock.h
        libbtutils/src/invariant_check.hpp
        libbtutils/src/RefBase.cpp
        libbtutils/src/RefBase.h
        libbtutils/src/sha1_hash.h
        libbtutils/src/smart_ptr.h
        libbtutils/src/snprintf.cpp
        libbtutils/src/snprintf.h
        libbtutils/src/sockaddr.cpp
        libbtutils/src/sockaddr.h
        libbtutils/src/tailqueue.h
        libbtutils/src/target.h
        libbtutils/src/udp_utils.cpp
        libbtutils/src/udp_utils.h
        libbtutils/src/utypes.h
        src/blockallocator.cpp
        src/blockallocator.h
        src/Buffer.h
        src/crc32c.cpp
        src/dht.cpp
        src/dht.h
        src/DhtImpl.cpp
        src/DhtImpl.h
        src/DHTMessage.cpp
        src/DHTMessage.h
        src/ExternalIPCounter.cpp
        src/ExternalIPCounter.h
        src/logger.h)

add_library(btdht ${SOURCE_FILES})

include_directories(${CMAKE_SOURCE_DIR})

target_compile_options(btdht PUBLIC -c -MD -g -pipe -Wall -O0 -D_UNICODE)

cmake_policy(SET CMP0003 NEW) ## Libraries linked via full path no longer produce linker search paths.

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
MESSAGE( STATUS "PROJECT_SOURCE_DIR:         " ${PROJECT_SOURCE_DIR} )
MESSAGE( STATUS "CMAKE_MODULE_PATH:         " ${CMAKE_MODULE_PATH} )

include_directories(${PROJECT_SOURCE_DIR}/btutils/src)

add_definitions(-DCHARSET_ANSI=ansi)
add_definitions(-DCHARSET_UNICODE=unicode)
add_definitions(-DCHARSET_DEFAULT=$(CHARSET_UNICODE))
