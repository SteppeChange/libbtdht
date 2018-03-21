cmake_minimum_required(VERSION 3.6)

set(CMAKE_CXX_STANDARD 11)

project(btdht)

set(SOURCE_FILES
        btutils/src/bench-json.h
        btutils/src/bencoding.cpp
        btutils/src/bencoding.h
        btutils/src/bencparser.cpp
        btutils/src/bencparser.h
        btutils/src/bitfield.cpp
        btutils/src/bitfield.h
        btutils/src/bloom_filter.cpp
        btutils/src/bloom_filter.h
        btutils/src/DecodeEncodedString.cpp
        btutils/src/DecodeEncodedString.h
        btutils/src/endian_utils.h
        btutils/src/enumtype.h
        btutils/src/get_microseconds.cpp
        btutils/src/get_microseconds.h
        btutils/src/inet_ntop.cpp
        btutils/src/inet_ntop.h
        btutils/src/interlock.cpp
        btutils/src/interlock.h
        btutils/src/invariant_check.hpp
        btutils/src/RefBase.cpp
        btutils/src/RefBase.h
        btutils/src/sha1_hash.h
        btutils/src/smart_ptr.h
        btutils/src/snprintf.cpp
        btutils/src/snprintf.h
        btutils/src/sockaddr.cpp
        btutils/src/sockaddr.h
        btutils/src/tailqueue.h
        btutils/src/target.h
        btutils/src/udp_utils.cpp
        btutils/src/udp_utils.h
        btutils/src/utypes.h
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
        src/ExternalIPCounter.h)

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


target_link_libraries(btdht PUBLIC m pthread )
