cmake_minimum_required(VERSION 3.0)
project(webrtc_server)

set(CMAKE_C_FLAGS "-lssl -lcrypto -lpthread -std=c99")

find_library(OPENSSL_LIB ssl crypto)

set(SOURCE_FILES webrtc_server.c stun.c ssl_functions.c sctp_server.c)
add_executable(webrtc_server ${SOURCE_FILES})

