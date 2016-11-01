cmake_minimum_required(VERSION 3.0)
project(webrtc_server)

set(CMAKE_C_FLAGS "-lssl -lcrypto -lpthread -std=c99")

find_library(OPENSSL_LIB ssl crypto)

set(SOURCE_FILES
  src/webrtc_server.c
  src/stun.c
  src/ssl_functions.c
  src/sctp.c
  src/dtls.c
  src/in_utils.c
  src/tunnel.c
  src/udp_api.c
  )
add_executable(webrtc_server ${SOURCE_FILES})

