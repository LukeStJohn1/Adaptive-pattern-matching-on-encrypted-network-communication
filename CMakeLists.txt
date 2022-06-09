cmake_minimum_required(VERSION 3.16)
project(SHVE)

FIND_PACKAGE(OpenSSL REQUIRED)

# load header
INCLUDE_DIRECTORIES(../Util)

# set executable outputs
ADD_EXECUTABLE(SHVETest packetToAttribute.cpp SHVE.cpp)

# use SSE/SSE2 instruction set
TARGET_COMPILE_OPTIONS(SHVETest PUBLIC -maes -msse2)

TARGET_LINK_LIBRARIES(SHVETest OpenSSL::Crypto pcap )
