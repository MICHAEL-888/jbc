cmake_minimum_required(VERSION 3.28)
project(jbc)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")

# 寻找OpenSSL库
find_package(OpenSSL REQUIRED)

#include_directories(${OPENSSL_INCLUDE_DIR})


add_executable(jbc main.cpp
        VirusTotal.cpp
        VirusTotal.h
        FileOperation.cpp
        FileOperation.h
)

# 将OpenSSL库链接到jbc目标
target_link_libraries(jbc OpenSSL::SSL)

#target_link_libraries(jbc sl)