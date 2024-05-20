cmake_minimum_required(VERSION 3.28)
project(jbc)

set(CMAKE_CXX_STANDARD 20)

# 设置静态编译
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static")

# 优先查找静态库
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a;.lib")

# 寻找OpenSSL库
find_package(OpenSSL REQUIRED)

#include_directories(${OPENSSL_INCLUDE_DIR})


add_executable(jbc main.cpp
        VirusTotal.cpp
        VirusTotal.h
        FileOperation.cpp
        FileOperation.h
)

#添加manifest，必须写在add_executable之后
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND "C:/Program Files (x86)/Windows Kits/10/bin/10.0.22621.0/x86/mt.exe" -manifest "${CMAKE_SOURCE_DIR}/app.manifest" -outputresource:"$<TARGET_FILE:${PROJECT_NAME}>"\;\#1
        COMMENT "Adding custom manifest...")

# 将OpenSSL库链接到jbc目标
target_link_libraries(jbc OpenSSL::SSL)

#target_link_libraries(jbc sl)