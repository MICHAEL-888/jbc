//
// Created by Michael on 24-4-29.
//

//#include <bits/stdc++.h>
#include <iostream>
#include <string>
#include <fstream>
#include "FileOperation.h"
//#include "FileOperation.h"
//#include <fstream>
#include <openssl/md5.h>
#include <windows.h>
//#include <filesystem>

// 定义FileOperation类的calculateMD5方法
std::string FileOperation::calculateMD5(const std::string &filePath) {
    // 转换路径为宽字符，解决中文路径问题
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &filePath[0], (int)filePath.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &filePath[0], (int)filePath.size(), &wstr[0], size_needed);

    // 创建一个unsigned char数组，用于存储MD5哈希值
    unsigned char result[MD5_DIGEST_LENGTH];
    // 以二进制模式打开文件
    std::ifstream file(wstr.c_str(), std::ios::binary);

    if (!file) {
        // 文件打开失败，返回空字符串
        return "";
    }

    // 创建一个MD5_CTX结构体，用于计算MD5哈希值
    MD5_CTX md5Context;
    // 初始化MD5_CTX结构体
    MD5_Init(&md5Context);

    // 创建一个缓冲区，用于读取文件
    char buf[1024 * 16];
    //char buf[1024 * 16 * ];
    // 循环读取文件，直到文件结束
    while (file.good()) {
        // 从文件中读取数据到缓冲区
        file.read(buf, sizeof(buf));
        // 更新MD5哈希值
        MD5_Update(&md5Context, buf, file.gcount());
    }

    // 计算最终的MD5哈希值
    MD5_Final(result, &md5Context);

    // 创建一个char数组，用于存储十六进制形式的MD5哈希值
    char hex[33];
    // 将MD5哈希值转换为十六进制形式
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(hex + i * 2, "%02x", result[i]);
    }

    // 返回十六进制形式的MD5哈希值
    //return string(hex);
    return {hex};
}
