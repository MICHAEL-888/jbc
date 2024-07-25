//
// Created by Michael on 24-4-29.
//

//#include <bits/stdc++.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <fstream>
#include "FileOperation.h"
//#include "FileOperation.h"
//#include <fstream>
#include <openssl/md5.h>
#include <windows.h>
//#include <filesystem>
#include <wincrypt.h>
#include <wintrust.h>
#include <Softpub.h>

// 定义FileOperation类的calculateMD5方法
std::string FileOperation::calculateMD5(const std::filesystem::path& filePath) {
    // 转换路径为宽字符，解决中文路径问题，MSVC编译器不使用此段代码
    /*
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &filePath[0], (int)filePath.size(), NULL, 0);
    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &filePath[0], (int)filePath.size(), &wstr[0], size_needed);
    */

    // 创建一个unsigned char数组，用于存储MD5哈希值
    unsigned char result[MD5_DIGEST_LENGTH];
    // 以二进制模式打开文件
    std::ifstream file(filePath, std::ios::binary);

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

bool FileOperation::isPEFile(const std::filesystem::path& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filePath.string() << std::endl;
        return false;
    }

    char buffer[2];
    if (!file.read(buffer, sizeof(buffer))) {
        std::cerr << "Failed to read file: " << filePath.string() << std::endl;
        return false;
    }

    return buffer[0] == 'M' && buffer[1] == 'Z';
}

bool FileOperation::VerifySignature(const std::wstring& filePath) {
    //https://learn.microsoft.com/en-us/windows/win32/seccrypto/example-c-program--verifying-the-signature-of-a-pe-file

    // 初始化WINTRUST_FILE_INFO结构体，用于指定要验证的文件
    WINTRUST_FILE_INFO fileInfo;
    memset(&fileInfo, 0, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    // 初始化WINTRUST_DATA结构体，用于指定验证的参数
    //https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data
    WINTRUST_DATA trustData;
    memset(&trustData, 0, sizeof(trustData));
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = NULL;
    trustData.pwszURLReference = NULL;
    trustData.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN | WTD_CACHE_ONLY_URL_RETRIEVAL;
    trustData.dwUIContext = 0;
    trustData.pFile = &fileInfo;

    // 指定要执行的操作，这里是验证文件的数字签名
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // 调用WinVerifyTrust函数来验证文件的数字签名
    LONG status = WinVerifyTrust(NULL, &action, &trustData);

    // Any hWVTStateData must be released by a call with close.
    //释放资源设置关闭标志后再次调用
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &action, &trustData);

    if (status == ERROR_SUCCESS) {
        // 如果WinVerifyTrust函数返回ERROR_SUCCESS，那么文件的数字签名是有效的
        return true;
    } else {
        // 否则，文件的数字签名是无效的
        return false;
    }
}
