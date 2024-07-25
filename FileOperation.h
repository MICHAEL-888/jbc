//
// Created by Michael on 24-4-29.
//

#ifndef JBC_FILEOPERATION_H
#define JBC_FILEOPERATION_H

//#include <bits/stdc++.h>
#include <filesystem>

class FileOperation {

public:

    static std::string calculateMD5(const std::filesystem::path& filePath);
    static bool isPEFile(const std::filesystem::path& filePath);
    static bool VerifySignature(const std::wstring& filePath);
};


#endif //JBC_FILEOPERATION_H
