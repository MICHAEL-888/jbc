//
// Created by Michael on 24-4-29.
//

#ifndef JBC_FILEOPERATION_H
#define JBC_FILEOPERATION_H

//#include <bits/stdc++.h>

class FileOperation {

public:

    static std::string calculateMD5(const std::string &filePath);
    static bool isPEFile(const std::string& filePath);
};


#endif //JBC_FILEOPERATION_H
