//
// Created by Michael on 24-4-29.
//

#ifndef JBC_CLOUDENGINE_H
#define JBC_CLOUDENGINE_H


#include <iostream>
#include <string>

class CloudEngine {
public:
    struct VT_FileReport{
        int httpStatus;
        std::string data;
    };

    static VT_FileReport VT_GetFileReport(const std::string &fileHash);
};


#endif //JBC_CLOUDENGINE_H
