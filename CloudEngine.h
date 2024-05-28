//
// Created by Michael on 24-4-29.
//

#ifndef JBC_CLOUDENGINE_H
#define JBC_CLOUDENGINE_H


#include <iostream>
#include <string>
#include <nlohmann/json.hpp>
#include <pugixml.hpp>

class CloudEngine {
public:
    struct VT_FileReport {
        int httpStatus;
        int attribute;  //0:safe    1:undetected    2:malware
        std::string ESET;
        std::string Kaspersky;
        std::string threat_label;
        std::string malicious;  //暂时不需要用到
    };
    struct QH_FileReport{
        int httpStatus;
        int attribute;  //0:safe    1:undetected    2:malware
        std::string threat_label;
        int ages;
        int pop;
    };

    static VT_FileReport VT_GetFileReport(const std::string &fileHash);

    static QH_FileReport QH_GetFileReport(const std::string &fileHash);
};


#endif //JBC_CLOUDENGINE_H
