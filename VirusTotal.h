//
// Created by Michael on 24-4-29.
//

#ifndef JBC_VIRUSTOTAL_H
#define JBC_VIRUSTOTAL_H


#include <iostream>
#include <string>

class VirusTotal {
public:
    static std::string GetFileReport(const std::string &fileHash);
};


#endif //JBC_VIRUSTOTAL_H
