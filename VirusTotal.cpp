//
// Created by Michael on 24-4-29.
//

#include "VirusTotal.h"
#include <iostream>
#include <string>
#include<curl/curl.h>
//#define CURL_STATICLIB

std::string VirusTotal::GetFileReport(const std::string &fileHash) {
    CURL *hnd = curl_easy_init();

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/files/id");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    CURLcode ret = curl_easy_perform(hnd);
    return std::string();
}
