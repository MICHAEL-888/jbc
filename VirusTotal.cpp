//
// Created by Michael on 24-4-29.
//

//Access level
//Limited , standard free public API
//        Upgrade to premium
//Usage 	Must not be used in business workflows, commercial products or services.
//Request rate 	4 lookups / min
//        Daily quota 	500 lookups / day
//        Monthly quota 	15.5 K lookups / month


#include "VirusTotal.h"
#include <iostream>
#include <string>
#include<curl/curl.h>
//#define CURL_STATICLIB
#define APIKEY "a7c30a1033f3351d685910312f5d4118bf2ad9deaedc9f77c6fb3666bca5d3df"

size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *userp) {
    //接收四个参数：一个指向数据的指针，数据项的大小，数据项的数量，以及一个用户定义的指针。
    //这个函数应该返回处理的数据的总字节数（即size * nmemb）
    size_t totalSize = size * nmemb;
    userp->append((char *) contents, totalSize);
    return totalSize;
}

std::string VirusTotal::GetFileReport(const std::string &fileHash) {
    //初始化一个CURL句柄
    CURL *hnd = curl_easy_init();

    //设置CURL句柄的选项为GET请求。
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    //设置CURL句柄的选项，将接收到的数据写入到标准输出(stdout)。
    //curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    //将返回结果写入回调函数当中
    std::string readBuffer;
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &readBuffer);
    //这行代码设置了CURL句柄的选项，指定了请求的URL
    curl_easy_setopt(hnd, CURLOPT_URL, (std::string("https://www.virustotal.com/api/v3/files/") + fileHash).c_str());

    //这行代码定义了一个指向curl_slist结构的指针。curl_slist结构用于存储HTTP头。
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, (std::string("x-apikey: ") + APIKEY).c_str());
    //这行代码设置了CURL句柄的选项，使其在发送请求时使用headers列表中的HTTP头。
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    //执行一个已经设置好选项的CURL操作，并将结果存储在ret变量中。如果操作成功，ret将等于CURLE_OK。
    CURLcode ret = curl_easy_perform(hnd);

    if (ret != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed:" << curl_easy_strerror(ret) << std::endl;
        return "";
    } else {
        return readBuffer;
    }
}


