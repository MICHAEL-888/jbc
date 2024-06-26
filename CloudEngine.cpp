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


#include "CloudEngine.h"
#include <iostream>
#include <string>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <pugixml.hpp>
#include <openssl/evp.h>
#include <fstream>
#include <vector>
//#define CURL_STATICLIB

extern std::filesystem::path PEM_path;

size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *userp) {
    //接收四个参数：一个指向数据的指针，数据项的大小，数据项的数量，以及一个用户定义的指针。
    //用户定义指针由这行代码确定curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &data);
    //这个函数应该返回处理的数据的总字节数（即size * nmemb）
    size_t totalSize = size * nmemb;
    userp->append((char *) contents, totalSize);
    return totalSize;
}

std::string Base64Encode(const std::string &filePath, const unsigned int binary_size) {
    //传入路径 及 文件大小

    // 创建一个编码上下文对象
    EVP_ENCODE_CTX *ectx = EVP_ENCODE_CTX_new();
    // 初始化Base64编码过程
    EVP_EncodeInit(ectx);

    // 此处仿照md5计算方法采取文件流读入形式
    // 以二进制模式打开文件
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        // 文件打开失败，返回空字符串
        return "";
    }

    // 计算编码后的长度，Base64编码规则是每3个字节编码为4个字符
    int out_length1 = (binary_size + 2) / 3 * 4;
    int out_length2, out_length3 = 0;

    // 创建一个缓冲区，用于读取文件
    char buf[1024 * 16];
    // 创建输出缓冲区，base64编码大33%，避免溢出设置2倍，+1为AI建议
    std::vector<unsigned char> out(out_length1 * 2 + 1);
    // 循环读取文件，直到文件结束
    while (file.good()) {
        // 从文件中读取数据到缓冲区
        file.read(buf, sizeof(buf));
        // 更新MD5哈希值
        EVP_EncodeUpdate(ectx, out.data(), &out_length2, reinterpret_cast<unsigned char *>(buf), file.gcount());
        out_length3 += out_length2;
    }

    EVP_EncodeFinal(ectx, out.data() + out_length3, &out_length2);

    // 释放编码上下文对象
    EVP_ENCODE_CTX_free(ectx);

    // 将编码后的二进制数据转换为字符串并返回
    return std::string(reinterpret_cast<char *>(out.data()));

}

CloudEngine::VT_FileReport CloudEngine::VT_GetFileReport(const std::string &fileHash) {

    VT_FileReport fileReport = {};

    //初始化一个CURL句柄
    CURL *hnd = curl_easy_init();

    std::string data;

    //设置CURL句柄的选项为GET请求。
    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
    //设置CURL句柄的选项，将接收到的数据写入到标准输出(stdout)。
    //curl_easy_setopt(hnd, CURLOPT_WRITEDATA, stdout);
    //将返回结果写入回调函数当中
    //std::string readBuffer;
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &data);
    //这行代码设置了CURL句柄的选项，指定了请求的URL
    curl_easy_setopt(hnd, CURLOPT_URL, (std::string("https://www.virustotal.com/api/v3/files/") + fileHash).c_str());
    //openssl默认不使用系统CA存储进行证书校验，需要单独设置标志
    curl_easy_setopt(hnd, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);

    //这行代码定义了一个指向curl_slist结构的指针。curl_slist结构用于存储HTTP头。
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, (std::string("x-apikey: ") + API_KEY).c_str());
    //这行代码设置了CURL句柄的选项，使其在发送请求时使用headers列表中的HTTP头。
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

    //执行一个已经设置好选项的CURL操作，并将结果存储在ret变量中。如果操作成功，ret将等于CURLE_OK。
    CURLcode ret = curl_easy_perform(hnd);

    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &fileReport.httpStatus);
    //std::cout << fileReport.httpStatus << std::endl;

    curl_easy_cleanup(hnd);
    if (ret != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed:" << curl_easy_strerror(ret) << std::endl;
        return fileReport;
    } else {
        if (fileReport.httpStatus == 200) {
            //解析JSON字符串，使用"[]"访问对象
            nlohmann::json jsonObject = nlohmann::json::parse(data);
            //fileInfo.malicious = jsonObject["data"]["attributes"]["last_analysis_stats"]["malicious"];
            //需要判断json对象是否存在否则报错！！！
            if (!jsonObject["data"]["attributes"]["last_analysis_results"]["ESET-NOD32"]["result"].is_null()) {
                fileReport.ESET = jsonObject["data"]["attributes"]["last_analysis_results"]["ESET-NOD32"]["result"];
            }
            if (!jsonObject["data"]["attributes"]["last_analysis_results"]["Kaspersky"]["result"].is_null()) {
                fileReport.Kaspersky = jsonObject["data"]["attributes"]["last_analysis_results"]["Kaspersky"]["result"];
            }
            if (!fileReport.Kaspersky.empty()) {
                //此处暂未过滤Hacktool报法，后续更新
                if (fileReport.Kaspersky.find("not-a-virus") == std::string::npos &&
                    fileReport.Kaspersky.find("Packed") == std::string::npos &&
                    fileReport.Kaspersky.find("Keygen") == std::string::npos) {

                    fileReport.threat_label = fileReport.Kaspersky;
                }
            } else if (!fileReport.ESET.empty()) {
                //此处暂未过滤Hacktool报法，后续更新
                if (fileReport.ESET.find("Packed") == std::string::npos &&
                    fileReport.ESET.find("Keygen") == std::string::npos &&
                    fileReport.ESET.find("FlyStudio") == std::string::npos &&
                    fileReport.ESET.find("BlackMoon") == std::string::npos) {

                    fileReport.threat_label = fileReport.ESET;
                }
            }
            if (fileReport.threat_label.empty()) {
                fileReport.attribute = 1;
                fileReport.threat_label = "Undetected";
            } else {
                fileReport.attribute = 2;
            }
        }
        return fileReport;
    }
}

CloudEngine::VT_UploadFile CloudEngine::VT_UploadFileReport(const std::filesystem::path filePath, const unsigned int binary_size) {
    VT_UploadFile uploadFile = {};
    std::string data;
    CURL *hnd = curl_easy_init();
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &data);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "accept: application/json");
    headers = curl_slist_append(headers, "content-type: multipart/form-data");
    headers = curl_slist_append(headers, (std::string("x-apikey: ") + API_KEY).c_str());
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &uploadFile.httpStatus);

    std::string contentType = "data:application/x-msdownload;name=" + filePath.filename().string() + ";base64," + Base64Encode(filePath.string(), file_size(filePath));

    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        // 文件打开失败，返回空字符串
        return uploadFile;
    }

    std::vector<unsigned char> buf(binary_size);
    file.read(reinterpret_cast<char *>(buf.data()), binary_size);


    //CURL对中文字符处理存在问题，此处传递utf-8编码字符
    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "file",
                 CURLFORM_BUFFER, filePath.filename().u8string().c_str(),
                 CURLFORM_BUFFERPTR, buf.data(),
                 CURLFORM_BUFFERLENGTH, binary_size,
                 CURLFORM_END);

//    std::cerr << filePath.string().c_str() << std::endl;
//    std::cerr << "_____" << std::endl;

    //openssl默认不使用系统CA存储进行证书校验，需要单独设置标志
    curl_easy_setopt(hnd, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.virustotal.com/api/v3/files");
    curl_easy_setopt(hnd, CURLOPT_HTTPPOST, formpost);

    CURLcode ret = curl_easy_perform(hnd);
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &uploadFile.httpStatus);

    curl_easy_cleanup(hnd);
    curl_formfree(formpost);
    if (ret != CURLE_OK) {
        std::cerr << "VT文件上传异常:" << curl_easy_strerror(ret) << std::endl;
        return uploadFile;
    } else {
        if (uploadFile.httpStatus == 200) {
            nlohmann::json jsonObject = nlohmann::json::parse(data);
            if (!jsonObject["data"]["id"].is_null()) {
                uploadFile.ret = jsonObject["data"]["id"];
            }
        }
        //此处获取到id后可通过api查询文件扫描状态，目前没有必要，浪费api次数
//        std::cerr << data << std::endl;
        return uploadFile;
    }
}

CloudEngine::QH_FileReport CloudEngine::QH_GetFileReport(const std::string &fileHash) {

//    -------------------------------7d83e2d7a141e
//    Content-Disposition: form-data; name="md5s"
//
//    @@@@@@@@@@		10485760 (风险)regqq.exe
//
//    -------------------------------7d83e2d7a141e
//    Content-Disposition: form-data; name="format"
//
//    XML
//    -------------------------------7d83e2d7a141e
//    Content-Disposition: form-data; name="product"
//
//    360safe
//            -------------------------------7d83e2d7a141e
//    Content-Disposition: form-data; name="combo"
//
//    360safe
//            -------------------------------7d83e2d7a141e
//    Content-Disposition: form-data; name="v"
//
//    2
//            -------------------------------7d83e2d7a141e
//    Content-Disposition: form-data; name="osver"
//
//    12
//            -------------------------------7d83e2d7a141e
//    Content-Disposition: form-data; name="vk"
//
//    a03bc211
//    -------------------------------7d83e2d7a141e
//    Content-Disposition: form-data; name="mid"
//
//    8a40d9eff408a78fe9ec10a0e7e60f62
//    -------------------------------7d83e2d7a141e--


    QH_FileReport fileReport = {};
    std::string data;
    CURL *hnd = curl_easy_init();
    //curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
    //curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYHOST, 0L);

//    //openssl默认不使用系统CA存储进行证书校验，需要单独设置标志
//    curl_easy_setopt(hnd, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
    //360忘记给这个域名上证书了，搞得我烦
    //总之先单独设置一下证书，360接口的证书一会儿有一会儿没有的
    curl_easy_setopt(hnd, CURLOPT_CAINFO, PEM_path.string().c_str());
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;

    curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &data);
    struct curl_slist *headers = NULL;
    //headers = curl_slist_append(headers, "accept: application/json");
    curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &fileReport.httpStatus);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "md5s",
                 CURLFORM_COPYCONTENTS, (fileHash + std::string("		10485760 (风险)regqq.exe")).c_str(),
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "format",
                 CURLFORM_COPYCONTENTS, "XML",
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "product",
                 CURLFORM_COPYCONTENTS, "360safe",
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "combo",
                 CURLFORM_COPYCONTENTS, "360safe",
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "v",
                 CURLFORM_COPYCONTENTS, "2",
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "osver",
                 CURLFORM_COPYCONTENTS, "12",
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "vk",
                 CURLFORM_COPYCONTENTS, "a03bc211",
                 CURLFORM_END);

    curl_formadd(&formpost,
                 &lastptr,
                 CURLFORM_COPYNAME, "mid",
                 CURLFORM_COPYCONTENTS, "8a40d9eff408a78fe9ec10a0e7e60f62",
                 CURLFORM_END);

    curl_easy_setopt(hnd, CURLOPT_URL, "https://qup.f.360.cn/file_health_info.php");
    curl_easy_setopt(hnd, CURLOPT_HTTPPOST, formpost);

    CURLcode ret = curl_easy_perform(hnd);
    curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &fileReport.httpStatus);

    curl_easy_cleanup(hnd);
    curl_formfree(formpost);
    if (ret != CURLE_OK) {
        std::cerr << "360云查接口异常:" << curl_easy_strerror(ret) << std::endl;
        return fileReport;
    } else {
        if (fileReport.httpStatus == 200) {
            std::string xml = data;

            pugi::xml_document doc;
            pugi::xml_parse_result result = doc.load_string(xml.c_str());

            if (result) {
                fileReport.pop = std::stoi(doc.child("ret").child("softs").child("soft").child_value("pop"));
                fileReport.ages = std::stoi(doc.child("ret").child("softs").child("soft").child_value("age"));
                float e_level = std::stof(doc.child("ret").child("softs").child("soft").child_value("e_level"));
                if (e_level <= 20) {
                    fileReport.attribute = 0;
                } else if (e_level > 20 && e_level < 50) {
                    fileReport.attribute = 1;
                } else if (e_level >= 50) {
                    fileReport.attribute = 2;
                    fileReport.threat_label = doc.child("ret").child("softs").child("soft").child_value("malware");
                }

            } else {
                std::cerr << "XML parsed with errors, attr value: [" << doc.child("node").attribute("attr").value()
                          << "]\n";
                std::cerr << "Error description: " << result.description() << "\n";
                std::cerr << "Error offset: " << result.offset << " (error at [..." << (xml.c_str() + result.offset)
                          << "]\n\n";
            }
        }
        return fileReport;
    }
}




