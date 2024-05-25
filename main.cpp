#include <iostream>
#include "FileOperation.h"
#include <filesystem>
//使用Windows.h头文件后严禁使用using namespace std，宏常量产生冲突！
#include <Windows.h>
#include "VirusTotal.h"
#include <nlohmann/json.hpp>
//#include <bits/stdc++.h>

//通过创建文件夹迭代器的方式判断程序有无权限访问，避免出错
bool canAccess(const std::filesystem::path &p) {
    try {
        std::filesystem::directory_iterator{p};
        return true;
    } catch (const std::filesystem::filesystem_error &e) {
        return false;
    }
}

std::string convertPath(const std::u8string &path) {
    return std::string(path.begin(), path.end());


}

int main() {
    //控制台编码默认936为GBK编码，代码文件采用65001 UTF-8编码
    //编码不同导致无法正确输出中文，此处设置控制台编码为UTF-8
    SetConsoleOutputCP(CP_UTF8);
    //设置控制台输入编码为UTF-8，getline耍大牌单字节读入，设置UTF-8会出错
    //SetConsoleCP(CP_UTF8);

    std::cout << "***Created by Michael***" << std::endl << std::endl;
    std::cout << "使用提示：" << std::endl;

    //这行输出很奇妙，不好评价，导致我去找半天getline的BUG;
    std::cout << "1、请输入文件夹路径例如:\"D:\\Folder\"" << std::endl;
    std::cout << "2、根目录请以\"\\\"结尾" << std::endl;
    std::cout << "3、仅扫描PE文件(exe,dll等)" << std::endl;

    //getline读入GBK输出也要GBK不然乱码
    //SetConsoleOutputCP(936);
    //SetConsoleCP(936);

    std::string Path;
    getline(std::cin, Path);
    std::cout << "FileName    Result    Hash" << std::endl;

    //再次设为UTF-8,要不然pause命令又乱码666
    //SetConsoleOutputCP(CP_UTF8);

    //定义一个FileOperation对象
    //FileOperation fileOp;

    //同理，此处由于中文路径也需要特殊处理
    if (!std::filesystem::exists(std::filesystem::path(std::u8string((char8_t *) Path.c_str())))) {
        std::cerr << "Path does not exist: " << Path << std::endl;
    }

    try {
        //AI给出的解决方案
        //中文路径转宽字符传入filesystem
        std::filesystem::recursive_directory_iterator dir(
                std::filesystem::path(std::u8string((char8_t *) Path.c_str())),
                std::filesystem::directory_options::skip_permission_denied), end;

        while (dir != end) {

            //此处判断文件夹是否有权限访问，避免迭代器出错
            if (std::filesystem::is_directory(*dir) && canAccess(*dir) == false) {
                dir.disable_recursion_pending();
            }

            try {
                //此处对文件进行操作
                if (!std::filesystem::is_regular_file(*dir)) {
                    ++dir;
                    continue;
                }
                if (!FileOperation::isPEFile((*dir).path().string())) {
                    ++dir;
                    continue;
                }
                if((*dir).file_size() > 512 * 1024 * 1024){
                    ++dir;
                    continue;
                }

                struct FileInfo {
                    std::string path;
                    std::string fileName;
                    std::string hash;
                    std::string ret;
                    std::string ESET;
                    std::string Kaspersky;
                    std::string threat_label;
                    std::string malicious;  //暂时不需要用到
                } fileInfo;

                fileInfo.path = convertPath((*dir).path().u8string());
                fileInfo.fileName = convertPath((*dir).path().filename().u8string());
                //此处必须直接传string，u8string转一遍后不能正常使用
                fileInfo.hash = FileOperation::calculateMD5((*dir).path().string());
                fileInfo.ret = VirusTotal::GetFileReport(fileInfo.hash);

                //此处为简单判断，后续会补充判断HTTP状态码
                if (!fileInfo.ret.empty() && fileInfo.ret.find("error") == std::string::npos) {
                    //解析JSON字符串，使用"[]"访问对象
                    nlohmann::json jsonObject = nlohmann::json::parse(fileInfo.ret);
                    //fileInfo.malicious = jsonObject["data"]["attributes"]["last_analysis_stats"]["malicious"];
                    //需要判断json对象是否存在否则报错！！！
                    if (!jsonObject["data"]["attributes"]["last_analysis_results"]["ESET-NOD32"]["result"].is_null()) {
                        fileInfo.ESET = jsonObject["data"]["attributes"]["last_analysis_results"]["ESET-NOD32"]["result"];
                    }
                    if (!jsonObject["data"]["attributes"]["last_analysis_results"]["Kaspersky"]["result"].is_null()) {
                        fileInfo.Kaspersky = jsonObject["data"]["attributes"]["last_analysis_results"]["Kaspersky"]["result"];
                    }
                } else {
                    while (fileInfo.ret.empty()) {
                        std::cout << "查询出现错误，可能是APIKEY速率限制，等待10秒后重试" << std::endl;
                        //Sleep为Windows API的一部分，std库中可使用std::this_thread::sleep_for()
                        Sleep(1000 * 10);
                        fileInfo.ret = VirusTotal::GetFileReport(fileInfo.hash);

                        //解析JSON字符串，使用"[]"访问对象
                        nlohmann::json jsonObject = nlohmann::json::parse(fileInfo.ret);
                        //fileInfo.malicious = jsonObject["data"]["attributes"]["last_analysis_stats"]["malicious"];
                        //需要判断json对象是否存在否则报错！！！
                        if (!jsonObject["data"]["attributes"]["last_analysis_results"]["ESET-NOD32"].is_null()) {
                            fileInfo.ESET = jsonObject["data"]["attributes"]["last_analysis_results"]["ESET-NOD32"]["result"];
                        }
                        if (!jsonObject["data"]["attributes"]["last_analysis_results"]["Kaspersky"].is_null()) {
                            fileInfo.Kaspersky = jsonObject["data"]["attributes"]["last_analysis_results"]["Kaspersky"]["result"];
                        }
                    }
                }

                if (!fileInfo.Kaspersky.empty()) {
                    //此处暂未过滤Hacktool报法，后续更新
                    if (fileInfo.Kaspersky.find("not-a-virus") == std::string::npos &&
                        fileInfo.Kaspersky.find("Packed") == std::string::npos &&
                        fileInfo.Kaspersky.find("Keygen") == std::string::npos) {

                        fileInfo.threat_label = fileInfo.Kaspersky;
                    }
                } else if (!fileInfo.ESET.empty()) {
                    //此处暂未过滤Hacktool报法，后续更新
                    if (fileInfo.ESET.find("Packed") == std::string::npos &&
                        fileInfo.ESET.find("Keygen") == std::string::npos &&
                        fileInfo.ESET.find("FlyStudio") == std::string::npos &&
                        fileInfo.ESET.find("BlackMoon") == std::string::npos) {

                        fileInfo.threat_label = fileInfo.ESET;
                    }
                }
                if (fileInfo.threat_label.empty()) {
                    fileInfo.threat_label = "Undetected";
                }
                std::cout << fileInfo.fileName << "    "
                          << fileInfo.threat_label << "    "
                          << fileInfo.hash << std::endl;

                ++dir;
            } catch (const std::filesystem::filesystem_error &e) {
                std::wcerr << "Filesystem error: " << e.what() << std::endl;
                return -1;
            }
        }
    } catch (const std::filesystem::filesystem_error &e) {
        std::wcerr << "Filesystem error: " << e.what() << std::endl;
        return -1;
    }


    system("pause");
    return 0;

}
