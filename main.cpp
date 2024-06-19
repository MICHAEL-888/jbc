#include <iostream>
#include "FileOperation.h"
#include <filesystem>
//使用Windows.h头文件后严禁使用using namespace std，宏常量产生冲突！
#include <Windows.h>
#include "CloudEngine.h"
//#include <nlohmann/json.hpp>
//#include <pugixml.hpp>
#include <fstream>
//#include <bits/stdc++.h>
#include <thread>
#include <chrono>
#include <mutex>

std::filesystem::path PEM_path;

bool stopFlag = false;

HANDLE hConsole;
COORD currentCoord;


//全局线程锁，避免控制台刷新线程与主线程冲突
std::mutex coutMutex;

struct scanStatus {
    unsigned int total = 0;
    unsigned int scanned = 0;
    unsigned int threat = 0;
};
scanStatus scanStatus;

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

//退出程序回调函数
void cleanup() {
    std::remove(PEM_path.string().c_str());
}

//定时器刷新当前扫描状态
void timerTask() {
    while (!stopFlag) {
        coutMutex.lock();

        COORD coord;
        coord.X = 0;
        coord.Y = 0;
        SetConsoleCursorPosition(hConsole, coord);

        std::cout << "Total: " << scanStatus.total
                  << "    Scanned: " << scanStatus.scanned
                  << "    Threat: " << scanStatus.threat << std::endl << std::endl
                  << "FilePath    Threat    Hash" << std::endl << std::endl;

        //线程冲突需要解决！！！
        //输出后将光标移动到控制台末尾
        SetConsoleCursorPosition(hConsole, currentCoord);

        coutMutex.unlock();

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

int main() {
    std::ofstream fileStream("error.log");
    // 将cerr的流缓冲区设置为文件流的流缓冲区
    std::cerr.rdbuf(fileStream.rdbuf());

    //注册退出回调
    std::atexit(cleanup);

    //写证书到TEMP目录
    PEM_path = std::filesystem::temp_directory_path() / "PEM";
    std::ofstream out(PEM_path);
    out << PEM;
    out.close();

    UINT BackupCP = GetConsoleOutputCP();
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
    std::cout << "3、仅扫描PE文件(exe,dll等)" << std::endl << std::endl;
    std::cout << "Please enter the path: ";

    //getline读入GBK输出也要GBK不然乱码
    //SetConsoleOutputCP(936);
    //SetConsoleCP(936);

    std::string Path;
    getline(std::cin, Path);
    system("cls");
    std::cout << "Total: 0    Scanned: 0    Threat: 0" << std::endl << std::endl;
    std::cout << "FilePath    Threat    Hash" << std::endl << std::endl;

    //string全部是GBK
    //SetConsoleOutputCP(936);
    SetConsoleOutputCP(BackupCP);

    //定义一个FileOperation对象
    //FileOperation fileOp;

    //同理，此处由于中文路径也需要特殊处理
    //std::cout << std::filesystem::path(Path) << std::endl;
    //Path为GBK编码，自动处理
    if (!std::filesystem::exists(std::filesystem::path(Path))) {
        std::cerr << "Path does not exist: " << Path << std::endl;
        return -1;
    }

    //获取控制台句柄
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    //创建线程用于定时刷新扫描状态
    std::thread refreshStatus(timerTask);

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        currentCoord = csbi.dwCursorPosition;
    }

    try {
        //AI给出的解决方案
        //中文路径转宽字符传入filesystem
        std::filesystem::recursive_directory_iterator dir(
                std::filesystem::path(std::filesystem::path(Path)),
                std::filesystem::directory_options::skip_permission_denied), end;

        while (dir != end) {

            //此处判断文件夹是否有权限访问，避免迭代器出错
            if (std::filesystem::is_directory(*dir) && canAccess(*dir) == false) {
                std::cerr << "Permission denied: " << (*dir).path().string() << std::endl;
                dir.disable_recursion_pending();
            }

            try {
                //此处对文件进行操作
                if (!std::filesystem::is_regular_file(*dir)) {
                    ++dir;
                    continue;
                }

                scanStatus.total++;

                if (!FileOperation::isPEFile((*dir).path().string())) {
                    ++dir;
                    continue;
                }
                if ((*dir).file_size() > 512 * 1024 * 1024) {
                    ++dir;
                    continue;
                }
                if (FileOperation::VerifySignature((*dir).path().wstring())) {
                    ++dir;
                    continue;
                }

                struct FileInfo {
                    std::string path;
                    std::string fileName;
                    std::string hash;
                    std::string threat_label;
                };

                FileInfo fileInfo = {};

                fileInfo.path = (*dir).path().string();
                fileInfo.fileName = (*dir).path().filename().string();
                //此处必须直接传string，u8string转一遍后不能正常使用
                fileInfo.hash = FileOperation::calculateMD5((*dir).path().string());

                CloudEngine::QH_FileReport QH_ret;
                QH_ret = CloudEngine::QH_GetFileReport(fileInfo.hash);

                //特殊网络抽风，循环到有结果为止
                while (QH_ret.httpStatus != 200) {
                    QH_ret = CloudEngine::QH_GetFileReport(fileInfo.hash);
                }

                if (QH_ret.attribute == 0) {
                    fileInfo.threat_label = "Undetected";
                } else if (QH_ret.attribute == 1) {
                    fileInfo.threat_label = "Undetected";
                    if (QH_ret.ages <= 3 && QH_ret.pop == 0) {
                        CloudEngine::VT_FileReport VT_ret;
                        VT_ret = CloudEngine::VT_GetFileReport(fileInfo.hash);

                        if (VT_ret.httpStatus == 200) {
                            if (VT_ret.attribute == 1) {
                                fileInfo.threat_label = "Undetected";
                            } else if (VT_ret.attribute == 2) {
                                fileInfo.threat_label = VT_ret.threat_label;
                            }
                        } else if (VT_ret.httpStatus == 404) {
                            //未知文件上传检测，只传一次，失败不重试
                            CloudEngine::VT_UploadFileReport((*dir).path(), (*dir).file_size());
                        } else if (VT_ret.httpStatus == 429) {
                            //此处为重试
                            while (VT_ret.httpStatus == 429) {
                                std::cerr << "请求达到APIKEY速率限制，等待10秒后重试" << std::endl;
                                //Sleep为Windows API的一部分，std库中可使用std::this_thread::sleep_for()
                                //Sleep(1000 * 10);
                                std::this_thread::sleep_for(std::chrono::milliseconds(1000 * 10));
                                VT_ret = CloudEngine::VT_GetFileReport(fileInfo.hash);

                                if (VT_ret.httpStatus == 200) {
                                    if (VT_ret.attribute == 1) {
                                        fileInfo.threat_label = "Undetected";
                                    } else if (VT_ret.attribute == 2) {
                                        fileInfo.threat_label = VT_ret.threat_label;
                                    }
                                } else if (VT_ret.httpStatus == 404) {
                                    CloudEngine::VT_UploadFileReport((*dir).path(), (*dir).file_size());
                                    break;
                                    //后续添加未知文件上传
                                } else if (VT_ret.httpStatus == 429) {
                                    continue;
                                } else {
                                    std::cerr << "VirusTotal接口异常，错误代码：" << VT_ret.httpStatus << std::endl;
                                }
                            }
                        } else {
                            std::cerr << "VirusTotal接口异常，错误代码：" << VT_ret.httpStatus << std::endl;
                        }

                    }
                } else if (QH_ret.attribute == 2) {
                    fileInfo.threat_label = QH_ret.threat_label;
                }

                scanStatus.scanned++;

                //加锁避免冲突
                coutMutex.lock();

                if (fileInfo.threat_label != "Undetected") {
                    scanStatus.threat++;
                    std::cout << fileInfo.fileName << "    "
                              << fileInfo.threat_label << "    "
                              << fileInfo.hash << std::endl;

                    //此处存储控制台光标位置，防止内容覆写
                    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
                        currentCoord = csbi.dwCursorPosition;
                    }
                }

                coutMutex.unlock();


                ++dir;
            } catch (const std::filesystem::filesystem_error &e) {
                std::cerr << "Filesystem error: " << e.what() << std::endl;
                return -1;
            }
        }
    } catch (const std::filesystem::filesystem_error &e) {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return -1;
    }

    //此处等待控制台刷新线程
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    stopFlag = true;

    refreshStatus.join();

    std::cout << std::endl;

    system("pause");

    return 0;

}
