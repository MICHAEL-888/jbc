#include <iostream>
#include "FileOperation.h"
#include <filesystem>
//使用Windows.h头文件后严禁使用using namespace std，宏常量产生冲突！
#include <Windows.h>
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


int main() {
    //控制台编码默认936为GBK编码，代码文件采用65001 UTF-8编码
    //编码不同导致无法正确输出中文，此处设置控制台编码为UTF-8
    SetConsoleOutputCP(CP_UTF8);
    //设置控制台输入编码为UTF-8，getline耍大牌单字节读入，设置UTF-8会出错
    //SetConsoleCP(CP_UTF8);

    std::cout << "***Created by Michael***" << std::endl << std::endl;
    std::cout << "使用提示：" << std::endl;
    std::cout << "1、访问高权限文件夹会报错退出" << std::endl;
    //这行输出很奇妙，不好评价，导致我去找半天getline的BUG
    std::cout << "2、请输入文件夹路径例如:\"D:\\Folder\"" << std::endl;

    //getline读入GBK输出也要GBK不然乱码
    SetConsoleOutputCP(936);
    //SetConsoleCP(936);

    std::string Path;
    getline(std::cin, Path);
    std::cout << Path << std::endl;

    //再次设为UTF-8,要不然pause命令又乱码666
    SetConsoleOutputCP(CP_UTF8);

    //定义一个FileOperation对象
    //FileOperation fileOp;

    if (!std::filesystem::exists(Path)) {
        std::cerr << "Path does not exist: " << Path << std::endl;
        //return -1;
    }

    try {
        std::filesystem::recursive_directory_iterator dir(Path,
                                                          std::filesystem::directory_options::skip_permission_denied), end;

        while (dir != end) {

            //此处判断文件夹是否有权限访问，避免迭代器出错
            if (std::filesystem::is_directory(*dir) && canAccess(*dir) == false) {
                dir.disable_recursion_pending();
                //std::cout << *dir << "|" << std::filesystem::exists(*dir) << "|" << std::filesystem::is_directory(*dir)
                //<< "|" << canAccess(*dir) << std::endl;

            }

            try {
                if (std::filesystem::is_regular_file(*dir)) {
                    std::string temp = (*dir).path().string();
                    std::cout << "FilePath:" << temp << std::endl << "MD5:" << FileOperation::calculateMD5(temp)
                              << std::endl;
                }
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
    system("pause");
    return 0;

}
