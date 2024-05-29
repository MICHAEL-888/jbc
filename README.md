# 文件扫描套件

程序功能为判断文件安全性

### 已实现：

1、支持含有中文及特殊Unicode目录及文件扫描

2、静态链接编译

3、启动时获取管理员权限，支持系统盘符遍历

4、接入VirusTotal平台

5、仅扫描PE文件

6、跳过大于512MB的文件

7、HTTP状态码判断

8、错误信息写文件error.log

9、支持校验文件数字签名有效性

10、接入360云查杀平台

### 未实现：

1、可疑文件上传扫描

2、文件映射内存

3、图形化界面

4、校验文件数字签名有效期（有待考量）

5、多线程

6、Hacktool报法过滤（没有样本）

7、加一个字符画

8、运行前先检查网络

9、ini设置文件

10、加一个进度条

11、360云查批量校验

12、多APIKEY负载均衡

——————————————

### 扩展功能：

1、解构PE文件

2、API导入表检测查杀

——————————————

### 待修复BUG:（lazy）

1、输入不存在的盘符会导致程序崩溃

2、CURL SSL Connect Error

3、证书吊销性检查可能导致扫描速度减慢

### 提示：

构建程序前需安装OpenSSL库、CURL库、nlohmann库、pugixml库

请安装Windows SDK套件

目前只支持amd64平台哦

程序采用MSVC构建，请使用utf-8编码

自带一个APIKEY，不可以滥用

TestFile目录下Safe.txt为测试文件，Unsafe.txt为安全软件通用测试代码

请勿使用Clion自带控制台调试，请勾选外部控制台选项

### 关于中文编码问题

程序先前采用MinGW工具链构建，我花费了好几天时间研究中文编码问题，控制台读入与输出，哪些是UTF-8哪些是GBK，哪里编码不一致需要转换，哪里要转宽字节等等，最终总算是解决问题。

后来由于Windows环境下C/C++导入第三方库实在是过分的麻烦，链接这个链接那个，一个库又要链接好多个库，自己编译真的心累。大家都说Vcpkg好用，行我尝试一下，我在Clion里面尝试安装，结果反反复复网络错误，v2是系统代理模式，而git又需要单独设置代理不会自动检测，跟Clion里面的设置无关，好吧解决了，然后又发现它非要我装Visual Studio，
把各种库都安装完成之后程序编译又出错了，噢不能再用gcc和g++，必须要用MSVC编译器，好吧我换！
换完之后原本正常的代码又开始弹一大堆莫名奇妙的问题，全部都和编码有关，一顿捣鼓程序算是能正常运行，编码转换过去转换过来真就是乱搞。

我真就不明白了为什么各个编译器不能统一标准？非要恶心人

最后感谢Github Copilot老师帮助我解决90%以上的问题，学习了非常多


