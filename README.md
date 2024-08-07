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

11、加个UPX

12、扫描进度显示

13、可疑文件上传扫描（不等待扫描结果，待多线程完善）

14、支持多线程扫描

### 未实现：

1、图形化界面

2、加一个字符画

3、运行前先检查网络

4、ini设置文件

5、多APIKEY负载均衡

——————————————

### 扩展功能：

1、解构PE文件

2、API导入表检测查杀

——————————————

### 暂不考虑：

1、文件映射内存

——————————————

### 待修复BUG:

1、系统盘有些畸形文件或文件夹造成扫描出错，尽管已经排除了部分（uwp应用文件夹，Microsoft Defender之类），但仍然存在扫描出错问题
，太麻烦了不好解决，filesystem迭代器报错会直接让程序退出

### 提示：

构建程序前需安装OpenSSL库、CURL库(with openssl)、nlohmann库、pugixml库

请安装Windows SDK套件

目前只支持amd64平台哦

程序采用MSVC构建，请使用utf-8编码

自带一个APIKEY，不可以滥用

请勿使用Clion自带控制台调试，请勾选外部控制台选项

### 注意：

360云查接口间歇性抽风问题我已查明原因，上海(移动/电信/联通)，河南移动机房不可用，
简单的解决方案是更换不同的dns 直到能够正常使用为止，
另外一种解决方案是手动hosts绑定接口到北京或河南(电信/联通)的ip，但是ip很容易失效需要重新绑定
且用且珍惜，接口已经被封过一次了，现在还没封彻底而已，严禁滥用！

最后感谢Github Copilot老师帮助我解决90%以上的问题，学习了非常多


