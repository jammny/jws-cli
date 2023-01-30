# JWS-CLI  

> 前言：目标是做一款全自动化信息收集工具，仅需一行命令就解放双手。为了提升脚本小子的编程能力，因此有了这个项目。

| 目标功能      | 完成状态 |
| ----- | ----------- |
| 子域名收集 | success |
| 指纹识别 | success |
| CDN识别 | success    |
| 端口扫描 | success    |
| C段扫描 | None    |
| POC扫描 | None    |

## 下载与部署 
1. 建议在kali下运行：`git clone https://github.com/jammny/jws-cli`

2. 初始化安装依赖：`python3 jws-cli.py`  

![img.png](img.png)

![img_1.png](img_1.png)

## 域名收集

1. 默认情况下，使用内置的模块进行域名收集，具体模块包括：  

```angular2html
1、常用搜索引擎（12）：baidu、bing、fofa、google（国内镜像）、hunter、yandex、zoomeye、360so、sougou、fullhunt、binaryedge、censys  
2、威胁情报平台（2）: alienvault、virustotal  
3、开放的DNS数据集（10）：sitedossier、securitytrails、robtex、dnsdumpster、chinaz、rapiddns、ip138、riddler、qianxian、hackertarget  
4、SSL证书（2）：crtsh、certspotter  
5、支持基于字典的暴力破解， 支持置换扫描技术fuzz更多子域。  
6、支持DNS域传输漏洞检测。  
（模块说明：想使用更多的数据接口可以联系我更新。）
```

2. 有部分模块需要自行到文件`/db/config.yaml`配置API才能正常使用，绝大部分都是可以免费注册的：  

![img_3.png](img_3.png)


3. 常规使用：`python3 jws-cli.py -t example.com --sub`  

![img_2.png](img_2.png)

4、爆破域名模式，有两个爆破模块，目前耗时比较长：`python3 jws-cli.py -t target.com --sub --brute`

## 指纹识别

1. url指纹识别：`python3 jws-cli.py -t https://www.example.com --finger `  

![img_4.png](img_4.png)

2. 域名收集+指纹识别：`python3 jws-cli.py -t example.com --sub --finger`

## CDN识别

1. CDN识别：`python3 jws-cli.py -t example.com --cdn`

![img_6.png](img_6.png)

## 端口扫描

1. 可以在文件`/db/config.yaml`配置扫描参数：

![img_7.png](img_7.png)

2. 端口扫描+指纹识别：`python3 jws-cli.py -t example.com --port --finger`

![img_9.png](img_9.png)

# 报告输出
1. `/reports/`目录下会生成对应目标的html报告文件:

![img_5.png](img_5.png)

## 后续更新：
1. 子域收集将加入代理，用于解决人机验证问题。   
2. 加入C段扫描模块。  
