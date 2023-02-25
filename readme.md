# JWS-CLI  

> 前言：目标是做一款全自动化信息收集工具，仅需一行命令就解放双手。为了提升脚本小子的编程能力，因此有了这个项目。

| 目标功能      | 完成状态    |
|-----------|---------|
| 子域名收集     | success |
| 指纹识别      | success |
| CDN识别     | success |
| 端口扫描      | success |
| C段扫描      | success |
| waf识别     | success |
| 目录扫描      | success |
| POC扫描     | success |
| Xray扫描    | success |
| 支持批量扫描    | success |
| 邮箱/微信推送报告 | ——      |
| 代理负载均衡    | ——      |

## 下载与部署 
1. 扫描器建议在Linux服务器上运行：`git clone https://github.com/jammny/jws-cli`

2. 初始化安装依赖：`pip install -r requirements.txt`  

3. 程序运行：`python3 jws-cli.py -t example.com --auto`  


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

2. 有部分模块需要自行到文件`/db/config.yaml`配置API才能正常使用，绝大部分都是可以免费注册的。  


3. 常规使用：`python3 jws-cli.py -t example.com --sub`


# 报告输出
1. `/reports/`目录下会生成对应目标的html报告文件。


