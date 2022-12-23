### 安装使用 
1、git clone https://github.com/jammny/jws-cli  
2、python jws-cli.py  
3、域名收集：python jws-cli.py -t target.com --sub  
4、爆破域名模式：python jws-cli.py -t target.com --sub --brute  
5、域名收集+指纹识别：python jws-cli.py -t target.com --sub --finger  
6、url指纹识别：python jws-cli.py -t https://target.com --finger  

### 配置API
1、在db目录下，有一个config.yaml文件，大部分API可以免费注册获取。  
2、当然这里建议花点时间配置一下api，可以将信息收集得更全面。

### 子域收集模块  
1、常用搜索引擎（12）：baidu、bing、fofa、google、hunter、yandex、zoomeye、360so、sougou、fullhunt、binaryedge、censys  
2、威胁情报平台（2）: alienvault、virustotal  
3、开放的DNS数据集（10）：sitedossier、securitytrails、robtex、dnsdumpster、chinaz、rapiddns、ip138、riddler、qianxian、hackertarget  
4、SSL证书（2）：crtsh、certspotter  
5、支持基于字典的暴力破解，支持DNS域传输漏洞检测  
（模块说明：想使用更多的数据接口可以联系我更新。）

### 结果报告输出
1、/reports/ 目录下会生成对应目标的Html报告文件。

### 后续更新：
1、子域收集将加入Altdns模块， 通过置换扫描技术发现更多子域。  
2、子域收集将加入archivecrawl、commoncrawl模块。  
3、子域收集将加入代理，用于解决人机验证问题。   
4、加入CDN识别模块。  
