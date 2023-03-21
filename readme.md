# JWS-CLI  

> 前言：目标是做一款全自动化信息收集工具，仅需一行命令就解放双手。为了提升脚本小子的编程能力，因此有了这个项目。程序采用模块化设计，所以下面每个模块都可以单独使用。最后，切勿将本工具和技术用于网络犯罪，三思而后行！

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
| 邮箱/微信推送报告 | success |
| 代理负载均衡    | ——      |

## 开始自动化扫描 
1. 扫描器建议在Linux服务器上运行：`git clone https://github.com/jammny/jws-cli`

2. 初始化安装依赖：`pip install -r requirements.txt`  

3. 自动化扫描：`python3 jws-cli.py -t example.com --auto --brute`  

4. 自动化批量扫描：`python3 jws-cli.py -f targets.txt --auto --brute`

5. 可以通过到文件`/db/config.yaml`配置，自行选择需要执行的模块：
```
# 自动化扫描配置，可以选择关闭的模块
auto_setting:
  port_scan: True
  cidr_scan: True
  dir_scan: True
  poc_scan: True
  xray_scan: True
```

## Usage

```yaml
## 子域名收集，有部分模块需要自行到文件`/db/config.yaml`配置API才能正常使用，绝大部分都是可以免费注册的。
常规使用：`python3 jws-cli.py -t example.com --sub`
使用爆破：`python3 jws-cli.py -t example.com --sub --brute`

## 指纹识别
常规使用：`python3 jws-cli.py -t http://example.com --finger`

## CDN识别
常规使用：`python3 jws-cli.py -t example.com --cdn`

## 端口扫描，扫描参数需要到件`/db/config.yaml`配置。
常规使用：`python3 jws-cli.py -t 192.168.2.1 --port`

## C段扫描
常规使用：`python3 jws-cli.py -t 192.168.2.1/24 --cidr`

## waf识别
常规使用：`python3 jws-cli.py -t example.com --waf`

## 目录扫描， 目前是直接调用dirsearch来实现，需要到`/db/dirsearch.ini`配置。
常规使用：`python3 jws-cli.py -t http://example.com --dir`

## poc扫描， 除了内置的poc框架之外，还支持调用其他漏扫引擎，需要到`/db/config.yaml`配置。

常规使用：`python3 jws-cli.py -t http://example.com --poc`

## xray扫描

常规使用：`python3 jws-cli.py -t http://example.com --xray`

## 邮件、微信通知
注意：需要到config.yaml文件中进行邮箱信息配置信息，微信关联一下邮箱就行了。

# 报告输出
`/reports/`目录下会生成对应目标的html报告文件，还有json结果文件。
`/reports/tmp/`目录下会生成每个模块输出的结果信息。

```

## 联系我们

![img.png](./img/fighter.jpg)


