# JWS-CLI  

> 前言：目标是做一款全自动化信息收集工具，仅需一行命令就解放双手。本项目适用于辅助测试人员在攻防演练和SRC项目场景下进行快速信息收集和资产梳理。所以下面每个模块都可以单独使用。最后，切勿将本工具和技术用于网络犯罪，三思而后行！

| 实现功能     | 完成状态    | 调用第三方模块 |
|----------|---------|---------|
| 子域名收集    | success | ----    |
| 指纹识别     | success | ----    |
| CDN识别    | success | ----    |
| 端口扫描     | success | ----    |
| C段扫描     | success | ----    |
| waf识别    | success | wafw00f |
| 目录扫描     | success | ffuf    |
| POC扫描    | success | afrog   |
| 支持批量扫描   | success | ----    |
| 生成扫描报告   | success | ----    |
| 邮箱推送报告   | success | ----    |
| 代理负载均衡   | ----    | ----    |
| 可视化WEB操作 | ----    | ----    |
| 资产监控管理   | ----    | ----    |

## 一键自动化扫描 
1. 扫描器建议在Linux服务器上运行：`git clone https://github.com/jammny/jws-cli.git`
2. 初始化安装依赖：`pip install -r requirements.txt`
3. 一键自动化扫描：`python jws-cli.py -t example.com --auto`
4. 一键自动化批量扫描：`python jws-cli.py -f targets.txt --auto`

## Usage

```yaml
## 自动化扫描
python jws-cli.py -t example.com --auto

## 子域名收集
python jws-cli.py -t example.com --sub

## 指纹识别
python jws-cli.py -t https://example.com --finger

## CDN识别
python jws-cli.py -t example.com --cdn

## 端口扫描
python jws-cli.py -t 192.168.2.1 --port

## C段扫描
python jws-cli.py -t 192.168.2.0/24 --cidr

## waf识别
python jws-cli.py -t example.com --waf

## 目录扫描
python jws-cli.py -t https://example.com --dir

## poc扫描
python jws-cli.py -t https://example.com --poc

## fofa接口调用，将收集结果用于其他模块：
用于指纹识别：python3 jws-cli.py -q "FOFA语句" --fofa --finger
用于poc扫描：python3 jws-cli.py -q "FOFA语句" --fofa --poc

## 企业信息查询
python jws-cli.py -t 百度 --firm

# 报告输出
`/reports/`目录下会生成对应目标的html报告文件，还有json结果文件。
`/reports/tmp/`目录下会生成每个模块输出的结果信息。
```

## Config.yaml
`/db/config.yaml`配置文件很重要，在这个文件里你可以自定义配置，自动化扫描时所需要开启的模块：
```yaml
## 自动化扫描配置，可以选择开启/关闭的模块
auto_setting:
  port_scan: True     # 开启/关闭 端口扫描
  cidr_scan: True     # 开启/关闭 C段扫描
  waf_scan: True      # 开启/关闭 WAF扫描
  dir_scan: False      # 开启/关闭 目录扫描
  poc_scan: False      # 开启/关闭 POC扫描
```
当然你可以给子域名收集模块配置更多的api，让它的能力更强大：<br/>
```yaml
## 子域名扫描配置
sub_scan:
  brute_scan: True      # 开启/关闭 爆破模式
  brute_thread: 1000    # 爆破域名时候的线程
  brute_fuzzy: False     # 开启/关闭 域名置换（注意：如果fuzz生成的字典较大，可能会导致爆破时间很长。）

  api_key:
    # zoomeye可以免费注册帐号密码
    # https://www.zoomeye.org/
    zoomeye_mail:
    zoomeye_pass:

    # hunter的api可免费获取，每天限量500条数据
    # https://hunter.qianxin.com/
    hunter_key:

    # securitytrails的api可免费获取
    # https://securitytrails.com
    securitytrails_key:

    # fullhunt的api可免费获取
    # https://fullhunt.io/search
    fullhunt_key:

    # Binaryedge免费注册获取API, 有效期只有1个月，到期之后可以再次生成，每月可以查询250次。
    # https://app.binaryedge.io/account/api
    binaryedge_key:

    # censys可以免费注册一个账号，填上你的账号密码即可。
    # https://search.censys.io/
    censys_username:
    censys_password:

    # fofa的api需要自费获取，因为我有key，所以就加一个吧
    # https://fofa.info/
    fofa_email:
    fofa_key:
    fofa_size: 1000
```
端口扫描范围格式支持解析："80,443"、"80,8080,8090-10000"、"1-65535"，如果你选择跳过IP存活检测，那么无论如何都会对每个目标进行端口扫描。反之，如果目标不存活那么它将被抛弃。
```yaml
## 端口扫描配置
port_scan:
  timeout: 5
  thread_num : 1000
  port_range: '21,22,23,80-99,135,139,442-445,666,800,801,808,880,888,889,1000-2379,3000-10010,11115,12018,12443,14000,16080,18000-18098,19001,19080,20000,20720,21000,21501,21502,28018,20880,27017'
  skip_alive: True  # 跳过IP存活检测
```

将邮件关联到微信，就可以在微信查收HTML扫描报告：
```yaml
# 163邮箱信息配置
smtp_server: smtp.163.com         # 邮箱服务器
smtp_port: 465                    # 端口号
send_email:                       # 发件人邮箱账号
send_pass:                        # 发件人邮箱授权码
rec_email:                        # 收件人邮箱,如果有多个收件人可以使用英文逗号隔开
```

当然可配置内容还有很多，其他模块的参数可以自行琢磨一下。

## 程序兼容性问题  

由于scapy库依赖的限制，所以如果你想在windows上运行此程序，你可能需要安装好nmap工具。因为项目的开发环境是Kali Linux，所以其实我还是更建议在Linux上运行此程序，当然如果你在VPS（linux）上扫描体验会更好。</br>

程序兼容环境： windows、Linux </br>
python版本 >= 3.8.0

## Update

| 更新时间（版本）          | 更新内容                                                                                         | 备注     |
|-------------------|----------------------------------------------------------------------------------------------|--------|
| 2023.5.29(v0.1.0) | 1、优化端口泛滥、域名泛滥处理逻辑。                                                                           |有问题联系我|
| 2023.5.12(v0.0.9) | 1、修复cidr模块单独使用出现的bug 。<br/>2、新增支持添加多个收邮人邮箱。<br/>                                             |   有问题联系我     |
| 2023.5.7(v0.0.8)  | 1、针对特殊情况下域名泛解析结果进行优化。<br/>2、新增html报告支持表格数据导出。<br/>3、新增配置参数python_name。                       |   有问题联系我     |
| 2023.5.6(v0.0.7)  | 1、修复一些程序业务逻辑bug。<br/>2、新增firm接口，实现企业信息查询功能，<br/>支持自动将结果生成excel表格。<br/> 3、配置文件新增debug_info选项。 |    有问题联系我    |

## Wechat

![img.png](./db/fightersec_wechat.jpg)
