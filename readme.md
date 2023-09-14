
<h2 align="center">JWS-CLI</h2>

> 前言：信息收集是渗透测试中最重要的一环，也是最繁琐和机械化的一环。jws-cli 是一款基于python的可拓展、可定制化的一键信息收集工具，适用于辅助测试人员在攻防演练和SRC项目场景下进行快速信息收集和资产梳理。

### 工具特点预览
1. 对目标资产实现一键收集：子域名收集+CDN识别+端口扫描+WEB指纹识别+C段扫描+WAF识别。
2. 支持把企业全称（如：XX有限公司）作为收集目标，程序将自动化收集关于目标企业的相关资产。
3. 支持通过编写配置文件来拓展DNS数据集，以增加子域名收集模块的灵活性。
4. 支持调用你喜欢的第三方工具来代替程序本身的功能模块，如：使用ksubdomain代替自身的爆破模块。
5. 不仅仅是信息收集，支持调用第三方工具对收集的资产进行漏洞扫描，如afrog。
6. 支持生成可视化收集结果页面，并推送到用户邮箱中。

### 一键自动化扫描 
1. 下载项目：`git clone https://github.com/jammny/jws-cli.git`
2. 安装依赖：`pip install -r requirements.txt`
3. 一键自动化扫描：`python jws-cli.py -t example.com --auto`
4. 一键自动化批量扫描：`python jws-cli.py -f targets.txt --auto`
5. 一键自动化收集目标企业资产：`python jws-cli.py -c "xx有限公司" --auto`
6. 使用帮助：`python jws-cli.py --help`


### 配置文件
程序配置文件路径： `jws-cli/db/config.yaml`  
```yaml
# 开启/关闭 调试模式
debug_mode: False

# 开启/关闭 数据表格展示
show_table: True


# 配置程序需要调用的api接口信息 #
api_key:
  # 零零信安 https://0.zone/
  zero_key: ""
  zero_size: 200

  # quake https://quake.360.net/quake/#/index
  quake_key: ""
  quake_size: 200

  # zoomeye https://www.zoomeye.org/
  zoomeye_mail: ""  # zoomeye账号
  zoomeye_pass: ""      # zoomeye密码
  zoomeye_size: 200   # 最大检索量

  # hunter https://hunter.qianxin.com/
  hunter_key: ""
  hunter_size: 200  # 最大检索量

  # fofa https://fofa.info/
  fofa_email: ""
  fofa_key: ""
  fofa_size: 200   # 最大检索量

  # securitytrails https://securitytrails.com/
  securitytrails_key: ""

  # fullhunt https://fullhunt.io/search
  fullhunt_key: ""

  # binaryedge https://binaryedge.io/
  binaryedge_key: ""

  # censys https://search.censys.io/
  censys_id: ""
  censys_secret: ""


# 自动化扫描配置 #
# 默认情况下，程序自动进行子域名收集和存活资产探测任务。你也可以根据自己的需求，自由搭配需要开启的扫描模块。
auto_setting:
  port_scan: True  # 开启/关闭 主机端口扫描。
  cidr_scan: True  # 开启/关闭 C段资产扫描。
  poc_scan: True   # 开启/关闭 POC漏洞扫描。

  # 开启/关闭 智能模式。
  # 智能模式下，会减少开销。仅对没有waf的url进行POC扫描。
  smart_mode: True

  # 支持通过定制化黑名单列表排除没有意义的C段资产，仅当 cidr_scan = True 时有效，列表中的值对应IP解析后的地址信息
  filter_blacklist: [
      '微软', '阿里云', '阿里云BGP节点', '阿里云BGP服务器', '阿里巴巴', 'Microsoft', 'CDN', 'Azure', '华为', '华为云',
      '腾讯云', '网宿', 'Amazon', '运营商','世纪互联BGP数据中心', '内部网', '局域网', '对方和您在同一内部网', '亚马逊', '127.0.0.1'
  ]

  # 开启/关闭 生成扫描报告
  generate_report: True

  # 邮箱信息配置
  smtp_server: smtp.163.com         # smtp 邮箱服务器
  smtp_port: 465                    # smtp 端口号
  send_email: ""   # 发件人邮箱账号
  send_pass: ""     # 发件人邮箱授权码
  rec_email: ""     # 收件人邮箱, 如果有多个收件人需要使用英文逗号隔开


# 子域名扫描配置 #
# 默认情况下，程序自动进行被动子域名信息收集，支持使用域名置换技术生成fuzz字典，支持额外调用ksubdomain来完成域名遍历任务。
sub_scan:
  # 爆破模式参数。
  brute_engine: "ksubdomain"   # 可选参数：system 和 ksubdomain。
  brute_fuzzy: False     # 开启/关闭 域名置换技术。


# 端口扫描配置 #
# 默认情况下，程序会对主机进行存活探测，并对存活的端口进行指纹识别。支持调用nimscan完成端口扫描任务，支持自定义要扫描的端口范围。
port_scan:
  engine: "nimscan"   # 可选参数：system 和 nimscan。
  banner_status: True # 开启/关闭 指纹识别。
  port_range: '21,22,23,80-99,135,139,442-445,666,800,801,808,880,888,889,1000-2379,3000-10010,11115,12018,12443,14000,16080,18000-18098,19001,19080,20000,20720,21000,21501,21502,28018,20880,27017'


# C段扫描配置 #
# 支持统计目标C段中，资产IP出现的次数；支持使用 occurrence_limit 参数跳过不符合条件的C段。
cidr_scan:
  engine: "system"    # 可选参数：system 和 fofa
  occurrence_limit: 3   # 如果相同C段统计IP出现次数，次数>=3才扫描


# POC扫描配置 #
# 支持调用afrog完成扫描任务。
poc_scan:
  engine: "afrog"   # 可选参数：afrog
```


### 更新日志

| 更新时间（版本）          | 更新内容             | 备注   |
|-------------------|------------------|------|
| 2023.9.11(v0.2.0) | 重写了一些模块，新增了一些功能。 |有问题联系我|
| 2023.5.29(v0.1.0) | 优化端口泛滥、域名泛滥处理逻辑。 |有问题联系我|
