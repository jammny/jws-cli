#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：程序常量数据配置
"""
import platform
from pathlib import Path

import yaml


# 版本信息 #
VERSION: str = "0.2.0"

# 操作系统信息 #
OSNAME: str = platform.system()

# 当前工作目录 #
DIRNAME: Path = Path.cwd()

# Banner信息 #
BANNER: str = (
    "[bold red]   ___  _    _ _____        _____  _     _____ \n"
    "  |_  || |  | /  ___|      /  __ \| |   |_   _|\n"
    "    | || |  | \ `--. ______| /  \/| |     | |  \n"
    "    | || |/\| |`--. \______| |    | |     | |  \n"
    "/\__/ /\  /\  /\__/ /      | \__/\| |_____| |_ \n"
    "\____/  \/  \/\____/        \____/\_____/\___/ [/bold red]\n"
    "\n"
    f"https://github.com/jammny    Version: {VERSION}\n"
)

# 定义各种目录路径 #
LOG = DIRNAME / "log"
WAF_PLUGINS = DIRNAME / "db/plugins/waf"    # 插件目录
REPORTS: Path = DIRNAME / "reports"     # 报告输出目录
TMP: Path = DIRNAME / "reports/tmp"   # 缓存目录
THIRDPARTY_PATH = DIRNAME / "thirdparty"    # 第三方程序目录
CONFIG_PATH = DIRNAME / "db/config.yaml"    # 配置文件目录
FINGER: Path = DIRNAME / "db/finger.json"  # 指纹库路径

# 读取配置数据 #
try:
    with open(CONFIG_PATH, mode="r", encoding="utf-8") as f:
        CONFIG_DATA = yaml.load(f.read(), Loader=yaml.FullLoader)
except Exception as e:
    raise Exception

# 数据表格展示
SHOW_TABLE: bool = CONFIG_DATA['show_table']

# 自动化扫描配置 #
AUTO_SETTING: dict = CONFIG_DATA['auto_setting']
SMART_MODE: bool = AUTO_SETTING['smart_mode']

# 邮箱配置 #
SEND_EMAIL = AUTO_SETTING['send_email']
SEND_PASS = AUTO_SETTING['send_pass']
REC_EMAIL = AUTO_SETTING['rec_email']
SMTP_SERVER = AUTO_SETTING['smtp_server']
SMTP_PORT = AUTO_SETTING['smtp_port']

# 子域名模块 #
SUB_CONFIG: dict = CONFIG_DATA['sub_scan']
SUBNAMES: Path = DIRNAME / 'db/dictionary/subnames.txt'
SUBWORIDS: Path = DIRNAME / 'db/dictionary/subwords.txt'
DNS_DATASETS_PATH: Path = DIRNAME / "db/subdomain"
QQWRYPATH: Path = DIRNAME / "db/qqwry.dat"  # 纯真ip数据库路径
BRUTE_FUZZY = SUB_CONFIG["brute_fuzzy"]
BRUTE_ENGINE = SUB_CONFIG["brute_engine"]
API_KEY: dict = CONFIG_DATA["api_key"]

# 端口扫描模块 #
PORT_CONFIG: dict = CONFIG_DATA['port_scan']

# C段扫描模块
CIDR_CONFIG: dict = CONFIG_DATA['cidr_scan']

# POC模块
POC_CONFIG: dict = CONFIG_DATA['poc_scan']

# 第三方模块 #
THIRDPARTY_APP: dict = {
    "afrog": THIRDPARTY_PATH / "afrog.exe" if OSNAME == "Windows" else THIRDPARTY_PATH / "afrog",
    "ksubdomain": THIRDPARTY_PATH / "ksubdomain.exe" if OSNAME == "Windows" else THIRDPARTY_PATH / "ksubdomain",
    "nimscan": THIRDPARTY_PATH / "nimscan.exe" if OSNAME == "Windows" else THIRDPARTY_PATH / "nimscan",
}
