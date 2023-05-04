#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：程序常量数据配置
"""
import platform
import yaml
from pathlib import Path

from rich.console import Console

console = Console(color_system='auto', style=None)

DIRNAME: Path = Path.cwd()    # 当前工作目录

# 读取config.yaml配置数据
with open(DIRNAME / "db/config.yaml", mode="r", encoding="utf-8") as f:
    CONFIG_DATA = yaml.load(f.read(), Loader=yaml.FullLoader)

VERSION = CONFIG_DATA['version']    # 当前程序版本信息

# banner信息
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

OSNAME: str = platform.system()    # 操作系统信息

# 指纹识别模块
FINGER: Path = DIRNAME / "db/finger.json"  # 指纹库路径

# CDN模块
QQWRYPATH: Path = DIRNAME / "db/qqwry.dat"  # 纯真ip数据库路径

# 自动扫描配置
AUTO_SETTING: dict = CONFIG_DATA['auto_setting']

# 子域名模块
SUBNAMES: Path = DIRNAME / 'db/subnames.txt'
SUBWORIDS: Path = DIRNAME / 'db/subwords.txt'
DNS_PATH: Path = DIRNAME / "db/dns"
SUB_CONFIG: dict = CONFIG_DATA['sub_scan']

# 目录扫描模块
DIR_CONFIG: dict = CONFIG_DATA['dir_scan']

# 端口扫描模块
PORT_CONFIG: dict = CONFIG_DATA['port_scan']

# C段扫描模块
CIDR_CONFIG: dict = CONFIG_DATA['cidr_scan']

# POC模块
POC_CONFIG: dict = CONFIG_DATA['poc_scan']

# 爬虫/代理模块
USER_AGENTS = CONFIG_DATA['user-agent']

# 报告/结果输出
REPORTS: Path = DIRNAME / "reports"
TMP: Path = DIRNAME / "reports/tmp"

# 第三方模块
MOD: dict = {
    "afrog": DIRNAME / "thirdparty/afrog/afrog.exe" if OSNAME == "Windows" else DIRNAME / "thirdparty/afrog/afrog",
    "ffuf": DIRNAME / "thirdparty/ffuf/ffuf.exe" if OSNAME == "Windows" else DIRNAME / "thirdparty/ffuf/ffuf",
    "wafw00f": DIRNAME / "thirdparty/wafw00f/main.py",
}

# 邮箱配置
SEND_EMAIL = CONFIG_DATA['send_email']
SEND_PASS = CONFIG_DATA['send_pass']
REC_EMAIL = CONFIG_DATA['rec_email']
SMTP_SERVER = CONFIG_DATA['smtp_server']
SMTP_PORT = CONFIG_DATA['smtp_port']
