#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：日志模块。
"""
import logging
from pathlib import Path

from rich.logging import RichHandler

from lib.utils.tools import get_time


class LoggingLevel:
    """自定义日志事件等级"""
    SUCCESS = 60
    CRITICAL = 50
    ERROR = 40
    WARNING = 30
    INFO = 20
    DEBUG = 10
    NOTSET = 0


# 配置rich处理器
logging.basicConfig(
    level="DEBUG",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, omit_repeated_times=False, markup=True)]
)

# 定义记录器
logger = logging.getLogger("rich")

# 配置文件输出
FORMAT = logging.Formatter("%(asctime)s - %(name)s - %(levelname)-9s - %(filename)-8s : %(lineno)s line - %(message)s",
                           datefmt="%Y/%m/%d %H:%M:%S")
LOGPATH = Path.cwd() / "log"
if not LOGPATH.exists():
    Path.mkdir(LOGPATH)
LOGNAME = LOGPATH / f"{get_time()}.log"
LOGGERFILE = logging.FileHandler(filename=LOGNAME, mode='w', encoding='utf-8')
LOGGERFILE.setLevel(LoggingLevel.DEBUG)
LOGGERFILE.setFormatter(FORMAT)
logger.addHandler(LOGGERFILE)
