#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：日志模块。
"""
import logging
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

from lib.core.settings import CONFIG_DATA, LOG
from lib.utils.tools import get_time


LEVEL = "DEBUG" if CONFIG_DATA['debug_mode'] else "INFO"

custom_theme = Theme({
    "g": "bold green",
    "y": "bold yellow",
    "red": "bold red"
})

console = Console(theme=custom_theme, color_system="auto", highlight=False)

# 配置rich记录器 #
logging.basicConfig(
    level=LEVEL,
    format="%(message)s",
    handlers=[
        RichHandler(
            show_time=True,
            console=console,
            omit_repeated_times=False,
            markup=True,
            log_time_format="[%H:%M:%S]"
        )
    ]
)

logger = logging.getLogger("rich")

# 配置日志文件输出 #
FORMAT = logging.Formatter("%(asctime)s - %(name)s - %(levelname)-9s - "
                           "%(filename)-8s : %(lineno)s line - %(message)s",
                           datefmt="%Y/%m/%d %H:%M:%S")
if not LOG.exists():
    Path.mkdir(LOG)
LOGGERFILE = logging.FileHandler(filename=f"{LOG}/{get_time()}.log", mode='w', encoding='utf-8')
LOGGERFILE.setLevel(LEVEL)
LOGGERFILE.setFormatter(FORMAT)
logger.addHandler(LOGGERFILE)
