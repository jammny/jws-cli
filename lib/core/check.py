#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：程序完整性检查
"""
from platform import python_version
from pathlib import Path

from httpx import Client

from lib.utils.log import logger
from lib.core.settings import REPORTS, MOD, VERSION, TMP

__all__ = ['CheckAll', ]


class CheckAll(object):
    def py_check(self):
        """py版本检测"""
        py_version: str = python_version()
        a: list = py_version.split('.')
        b: int = int(a[0])
        c: int = int(a[1])
        if b < 3 or c < 8:
            logger.error(f"The current version ({py_version}) is not compatible, need at least >= 3.8)")
            exit(0)

    def report_check(self):
        """报告输出目录检测"""
        if not REPORTS.exists():
            Path.mkdir(REPORTS)
        if not TMP.exists():
            Path.mkdir(TMP)

    def update_check(self):
        """软件更新检测"""
        with Client(timeout=5, verify=False) as c:
            try:
                response = c.get("https://jammny.github.io/jws/version.txt")
                new_version: str = response.text.rstrip()
                if new_version != VERSION:
                    logger.info(f"Found new version: {new_version} —> https://github.com/jammny/jws-cli")
            except:
                pass

    def mod_check(self):
        """mod模块检测"""
        for i in MOD.values():
            if not i.exists():
                logger.warning(f"Some features will not be available, because '{i}' is missing.")

    def run(self):
        """类统一执行入口"""
        logger.info("Checking for the program compatibility...")
        self.py_check()
        self.report_check()
        self.mod_check()
        logger.info("Checking for the latest version...")
        self.update_check()
