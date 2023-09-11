#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：程序启动前的兼容性检查。
"""
from platform import python_version
from pathlib import Path

from httpx import Client

from lib.core.log import logger
from lib.core.settings import REPORTS, VERSION, TMP, THIRDPARTY_APP

__all__ = ['CheckAll', 'args_check']


def args_check(target, file, query, company) -> list:
    """

    :param target:  目标域名/链接
    :param file:    文件路径
    :param query:   空间搜索引擎查询语法
    :param company: 企业名称
    :return: 需要扫描的目标列表
    """
    def fuc(s):
        # 去掉多余的 \n 空格 /
        return s.rstrip("\n").replace(" ", "").rstrip("/")

    input_list: list = [target, file, query, company]
    are_all_none = all(item is None for item in input_list)

    # 确保输入必要参数 #
    if are_all_none:
        logger.info('[y]You need to provide the args like -t/-f/-q/-c , enter "--help" for help!')
        raise exit(0)

    # 确保可控参数唯一 #
    if input_list.count(None) != 3:
        logger.info('[y]The input parameter is incorrect, enter "--help" for help!')

    # 从文件读取目标 #
    if file:
        with open(file, mode='r', encoding='utf-8') as f:
            tmp: list = f.readlines()
            target_list: list = [fuc(i) for i in tmp if fuc(i)]
        if not target_list:
            logger.error('[red]The file is null!')
            raise exit(0)
    elif company:
        target_list: list = [company.rstrip("/")]
    elif query:
        target_list: list = [query.rstrip("/")]
    else:
        target_list: list = [target.rstrip("/")]

    return target_list


class CheckAll(object):
    def __int__(self, target: str, file: str, query: str, company: str):
        self.target: str = target   # 目标域名
        self.file: str = file       # 本地文件
        self.query: str = query     # 查询语句
        self.company: str = company     # 企业名称

    @staticmethod
    def py_version_check() -> None:
        """py版本兼容性检测

        :return: None
        """
        py_version: str = python_version()
        a: list = py_version.split('.')
        if int(a[0]) < 3 or int(a[1]) < 8:
            logger.error(f"[red]The current version ({py_version}) is not compatible, maybe need at least >= 3.11)")
            raise exit(0)

    @staticmethod
    def dir_check() -> None:
        """目录检测"""
        if not REPORTS.exists():
            Path.mkdir(REPORTS)

        if not TMP.exists():
            Path.mkdir(TMP)

    @staticmethod
    def update_check():
        """软件更新检测

        :return:
        """
        logger.debug("Checking for the latest version...")
        with Client(timeout=3, verify=False) as c:
            try:
                response = c.get("https://jammny.github.io/jws/version.txt")
                new_version: str = response.text.rstrip()
                if new_version != VERSION:
                    logger.info(f"Found new version: {new_version} —> https://github.com/jammny/jws-cli")
            except:
                pass

    @staticmethod
    def mod_check():
        """mod模块检测

        :return:
        """
        for i in THIRDPARTY_APP.values():
            if not i.exists():
                logger.error(f"[y]Some features will not be available, because '{i}' is missing.")

    def run(self):
        self.py_version_check()
        self.dir_check()
        self.mod_check()
        # self.update_check()