#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：第三方程序的调用
"""
from os import system
from lib.config.settings import TMP, MOD
from lib.config.logger import logger
from lib.utils.encrypt import GetKey


def afrog(urls: list, target=None):
    """

    :param file_path:
    :return:
    """
    logger.critical(f"执行任务：POC扫描")
    logger.info(f"Running afrog...")
    if target is None:
        name = GetKey().random_key(7)
        with open(f"{TMP}/afrog_{name}.txt", encoding="utf-8", mode="w+") as f:
            f.write("\n".join(urls))
        system(f"{MOD['afrog']} -T {TMP}/afrog_{name}.txt -o afrog_{name}.html")
    else:
        system(f"{MOD['afrog']} -T {TMP}/{target}/valid_all_url.txt -o afrog_{target}.html")
