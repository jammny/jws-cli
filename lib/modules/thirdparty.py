#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：第三方程序的调用
"""
import os
from os import system
from lib.config.settings import TMP, MOD, REPORTS, DIRNAME, MOD_DIR
from lib.config.logger import logger
from lib.utils.encrypt import GetKey


def afrog(urls: list, target=None):
    """

    :param file_path:
    :return:
    """
    logger.critical(f"执行任务：afrog扫描")
    if target is None:
        name = GetKey().random_key(7)
        with open(f"{TMP}/afrog_{name}.txt", encoding="utf-8", mode="w+") as f:
            f.write("\n".join(urls))
        system(f"{MOD['afrog']} -T {TMP}/afrog_{name}.txt -o afrog_{name}.html")
    else:
        system(f"{MOD['afrog']} -T {TMP}/{target}/valid_all_url.txt -o afrog_{target}.html")


def xray(urls: list, target=None):
    """

    :param file_path:
    :return:
    """
    logger.critical(f"执行任务：Xray扫描")
    os.chdir(MOD_DIR['xray_dir'])
    if target is None:
        name = GetKey().random_key(7)
        with open(f"{TMP}/xray_{name}.txt", encoding="utf-8", mode="w+") as f:
            f.write("\n".join(urls))
        with open(f"{TMP}/xray_{name}.txt", mode="r") as f:
            urls_tmp = f.readlines()
        for url in urls_tmp:
            system(f"{MOD['xray']} webscan --browser-crawler {url} --html-output {REPORTS}/xray_{name}.html")
    else:
        with open(f"{TMP}/{target}/valid_all_url.txt", mode="r") as f:
            urls_tmp = f.readlines()
        for u in urls_tmp:
            url = u.rstrip()
            name = GetKey().random_key(7)
            system(f"{MOD['xray']} webscan --browser-crawler {url} --html-output {REPORTS}/xray_{name}.html")
    os.chdir(DIRNAME)
