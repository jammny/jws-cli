#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 第三方控制模块
"""
import os
from os import system
from lib.core.settings import TMP, MOD, REPORTS, DIRNAME, MOD_DIR, DICC, DICC_CONFIG
from lib.utils.encrypt import GetKey


def wafw00f(target_list=None, target=None):
    """

    """
    if target_list:
        for i in target_list:
            system(f"wafw00f {i}")
    else:
        system(f"wafw00f -i {TMP}/{target}/valid_all_url.txt -o {TMP}/{target}/waf.json")


def dirsearch(target_list=None, target=None):
    """

    :return:
    """
    if target_list:
        for url in target_list:
            system(f"dirsearch -u {url} -w {DICC} --config={DICC_CONFIG}")
    else:
        system(f"dirsearch -l {TMP}/{target}/valid_no_waf_urls.txt -w {DICC} --config={DICC_CONFIG} "
               f"--exclude-text 'Sorry for the inconvenience' -o {TMP}/{target}/dir.json --format=json")


def afrog(target_list=None, target=None):
    """

    :param file_path:
    :return:
    """
    if target_list:
        for url in target_list:
            system(f"{MOD['afrog']} -t {url}")
    else:
        system(f"{MOD['afrog']} -T {TMP}/{target}/valid_no_waf_urls.txt -o {target}_afrog.html")


def xray(target_list, target):
    """
    poc扫描
    :param name:
    :param urls:
    :return:
    """
    os.chdir(MOD_DIR['xray_dir'])
    if target_list:
        for url in target_list:
            name = GetKey().random_key(7)
            system(f"{MOD['xray']} webscan --browser-crawler {url} --html-output {REPORTS}/xray_{name}.html")
    else:
        with open(f"{TMP}/{target}/valid_no_waf_urls.txt", mode="r") as f:
            urls_tmp = f.readlines()
        for u in urls_tmp:
            url = u.rstrip()
            name = GetKey().random_key(7)
            system(f"{MOD['xray']} webscan --browser-crawler {url} --html-output {REPORTS}/xray_{name}.html")
    os.chdir(DIRNAME)
