#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 工具函数。
"""
import os
from typing import List

import yaml

from lib.modules.cdn.dns_resolver import DnsResolver


def get_subname(subdomain: str):
    """获取子域名中 子域的数据

    :param subdomain: 子域名数据：test.baidu.com
    :return:
    """
    # 直接通过 . 进行分割
    return subdomain.split('.')[0]


def get_dir_yaml(file_path: str) -> list:
    """从目录中获取自定义DNS数据集的文件内容

    :return: 返回文件内容
    """
    # 遍历目录中的文件名
    yaml_files: list = list()
    for root, dirs, files in os.walk(file_path):
        for file in files:
            yaml_files.append(os.path.join(root, file))  # 将文件名添加到列表
    # 遍历文件内容
    context: list = list()
    for i in yaml_files:
        with open(i, mode='r', encoding='utf-8') as f:
            data: dict = yaml.safe_load(f.read())
            context.append(data)
    return context


def generic_parsing(domain: str) -> List[str]:
    """检测域名泛解析

    :param domain: 目标域名
    :return:
    """
    test_domain: str = f"fuckfucktest.{domain}"
    # 如果能够成功解析出IP，说明存在泛解析
    dns_results: List[tuple] = DnsResolver().run(targets_list=[test_domain],)
    if dns_results:
        ip: List[str] = dns_results[0][1]
        return ip
    return list()
