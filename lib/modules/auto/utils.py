#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：此模块专门用于处理数据。
"""
from re import compile as re_compile, Pattern
from typing import AnyStr, List


def distinguish_between_ip(ip_list: List[str]) -> dict:
    """区分内网IP和外网IP

    :param ip_list: [IP地址]
    :return: dict
    """
    # 先对输入的列表进行去重
    ip_list = set(ip_list)
    rex: Pattern[AnyStr] = re_compile('^(127\\.0\\.0\\.1)|(localhost)|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(172\\.((1[6-9])|(2\\d)|'
                     '(3[01]))\\.\\d{1,3}\\.\\d{1,3})|(192\\.168\\.\\d{1,3}\\.\\d{1,3})$')
    internal_network_ip: list = [rex.search(i).group() for i in ip_list if rex.search(i)]
    external_network_ip: list = [i for i in ip_list if not rex.search(i)]
    # print(internal_network_ip)
    # print(external_network_ip)
    return {
        'internal_network_ip': internal_network_ip,
        'external_network_ip': external_network_ip
    }
