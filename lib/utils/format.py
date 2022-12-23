#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：
"""
import re

from IPy import IP


def domain_format(data: str):
    """
    提取域名
    :param data:
    :return:
    """
    # 处理 https://www.baidu.com
    if '://' in data:
        data: str = data.split('://')[1]
    # 处理 www.baidu.com:443/
    if ":" in data:
        domain: str = data.split(':')[0]
    # 处理 www.baidu.com/test
    elif "/" in data:
        domain: str = data.split('/')[0]
    # 处理 *.baidu.com
    elif "*." in data:
        domain: str = data.replace('*.', '')
    else:
        domain = data
    # 正则处理
    res = re.search('((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}', domain)
    if res:
        domain = res.group()
    return domain


def blacklist_ipaddress(data):
    """
    物理IP地址 黑名单过滤
    :return:
    """
    black_list = [
        '微软', '阿里', 'Microsoft', 'CDN', 'Azure', '华为', "亚马逊", '腾讯云', '网宿', 'Amazon', '运营商：IP',
        '世纪互联BGP数据中心', '内部网', '局域网'
    ]
    return all(i not in data for i in black_list)


def blacklist_cidr(ip):
    """
    IP地址 黑名单过滤
    :return:
    """
    # 将IP转成cidr的格式
    ip_mask = IP(f"{ip}/255.255.255.0", make_net=True)
    cidr = str(ip_mask)
    black_list = [
        '112.90.80.0/24'
    ]
    return all(i not in cidr for i in black_list)
