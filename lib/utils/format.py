#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：
"""
import re

from IPy import IP

from lib.core.settings import CIDR_BLACKLIST


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
    black_list = CIDR_BLACKLIST
    for i in black_list:
        if i in data:
            return False
    return True


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


def match_subdomains(domain, html, distinct=True, fuzzy=True):
    """
    正则

    :param  str domain: main domain
    :param  str html: response html text
    :param  bool distinct: deduplicate results or not (default True)
    :param  bool fuzzy: fuzzy match subdomain or not (default True)
    :return set/list: result set or list
    """
    if fuzzy:
        regexp = r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}' + domain.replace('.', r'\.')
        result = re.findall(regexp, html, re.I)
        if not result:
            return set()
        deal = map(lambda s: s.lower(), result)
        if distinct:
            return list(set(deal))
        else:
            return list(deal)

    else:
        regexp = r'(?:\>|\"|\'|\=|\,)(?:http\:\/\/|https\:\/\/)?' \
                 r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}' \
                 + domain.replace('.', r'\.')
        result = re.findall(regexp, html, re.I)
        if not result:
            return set()
        regexp = r'(?:http://|https://)'
        deal = map(lambda s: re.sub(regexp, '', s[1:].lower()), result)
        if distinct:
            return set(deal)
        else:
            return list(deal)


def rex_ip(data: list):
    """
    内网ip过滤
    :param data:
    :return: dict
    """
    rex = re.compile(
        '^(127\\.0\\.0\\.1)|(localhost)|(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|(172\\.((1[6-9])|(2\\d)|(3[01]))\\.\\d{1,3}\\.\\d{1,3})|(192\\.168\\.\\d{1,3}\\.\\d{1,3})$')
    internal_network_ip = [rex.search(i).group() for i in data if rex.search(i)]
    external_network_ip = [i for i in data if not rex.search(i)]
    # print(internal_network_ip)
    # print(external_network_ip)
    results = {
        'internal_network_ip': internal_network_ip,
        'external_network_ip': external_network_ip
    }
    return results
