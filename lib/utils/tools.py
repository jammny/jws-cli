#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：此模块专门用于处理数据。
"""
import re
import time
from typing import Union, Optional, Set

from IPy import IP

from lib.core.settings import CIDR_CONFIG


def match_ip(string: str) -> Set[str]:
    """从字符串中提取IP

    :param string: 需要处理的字符串
    :return:
    """
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # 此正则匹配标准IPv4地址
    return set(re.findall(ip_pattern, string))


def domain_format(data: str) -> Union[str, None]:
    """提取字符串中的域名数据

    :param data: str
    :return: str
    """
    # 正则处理
    res = re.search('((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}', data)
    if res:
        return res.group()
    else:
        return


def match_subdomains(domain: str, html: str, distinct: bool = True, fuzzy: bool = True) -> Union[list, set]:
    """正则匹配域名
    
    :param domain: 目标域名
    :param html: 需要提取域名的页面
    :param distinct: 是否返回集合
    :param fuzzy: 是否开启fuzz匹配
    :return: dict | set
    """
    if fuzzy:
        regexp = r'(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){0,}' + domain.replace('.', r'\.')
        result = re.findall(regexp, html, re.I)
        if not result:
            return set()
        deal = map(lambda s: s.lower(), result)
        if distinct:
            return set(deal)
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


def runtime_format(start_time: float, end_time: float) -> str:
    """计算程序运行时长，格式化输出结果
    
    :param start_time: 程序开始时间
    :param end_time: 程序结束时间
    :return: 程序运行时长
    """
    run_time: float = end_time - start_time
    seconds: int = int(run_time)   # 秒
    # milliseconds = int((run_time - seconds) * 1000)   # 毫秒
    if seconds > 60:
        mintues: int = seconds // 60
        new_seconds: int = seconds % 60
        formatted_time = f"{mintues}min {new_seconds}s"
    else:
        formatted_time = f"{seconds}s"
    return formatted_time





def blacklist_cidr(ip):
    """IP地址 黑名单过滤
    
    :return:
    """
    # 将IP转成cidr的格式
    ip_mask = IP(f"{ip}/255.255.255.0", make_net=True)
    cidr = str(ip_mask)
    black_list = [
        '112.90.80.0/24'
    ]
    return all(i not in cidr for i in black_list)



def get_time():
    """获取当前时间，将时间戳转成：年/月/日 时/分/秒

    :return: 当前时间
    """
    time_format = "%Y%m%d%H%M%S"
    time_now = time.localtime(int(round(time.time()*1000))/1000)
    return time.strftime(time_format, time_now)
