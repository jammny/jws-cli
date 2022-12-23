#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：
"""
from dns import resolver


def a_record(domain):
    """
    dns解析，获取A记录
    :param domain:
    :return:
    """
    ip = []
    A = resolver.query(domain, 'A')  # 查询记录为A记录
    for y in A.response.answer:
        for j in y.items:
            if j.rdtype == 1:
                ip.append(j.address)
    return ip
