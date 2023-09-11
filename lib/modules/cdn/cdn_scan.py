#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 利用域名解析结果 快速判断CDN使用情况。
"""
from typing import Optional, List

from lib.core.settings import QQWRYPATH
from lib.modules.cdn.qqwry import QQwry

from lib.modules.cdn.dns_resolver import DnsResolver


class CdnScan(object):
    def __init__(self,) -> None:
        self.cdn_result: list = []    # 存放扫描结果
        self.qqwry: QQwry = QQwry()
        self.qqwry.load_file(str(QQWRYPATH))

    def query_address(self, ip: list) -> list:
        """查询物理地址

        :param ip: 需要查询物理地址的IP列表
        :return:
        """
        return [self.qqwry.lookup(i) for i in ip]

    def dns_lookup(self, domain_list: List[str], thread_count=100) -> None:
        """利用dns解析域名

        :param thread_count:
        :param domain_list: [需要解析的域名]
        :return:
        """
        def func(data) -> Optional[dict]:
            domain: str = data[0]
            ip: list = data[1]
            address: List[list] = self.query_address(ip)  # 查询IP物理地址
            cdn: str = "true" if len(ip) > 1 else ""
            return {
                "subdomain": domain,
                "ip": ip,
                "cdn": cdn,
                "address": address,
                'method': "brute"
            }

        dns_results: List[tuple] = DnsResolver().run(targets_list=list(domain_list), thread_count=thread_count)

        if dns_results:  # 对解析的数据进行有效性筛选
            self.cdn_result = list(map(func, dns_results))

    def run(self, target_list: List[str], thread_count=100) -> List[dict]:
        """类执行入口

        :param thread_count:
        :param target_list: [域名,...]
        :return: [扫描结果,...]
        """
        self.dns_lookup(target_list, thread_count)
        return self.cdn_result
