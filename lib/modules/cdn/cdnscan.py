#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 利用域名解析结果 快速判断CDN使用情况。
"""
from time import time
from typing import Optional

from qqwry import QQwry
from rich.console import Console
from rich.table import Table

from lib.core.settings import QQWRYPATH
from lib.utils.tools import runtime_format
from lib.utils.dns_resolver import DnsResolver

from lib.utils.log import logger


class CdnScan(object):
    def __init__(self, ) -> None:
        self.cdn_result: list = []    # 存放扫描结果
        self.qqwry: QQwry = QQwry()
        self.qqwry.load_file(str(QQWRYPATH))

    def query_address(self, ip: list) -> list:
        """
        查询物理地址
        :param ip: 需要查询物理地址的IP列表
        :return:
        """
        return [self.qqwry.lookup(i) for i in ip]

    def dns_lookup(self, target_list: list) -> None:
        """
        利用异步批量解析域名
        :param target_list: 目标域名列表
        :return:
        """
        def func(data) -> Optional[dict]:
            domain: str = data[0]
            ip: list = data[1]
            address: list = self.query_address(ip)  # 查询IP物理地址
            if len(ip) > 1:
                logger.debug(f"{domain} has CDNS!")
                cdn: str = "true"
            else:
                logger.debug(f"{domain} has not CDNS!")
                cdn: str = "false"
            return {
                "domain": domain,
                "ip": ip,
                "cdn": cdn,
                "address": address
            }
        dns_results = DnsResolver().run(target_list)
        self.cdn_result = list(map(func, dns_results))

    def show_table(self):
        """
        表格展示数据
        :param: data
        :return:
        """
        data = self.cdn_result
        if not data:
            return
        table = Table(title="cdn results", show_lines=False)
        table.add_column("domain", justify="left", style="cyan", no_wrap=True)
        table.add_column("ip", justify="left", style="magenta")
        table.add_column("cdn", justify="left", style="red")
        table.add_column("address", justify="left", style="red")
        for i in data:
            table.add_row(i['domain'], str(i['ip']), i['cdn'], str(i['address']))
        console = Console()
        console.print(table)

    def run(self, target_list: list):
        """
        类统一执行入口
        :return:
        """
        start: float = time()
        logger.info(f"Current task: CdnScan | Target numbers: {len(target_list)}")
        self.dns_lookup(target_list)
        logger.info(f"Cdn task finished! Total time：{runtime_format(start, time())}")
        logger.info(f"Effective collection quantity：{len(self.cdn_result)}")
        self.show_table()
        return self.cdn_result


if __name__ == '__main__':
    targets = ['www.python.org', 'google.com', 'baidu.com']
    CdnScan().run(targets)

