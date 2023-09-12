#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 利用协程写了一个端口扫描模块。
"""
from collections import Counter
from typing import Tuple

from IPy import IP

from .thirdparty import CidrFofa
from .cidr_system import CidrSystem

from lib.core.log import logger

from lib.core.settings import CIDR_CONFIG, SHOW_TABLE
from rich.console import Console
from rich.table import Table


class Cidr:
    def __init__(self, engine: str):
        self.engine: str = engine
        self.ip: list = []  # 存放存活ip
        self.cidr_results: list = []    # 存放结果
        self.cidr_counter = []  # 统计C段划分

    def format_cidr(self, target_list: list, auto=False):
        """格式化IP信息 整理划分C段

        :param auto:
        :param target_list:
        :return:
        """
        def func(item):
            if "/24" not in item:
                ip_mask = IP(f"{item}/255.255.255.0", make_net=True)   # 将IP转成cidr的格式
                return str(ip_mask)
            else:
                return item
        cdir = [func(i) for i in target_list]
        # 统计cidr出现的次数
        res = []

        for c in Counter(cdir).items():
            logger.info(f"cidr: {c[0]}, occurrence number:{c[1]}")
            self.cidr_counter.append(f"cidr: {c[0]}, occurrence number:{c[1]}")
            # 如果大于设置的阈值，就添加进入目标
            if c[1] >= CIDR_CONFIG['occurrence_limit'] and auto:
                res.append(c[0])
            elif c[1] < CIDR_CONFIG['occurrence_limit'] and auto:
                pass
            else:
                res.append(c[0])
        logger.info(f"According to the set threshold, the cidr range to be scanned is: {res}")
        return res

    def show_table(self):
        """表格展示数据

        :return:
        """
        data = self.cidr_results
        table = Table(title="cdn results", show_lines=False)
        table.add_column("host", justify="left", style="cyan", no_wrap=True)
        table.add_column("port", justify="left", style="magenta")
        table.add_column("protocol", justify="left", style="red")
        table.add_column("banner", justify="left", style="red")
        for i in data:
            table.add_row(i['host'], str(i['port']), i['protocol'], i['banner'])
        console = Console()
        console.print(table)

    def run(self, target_list: list, auto=False) -> Tuple[list, list]:
        """类执行入口

        :param auto:
        :param target_list:
        :return:
        """
        engine = self.engine

        if not target_list:
            logger.info(f"No target input: {target_list}")
            return self.cidr_results, self.cidr_counter
        else:
            target_list = list(set(target_list))    # 去重

        logger.info(f"[g]Current task: CidrScan | Target numbers: {len(target_list)} | Engine: {engine} |[/g]")

        # 首先将IP整理成C段
        cidr: list = self.format_cidr(target_list, auto)

        if engine == 'fofa':
            self.cidr_results = CidrFofa().run(cidr)
            # if not self.cidr_results:    # 如果fofa不能用,就用系统默认扫描方法。
                # self.cidr_results = CidrSystem().run(cidr)
        elif engine == 'system':
            self.cidr_results = CidrSystem().run(cidr)

        if SHOW_TABLE:
            self.show_table()

        logger.info(f"CIDR task finished! Effective collection quantity: {len(self.cidr_results)}")
        return self.cidr_results, self.cidr_counter
