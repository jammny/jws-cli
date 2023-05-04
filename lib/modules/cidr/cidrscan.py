#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 利用协程写了一个端口扫描模块。
"""
from time import time
from collections import Counter

from IPy import IP

from .cidr_fofa import CidrFofa
from .cidr_system import CidrSystem

from lib.utils.tools import runtime_format
from lib.utils.log import logger

from lib.core.settings import CIDR_CONFIG


class Cidr:
    def __init__(self, ):
        self.ip: list = []  # 存放存活ip
        self.cidr_results: list = []    # 存放结果
        self.method: str = CIDR_CONFIG['method']

    def format_cidr(self, target_list: list):
        """
        格式化IP信息 整理划分C段
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
            # 如果大于设置的阈值，就添加进入目标
            if c[1] > CIDR_CONFIG['occurrence_limit']:
                res.append(c[0])
        logger.info(f"According to the set threshold, the cidr range to be scanned is: {res}")
        return res

    def run(self, target_list: list):
        """
        类执行入口
        :param target_list:
        :return:
        """
        start: float = time()
        logger.info(f"Current task: CidrScan | Target numbers: {len(target_list)}")
        cidr: list = self.format_cidr(target_list)    # 首先将IP整理成C段
        if self.method == 'fofa':
            self.cidr_results = CidrFofa().run(cidr)
            if not self.cidr_results:    # 如果fofa不能用,就用系统默认扫描方法。
                self.cidr_results = CidrSystem().run(cidr)
        elif self.method == 'system':
            self.cidr_results = CidrSystem().run(cidr)
        logger.info(f"CIDR task finished! Total time: {runtime_format(start, time())}")
        logger.info(f"Effective collection quantity: {len(self.cidr_results)}")
        return self.cidr_results

