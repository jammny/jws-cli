#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述： C段扫描模块代码
"""
import ipaddress
from time import time
from collections import Counter

from IPy import IP
from colorama import Back
from ping3 import ping

from lib.config.logger import logger
from lib.config.settings import console
from lib.modules.portscan import Port

from lib.utils.thread import thread_task, get_queue

from lib.modules.subdomian.search.fofa_api import Fofa


class Cidr:
    def __init__(self, target: list):
        # 目标列表
        self.target: list = target
        # 存放存活ip
        self.ip: list = []
        # 存放结果
        self.results: list = []

    def icmp_ping(self, queue):
        """
        利用icmp来判断外网主机是否存活
        :return:
        """
        while not queue.empty():
            ip: str = queue.get()
            if ip == u'end_tag':  # 接收到结束码，就结束
                break
            if ping(ip):
                logger.info(f"icmp：{ip} is up")
                self.ip.append(ip)

    def format_cidr(self, ):
        """
        格式化IP信息，整理划分C段
        :return:
        """
        cdir = []
        for i in self.target:
            if "/24" not in i:
                # 将IP转成cidr的格式
                ip_mask = IP(f"{i}/255.255.255.0", make_net=True)
                cdir.append(str(ip_mask))
            else:
                cdir.append(i)
        # 统计cidr次数
        for c in Counter(cdir).items():
            logger.info(f"cidr: {c[0]}, occurrence number:{c[1]}")
        # 去重之后返回
        return list(set(cdir))

    def add_ip(self, cidr) -> list:
        """
        根据cidr 把所有ip都加上
        :return:
        """
        ip: list = []
        for c in cidr:
            net4 = ipaddress.ip_network(c)
            for x in net4.hosts():
                ip.append(str(x))
        return ip

    def parse_response(self, response: dict):
        """
        解析响应包数据
        :return:
        """
        results: list = response['results']
        for i in results:
            if i[5] == '':
                if '://' in i[0]:
                    self.results.append(i[0].split('://')[1])
                else:
                    self.results.append(i[0])
        # 列表去重
        self.results = list(set(self.results))

    def fofa_(self, cidr: list):
        """
        使用fofa api 来收集C段信息
        :return:
        """
        logger.info("trying to use fofa api...")
        for i in cidr:
            query: str = f'ip="{i}" && protocol="http"'
            response = Fofa(query).run()
            if response and response['error'] != True:
                self.parse_response(response)
                continue
            else:
                return False
        return True

    def original(self, cidr):
        """
        原始方法，C段扫描
        :return:
        """
        logger.info("Running original...")
        # 添加对应的C段IP数，icmp探测存活
        ip: list = self.add_ip(cidr)
        queue = get_queue(ip)
        thread_task(task=self.icmp_ping, args=[queue], thread_count=255)
        # 调用端口扫描
        port_results: list = Port(self.ip).run()
        port: list = [f"{i['target']}:{i['port']}" for i in port_results]
        # 如果不为空就添加
        if port:
            self.results += port

    def run(self):
        """
        类执行统一入口
        :return:
        """
        start = time()
        logger.critical(f"执行任务：C段扫描")
        logger.info(f"Get the target number：{len(self.target)}")
        # 首先将IP整理成C段
        cidr: list = self.format_cidr()
        # 如果fofa api不能用， 就用原始方法。
        if not self.fofa_(cidr):
            self.original(cidr)
        end = time()
        logger.info(f"Cidr task finished! Total time：{end - start}")
        logger.debug(self.results)
        return self.results
