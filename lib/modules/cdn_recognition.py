#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述： CDN识别模块
"""
from time import time
from random import choice

from dns import resolver
from httpx import Client

from lib.utils.thread import thread_task, get_queue
from lib.utils.qqwry import QQwry

from lib.config.logger import logger
from lib.config.settings import USER_AGENTS, CDN_KEY
from lib.config.settings import QQWRY


class CDN:
    def __init__(self, target: list):
        # 目标列表
        self.target: list = target
        # 自定义头
        self.headers: dict = {"User-Agent": choice(USER_AGENTS)}
        # 存放结果
        self.result = []
        # 初始化对象
        self.qqwry = QQwry()
        self.qqwry.load_file(QQWRY)

    def m_ping(self, domain):
        """
        利用多地PING进行cdn筛选
        """
        ip = []
        params = {"key": CDN_KEY, "host": domain}
        try:
            with Client(headers=self.headers, verify=False, params=params, timeout=15) as c:
                res = c.get("https://api.tjit.net/api/ping/v2")
        except Exception as e:
            logger.error(f"{domain} 多地ping接口异常！{e}")
            return
        res_: dict = res.json()
        data: list = res_['data']
        del data[-1]
        for i in data:
            # logger.info(f"{i}")
            if i.__contains__('Parse_ip'):  # 预防报错 KeyError: 'Parse_ip'
                ip.append(i['Parse_ip'])
        if len(set(ip)) > 1:
            cdn: str = "true"
            logger.warning(f"{domain} has CDNS!")
        else:
            cdn: str = "false"
            logger.debug(f"{domain} has not CDNS!")
        return cdn

    def query_address(self, ip: list):
        """
        查询物理地址
        :param ip:
        :return:
        """
        return [self.qqwry.lookup(i) for i in ip]

    def dns_lookup(self, queue):
        """
        效果和nslookup一样
        :return:
        """
        while not queue.empty():
            ip: list = []
            domain: str = queue.get()
            if domain == u'end_tag':  # 接收到结束码，就结束
                break
            try:
                # 查询记录为A记录
                a = resolver.query(domain, 'A')
                for y in a.response.answer:
                    for j in y.items:
                        # 加判断，不然会出现AttributeError: 'CNAME' object has no attribute 'address'
                        if j.rdtype == 1:
                            ip.append(j.address)
                if len(ip) > 1:
                    # 如果识别结果有多个，大概率就是CDN
                    logger.debug(f"{domain} {ip}")
                    logger.warning(f"{domain} has CDNS!")
                    cdn: str = "true"
                else:
                    logger.info(f"{domain} has not CDNS!")
                    # dns解析只有一个IP，但不一定就没CDN，保险起见可以使用多地ping复测一下
                    # logger.info(f"Running multiple ping...")
                    # cdn: str = self.m_ping(domain)
                    cdn: str = "false"
                # 查询IP物理地址
                address = self.query_address(ip)
                self.result.append({
                    "domain": domain,
                    "ip": ip,
                    "cdn": cdn,
                    "address": address
                })
            except Exception as e:
                logger.warning(f"{domain} {e}")

    def run(self):
        """
        类统一执行入口
        :return:
        """
        start = time()
        logger.critical(f"执行任务：CDN识别")
        logger.info(f"Get the target number：{len(self.target)}")
        queue = get_queue(self.target)
        thread_task(task=self.dns_lookup, args=[queue], thread_count=3)
        end = time()
        logger.info(f"Cdn task finished! Total time：{end - start}")
        logger.debug(self.result)
        return self.result


if __name__ == '__main__':
    CDN(['baidu.com']).run()

