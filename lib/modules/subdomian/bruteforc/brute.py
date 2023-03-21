#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 子域名爆破模块，使用异步协程进行任务处理。
"""
import asyncio
from time import time
from dataclasses import dataclass

from lib.core.logger import logger
from lib.modules.subdomian.common import AsyncDnsResolver
from lib.utils.format import runtime_format


@dataclass()
class Brute(object):
    target: str  # 获取目标域名
    domain_dict: list  # 域名字典
    root_generic: list  # 泛解析结果

    def run(self) -> list:
        """
        类的统一执行路径
        :return:
        """
        start = time()
        results = asyncio.run(AsyncDnsResolver(self.domain_dict).main())
        domian_result = []
        for domain, result in results:
            if result:
                ip = [i.host for i in result]
                if ip != self.root_generic:   # 筛选掉存在泛解析的IP
                    domian_result.append({'subdomain': domain, 'method': 'brute', 'ip': ip})
        end = time()
        run_time = runtime_format(start, end)
        logger.info(f"Subdomain Brute: {len(domian_result)} results found! Total time：{run_time}")
        logger.debug(domian_result)
        return domian_result
