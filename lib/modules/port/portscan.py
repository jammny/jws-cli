#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 利用协程写了一个端口扫描模块。
"""
from time import time
from dataclasses import dataclass

from .async_scan import AsyncScan
from .check_overflow import CheckOverFlow
from .host_scan import HostScan

from lib.utils.tools import runtime_format
from lib.utils.log import logger
from lib.core.settings import PORT_CONFIG


@dataclass()
class PortScan(object):
    port_range: str = PORT_CONFIG['port_range']    # 默认端口范围
    thread_count: int = PORT_CONFIG['thread_num']    # 并发数
    result = []  # 存扫描结果

    def get_portlist(self,) -> list:
        """
        用于处理格式: 80,135,445,500-65535
        :return: [待扫描的端口，]
        """
        port_range: str = self.port_range

        def fuc(data) -> list:
            ran: list = data.split("-")
            s: int = int(ran[0])
            e: int = int(ran[1])
            return [n for n in range(s, e + 1)]

        if "," in port_range:
            tmp: list = port_range.split(",")
            result = []
            for i in tmp:
                if "-" in i:
                    result += fuc(i)
                else:
                    result.append(i)
            return result
        elif "-" in port_range:
            return fuc(port_range)
        else:
            return [int(port_range)]

    def run(self, hosts: list, skip_alive=PORT_CONFIG['skip_alive']) -> list:
        """类执行入口

        :param hosts:
        :param skip_alive: 是否跳过主机发现
        :return:
        """
        start = time()
        logger.info(f"Current task: PortScan | Target number: {len(hosts)} | Thread: {self.thread_count}")
        portlist: list = self.get_portlist()
        for index, host in enumerate(hosts):
            logger.info(f"Scanning {host} ({index + 1}/{len(hosts)})...")
            if CheckOverFlow().run(host):
                # 存在端口泛滥, 跳过扫描
                continue
            if not skip_alive and not HostScan().run([host]):
                # 如果IP不存活，默认不扫描
                continue
            scan = AsyncScan(host, portlist, self.thread_count)
            port_results: list = scan.run()
            # 最后检测扫描结果是否异常
            if len(port_results) > 500:
                logger.warning(f"The scan result is abnormal. The number of open ports exceeds 500.")
                port_results = []
            self.result += port_results
        logger.info(f"Port scan task finished! Total time：{runtime_format(start, time())}")
        return self.result
