#!/usr/bin/env python
# -*- coding : utf-8-*-
"""
作者：jammny
文件描述： 端口扫描模块
"""

from queue import Queue
from time import time
from typing import Any

from lib.core.logger import logger
from lib.core.settings import PORT, PORT_THREAD, PORT_METHOD

from .hostscan import HostScan
from .portscan import PortScan
from .table import show_table


class Port:
    def __init__(self, target: list) -> None:
        # 目标列表
        self.target: list = target
        # 默认端口范围
        self.ports: str = PORT
        # 存扫描结果
        self.result: list = []

    def add_queue(self, ports: str) -> Any:
        """
        将"1-65535"拆分，分别添加进队列
        :return:
        """
        queue = Queue()
        if "," in ports and "-" in ports:
            port_list: list = ports.split(',')
            length: int = len(port_list)
            for i in range(0, length):
                if "-" in port_list[i]:
                    p_list: list = port_list[i].split('-')
                    start: int = int(p_list[0])
                    end: int = int(p_list[1]) + 1
                    for l in range(start, end):
                        queue.put(l)
                else:
                    queue.put(int(port_list[i]))
        elif "-" in ports:
            port_list: list = ports.split('-')
            start: int = int(port_list[0])
            end: int = int(port_list[1]) + 1
            for i in range(start, end):
                queue.put(i)
        elif "," in ports:
            port_list: list = ports.split(',')
            length: int = len(port_list)
            for i in range(0, length):
                queue.put(int(port_list[i]))
        else:
            queue.put(int(ports))
        return queue

    def run(self):
        """
        类统一入口
        :return:
        """
        start1 = time()
        # 将目标放进队列
        logger.info(f"Get the target number：{len(self.target)}, thread counts: {PORT_THREAD}, method: {PORT_METHOD}")
        # 端口扫描
        if len(self.ports) > 400:
            thread_count = PORT_THREAD
        else:
            thread_count = len(self.ports)
        for host in self.target:
            # 主机存活检测
            res = HostScan().single_task(host)
            if not res:
                logger.debug(f"[TARGET] {host} is not alive.")
                continue
            queue = self.add_queue(self.ports)
            results = PortScan().run(host, queue=queue, thread_count=thread_count)
            self.result += results
        end1 = time()
        logger.info(f"Port scan task finished! Total time：{end1 - start1}")
        show_table(self.result)
        return self.result
