#!/usr/bin/env python
# -*- coding : utf-8-*-
"""
作者：jammny
文件描述： 端口扫描模块
"""
from socket import AF_INET, SOCK_STREAM, socket
from queue import Queue
from time import time
from typing import Any

from lib.config.logger import logger
from lib.config.settings import PORT, PORT_THREAD

from lib.utils.thread import thread_task


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

    def tcp_scan(self, queue, target):
        """
        基于socket tcp连接方式，进行端口扫描
        :param target: 扫描目标
        :param queue: 队列中存放了待扫描的端口
        :return:
        """
        while not queue.empty():
            port = queue.get()
            if port == u'end_tag':  # 接收到结束码，就结束
                break
            try:
                conn = socket(AF_INET, SOCK_STREAM)
                conn.settimeout(2)
                conn.connect((target, port))
                conn.close()
                logger.debug(f"{target}:{port}")
                self.result.append({'target': target, 'port': port})
            except Exception as e:
                # logger.error(e)
                pass

    def run(self):
        """
        类统一入口
        :return:
        """
        start1 = time()
        logger.critical(f"执行任务：端口扫描")
        logger.info(f"Get the target number：{len(self.target)}")
        # 简单弄个进度显示
        progress: int = 0
        for target in self.target:
            progress += 1
            logger.info(f"Scanning target: {target} ({progress}/{len(self.target)})")
            # 这里需要加入queue的是端口，端口数量比较多
            queue = self.add_queue(self.ports)
            thread_task(task=self.tcp_scan, args=[queue, target], thread_count=PORT_THREAD)
        end1 = time()
        logger.info(f"Port scan task finished! Total time：{end1 - start1}")
        logger.debug(self.result)
        return self.result
