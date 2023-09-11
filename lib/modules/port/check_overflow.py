#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：扫描过程中，经常会遇到某些防火墙在单个ip上开放成千上万个端口，实际上是没有资产的，此模块用于解决端口泛滥的问题。
"""
import socket

__all__ = ['CheckOverFlow', ]

from lib.core.log import logger
from lib.utils.thread import threadpool_task


class CheckOverFlow:
    def __init__(self):
        self.threshold_value = 6  # 阈值
        self.portlist = [1, 2, 3, 4, 5, 65535, 65534, 65533, 65532, 65531, 2000, 2001, 2002, 2003, 2004, 2005, 10000,
                         10001, 10002, 10003, 10004, 10005]  # 冷门端口
        # 可能还需要加个常见端口？有些会特地弄一些常见的端口开放，扰乱扫描结果？后续根据实战经验再看看要不要加。
        self.port_results = []

    def scan_port(self, host: str, queue_obj) -> None:
        """

        :param queue_obj: queue.Queue
        :param host: 目标主机
        :return:
        """
        port = queue_obj.get()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((host, port))
            if result == 0:
                self.port_results.append(port)

    def run(self, ip) -> bool:
        """
        任务执行入口
        :return:
        """
        logger.info("Check overflowing...")
        threadpool_task(task=self.scan_port, queue_data=self.portlist, task_args=(ip,), thread_count=30)
        if len(self.port_results) >= self.threshold_value:
            logger.error(f"IP {ip} port is overflowing, Scan has been skipped.")
            return True
        else:
            return False
