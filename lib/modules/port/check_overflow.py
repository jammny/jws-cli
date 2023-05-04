#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：扫描过程中，经常会遇到某些防火墙在单个ip上开放成千上万个端口，实际上是没有资产的，此模块用于解决端口泛滥的问题。
"""
import asyncio

__all__ = ['CheckOverFlow', ]

from lib.utils.log import logger


class CheckOverFlow:
    def __init__(self):
        self.threshold_value = 8  # 阈值
        self.portlist = [1, 2, 3, 4, 5, 65535, 65534, 65533, 65532, 65531]  # 冷门端口
        # 可能还需要加个常见端口？有些会特地弄一些常见的端口开放，扰乱扫描结果？后续根据实战经验再看看要不要加。
        self.port_results = []

    async def main(self, ip) -> None:
        """
        异步任务执行
        :return:
        """
        sem = asyncio.Semaphore(5)  # 设置并发数, 这里sem不要放到全局中去
        tasks: list = [self.tcp_scan(ip, port, sem) for port in self.portlist]
        await asyncio.gather(*tasks)  # 开启并发任务

    async def tcp_scan(self, ip, port, sem) -> None:
        """
        socket 实现端口扫描

        :param ip:
        :param sem: 设置并发数
        :param port: 目标端口
        :return:
        """
        try:
            async with sem:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=5)
                writer.close()
                self.port_results.append(port)
        except:
            pass

    def run(self, ip) -> bool:
        """
        任务执行入口
        :return:
        """
        asyncio.run(self.main(ip))
        if len(self.port_results) >= self.threshold_value:
            logger.warning(f"IP {ip} port is overflowing, Scan has been skipped.")
            return True
        else:
            return False
