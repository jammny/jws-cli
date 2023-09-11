#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：异步端口扫描实现
"""
import asyncio

from rich.progress import Progress

from lib.core.log import logger


class AsyncScan:
    """异步TCP扫描"""
    def __init__(self, host: str, portlist: list) -> None:
        self.ip: str = host   # 目标IP
        self.portlist: list = portlist  # 待扫描的端口列表
        self.thread_count: int = 1000   # 并发数
        self.open_port = set()  # 开放的端口

    async def main(self, progress, task) -> None:
        """异步任务执行

        :return:
        """
        thread_count = self.thread_count
        sem = asyncio.Semaphore(thread_count)  # 设置并发数, 这里sem不要放到全局中去
        tasks: list = [self.tcp_scan(port, sem, progress, task) for port in self.portlist]
        await asyncio.gather(*tasks)  # 开启并发任务

    async def tcp_scan(self, port, sem, progress, task) -> None:
        """socket 实现端口扫描

        :param task:
        :param progress:
        :param sem: 设置并发数
        :param port: 目标端口
        :return:
        """
        try:
            async with sem:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(self.ip, port), timeout=5.0)
                # 关闭连接 #
                writer.close()
                await writer.wait_closed()
            self.open_port.add(port)
            progress.console.print(f"{self.ip}:{port}")
        except:
            pass
        finally:
            progress.update(task, advance=1)

    def run(self, ) -> set:
        """任务执行入口

        :return:
        """
        logger.info("Async socket scan...")
        with Progress(transient=True) as progress:
            task = progress.add_task("[green]Scanning...", total=len(self.portlist))  # 定义一个进度条对象
            asyncio.run(self.main(progress, task))
        return self.open_port
