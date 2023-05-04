#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：异步端口扫描实现
"""
import asyncio

from rich.progress import Progress

from lib.core.settings import PORT_CONFIG


class AsyncScan:
    def __init__(self, host: str, portlist: list, thread_count: int) -> None:
        """
        异步TCP扫描
        :param host: 目标IP
        :param portlist: 待扫描的端口列表
        :param thread_count: 并发数
        """
        self.ip: str = host   # 目标IP
        self.portlist: list = portlist  # 待扫描的端口列表
        self.timeout: int = PORT_CONFIG['timeout']  # 超时
        self.thread_count: int = thread_count   # 并发数
        self.port_results = []

    async def main(self, progress, task) -> None:
        """
        异步任务执行
        :return:
        """
        sem = asyncio.Semaphore(self.thread_count)  # 设置并发数, 这里sem不要放到全局中去
        tasks: list = [self.tcp_scan(port, sem, progress, task) for port in self.portlist]
        await asyncio.gather(*tasks)  # 开启并发任务

    async def tcp_scan(self, port, sem, progress, task) -> None:
        """
        socket 实现端口扫描
        :param task:
        :param progress:
        :param sem: 设置并发数
        :param port: 目标端口
        :return:
        """
        try:
            async with sem:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(self.ip, port), timeout=self.timeout)
                writer.close()
                self.port_results.append({"ip": self.ip, "port": str(port), "protocol": ""})
                progress.console.print(f"{self.ip}:{str(port)}")
        except:
            pass
        finally:
            # 进度条渲染
            progress.update(task, advance=1)

    def run(self, ) -> list:
        """
        任务执行入口
        :return:
        """
        with Progress(transient=True) as progress:
            task = progress.add_task("[green]Processing...", total=len(self.portlist))  # 定义一个进度条对象
            while not progress.finished:
                asyncio.run(self.main(progress, task))
        return self.port_results
