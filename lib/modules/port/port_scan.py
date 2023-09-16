#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 利用协程写了一个端口扫描模块。
"""
from time import time

from rich.console import Console
from rich.table import Table

from lib.core.settings import SHOW_TABLE
from lib.modules.port.async_scan import AsyncScan
from lib.modules.port.banner_scan import BannerScan
from lib.modules.port.check_overflow import CheckOverFlow
from lib.modules.port.thirdparty import nimscan
from lib.utils.thread import threadpool_task
from lib.utils.tools import runtime_format
from lib.core.log import logger


class PortScan(object):
    def __init__(self, port_range: str, engine: str, banner_status: bool):
        self.port_range: str = port_range    # 默认端口范围
        self.engine: str = engine
        self.banner_status: bool = banner_status

        self.port_results = list()  # 存扫描结果

    def get_port_list(self) -> list:
        """用于处理格式: 80,135,445,500-65535

        :return: [待扫描的端口，]
        """
        def fuc(data) -> list:
            ran: list = data.split("-")
            s: int = int(ran[0])
            e: int = int(ran[1])
            return [n for n in range(s, e + 1)]

        port_range: str = self.port_range

        if "," in port_range:
            a: list = port_range.split(",")
            result = []
            for i in a:
                if "-" in i:
                    result += fuc(i)
                else:
                    result.append(int(i))
            return result

        elif "-" in port_range:
            return fuc(port_range)
        else:
            return [int(port_range)]

    def banner_scan(self, host, queue_obj):
        """指纹识别

        :param host:
        :param queue_obj:
        :return:
        """
        port = queue_obj.get()
        protocol, banner = BannerScan(host, port).run() if self.banner_status else ("", "")
        res = {'host': host, 'port': port, 'protocol': protocol, 'banner': banner[:20]}
        self.port_results.append(res)

    def show_table(self) -> None:
        """表格展示数据"""
        data: list = self.port_results
        if not data:
            return
        table = Table(title="Port Results", show_lines=False)
        table.add_column("host", justify="left", style="cyan", no_wrap=True)
        table.add_column("port", justify="left", style="magenta")
        table.add_column("protocol", justify="left", style="red")
        table.add_column("banner", justify="left", style="green")
        for i in data:
            table.add_row(i['host'], str(i['port']), i['protocol'], i['banner'])
        console = Console()
        console.print(table)
        return

    def run(self, hosts: list) -> list:
        """类执行入口

        :param hosts:
        :return:
        """
        start = time()
        engine = self.engine
        logger.info(f"[g]| Current task: PortScan | Target number: {len(hosts)} | Engine: {engine} |[/g]")

        port_list: list = self.get_port_list()

        for index, host in enumerate(hosts):
            logger.info(f"Scanning {host} ({index + 1}/{len(hosts)})...")

            # 如果端口泛滥, 跳过扫描 #
            check = CheckOverFlow()
            bool_status: bool = check.run(host)
            if bool_status:
                self.port_results.append(
                    {'host': host, 'port': "overflow", 'protocol': "", 'banner': ""})
                continue

            # 判断使用什么引擎扫描 #
            if engine == 'system':
                scan = AsyncScan(host, port_list)
                port_result: set = scan.run()
            elif engine == 'nimscan':
                port_result: set = nimscan(host)
            else:
                logger.error("[r]Port scan engine is error![/r]")
                exit(1)

            # 最后检测扫描结果是否异常 #
            if port_result and len(port_result) > 500:
                logger.error("[r]The scan result is abnormal. The number of open ports exceeds 500.[/r]")
                continue
            elif port_result:
                # 对存活的端口，进行指纹识别
                logger.info("Identifying the port fingerprint...")
                queue_data: list = list(port_result)
                threadpool_task(task=self.banner_scan, thread_count=500, task_args=(host,), queue_data=queue_data)
            else:
                logger.info(f"[y]This IP ({host}) has no open port.[/y]")
                continue

        if SHOW_TABLE:
            self.show_table()

        logger.info(f"Effective collection quantity: {len(self.port_results)}")
        logger.info(f"Port scan task finished! Total time：{runtime_format(start, time())}")
        return self.port_results
