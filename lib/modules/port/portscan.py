#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 利用协程写了一个端口扫描模块。
"""
import re
from time import time
from typing import Callable
from dataclasses import dataclass
import socket

import eventlet
from rich.console import Console
from rich.table import Table

from lib.modules.port.hostscan import HostScan
from lib.modules.port.rules import PROBES, signs_rules, SERVER
from lib.utils.format import runtime_format
from lib.core.logger import logger
from lib.core.settings import PORT, PORT_THREAD, PORT_METHOD, PORT_TIMEOUT


eventlet.monkey_patch(socket=True)


@dataclass()
class Port:
    target: list    # 目标列表

    port_range: str = PORT  # 默认端口范围
    result = []  # 存扫描结果

    def run(self):
        """
        类统一入口
        :return:
        """
        start = time()
        # 将目标放进队列
        logger.info(f"Get the target number：{len(self.target)}, thread counts: {PORT_THREAD}, method: {PORT_METHOD}")
        # 端口扫描
        if len(self.port_range) > 400:
            thread_count = PORT_THREAD
        else:
            thread_count = len(self.port_range)
        for host in self.target:
            # 主机存活检测
            res = HostScan().single_task(host)
            if not res:
                logger.debug(f"[TARGET] {host} is not alive.")
                continue
            ports_list = get_ports(self.port_range)
            results = PortScan().run(host, ports_list, thread_count)
            self.result += results
        logger.info(f"Port scan task finished! Total time：{runtime_format(start, time())}")
        show_table(self.result)
        return self.result


@dataclass()
class PortScan(object):
    port_results = []   # 存放端口扫描的结果

    def coroutinepool_task(self, task: Callable, data: list, thread_count: int, task_args: tuple = ()) -> None:
        """

        :param task: 需要异步运行的函数
        :param data: 需要加入到队列的数据
        :param thread_count: 协程数
        :param task_args: 需要异步运行的函数，夹带的参数
        :return:
        """
        # 把数据放到列队
        queue = eventlet.Queue()
        for i in data:
            queue.put(i)
        args: tuple = task_args + (queue,)
        # 创建协程池
        pool = eventlet.GreenPool(thread_count)
        # 循环创建协程并加入协程池
        for _ in range(queue.qsize()):
            pool.spawn_n(task, *args)
        # 等待所有协程执行完毕
        pool.waitall()

    def tcp_scan(self, host: str, queue) -> None:
        """
        TCP 扫描
        :param host:
        :param queue:
        :return:
        """
        try:
            port: int = queue.get()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    # 创建套接字
            sock.settimeout(PORT_TIMEOUT)   # 设置超时时间
            res = sock.connect_ex((host, port))   # 连接主机和端口
            sock.close()    # 关闭套接字
            if res == 0:
                # 打印端口信息
                service, Banner = self.get_banner(host, port)
                tmp = {'target': host, 'port': str(port), 'service': service, 'banner': Banner[:50]}
                logger.debug(tmp)
                self.port_results.append(tmp)
        except:
            pass

    def udp_scan(self, host: str, queue) -> None:
        try:
            port: int = queue.get()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(PORT_TIMEOUT)
            sock.sendto(b'', (host, port))
            data, addr = sock.recvfrom(1024)
            sock.close()
            # 打印端口信息
            service, Banner = self.get_banner(host, port)
            tmp = {'target': host, 'port': str(port), 'service': service, 'banner': Banner[:50]}
            logger.debug(tmp)
            self.port_results.append(tmp)
        except socket.timeout:
            pass

    def get_banner(self, host, port) -> tuple:
        """
        获取指纹
        :param host:
        :param port:
        :return:
        """
        Banner = ''
        service = ''
        for probe in PROBES:
            try:
                sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sd.settimeout(PORT_TIMEOUT)
                sd.connect((host, int(port)))
                sd.send(probe.encode(encoding='utf-8'))
                result = sd.recv(1024)
                # print(result)
                try:
                    Banner = result.decode("utf-8")
                except:
                    Banner = str(result.decode("raw_unicode_escape").strip().encode("utf-8"))
                service = self.matchbanner(Banner, signs_rules)
                if service != '':
                    break
            except:
                continue

        if service == "":
            service = self.get_server(port)
        return service, Banner

    def get_server(self, port) -> str:
        """
        匹配指纹
        :param port:
        :return:
        """
        for k, v in SERVER.items():
            if v == port:
                return k
        return ''

    def matchbanner(self, banner, slist) -> str:
        """
        匹配指纹
        :param banner:
        :param slist:
        :return:
        """
        for item in slist:
            item = item.split('|')
            p = re.compile(item[1])
            if p.search(banner) is not None:
                return item[0]
        return ''

    def run(self, host: str, ports_list: list, thread_count: int) -> list:
        """

        :param host:
        :param thread_count:
        :param host: 目标
        :param ports_list: 待扫描的端口列表
        :return:
        """
        if PORT_METHOD == "tcp":
            self.coroutinepool_task(self.tcp_scan, ports_list, thread_count, (host,))
        elif PORT_METHOD == "udp":
            self.coroutinepool_task(self.udp_scan, ports_list, thread_count, (host,))
        return self.port_results


def get_ports(port_range: str) -> list:
    """
    将 1-65535 或 21,22,80-90,8000-9000 拆分
    :param port_range:
    :return:
    """
    port_list: list = []
    if "," in port_range:
        tmp: list = port_range.split(",")
        for port in tmp:
            if "-" in port:
                ran: list = port.split("-")
                for n in range(int(ran[0]), int(ran[1])+1):
                    port_list.append(n)
            else:
                port_list.append(int(port))
    elif "-" in port_range:
        ran: list = port_range.split("-")
        for n in range(int(ran[0]), int(ran[1]) + 1):
            port_list.append(n)
    else:
        port_list.append(int(port_range))
    return port_list


def show_table(data: list) -> None:
    """
    表格展示数据
    :param: data
    :return:
    """
    table = Table(title="ports results", show_lines=False)
    table.add_column("target", justify="left", style="cyan", no_wrap=True)
    table.add_column("port", justify="left", style="magenta")
    table.add_column("service", justify="left", style="red")
    table.add_column("banner", justify="left", style="red")
    for i in data:
        table.add_row(i['target'], (i['port']), i['service'], (i['banner']))
    console = Console()
    console.print(table)
