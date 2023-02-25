#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：jammny
文件描述:
"""
import re
import threading

from scapy.layers.inet import IP, TCP, UDP

from rich.progress import Progress, BarColumn, TransferSpeedColumn, TimeRemainingColumn
from scapy.sendrecv import sr1
from scapy.volatile import RandShort

from lib.core.settings import PORT_TIMEOUT, PORT_METHOD
from .rules import PROBES, signs_rules, SERVER
from lib.utils.thread import threadpool_task

from socket import AF_INET, SOCK_STREAM, socket

lock = threading.Lock()


class PortScan:
    def __init__(self):
        self.results = list()

    def get_banner(self, host, port):
        Banner = ''
        service = ''
        for probe in PROBES:
            try:
                sd = socket(AF_INET, SOCK_STREAM)
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

    def get_server(self, port):
        for k, v in SERVER.items():
            if v == port:
                return k
        return ''

    def matchbanner(self, banner, slist):
        for item in slist:
            item = item.split('|')
            p = re.compile(item[1])
            if p.search(banner) is not None:
                return item[0]
        return ''

    def socket_scan(self, queue, host, task, progress):
        """
        基于 socket tcp 连接方式，进行端口扫描
        :param host: 扫描目标
        :param queue: 队列中存放了待扫描的端口
        :return:
        """
        while True:
            try:
                with lock:
                    if queue.empty():
                        break
                port = queue.get()
                conn = socket(AF_INET, SOCK_STREAM)
                conn.settimeout(PORT_TIMEOUT)
                result = conn.connect_ex((host, port))
                conn.close()
                # 如果端口开放，返回0
                if result == 0:
                    progress.console.print(f"{host}:{port}")
                    # 获取指纹
                    service, banner = self.get_banner(host, str(port))
                    tmp = {'target': host, 'port': str(port), 'service': service, 'banner': banner[:100]}
                    self.results.append(tmp)
            except Exception as e:
                continue
            finally:
                # 更新进度
                if not progress.finished:
                    progress.update(task, advance=1)

    def syn_scan(self, queue, host, task, progress):
        while True:
            try:
                if queue.empty():
                    break
                port = queue.get()
                sport = RandShort()
                pkt = IP(dst=host) / TCP(flags="S", sport=sport, dport=port)  # 构造标志位为ACK的数据包
                response = sr1(pkt, timeout=5, verbose=0)
                if response is not None and response.haslayer(TCP) and response[TCP].flags == "SA":
                    progress.console.print(f"{host}:{port}")
                    # 获取指纹
                    service, banner = self.get_banner(host, str(port))
                    tmp = {'target': host, 'port': str(port), 'service': service, 'banner': banner[:100]}
                    self.results.append(tmp)
            except:
                continue
            finally:
                # 更新进度
                if not progress.finished:
                    progress.update(task, advance=1)

    def udp_scan(self, queue, host, task, progress):
        while True:
            try:
                if queue.empty():
                    break
                port = queue.get()
                sport = RandShort()
                udp_packet = IP(dst=host)/UDP(dport=port, sport=sport)
                response = sr1(udp_packet, timeout=5, verbose=0)
                if response is not None and response.haslayer(UDP):
                    progress.console.print(f"{host}:{port}")
                    # 获取指纹
                    service, banner = self.get_banner(host, str(port))
                    tmp = {'target': host, 'port': str(port), 'service': service, 'banner': banner[:100]}
                    self.results.append(tmp)
            except Exception as e:
                continue
            finally:
                # 更新进度
                if not progress.finished:
                    progress.update(task, advance=1)

    def run(self, host, queue, thread_count):
        """

        :param hosts: 目标列表
        :param queue: 队列中存放了待扫描的端口
        :return:
        """
        # 进度条
        progress = Progress(BarColumn(bar_width=40), "[progress.percentage]{task.percentage:>3.1f}%",
                            TransferSpeedColumn(), "•", TimeRemainingColumn(), transient=True)
        with progress:
            task = progress.add_task(f'[red]', total=queue.qsize())
            if PORT_METHOD == "socket":
                threadpool_task(task=self.socket_scan, args=[queue, host, task, progress], thread_count=thread_count)
            elif PORT_METHOD == "syn":
                threadpool_task(task=self.syn_scan, args=[queue, host, task, progress], thread_count=thread_count)
            elif PORT_METHOD == "udp":
                threadpool_task(task=self.udp_scan, args=[queue, host, task, progress], thread_count=thread_count)
        return self.results


