#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 主机存活扫描
"""
from random import randint

from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.all import *
from ping3 import ping

from lib.utils.log import logger
from lib.utils.thread import threadpool_task


class HostScan(object):

    def __init__(self):
        self.results: list = []    # 存储IP存活结果

    def start_scan(self, queue_obj: any):
        """
        区别内外网ip 如果是内网IP就使用arp 外网使用ping
        :param queue_obj: queue.Queue
        :return:
        """
        while True:
            if queue_obj.empty():
                break
            ip: str = queue_obj.get()
            if ip[:3] == '10.' or ip[:6] == '172.16' or ip[:6] == '172.31' or ip[:7] == '192.168':
                self.arp_scan(ip)
            else:
                self.ping_scan(ip)

    def arp_scan(self, ip: str) -> None:
        """
        发送arp包
        :param ip: 目标IP
        :return:
        """
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            # 发送arp请求，并获取响应结果。设置3s超时。
            res = sr1(pkt, timeout=3, verbose=0)
            if res:
                self.results.append(ip)
                logger.info(f"Method: ARP, {ip} is alive.")
            else:
                self.ping_scan(ip)
        except:
            self.ping_scan(ip)

    def ping_scan(self, ip: str) -> None:
        """
        ping方法
        :param ip: 目标IP
        :return:
        """
        if ping(ip):
            self.results.append(ip)
            logger.info(f"Method: PING, {ip} is alive.")
        else:
            self.icmp_scan(ip)

    def icmp_scan(self, ip: str) -> None:
        """
        发送icmp包 防止ping工具没识别到
        :param ip: 目标IP
        :return:
        """
        try:
            id_ip = randint(1, 65535)
            id_ping = randint(1, 65535)
            seq_ping = randint(1, 65535)
            pkt = IP(dst=ip, ttl=128, id=id_ip) / ICMP(id=id_ping, seq=seq_ping) / b'hi!'
            icmp = sr1(pkt, timeout=3, verbose=False)
            if icmp:
                logger.info(f"Method: ICMP, {ip} is alive.")
                self.results.append(ip)
            else:
                self.syn_scan(ip)
        except:
            self.syn_scan(ip)

    def syn_scan(self, ip: str) -> None:
        """
        发送syn包
        :param ip: 目标IP
        :return:
        """
        try:
            # 构造标志位为syn的数据包
            pkt = IP(dst=ip) / TCP(dport=80, flags="A")
            result = sr1(pkt, timeout=3, verbose=0)
            if int(result[TCP].flags) == 4:
                self.results.append(ip)
                logger.info(f"Method: SYN, {ip} is alive.")
            else:
                self.udp_scan(ip)
        except:
            self.udp_scan(ip)

    def udp_scan(self, ip) -> None:
        """
        UDP扫描不准啊
        :param ip: 目标IP
        :return:
        """
        try:
            pkt = IP(dst=ip) / UDP(dport=80)
            result = sr1(pkt, timeout=3, verbose=0)
            # result.show()
            # 0x01 代表的ICMP字段值
            if int(result[IP].proto) == 0x01:
                self.results.append(ip)
                logger.info(f"Method: UDP, {ip} is alive.")
            else:
                self.results.append(ip)
                pass
                # logger.error(f"{ip} is not alive.")
        except:
            self.results.append(ip)
            pass
            # logger.error(f"{ip} is not alive.")

    def run(self, data: list, thread_count: int = 30) -> list:
        """
        data: 待识别存活的IP
        thread_count: 并发线程数
        """
        threadpool_task(task=self.start_scan, queue_data=data, thread_count=thread_count)
        return self.results
