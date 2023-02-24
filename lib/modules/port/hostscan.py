#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：jammny
文件描述： 
"""
from random import randint

from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.all import *

from ping3 import ping

from lib.core.logger import logger
from lib.utils.thread import threadpool_task, get_queue


class HostScan:
    """
    主机存活扫描
    """
    def __init__(self):
        self.results = []

    def start_scan(self, queue):
        """
        区别内外网ip，如果是内网IP就使用arp，外网使用ping
        :param: queue 队列
        """
        while True:
            if queue.empty():
                break
            ip = queue.get()
            if ip[:3] == '10.' or ip[:6] == '172.16' or ip[:6] == '172.31' or ip[:7] == '192.168':
                self.arp_scan(ip)
            else:
                self.icmp_scan(ip)

    def single_task(self, ip):
        """
        独立运行入口
        """
        # 内网ip扫描
        if ip[:3] == '10.' or ip[:6] == '172.16' or ip[:6] == '172.31' or ip[:7] == '192.168':
            self.arp_scan(ip)
        else:
            self.icmp_scan(ip)
        return self.results

    def arp_scan(self, ip):
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            # 发送arp请求，并获取响应结果。设置1s超时。
            res = srp1(pkt, timeout=5, verbose=0)
            if res:
                self.results.append(ip)
                logger.warning(f"[ARP] {ip} is alive.")
            else:
                self.icmp_scan(ip)
        except:
            self.icmp_scan(ip)

    def icmp_scan(self, ip):
        try:
            id_ip = randint(1, 65535)
            id_ping = randint(1, 65535)
            seq_ping = randint(1, 65535)
            pkt = IP(dst=ip, ttl=128, id=id_ip) / ICMP(id=id_ping, seq=seq_ping) / b'hi! I am jammny'
            icmp = sr1(pkt, timeout=5, verbose=False)
            if icmp:
                logger.warning(f"[ICMP] {ip} is alive.")
                self.results.append(ip)

            else:
                self.tcp_scan(ip)
        except:
            self.tcp_scan(ip)

    def tcp_scan(self, ip):
        try:
            # 构造标志位为syn的数据包
            pkt = IP(dst=ip) / TCP(dport=22, flags="A")
            result = sr1(pkt, timeout=5, verbose=0)
            if int(result[TCP].flags) == 4:
                self.results.append(ip)
                logger.warning(f"[SYN] {ip} is alive.")
            else:
                self.udp_scan(ip)
        except:
            self.udp_scan(ip)

    def udp_scan(self, ip):
        """
        UDP扫描不准啊
        """
        # 端口要求一定是没开放
        try:
            pkt = IP(dst=ip) / UDP(dport=52249)
            result = sr1(pkt, timeout=5, verbose=0)
            # result.show()
            # 0x01 代表的ICMP字段值
            if int(result[IP].proto) == 0x01:
                self.results.append(ip)
                logger.warning(f"[UDP] {ip} is alive.")
            else:
                # logger.debug(f"[TARGET] {ip} is not alive.")
                pass
        except:
            # logger.debug(f"[TARGET] {ip} is not alive.")
            pass

    def ping_scan(self, ip):
        if ping(ip):
            self.results.append(ip)
            logger.warning(f"[PING] {ip} is alive.")
        else:
            logger.debug(f"[PING] {ip} is not alive.")

    def run(self, queue, thread_count: int = 100) -> list:
        """
        类执行入口
        :param: queue 队列
        :return:
        """
        threadpool_task(task=self.start_scan, args=[queue], thread_count=thread_count)
        return self.results


if __name__ == '__main__':
    targets = ['192.168.8.1', '192.168.8.151']
    queue = get_queue(targets)
    results = HostScan().run(queue)
    print(results)
