#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 基于主机发现技术，识别网段中存货的IP
"""
import ipaddress

from lib.utils.log import logger
from .cidr_table import show_table

from lib.modules.port.host_scan import HostScan
from lib.modules.port.portscan import PortScan

from lib.core.settings import CIDR_CONFIG


class CidrSystem(object):
    def __init__(self):
        self.cidr_results: list = []
        self.skip_alive: bool = CIDR_CONFIG['skip_alive']

    def run(self, cidr: list):
        """类执行入口

        :param cidr:
        :return:
        """
        for c in cidr:
            logger.info(f"Scanner {c}...")
            ip_list: list = [str(x) for x in ipaddress.ip_network(c).hosts()]  # 添加对应的C段IP数
            if self.skip_alive:
                hosts: list = ip_list
            else:
                hosts: list = HostScan().run(ip_list)    # 主机存活检测
            if hosts:
                port_results: list = PortScan().run(hosts)
                # show_table(port_results)
                for i in port_results:
                    i['cidr'] = c
                    self.cidr_results.append(i)
        return self.cidr_results


if __name__ == "__main__":
    pass