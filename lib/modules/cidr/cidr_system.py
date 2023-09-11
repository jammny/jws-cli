#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 基于主机发现技术，识别网段中存货的IP
"""
import ipaddress

from lib.core.settings import PORT_CONFIG
from lib.core.log import logger
from lib.modules.port.port_scan import PortScan


class CidrSystem(object):
    def __init__(self):
        self.cidr_results: list = []

    def run(self, cidr: list):
        """类执行入口

        :param cidr:
        :return:
        """
        for c in cidr:
            logger.info(f"Scanner {c}...")
            ip_list: list = [str(x) for x in ipaddress.ip_network(c).hosts()]  # 添加对应的C段IP数
            hosts: list = ip_list
            if hosts:
                port_range = PORT_CONFIG['port_range']
                engine = PORT_CONFIG['engine']
                banner_status = PORT_CONFIG['banner_status']
                s = PortScan(port_range, engine, banner_status)
                port_results = s.run(hosts)
                for i in port_results:
                    i['cidr'] = c
                    self.cidr_results.append(i)
        return self.cidr_results


if __name__ == "__main__":
    pass