#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 控制中心。
"""
from time import time

from lib.core.settings import POC_CONFIG
from lib.core.report import save_results
from lib.modules.auto.autoscan import AutoScan
from lib.modules.cidr.cidrscan import Cidr
from lib.modules.firm.firmscan import FirmScan
from lib.modules.port.portscan import PortScan
from lib.modules.sub.search.fofa_api import Fofa
from lib.modules.sub.subscan import SubScan
from lib.modules.finger.fingerscan import FingerJScan
from lib.modules.cdn.cdnscan import CdnScan
from lib.modules.thirdparty import afrog, ffuf, wafw00f
from lib.utils.log import logger
from lib.utils.tools import runtime_format

__all__ = ['Router', ]


class Router(object):
    @staticmethod
    def args_auto(target_list: list) -> None:
        """自动化扫描

        :param target_list: 目标域名列表
        :return:
        """
        start = time()
        for target in target_list:
            logger.info(f"Current task: AutoScan | Target numbers: {len(target_list)} | ")
            AutoScan().run(target)
        logger.info(f"AutoScan task finished! Total time: {runtime_format(start, time())}")
        return

    @staticmethod
    def args_sub(target_list: list) -> None:
        """子域名收集

        :param target_list: 目标域名列表
        :return: list
        """
        for target in target_list:
            sub_results = SubScan().run(target)
            save_results(keyword="sub", data=[i['subdomain'] for i in sub_results], name=target)
        return

    @staticmethod
    def args_fofa(query: str, finger_status: bool, poc_status: bool) -> None:
        """Fofo接口调用，搭配finger、poc等模块使用
        
        :param query: 查询参数
        :param finger_status: 查询参数
        :param poc_status: 查询参数
        :return:
        """
        fofa_results: list = Fofa(query).run()
        if not fofa_results:
            pass
        elif finger_status:
            finger_results: list = FingerJScan().run(fofa_results)
            save_results(keyword="finger", data=[i['url'] for i in finger_results])
        elif poc_status:
            afrog(fofa_results)
        return

    @staticmethod
    def args_finger(target_list: list) -> list:
        """指纹识别
        
        :param target_list: 目标域名列表
        :return: list
        """
        finger_results: list = FingerJScan().run(target_list)
        if finger_results:
            save_results(keyword="finger", data=[i['url'] for i in finger_results])
        return finger_results

    @staticmethod
    def args_cdn(target_list: list) -> list:
        """CDN识别
        
        :param target_list: 目标域名列表
        :return: list
        """
        cdn_results: list = CdnScan().run(target_list)
        if cdn_results:
            save_results(keyword="cdn", data=[str(i) for i in cdn_results])
        return cdn_results

    @staticmethod
    def args_port(target_list: list) -> list:
        """端口扫描
        
        :param target_list: 目标域名列表
        :return:
        """
        port_results: list = PortScan().run(target_list)
        if port_results:
            save_results(keyword="port", data=[f"{i['ip']}:{i['port']}" for i in port_results])
        return port_results

    @staticmethod
    def args_cidr(target_list: list) -> list:
        """C段扫描

        :param target_list: 目标域名列表
        :return:
        """
        cidr_results: list = Cidr().run(target_list)
        if cidr_results:
            save_results(keyword="cidr", data=[f"{str(i)}" for i in cidr_results])
        return cidr_results

    @staticmethod
    def args_waf(target_list: list) -> list:
        """WAF扫描
        
        :param target_list: 目标域名列表
        :return:
        """
        return wafw00f(target_list)

    @staticmethod
    def args_dir(target_list: list) -> list:
        """目录扫描

        :param target_list: 目标域名列表
        :return:
        """
        return ffuf(target_list)

    @staticmethod
    def args_poc(target_list: list) -> list:
        """poc扫描

        :param target_list: 目标域名列表
        :return:
        """
        if POC_CONFIG['afrog_engine']:
            return afrog(target_list)

    @staticmethod
    def args_firm(target_list: list) -> list:
        """企业信息查询

        :param target_list: 目标企业名称
        :return:
        """
        firm_results: list = FirmScan().run(target_list)
        return firm_results
