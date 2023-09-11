#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 控制中心。
"""
from lib.core.settings import POC_CONFIG, BRUTE_ENGINE, BRUTE_FUZZY, PORT_CONFIG, CIDR_CONFIG
from lib.core.report import Report
from lib.modules.auto.auto_scan import AutoScan
from lib.modules.cidr.cidr_scan import Cidr
from lib.modules.company.company_scan import CompanyScan
from lib.modules.poc.poc_scan import PocScan
from lib.modules.port.port_scan import PortScan
from lib.modules.search.api_fofa import Fofa

from lib.modules.sub.sub_scan import SubScan
from lib.modules.finger.finger_scan import FingerJScan

__all__ = ['Router', ]


class Router(object):
    def __init__(self, targets_list: list) -> None:
        self.targets_list: list = targets_list  # 待扫描目标列表

    @staticmethod
    def args_fofa(query: str, poc_status: bool) -> None:
        """fofo接口调用，可搭配poc等模块使用

        :param query: 查询参数
        :param poc_status: 查询参数
        :return:
        """
        fofa_results: list = Fofa(query).run()
        if not fofa_results:
            return

        target_list = [i[0] for i in fofa_results]
        finger_results: list = FingerJScan().run(target_list)
        if not finger_results:
            return

        if poc_status:
            url_list = [i['url'] for i in finger_results]
            engine = POC_CONFIG['engine']
            scan = PocScan(engine)
            scan.run(url_list)

        return

    def args_auto(self, ) -> None:
        """自动化扫描"""
        targets_list: list = self.targets_list
        for target in targets_list:
            AutoScan().run(target)
        return

    def args_sub(self, finger=False) -> None:
        """子域名收集"""

        targets_list: list = self.targets_list
        scan = SubScan(brute_fuzzy=BRUTE_FUZZY, engine=BRUTE_ENGINE)
        for target in targets_list:
            report = Report(target)
            sub_results = scan.run(target)
            if not sub_results:
                continue
            report.run('sub', sub_results)
            data_list = [i['subdomain'] for i in sub_results]
            report.write_txt('sub', data_list)

            # 判断是否需要web识别 #
            if not finger:
                continue
            finger_results: list = FingerJScan().run(data_list)
            if finger_results:
                report.run('sub_web', finger_results)
                report.write_txt('sub_web', [i['url'] for i in finger_results])
        return

    def args_finger(self) -> None:
        """指纹识别"""
        targets_list: list = self.targets_list
        finger_results: list = FingerJScan().run(targets_list)
        if finger_results:
            report = Report()
            report.run('finger_results', finger_results)
            report.write_txt('finger', [i['url'] for i in finger_results])
        return

    def args_port(self, finger=None) -> None:
        """端口扫描"""
        targets_list: list = self.targets_list
        port_range: str = PORT_CONFIG['port_range']
        engine: str = PORT_CONFIG['engine']
        banner_status: bool = PORT_CONFIG['banner_status']
        port_results: list = PortScan(port_range, engine, banner_status).run(targets_list)
        if not port_results:
            return
        report = Report()
        report.run('port_results', port_results)
        data_list = [f"{i['host']}:{i['port']}" for i in port_results]
        report.write_txt('port', data_list)

        # 判断是否需要web识别 #
        if not finger:
            return
        finger_results: list = FingerJScan().run(data_list)
        if finger_results:
            report.run('port_web', finger_results)
            report.write_txt('port_web', [i['url'] for i in finger_results])
        return

    def args_cidr(self, finger) -> None:
        """C段扫描"""
        targets_list: list = self.targets_list
        engine = CIDR_CONFIG['engine']
        cidr_results: list = Cidr(engine).run(targets_list)
        cidr_ip_port = [f"{i['host']}:{i['port']}" for i in cidr_results]
        if not cidr_results:
            return
        report = Report()
        report.run('cidr_results', cidr_results)
        report.write_txt('cidr', list(set(cidr_ip_port)))

        # 判断是否需要web识别 #
        if not finger:
            return
        finger_results: list = FingerJScan().run(cidr_ip_port)
        if finger_results:
            report.run('port_web', finger_results)
            report.write_txt('port_web', [i['url'] for i in finger_results])
        return

    def args_poc(self) -> None:
        """poc扫描"""
        targets_list = self.targets_list
        engine = POC_CONFIG['engine']
        PocScan(engine).run(targets_list)
        return

    def args_company(target_list: list) -> None:
        """企业信息查询

        :param target_list: 目标企业名称
        :return:
        """
        scan = CompanyScan()
        scan.run(target_list)
        return
