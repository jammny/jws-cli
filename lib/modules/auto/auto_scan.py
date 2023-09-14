#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 自动化扫描任务模块
"""
from lib.core.report import Report
from lib.core.settings import BRUTE_FUZZY, BRUTE_ENGINE, TMP, AUTO_SETTING, PORT_CONFIG, CIDR_CONFIG, SMART_MODE, \
    REPORTS, POC_CONFIG
from lib.modules.auto.utils import distinguish_between_ip
from lib.modules.cidr.cidr_scan import Cidr
from lib.modules.finger.finger_scan import FingerJScan
from lib.modules.poc.poc_scan import PocScan
from lib.modules.port.port_scan import PortScan
from lib.modules.sub.sub_scan import SubScan

from lib.core.log import logger
from lib.utils.mail import SendEmail


def blacklist_ipaddress(data: list) -> bool:
    """物理IP地址 黑名单过滤

    :return:
    """
    black_list: list = AUTO_SETTING['filter_blacklist']
    for i in black_list:
        if i in data:
            return False
    return True


class AutoScan:
    def __init__(self):
        self.not_waf_url: set = set()  # 用于添加没waf的url目标
        self.url: set = set()  # 全部可访问的URL链接

    def run(self, target: str):
        """任务执行

        :param target:
        :return:
        """
        # 有些人分不清楚根域名，删除www. #
        if target[0:4] == "www.":
            target = target[4:]

        # 第一步，域名收集 #
        sub_results = SubScan(brute_fuzzy=BRUTE_FUZZY, engine=BRUTE_ENGINE).run(target)
        if not sub_results:
            logger.info("[bold yellow]No subdomain name found![/bold yellow]")
            SendEmail(f"{target} scan complete.").send_msg("No subdomian name found.")
            # 如果没有收集到域名，直接退出
            return
        report = Report(target)
        report.run('sub', sub_results)
        targets_list = [i['subdomain'] for i in sub_results]
        report.write_txt('sub', targets_list)
        
        # 筛选没有cdn的IP, 并区分内外网IP #
        no_cdn_ip: list = [i['ip'][0] for i in sub_results if i['cdn'] == '']
        ip_results: dict = distinguish_between_ip(no_cdn_ip)
        internal_network_ip: list = ip_results['internal_network_ip']
        external_network_ip: list = ip_results['external_network_ip']   # 内网ip后续可以考虑弄个host头碰撞
        report.write_txt('internal_network_ip', internal_network_ip)
        report.write_txt('external_network_ip', external_network_ip)
        
        # 将收集到的域名，进行web指纹识别 #
        finger_results: list = FingerJScan().run(targets_list)
        if finger_results:
            report.run('sub_web', finger_results)
            sub_web: list = [i['url'] for i in finger_results]
            report.write_txt('sub_web', sub_web)
            self.url = self.url.union(set(sub_web))
            # 筛选没有WAF的URL
            self.not_waf_url = self.not_waf_url.union(set([i['url'] for i in finger_results if i['waf'] == "None"]))
        else:
            logger.info("[bold yellow]No subdomain web found![/bold yellow]")
        
        # 对外网的IP进行端口扫描 #
        if not external_network_ip:
            logger.info("[bold yellow]No internal network ip found![/bold yellow]")

        if AUTO_SETTING['port_scan'] and external_network_ip:
            port_range: str = PORT_CONFIG['port_range']
            engine: str = PORT_CONFIG['engine']
            banner_status: bool = PORT_CONFIG['banner_status']
            port_results: list = PortScan(port_range, engine, banner_status).run(external_network_ip)
            if port_results:
                report.run('port', port_results)
                
                # 进行web指纹识别 #
                host_port = [f"{i['host']}:{i['port']}" for i in port_results]
                report.write_txt('port', host_port)
                finger_results_2: list = FingerJScan().run(host_port)
                if finger_results_2:
                    report.run('port_web', finger_results_2)
                    port_web: list = [i['url'] for i in finger_results_2]
                    report.write_txt('port_web', port_web)
                    self.url = self.url.union(set(port_web))
                    # 筛选没有WAF的URL
                    self.not_waf_url = self.not_waf_url.union(set([i['url'] for i in finger_results_2 if i['waf'] == "None"]))

        # C段黑名单过滤，筛选出有效的C段 #
        if AUTO_SETTING['cidr_scan'] and external_network_ip:
            ip_list = [i['ip'][0] for i in sub_results if i['cdn'] == '' and blacklist_ipaddress(i['address'][0])]
            engine = CIDR_CONFIG['engine']
            cidr_results, cidr_counter = Cidr(engine).run(ip_list, auto=True)
            report.write_txt('cidr_counter', cidr_counter)
            if cidr_results:
                report.run('cidr', cidr_results)
                cidr_host_port = [f"{i['host']}:{i['port']}" for i in cidr_results]
                cidr_port: list = list(set(cidr_host_port))  # 去重
                report.write_txt('cidr_port', cidr_port)
                finger_results_3: list = FingerJScan().run(cidr_port)
                if finger_results_3:
                    report.run('cidr_web', finger_results_3)
                    cidr_web: list = [i['url'] for i in finger_results_3]
                    report.write_txt('cidr_web', cidr_web)
                    self.url = self.url.union(set(cidr_web))
                    self.not_waf_url = self.not_waf_url.union(set([i['url'] for i in finger_results_3 if i['waf'] == "None"]))

        # 筛选出没有防护的目标，方便后续扫描 #
        report.write_txt('urls_not_waf', self.not_waf_url)
        report.write_txt('urls', self.url)

        # 智能扫描
        if SMART_MODE:
            logger.info("Intelligent scan has been enabled.")
            poc_targets: list = list(self.not_waf_url)
        else:
            poc_targets: list = list(self.url)

        # POC漏洞扫描 #
        if AUTO_SETTING['poc_scan'] and poc_targets:
            engine = POC_CONFIG['engine']
            poc_results: list = PocScan(engine).run(poc_targets, target)
            if poc_results:
                report.run('poc', poc_results)

        if AUTO_SETTING['generate_report']:
            report.html()   # 生成报告

            # 邮件发送
            mail_header = f"{target} scanning task completed！"
            file_name = f"{REPORTS}/{target}.html"
            report_name = f"{target}.html"
            mail_msg = "The information collection scan report has been generated. Click the attachment to download it."
            SendEmail(mail_header).send_file(mail_msg, file_name, report_name)
            logger.info(f"Report Output：{REPORTS}/{target}.html")

