#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 自动化扫描任务模块
"""
from time import time

from lib.core.report import Report
from lib.core.settings import AUTO_SETTING, REPORTS, POC_CONFIG
from lib.modules.cdn.cdnscan import CdnScan
from lib.modules.cidr.cidrscan import Cidr
from lib.modules.finger.fingerscan import FingerJScan
from lib.modules.port.portscan import PortScan
from lib.modules.sub.subscan import SubScan
from lib.modules.thirdparty import wafw00f, ffuf, afrog
from lib.utils.log import logger
from lib.utils.send_mail import SendEmail
from lib.utils.tools import rex_ip, blacklist_ipaddress, runtime_format


class AutoScan:
    def __init__(self):
        self.urls = list()  # 用于添加URLs

    def task(self, target):
        report = Report(target)

        # 域名收集
        sub_results: list = SubScan().run(target)
        report.run('sub_results', sub_results)  # 实时生成报告
        # 从扫描结果中将域名单独提取出来, 并保存
        domains = [i['subdomain'] for i in sub_results]
        report.write_tmp('sub_results', domains)

        # 如果domains为空就退出
        if not domains:
            logger.error("No domain name is available!")
            return

        # 指纹识别
        sub_finger_results: list = FingerJScan().run(domains)
        report.run('sub_finger_results', sub_finger_results)
        sub_url_results = [i['url'] for i in sub_finger_results]
        report.write_tmp('sub_url_results', sub_url_results)

        self.urls += sub_url_results

        # CDN识别
        cdn_results: list = CdnScan().run(domains)
        report.run('cdn_results', cdn_results)

        # 筛选出不存在cdn的IP数据
        ip_tmp = [i['ip'][0] for i in cdn_results if i['cdn'] == 'false']
        ip_results = list(set(ip_tmp))

        # 将解析到内网的ip过滤，内网ip后续可以做个host碰撞。
        data_tmp = rex_ip(ip_results)
        internal_network_ip = data_tmp['internal_network_ip']
        report.write_tmp('internal_network_ip', internal_network_ip)
        external_network_ip = data_tmp['external_network_ip']
        report.write_tmp('external_network_ip', external_network_ip)
        
        # 端口扫描
        if AUTO_SETTING['port_scan']:
            port_results: list = PortScan().run(external_network_ip)
            report.run('port_results', port_results)
            ip_port = [f"{i['ip']}:{i['port']}" for i in port_results]
            report.write_tmp('port_results', ip_port)

            # 指纹识别
            ip_finger_results: list = FingerJScan().run(ip_port)
            report.run('ip_finger_results', ip_finger_results)
            port_web_urls = [i['url'] for i in ip_finger_results]
            report.write_tmp('port_web_urls', port_web_urls)

            self.urls += port_web_urls

        # C段扫描
        if AUTO_SETTING['cidr_scan']:
            # 将cdn识别的结果，进行ip云资产、cdn资产黑名单过滤，尽可能找出有效的C段IP
            cdn_tmp = [i['ip'][0] for i in cdn_results if len(i['ip']) == 1 and blacklist_ipaddress(i['address'][0])]
            cidr_results: list = Cidr().run(cdn_tmp)
            report.run('cidr_results', cidr_results)
            cidr_ip_port = [f"{i['ip']}:{i['port']}" for i in cidr_results]
            cidr_ip_port = list(set(cidr_ip_port))

            # 指纹识别
            cidr_finger_results: list = FingerJScan().run(cidr_ip_port)
            report.run('cidr_finger_results', cidr_finger_results)
            cidr_web_urls = [i['url'] for i in cidr_finger_results]
            report.write_tmp('cidr_web_urls', cidr_web_urls)

            self.urls += cidr_web_urls

        # 整合所有有效的url目标
        url_targets = list(set(self.urls))

        # WAF扫描
        if AUTO_SETTING['waf_scan']:
            # 主要筛选出没有防护的目标，方便后续扫描
            waf_results = wafw00f(url_targets, target)
            report.run('waf_results', waf_results)
            no_waf_urls = []
            if waf_results:
                for i in waf_results:
                    if not i['detected']:
                        no_waf_urls.append(i['url'])
                    i['detected'] = str(i['detected'])
                url_targets = no_waf_urls  # 替换扫描目标列表
            report.write_tmp('no_waf_urls', no_waf_urls)

        # 目录扫描
        if AUTO_SETTING['dir_scan']:
            dir_results = ffuf(url_targets, target)
            report.run('dir_results', dir_results)

        # POC扫描
        if AUTO_SETTING['poc_scan']:
            if POC_CONFIG['afrog_engine']:
                poc_results = afrog(url_targets, target)
                report.run('poc_results', poc_results)

        report.html()

        # 邮件发送
        mail_msg = f"{target} scanning task completed！"
        file_name = f"{REPORTS}/{target}.html"
        SendEmail(mail_msg, file_name).send()
        logger.info(f"Report Output：{REPORTS}/{target}.html")

    def run(self, target_list: list):
        start = time()
        logger.info(f"Current task: AutoScan | Target numbers: {len(target_list)} | ")
        for target in target_list:
            self.task(target)
        logger.info(f"AutoScan task finished! Total time: {runtime_format(start, time())}")
