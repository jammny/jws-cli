#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 控制中心。
"""
import json
from typing import Any
from dataclasses import dataclass

from lib.core.logger import logger
from lib.core.settings import REPORTS, POC_ENGINE, TMP, AUTO_SETTING

from lib.core.update import Update
from lib.core.report import Report

from lib.modules.cidr.main import Cidr
from lib.modules.pocscan import Poc
from lib.modules.port.portscan import Port
from lib.modules.subdomian.subscan import Sub
from lib.modules.finger.main import Finger
from lib.modules.cdn.main import CDN
from lib.modules.thirdparty import afrog, xray, dirsearch, wafw00f
from lib.utils.encrypt import GetKey
from lib.utils.format import blacklist_ipaddress, rex_ip
from lib.utils.send_mail import SendEmail

__all__ = ['Option', ]


@dataclass()
class Option(object):
    urls = list()   # 用于添加URLs

    def args_update(self) -> None:
        """
        程序版本更新
        :return:
        """
        update = Update()
        update.run()

    def args_auto(self, target_list: list, brute: bool) -> None:
        if len(target_list) > 1:
            name = f"BatchTask_{GetKey().random_key(5)}"
        else:
            name = target_list[0]

        report = Report(name)
        # 域名收集
        sub_results: list = self.args_sub(target_list, brute)
        # 生成报告
        report.run('valid_sub', sub_results)
        # 从扫描结果中将域名单独提取出来, 将数据写入tmp目录，保存成txt格式
        domain: list = [i['subdomain'] for i in sub_results]
        report.write_tmp('valid_sub', domain)
        # 如果domain为空就退出
        if not domain:
            logger.error("Errors: No domain name is available!")
            return

        # 指纹识别
        sub_web: list = self.args_finger(domain)
        # 生成报告
        report.run('valid_sub_web', sub_web)
        sub_web_url = [i['url'] for i in sub_web]
        report.write_tmp('valid_sub_url', sub_web_url)
        self.urls += sub_web_url

        # CDN识别
        cdn_results: list = self.args_cdn(domain)
        # 生成报告
        report.run('valid_cdn', cdn_results)
        # 存在cdn的数据
        is_cdn = [i['domain'] for i in cdn_results if i['cdn'] == 'true']
        report.write_tmp('valid_is_cdn', is_cdn)
        # 不存在cdn的数据
        ip_tmp = [i['ip'][0] for i in cdn_results if i['cdn'] == 'false']
        ip_results = list(set(ip_tmp))
        # 将解析到内网的ip过滤，内网ip后续可以做个host碰撞
        data_tmp = rex_ip(ip_results)
        external_network_ip = data_tmp['external_network_ip']
        report.write_tmp('valid_ip', external_network_ip)

        if not AUTO_SETTING['port_scan']:
            logger.info(f"报告输出路径：{REPORTS}/{name}.html")
            return
        # 端口扫描
        port_results: list = self.args_port(external_network_ip)
        # 生成报告
        report.run('valid_port', port_results)
        port = [f"{i['target']}:{i['port']}" for i in port_results]
        report.write_tmp('valid_port', port)
        # 指纹识别
        port_web: list = self.args_finger(port)
        # 生成报告
        report.run('valid_port_web', port_web)
        port_web_url = [i['url'] for i in port_web]
        report.write_tmp('valid_port_url', port_web_url)
        self.urls += port_web_url

        if not AUTO_SETTING['cidr_scan']:
            logger.info(f"报告输出路径：{REPORTS}/{name}.html")
            return
        # C段扫描
        # 将cdn识别的结果，进行ip云资产、cdn资产黑名单过滤，尽可能找出有效的C段IP
        cdn_tmp = [i['ip'][0] for i in cdn_results if len(i['ip']) == 1 and blacklist_ipaddress(i['address'][0])]
        cidr_port: list = self.args_cidr(cdn_tmp)
        report.write_tmp('valid_cidr_port', cidr_port)
        # 指纹识别
        cidr_web: list = self.args_finger(cidr_port)
        # 生成报告
        report.run('valid_cidr_web', cidr_web)
        cidr_web_url = [i['url'] for i in cidr_web]
        report.write_tmp('valid_cidr_url', cidr_web_url)
        self.urls += cidr_web_url

        # 整合所有url
        all_url = list(set(self.urls))
        report.write_tmp('valid_all_url', all_url)

        # WAF扫描
        self.args_waf(target=name)
        no_waf_urls = []
        try:
            with open(f"{TMP}/{name}/waf.json", mode='r') as f:
                waf = json.load(f)
            for i in waf:
                if not i['detected']:
                    no_waf_urls.append(i['url'])
                i['detected'] = str(i['detected'])
        except:
            waf = []
        report.run('valid_waf', waf)
        report.write_tmp('valid_no_waf_urls', no_waf_urls)

        if not AUTO_SETTING['dir_scan']:
            logger.info(f"报告输出路径：{REPORTS}/{name}.html")
            return
        # 目录扫描
        self.args_dir(target=name)
        try:
            with open(f"{TMP}/{name}/dir.json", mode='r') as f:
                tmp = json.load(f)
                dir_results = tmp['results']
        except:
            dir_results = []
        report.run('valid_dir', dir_results)

        if not AUTO_SETTING['dir_scan']:
            logger.info(f"报告输出路径：{REPORTS}/{name}.html")
            return
        # POC扫描
        poc_results: list = self.args_poc(target=name)
        if poc_results:
            # 生成报告
            report.run('valid_poc', poc_results)

        if not AUTO_SETTING['xray_scan']:
            logger.info(f"报告输出路径：{REPORTS}/{name}.html")
            return
        # xray扫描
        self.args_xray(target=name)

        # 邮件发送
        mail_msg = f"{name} 扫描任务完成！"
        file_name = f"{REPORTS}/{name}.html"
        SendEmail(mail_msg, file_name).send()
        
        logger.info(f"报告输出路径：{REPORTS}/{name}.html")

    def args_sub(self, target_list: list, brute_status: bool, report: bool) -> list:
        """
        子域名收集
        :param report: 是否需要生成报告
        :param target_list: 目标域名列表
        :param brute_status: 爆破模式状态
        :return: list
        """
        logger.critical(f"执行任务：域名收集")
        sub_results = []
        for target in target_list:
            tmp: list = Sub(target).run(brute_status)
            sub_results: list = tmp + sub_results
        # 如果需要，生成报告
        if report:
            if len(target_list) > 1:
                name = GetKey().random_key(6)
            else:
                name = target_list[0]
            Report(name).run('valid_sub', sub_results)
            domain: list = [i['subdomain'] for i in sub_results]
            Report(name).write_tmp('valid_sub', domain)
            logger.info(f"报告输出路径：{REPORTS}/{name}.html")
        return sub_results

    def args_finger(self, target_list: list) -> list:
        """
        指纹识别
        :param target_list: 目标域名列表
        :return: list
        """
        logger.critical(f"执行任务：指纹识别")
        finger_results: list = Finger(target_list).run()
        return finger_results

    def args_cdn(self, target_list: list) -> list:
        """
        cdn识别
        :param target_list: 目标域名列表
        :return: list
        """
        logger.critical(f"执行任务：CDN识别")
        cdn_results: list = CDN(target_list).run()
        return cdn_results

    def args_port(self, target_list: list) -> list:
        """
        端口扫描
        :param target_list
        :return:
        """
        logger.critical(f"执行任务：端口扫描")
        port_results: list = Port(target_list).run()
        return port_results

    def args_cidr(self, target_list: list) -> list:
        """
        c段扫描
        :return:
        """
        logger.critical(f"执行任务：C段扫描")
        cidr_results: list = Cidr(target_list).run()
        return cidr_results

    def args_waf(self, target_list=None, target=None) -> None:
        """
        waf扫描
        :param target_list:
        :param target:
        :return:
        """
        logger.critical(f"执行任务：WAF识别")
        wafw00f(target_list, target)
        return

    def args_dir(self, target_list=None, target=None) -> None:
        """
        poc扫描
        :param name:
        :param urls:
        :return:
        """
        logger.critical(f"执行任务：目录扫描")
        dirsearch(target_list, target)
        return

    def args_poc(self, target_list=None, target=None) -> Any:
        """
        poc扫描
        :param name:
        :param urls:
        :return:
        """
        logger.critical(f"执行任务：POC扫描")
        if POC_ENGINE == 'system':
            poc_results = Poc(target_list).run()
            return poc_results
        elif POC_ENGINE == 'afrog':
            afrog(target_list, target)
            return
        else:
            return

    def args_xray(self, target_list=None, target=None) -> None:
        """
        poc扫描
        :param target_list:
        :param target:
        :return: None
        """
        logger.critical(f"执行任务：Xray扫描")
        xray(target_list, target)
        return

