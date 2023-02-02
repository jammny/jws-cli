#!/usr/bin/env python 
# -- coding:utf-8
"""
作者：jammny
文件描述： 控制台
"""
from lib.config.logger import logger
from lib.config.settings import REPORTS, POC_ENGINE

from lib.core.update import Update
from lib.core.report import Report

from lib.modules.cidrscan import Cidr
from lib.modules.pocscan import Poc
from lib.modules.portscan import Port
from lib.modules.subdomian.subdomain import Sub
from lib.modules.fingerprint import Finger
from lib.modules.cdn_recognition import CDN
from lib.modules.thirdparty import afrog, xray

from lib.utils.format import rex_ip, blacklist_ipaddress, blacklist_cidr


class Option:
    def __init__(self, args: dict):
        self.target = None
        # 获取命令行参数
        self.args: dict = args
        # 用于添加URLs
        self.urls: list = []

    def args_update(self):
        """
        程序版本更新
        :return:
        """
        update = Update()
        update.run()

    def args_auto(self):
        target: str = self.target
        report = Report(target)
        '''
        # 域名收集
        sub_results: list = self.args_sub(target)
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
        report.write_tmp('valid_ip', ip_results)
        
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
        report.write_tmp('valid_url', port_web_url)
        self.urls += port_web_url

        # C段扫描
        # 将cdn识别的结果，进行ip云资产、cdn资产黑名单过滤，尽可能找出有效的C段IP
        cdn_tmp = [i['ip'][0] for i in cdn_results if len(i['ip']) == 1 and blacklist_ipaddress(i['address'][0]) and blacklist_cidr(i['ip'][0])]
        cidr_port: list = self.args_cidr(cdn_tmp)
        report.write_tmp('valid_cidr_port', cidr_port)

        # 指纹识别
        cidr_web: list = self.args_finger(cidr_port)
        # 生成报告
        report.run('valid_cidr_web', cidr_web)
        cidr_web_url = [i['url'] for i in cidr_web]
        report.write_tmp('valid_cidr_url', cidr_web_url)
        self.urls += cidr_web_url
        report.write_tmp('valid_all_url', self.urls)

        # POC扫描
        poc_results: list = self.args_poc(self.urls, target)
        if poc_results:
            # 生成报告
            report.run('valid_poc', poc_results)
        '''
        # xray扫描
        self.args_xray(self.urls, target)

        logger.info(f"报告输出路径：{REPORTS}/{self.target}.html")

    def args_sub(self, target=None):
        """
        子域名收集
        :return:
        """
        # 设置爆破模式
        if self.args['brute']:
            brute_status = True
        else:
            brute_status = False

        if target is None:
            # 单独调用
            target = self.target
            sub_results: list = Sub(target).run(brute_status)
            # 生成报告
            report = Report(target)
            report.run('valid_sub', sub_results)
            # 从扫描结果中将域名单独提取出来
            domain = [i['subdomain'] for i in sub_results]
            # 将数据写入tmp目录，保存成txt格式
            report.write_tmp('valid_sub', domain)

            # 判断是否需要进行指纹识别
            if self.args['finger'] and domain:
                sub_web: list = self.args_finger(domain)
                # 生成报告
                Report(self.target).run('valid_sub_web', sub_web)

            logger.info(f"报告输出路径：{REPORTS}/{self.target}_sub.html")
        else:
            sub_results: list = Sub(target).run(brute_status)
            return sub_results

    def args_finger(self, target=None):
        """
        指纹识别
        :return:
        """
        if target is None:
            target: list = [self.target]
            Finger(target).run()
        else:
            finger_results: list = Finger(target).run()
            return finger_results

    def args_cdn(self, target=None):
        """
        cdn识别
        :param target: list | None
        :return:
        """
        if target is None:
            target: list = [self.target]
            CDN(target).run()
        else:
            cdn_results: list = CDN(target).run()
            return cdn_results

    def args_port(self, target=None):
        """
        端口扫描
        :param target: list | None
        :return:
        """
        if target is None:
            target: list = [self.target]
            port_results = Port(target).run()
            port = [f"{i['target']}:{i['port']}" for i in port_results]
            # 判断是否需要进行指纹识别
            if self.args['finger'] and port:
                self.args_finger(port)
        else:
            port_results: list = Port(target).run()
            return port_results

    def args_cidr(self, target=None) -> list:
        """
        c段扫描
        :return:
        """
        if target is None:
            target: list = [self.target]
            cidr_results = Cidr(target).run()
            # 判断是否需要进行指纹识别
            if self.args['finger'] and cidr_results:
                self.args_finger(cidr_results)
        else:
            cidr_results: list = Cidr(target).run()
            return cidr_results

    def args_poc(self, urls=None, name=None):
        """
        poc扫描
        :param name:
        :param urls:
        :return:
        """
        if urls is None:
            urls: list = [self.target]

        if POC_ENGINE == 'system':
            poc_results = Poc(urls).run()
            return poc_results
        elif POC_ENGINE == 'afrog':
            afrog(urls, name)
            return list()
        else:
            return

    def args_xray(self, urls=None, name=None):
        """
        poc扫描
        :param name:
        :param urls:
        :return:
        """
        if urls is None:
            urls: list = [self.target]
        xray(urls, name)
        return


    def run(self):
        """
        类统一入口
        :return:
        """
        # console.print(self.args)
        # 对是否存在-t参数做判断
        if self.args['target']:
            self.target: str = self.args['target']
        else:
            logger.error('You need to provide the target！')
            exit(0)
        # 程序更新
        if self.args['update']:
            self.args_update()
        # 自动化
        elif self.args['auto']:
            self.args_auto()
        # 域名收集
        elif self.args['sub']:
            self.args_sub()
        # 端口扫描
        elif self.args['port']:
            self.args_port()
        # C段扫描
        elif self.args['cidr']:
            self.args_cidr()
        # 指纹识别
        elif self.args['finger']:
            self.args_finger()
        # CDN识别
        elif self.args['cdn']:
            self.args_cdn()
        # POC扫描
        elif self.args['poc']:
            self.args_poc()
        # POC扫描
        elif self.args['xray']:
            self.args_xray()
