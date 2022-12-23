#!/usr/bin/env python 
# -- coding:utf-8
"""
作者：jammny
文件描述： 控制台
"""
from lib.config.logger import logger
from lib.config.settings import REPORTS

from lib.core.update import Update
from lib.core.report import Report
from lib.modules.subdomian.subdomain import Sub
from lib.core.fingerprint import Finger


class Option:
    def __init__(self, args: dict) -> None:
        self.target = None
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
        # 域名收集
        sub: list = self.args_sub(target)
        Report(target).run('valid_sub', sub)

        # 指纹识别，从扫描结果中将域名单独提取出来
        domain = [i['subdomain'] for i in sub]
        if domain:
            sub_web: list = self.args_finger(domain)
            self.urls += [i['url'] for i in sub_web]
            Report(self.target).run('valid_sub_web', sub_web)

        logger.info(f"报告输出路径：{REPORTS}/{self.target}.html")

    def args_sub(self, target=None) -> list:
        """
        子域名收集
        :return:
        """
        if self.args['brute']:
            brute_status = True
        else:
            brute_status = False
        if target is None:
            # 单独模式
            target = self.target
            sub_results: list = Sub(target).run(brute_status)
            # 生成报告
            Report(self.target).run('valid_sub', sub_results)
            if self.args['finger']:
                # 指纹识别，从扫描结果中将域名单独提取出来
                domain = [i['subdomain'] for i in sub_results]
                if domain:
                    sub_web: list = self.args_finger(domain)
                    self.urls += [i['url'] for i in sub_web]
                    Report(self.target).run('valid_sub_web', sub_web)
            logger.info(f"报告输出路径：{REPORTS}/{self.target}_sub.html")
        else:
            sub_results: list = Sub(target).run(brute_status)
            return sub_results

    def args_finger(self, target=None) -> list:
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
        # 指纹识别
        elif self.args['finger']:
            self.args_finger()
