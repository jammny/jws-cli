#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：POC框架核心代码
"""
import os
from time import time

import httpx
import yaml
from colorama import Fore

from lib.core.settings import POC, console
from lib.core.logger import logger

from lib.utils.thread import thread_task, get_queue


class Poc:
    def __init__(self, target: list):
        # 目标列表
        self.target: list = target
        # 存储结果
        self.results: list = []

    def req_poc(self, method, url, headers=None, cookies=None, follow_redirects=None):
        """
        发生POC请求包
        :param method:
        :param url:
        :param headers:
        :param cookies:
        :param follow_redirects:
        :return:
        """
        try:
            with httpx.Client(verify=False, headers=headers, cookies=cookies, follow_redirects=follow_redirects) as c:
                # print(c.event_hooks)
                if method == "GET":
                    response = c.get(url)
                elif method == "POST":
                    response = c.post(url)
            return response
        except Exception as e:
            logger.debug(f"连接失败：{url} 异常：{e}")
            return None

    def parser_exp(self, response, expression):
        """
        解析POC表达式
        :param response: poc响应包
        :return: True or Flase
        """
        if response:
            return eval(expression)

    def parser_poc(self, queue, url):
        """
        解析POC的主体内容
        :param url:
        :param queue:
        :return:
        """
        while not queue.empty():
            yaml_poc = queue.get()
            if yaml_poc == u'end_tag':  # 接收到结束码，就结束
                break
            with open(yaml_poc, mode="r", encoding="utf-8") as f:
                data = yaml.load(f.read(), Loader=yaml.FullLoader)

            # poc id
            poc_id = data['id']

            # poc危害等级
            severity = data['info']['severity']
            if severity == 'HIGH':
                severity = f"{Fore.RED}{severity}{Fore.RESET}"
            elif severity == 'INFO':
                severity = f"{Fore.BLUE}{severity}{Fore.RESET}"

            for k, v in data['rules'].items():
                #print(k, v)

                request = v['request']

                method = request['method']

                expression = v['expression']

                # 标识变量，用于退出这层循环
                finish = 0

                # 因为可能有多个路径，需要遍历
                path = request['path']

                for i in path:
                    poc_url = f"{url.rstrip('/')}{i}"
                    response = self.req_poc(method, poc_url)
                    if self.parser_exp(response, expression):
                        logger.warn(f"[+] {poc_id} {severity} {poc_url}")
                        self.results.append({
                            'id': poc_id,
                            'severity': data['info']['severity'],
                            'poc': poc_url
                        })
                        finish = 1
                        break
                if finish:
                    break

    def get_all_poc(self):
        """
        遍历poc, 返回包含文件路径的列表
        :return:
        """
        poc_files = []
        for root, dirs, files in os.walk(POC):
            for file in files:
                poc_files.append(os.path.join(root, file))
        return poc_files

    def run(self):
        """
        类统一执行入口
        :return:
        """
        start = time()
        logger.critical(f"执行任务：POC扫描")
        logger.info(f"Get the target number：{len(self.target)}")
        poc: list = self.get_all_poc()
        logger.info(f"{len(poc)} POCs were successfully loaded!")
        for url in self.target:
            queue = get_queue(poc)
            thread_task(task=self.parser_poc, args=[queue, url])
        end = time()
        logger.info(f"POC task finished! Total time：{end - start}")
        logger.debug(self.results)
        console.print(self.results)
        return self.results
