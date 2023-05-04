#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：解析自定义DNS数据源的核心模块。
"""
import ast
import time
from typing import Union

from httpx import Client

from lib.utils.log import logger
from lib.utils.tools import match_subdomains


class Custom(object):
    def __init__(self, domain: str, datasets: dict) -> None:
        """参数初始化

        :param domain: 目标域名
        :param datasets: YAML解析规则内容
        """
        self.domain: str = domain
        self.datasets: dict = datasets
        self.result_domain: set = set()    # 存储结果
        self.id: str = self.datasets['id']
        self.rule: dict = self.datasets['rule']
        self.type = self.datasets['type']
        # 是否循环页数
        if self.rule['while']:
            self.page = self.rule['start_page']
            self.add_num = self.rule['add_num']
        # 请求参数
        self.request: dict = self.rule['request']
        self.header: str = self.request['header']
        self.method: str = self.request['method']
        self.timeout: int = self.request['timeout']
        self.url: str = self.request['url'].replace('{domain}', self.domain)
        # 响应参数
        self.response: dict = self.rule['response']
        self.code: str = self.response['code']

    def circular_process(self):
        """循环处理， 处理那些有页数增加的
        
        :return:
        """
        url = self.url
        while True:
            logger.debug(f"{self.id} current page: {self.page}")
            self.url: str = url.replace('{page}', str(self.page))
            self.page += self.add_num
            response_text: Union[str, None] = self.send_request()
            if response_text:
                # 解析请求
                res: set = match_subdomains(self.domain, response_text)
                # 删除影响元素
                res.discard(self.domain)
                if res:
                    self.result_domain = self.result_domain.union(res)
                else:
                    logger.debug(f"{self.id} crawl to the end！")
                    break
            else:
                break
            time.sleep(2)

    def send_request(self) -> Union[str, None]:
        """发送接口请求
        
        :return:
        """
        try:
            with Client(verify=False, timeout=self.timeout, headers=self.header, follow_redirects=True) as c:
                # 判断使用什么请求方法
                if self.method == 'get':
                    response = c.get(self.url)
                elif self.method == 'post':
                    # 携带请求参数
                    tmp: str = self.request['data']
                    if tmp.__contains__('{domain}'):
                        tmp: str = tmp.replace('{domain}', self.domain)
                    data: dict = ast.literal_eval(tmp)
                    response = c.post(self.url, data=data)
                else:
                    logger.error(f"不支持使用{self.method}方法！")
        except Exception as e:
            logger.error(f'{self.url} {e}')
            return
        # 判断响应码是否一致
        if response.status_code == self.code:
            return response.text
        else:
            logger.error(f"{self.id} error! response code: {response.status_code}")
            # logger.debug(response.text)
            return

    def run(self) -> list:
        """类执行入口
        
        :return:
        """
        logger.info(f"Running {self.id} modules...")
        if self.rule['while']:
            self.circular_process()
        else:
            response_text: Union[str, None] = self.send_request()
            if response_text:
                # 解析请求
                res = match_subdomains(self.domain, response_text)
                # 删除影响元素
                res.discard(self.domain)
                if res:
                    self.result_domain = self.result_domain.union(res)
        if self.result_domain:
            logger.info(f"{self.id}： {len(self.result_domain)} results found!")
            logger.debug(f"{self.id}： {self.result_domain}")
        return list(self.result_domain)
