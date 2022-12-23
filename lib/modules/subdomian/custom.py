#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：jammny
文件描述： 
"""
import ast

from httpx import Client
from parsel import Selector

from lib.config.logger import logger
from lib.utils.format import domain_format


class Custom:
    def __init__(self, domain: str, datasets: dict) -> None:
        # 存储结果
        self.result_domain: list = []
        self.domain: str = domain
        self.id: str = datasets['id']
        self.type: str = datasets['type']
        self.request: dict = datasets['rule']['request']
        self.header: str = self.request['header']
        self.url: str = self.request['url'].replace('{domain}', domain)
        self.method: str = self.request['method']
        self.timeout: int = self.request['timeout']
        self.response: dict = datasets['rule']['response']
        self.code: str = self.response['code']

        # 是否循环页数
        self.w = datasets['rule']['while']
        if self.w:
            self.page = datasets['rule']['start_page']
            self.num = datasets['rule']['add_num']

    def parse_html(self, response) -> bool:
        # selector选择器
        s = self.response['selector']
        selector = Selector(response)
        if s['method'] == 'css':
            res: list = selector.css(s['data']).getall()
        else:
            res: list = selector.xpath(s['data']).getall()
        if res:
            # print(res)
            # 遍历列表的值, 并对值进行域名提取
            for i in res:
                if i.__contains__(self.domain):
                    domain = domain_format(i)
                    self.result_domain.append(domain)
            return True
        else:
            # logger.debug(response)
            return False

    def parse_json(self, response):
        key: list = self.response['key']

        if not response:
            return False

        # 解析类型1：[{"domain":["xxxx.domain.cn", ...]}, ...]
        # 先判断外面是不是列表
        if isinstance(response, list):
            for i in response:
                data = i[key[0]]
                # 判断第二层 是不是列表
                if isinstance(data, list):
                    for d in data:
                        domain = domain_format(d)
                        self.result_domain.append(domain)
                else:
                    domain = domain_format(data)
                    self.result_domain.append(domain)

        # 解析类型2：{'passive_dns': [{'hostname': ''}, ...], ...}
        # 先判断外面是不是字典
        elif isinstance(response, dict):
            data = response[key[0]]
            #  判断第二层 是不是列表
            if isinstance(data, list):
                for i in data:
                    data2 = i[key[1]]
                    # 判断第三层 是不是列表
                    if isinstance(data2, list):
                        for d in data:
                            domain = domain_format(d)
                            self.result_domain.append(domain)
                    else:
                        domain = domain_format(data2)
                        self.result_domain.append(domain)
        return True

    def parse_txt(self, response):
        if response.__contains__(self.domain):
            data = response.split('\n')
            for i in data:
                domain = domain_format(i)
                self.result_domain.append(domain)
            return True
        else:
            return False

    def parse_response(self, response) -> bool:
        """
        解析响应包数据
        :return:
        """
        if self.type == 'html':
            return self.parse_html(response)
        elif self.type == 'json':
            return self.parse_json(response)
        elif self.type == 'txt':
            return self.parse_txt(response)
        else:
            return False

    def send_request(self):
        """
        发送接口请求
        :return: response.text， response.json(), bool
        """
        try:
            with Client(verify=False, timeout=self.timeout, headers=self.header) as c:

                # 判断使用什么请求方法
                if self.method == 'get':
                    response = c.get(self.url)
                if self.method == 'post':
                    # 携带请求参数
                    tmp: str = self.request['data']
                    if tmp.__contains__('{domain}'):
                        tmp: str = tmp.replace('{domain}', self.domain)
                    data: dict = ast.literal_eval(tmp)
                    response = c.post(self.url, data=data)

        except Exception as e:
            logger.error(f'{self.url} {e}')
            return False

        # 判断响应码是否一致
        if response.status_code == self.code:
            # 选择解析类型
            if self.type == 'html':
                return response.text
            elif self.type == 'json':
                return response.json()
            elif self.type == 'txt':
                return response.text
            else:
                return False
        else:
            logger.warn(f"{self.id} error! response code: {response.status_code}")
            # logger.debug(response.text)
            return False

    def circular_process(self) -> bool:
        """
        循环处理， 处理那些有页数增加的
        :return:
        """
        url = self.url
        while self.w:
            self.page += self.num
            logger.debug(f"{self.id} current page: {self.page}")
            self.url: str = url.replace('{page}', str(self.page))
            response: str | dict | bool = self.send_request()
            if response:
                # 解析请求
                if not self.parse_response(response):
                    logger.debug(f"{self.id} crawl to the end！")
                    return False
            else:
                return False

    def get_domain(self,) -> bool:
        """
        获取域名
        :return: bool
        """
        if self.w:
            return self.circular_process()
        else:
            response: str | dict | bool = self.send_request()
            if response:
                # 解析请求
                self.parse_response(response)
                return True
            else:
                return False

    def run(self):
        """
        类执行入口
        :return:
        """
        logger.info(f"Running {self.id}...")
        if self.get_domain():
            if self.result_domain:
                # 差点忘记去重
                self.result_domain = list(set(self.result_domain))
                logger.info(f"{self.id}： {len(self.result_domain)} results found!")
                logger.debug(f"{self.id}： {self.result_domain}")
        return self.result_domain
