#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 封装一些公共类
"""
from time import sleep
from typing import Optional, Set, Union

from httpx import Client, Response
from tenacity import retry, stop_after_attempt

from lib.core.settings import API_KEY
from lib.core.log import logger
from lib.utils.tools import match_subdomains


class ApiBase(object):

    def __init__(self) -> None:
        self.config: dict = API_KEY
        self.name = None  # API 名称
        self.url = None  # API 接口URL地址
        self.domain = None  # 目标域名
        self.result_domain = set()  # 仅存子域名收集结果
        self.results: set = set()  # 存收集结果
        self.headers: dict = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        }
        self.data: dict = {}    # post请求的数据

    # @retry(stop=stop_after_attempt(2))
    def send_request(self, url: str, api: bool = True, method: str = "get",) -> Union[dict, str, None]:
        """发起URL请求

        :param method: 默认的http请求方法
        :param api: 默认为True，表示返回的是json数据
        :param url: 因为有指定的接口，url不一样，需要单独提供
        :return:
        """
        headers: dict = self.headers
        name: str = self.name
        with Client(verify=False, headers=headers, timeout=10) as c:
            if method == "get":
                response: Response = c.get(url)
            elif method == "post":
                response: Response = c.post(url, json=self.data)
        if response.status_code == 200:
            if api:
                return response.json()
            else:
                return response.text
        else:
            logger.error(f"{name} status_code error： {response} {response.text}")
            return

    @staticmethod
    def get_page(total, size, page_size):
        """通过比较返回的检索数量和设置的最大检索数，来判断需要遍历的页数。

        :param total: response返回的的total
        :param size: 配置文件设定的检索数
        :param page_size: 每页返回的检索数
        :return:
        """
        # 如果检索的内容小于设定的值，那么设定值就是检索值 #
        if size > total:
            size = total
        # 不能整除页数加1 #
        page = size // page_size
        if size % page_size > 0:
            page += 1
        return page

    def circular_process(self, page: int, url: str, domain: str, method: str = "get"):
        """循环遍历页数

        :param method:
        :param page: 总共需要遍历的页面数
        :param url: 接口URL
        :param domain: 目标域名
        :return:
        """
        page = page - 1  # 因为第一页数据已经拿了，所以少一页

        if page == 0:  # 正常情况下，页数不可能为负数，如果为0说明不需要遍历
            return

        # 如果有页数不为0，就开始循环遍历
        for i in range(page):
            sleep(1)
            try:
                if method == "get":
                    new_url = url.replace("[page]", f"{i + 2}")  # page 从第二页开始
                    response_json: Optional[dict] = self.send_request(new_url)
                else:
                    self.data['page'] = i + 2   # zero 页面 从第二页开始
                    response_json: Optional[dict] = self.send_request(url, method="post")
            except Exception as e:
                logger.error(f"Circular connect error! {url} {e}")
                break

            if not response_json:
                break

            result_domain: Set[str] = self.parse_response(domain, response_json)
            self.result_domain = self.result_domain.union(result_domain)

    def parse_response(self, domain, response_json):
        """解析响应数据


        :param domain:
        :param response_json:
        :return:
        """
        return match_subdomains(domain, str(response_json))

    def get_domain(self, ) -> Set[str]:
        """域名收集调用"""
        domain: str = self.domain
        name: str = self.name
        url: str = self.url
        logger.info(f"Running {name}...")

        try:
            response_json: Optional[dict] = self.send_request(url)
        except Exception as e:
            logger.error(f"{name} connect error! {url} {e}")
            return self.result_domain

        if not response_json:
            return self.result_domain

        # 正则提取页面中域名
        self.result_domain: Set[str] = self.parse_response(domain, response_json)

        logger.info(f"{name}：{len(self.result_domain)} results found!")
        logger.debug(f"{name}：{self.result_domain}")
        return self.result_domain
