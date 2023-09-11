#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 内置的DNS数据源模块，爬取 https://www.dnsdumpster.com/ 的数据。
"""
from typing import Union, Set

from httpx import Client
from tenacity import retry, stop_after_attempt

from lib.core.log import logger
from lib.modules.search.api_base import ApiBase
from lib.utils.tools import match_subdomains


class Dnsdumpster(ApiBase):

    def __init__(self, domain: str):
        super().__init__()
        self.name: str = "Dnsdumpster"
        self.domain: str = domain
        self.result_domain = set()
        self.url = f"https://dnsdumpster.com/"
        self.headers = {
            'Referer': 'https://dnsdumpster.com',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

    @retry(stop=stop_after_attempt(2))
    def send_request(self, url) -> Union[str, None]:
        """请求接口，返回响应内容

        :return:
        """
        headers: dict = self.headers
        name: str = self.name
        domain: str = self.domain
        with Client(verify=False, headers=headers, timeout=10) as c:
            c.get(url)
            data = {
                # 从返回的set-cookies中，拿到csrftoken
                'csrfmiddlewaretoken': c.cookies.get('csrftoken'),
                'targetip': domain,
                'user': 'free'
            }
            response = c.post(self.url, headers=self.headers, data=data)
            if response.status_code == 200:
                return response.text
            else:
                logger.error(f"{name} status_code error： {response} {response.text}")
                return

    def get_domain(self) -> Set[str]:
        """获取域名数据

        :return:
        """
        name: str = self.name
        domain: str = self.domain
        url: str = self.url
        logger.info(f"Running {name}...")

        try:
            response_body = self.send_request(url)
        except Exception as e:
            logger.error(f"{name} connect error! {url} {e}")
            return self.result_domain

        if response_body:
            self.result_domain = match_subdomains(domain, response_body)

        logger.info(f"Dnsdumpster：{len(self.result_domain)} results found!")
        return self.result_domain
