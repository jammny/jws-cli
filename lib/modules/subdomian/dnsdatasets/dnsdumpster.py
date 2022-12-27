#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：通过dnsdumpster查看dns解析记录，筛选其中域名
"""
from typing import Any

from httpx import Client
from parsel import Selector

from lib.utils.format import domain_format
from lib.config.logger import logger


class Dnsdumpster:
    def __init__(self, domain: str) -> None:
        self.domain: str = domain
        self.result_domain: list = []
        self.url: str = f"https://dnsdumpster.com/"
        self.headers: dict = {
            'Referer': 'https://dnsdumpster.com',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        selector = Selector(response)
        res: list = selector.css('td[class="col-md-4"] ::text').getall()
        if res:
            for i in res:
                if i.__contains__(self.domain):
                    domain: str = domain_format(i)
                    self.result_domain.append(domain)
            return True
        else:
            return False

    def send_request(self) -> Any:
        """
        请求接口，返回响应内容
        :return:
        """
        with Client(verify=False, timeout=10) as c:
            try:
                # 先获取返回的set-cookies
                c.get(self.url)
                data = {
                    # 从返回的set-cookies中，拿到csrftoken
                    'csrfmiddlewaretoken': c.cookies.get('csrftoken'),
                    'targetip': self.domain,
                    'user': 'free'
                }
                response = c.post(self.url, headers=self.headers, data=data)
            except Exception as e:
                logger.error(f"{self.url} {e}")
                return False
        if response.status_code == 200:
            return response.text
        else:
            logger.debug(f"dnsdumpster connect error！ Code： {response.status_code}")
            # logger.debug(response.text)
            return False

    def get_domain(self) -> list:
        """
        https://dnsdumpster.com/
        :return:
        """
        logger.info("Running Dnsdumpster...")
        response = self.send_request()
        if response:
            self.parse_resqonse(response)

        if self.result_domain:
            # 去重复
            self.result_domain = list(set(self.result_domain))
            logger.info(f"Dnsdumpster：{len(self.result_domain)} results found!")
            logger.debug(f"Dnsdumpster：{self.result_domain}")
        return self.result_domain

    def run(self):
        pass
