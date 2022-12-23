#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：通过dnsdumpster查看dns解析记录，筛选其中域名
"""
from httpx import Client
from parsel import Selector

from lib.utils.format import domain_format
from lib.config.logger import logger


class Dnsdumpster:
    def __init__(self, domain: str) -> None:
        self.domain = domain
        self.result_domain: list = []
        self.url: str = f"https://dnsdumpster.com/"

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        selector = Selector(response)  # 创建Selector类实例
        res: list = selector.css('td[class="col-md-4"] ::text').getall()
        if res:
            for i in res:
                if i.__contains__(self.domain):
                    domain = domain_format(i)
                    self.result_domain.append(domain)
            return True
        else:
            return False

    def send_request(self) -> str | bool:
        """
        请求接口，返回响应内容
        :return:
        """
        try:
            with Client(verify=False, timeout=10) as c:
                c.get(self.url)  # 自动获取返回的set-cookies
                headers = {
                    'Referer': 'https://dnsdumpster.com',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
                data = {
                    'csrfmiddlewaretoken': c.cookies.get('csrftoken'),
                    'targetip': self.domain,
                    'user': 'free'
                }
                response2 = c.post(self.url, headers=headers, data=data)
            if response2.status_code == 200:
                return response2.text
            else:
                logger.debug(f"dnsdumpster connect error！ Code： {response2.status_code}")
                # logger.debug(response2.text)
                return False
        except Exception as e:
            logger.error(f"{self.url} {e}")
            return False

    def get_domain(self) -> list:
        """
        https://dnsdumpster.com/
        :return:
        """
        logger.info("Running Dnsdumpster...")
        response: str | bool = self.send_request()
        if response:
            self.parse_resqonse(response)
        # 去重复
        self.result_domain = list(set(self.result_domain))
        logger.info(f"Dnsdumpster：{len(self.result_domain)} results found!")
        logger.debug(f"Dnsdumpster：{self.result_domain}")
        return self.result_domain

    def run(self):
        pass
