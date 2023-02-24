#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：收集sitedossier的子域名信息
"""
from typing import Any

from httpx import Client
from parsel import Selector

from lib.utils.format import domain_format

from lib.core.logger import logger


class Sitedossier:
    def __init__(self, domain: str) -> None:
        self.domain: str = domain
        self.result_domain: list = []
        self.page: int = 1

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        selector = Selector(response)  # 创建Selector类实例
        res: list = selector.css('a ::text').getall()
        if res:
            for i in res:
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
        url = f"http://www.sitedossier.com/parentdomain/{self.domain}/{self.page}"
        try:
            headers: dict = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
            }
            with Client(verify=False, headers=headers, follow_redirects=True, timeout=10) as c:
                response = c.get(url)
                if response.status_code == 200:
                    if response.text.__contains__('detected'):
                        logger.warn("sitedossier 人机验证！")
                        return False
                    return response.text
                else:
                    if response.text.__contains__(self.domain):
                        logger.debug("sitedossier crawl to the end！")
                    else:
                        logger.debug(f"sitedossier connect error！ Code： {response.status_code}")
                        logger.debug(response.text)
                    return False
        except Exception as e:
            logger.warning(f"{url} {e}")
            return False

    def get_domain(self) -> list:
        """
        http://www.sitedossier.com/
        获取子域名
        :return:
        """
        logger.info("Running Sitedossier...")
        n = 0
        while True:
            response = self.send_request()
            if not response:
                break
            elif self.parse_resqonse(response):
                n += 1
                logger.debug(f"sitedossier current page: {n}")
                self.page += 100
            else:
                break

        if self.result_domain:
            logger.info(f"Sitedossier：{len(self.result_domain)} results found!")
            logger.debug(f"Sitedossier：{self.result_domain}")
        return self.result_domain

    def run(self):
        pass
