#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：fullhunt api接口调用
Hunter语法：

"""
from typing import Any

from httpx import Client

from lib.config.logger import logger
from lib.config.settings import CONFIG_DATA


class Fullhunt:
    def __init__(self, domain) -> None:
        self.name = "Fullhunt"
        self.key: str = CONFIG_DATA['fullhunt_key']
        self.url: str = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
        self.result_domain: list = []

    def parse_response(self, response: dict) -> bool:
        """
        解析响应包数据
        :return:
        """
        if response.__contains__('hosts'):
            data = response['hosts']
            for i in data:
                self.result_domain.append(i)
            return True
        else:
            logger.debug(response)
            return False

    def send_request(self) -> Any:
        """
        发送搜索请求
        """
        headers = {
            'X-API-KEY': self.key,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        }
        try:
            with Client(headers=headers, verify=False) as c:
                response = c.get(self.url)
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warn(f'Censys connect error！ Code: {response.status_code}')
                    # logger.debug(response.text)
                    return False
        except Exception as e:
            logger.error(f"{self.url},{e}")
            return False

    def get_domain(self) -> list:
        """
        域名收集
        :return:
        """
        logger.info("Running Fullhunt ...")
        # 判断key是否可用
        if not self.key:
            logger.warn(f"{self.name} api key error!")
            return self.result_domain

        response: bool | dict = self.send_request()
        if response:
            self.parse_response(response)

        if self.result_domain:
            logger.info(f"Fullhunt：{len(self.result_domain)} results found!")
            logger.debug(self.result_domain)
        return self.result_domain

    def run(self):
        """
        类执行入口
        """
        pass
