#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：binaryedge api接口调用
"""
from typing import Any

from httpx import Client

from lib.config.logger import logger
from lib.config.settings import CONFIG_DATA


class Binaryedge:
    def __init__(self, domain: str) -> None:
        self.name = "Binaryedge"
        self.key: str = CONFIG_DATA['binaryedge_key']
        self.url: str = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
        self.result_domain: list = []
        self.headers = {
            'X-Key': self.key,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        }

    def parse_response(self, response: dict) -> bool:
        """
        解析响应包数据
        :return:
        """
        if response.__contains__('events'):
            data = response['events']
            for i in data:
                self.result_domain.append(i)
            return True
        else:
            # logger.debug(response)
            return False

    def send_request(self) -> Any:
        """
        发送搜索请求
        """
        try:
            with Client(headers=self.headers, verify=False) as c:
                response = c.get(self.url)
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warn(f"Binaryedge connect error！ Code：{response.status_code}")
                    # logger.debug(response.text)
                    return False
        except Exception as e:
            logger.error(f"{self.url} {e}")
            return False

    def get_domain(self) -> list:
        """
        域名收集
        :return:
        """
        logger.info("Running Binaryedge ...")
        if not self.key:
            logger.warn(f"{self.name} api key error!")
            return self.result_domain

        response = self.send_request()
        if response:
            self.parse_response(response)

        if self.result_domain:
            logger.info(f"Binaryedge：{len(self.result_domain)} results found!")
            logger.debug(f"Binaryedge：{self.result_domain}")
        return self.result_domain

    def run(self):
        """
        类执行入口
        """
        pass
