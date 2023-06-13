#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：收集securitytrails的子域名信息
"""
from typing import Any

from httpx import Client

from lib.utils.log import logger
from lib.core.settings import SUB_CONFIG


class Securitytrails:
    def __init__(self, domain: str) -> None:
        self.name = "Securitytrails"
        # securitytrails api key
        self.key: str = SUB_CONFIG['api_key']['securitytrails_key']
        self.domain: str = domain
        self.result_domain: list = []

        self.url: str = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains?children_only=false" \
                        f"&include_inactive=true"

    def parse_resqonse(self, response: dict) -> bool:
        """
        解析resqonse包
        :return:
        """
        if response.__contains__('subdomains'):
            data: list = response['subdomains']
            for i in data:
                domain: str = f"{i}.{self.domain}"
                self.result_domain.append(domain)
            return True
        else:
            # logger.debug(response)
            return False

    def send_request(self) -> Any:
        """
        请求接口，返回响应内容
        :return:
        """
        try:
            headers: dict = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
                "accept": "application/json",
                "APIKEY": self.key
            }
            with Client(verify=False, headers=headers) as c:
                response = c.get(self.url)
                if response.status_code == 200:
                    # logger.debug(response.text)
                    return response.json()
                else:
                    logger.debug(f"securitytrails connect error！ Code： {response.status_code}")
                    # logger.debug(response.text)
                    return False
        except Exception as e:
            logger.warning(f"{self.url} {e}")
            return False

    def get_domain(self) -> list:
        """
        https://docs.securitytrails.com/reference/domain-subdomains
        获取子域名
        :return:
        """
        logger.info(f"Running {self.name}...")
        # 判断key是否可用
        if not self.key:
            logger.warn(f"{self.name} api key error!")
            return self.result_domain

        response = self.send_request()
        if response:
            self.parse_resqonse(response)

        logger.info(f"{self.name}：{len(self.result_domain)} results found!")
        logger.debug(self.result_domain)
        return self.result_domain

    def run(self):
        pass
