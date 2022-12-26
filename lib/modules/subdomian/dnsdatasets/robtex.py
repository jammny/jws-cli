#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：通过robtex查询域名的dns解析记录，收集其中的域名信息。如果是['A', 'AAAA']记录，那么需要提取IP，然后再反查IP的域名解析。
"""
from time import sleep
from ast import literal_eval
from typing import Any

from httpx import Client

from lib.config.logger import logger


class Robtex:
    def __init__(self, domain: str) -> None:
        self.domain = domain
        self.result_domain: list = []
        self.ip = []
        self.url: str = f"https://freeapi.robtex.com/pdns/forward/{self.domain}"

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        if response.__contains__('rrname'):
            data: list = response.splitlines()
            for i in data:
                res: dict = literal_eval(i)
                rrtype: str = res['rrtype']
                rrdata: str = res['rrdata']
                if rrtype in ['A', 'AAAA']:
                    self.ip.append(rrdata)
                elif rrdata.__contains__(self.domain):
                    self.result_domain.append(rrdata)
                else:
                    pass
            return True
        else:
            return False

    def parse_resqonse2(self, response: str) -> bool:
        """
        解析resqonse2包
        :return:
        """
        if response.__contains__('rrname'):
            data: list = response.splitlines()
            for i in data:
                res: dict = literal_eval(i)
                rrname: str = res['rrname']
                if rrname.__contains__(self.domain):
                    self.result_domain.append(rrname)
            return True
        else:
            return False

    def send_request(self, url) -> Any:
        """
        请求接口，返回响应内容
        :return:
        """
        try:
            with Client(verify=False, timeout=10) as c:
                response = c.get(url)
                if response.status_code == 200:
                    return response.text
                else:
                    logger.debug(f"robtex connect error！ Code： {response.status_code}")
                    # logger.debug(response.text)
                    return False
        except Exception as e:
            logger.error(f"{url} {e}")
            return False

    def get_domain(self) -> list:
        """
        https://freeapi.robtex.com/
        :return:
        """
        logger.info("Running Robtex...")
        response: str | bool = self.send_request(self.url)
        if response:
            self.parse_resqonse(response)
        if self.ip:
            for ip in self.ip:
                url: str = f"https://freeapi.robtex.com/pdns/reverse/{ip}"
                response2: str | bool = self.send_request(url)
                if response2:
                    self.parse_resqonse2(response2)
            sleep(1)

        if self.result_domain:
            # 去重复
            self.result_domain = list(set(self.result_domain))
            logger.info(f"Robtex：{len(self.result_domain)} results found!")
            logger.debug(f"Robtex：{self.result_domain}")
        return self.result_domain

    def run(self):
        pass
