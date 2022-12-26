#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：收集virustotal的子域名信息
"""
from time import sleep
from typing import Any

from httpx import Client
from lib.config.logger import logger


class Virustotal:
    def __init__(self, domain: str) -> None:
        self.domain: str = domain
        self.result_domain: list = []
        self.url: str = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?relationships=resolutions" \
                        f"&cursor=&limit=10"
        self.page: int = 1
        self.headers: dict = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
            'Content-Type': 'application/json',
            'X-Tool': 'vt-ui-main',
            'X-App-Version': 'v1x132x0',
            'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8',
            'X-Vt-Anti-Abuse-Header': 'MTQ5NTc4NTM1OTItWkc5dWRDQmlaU0JsZG1scy0xNjY4MTQ5NzAxLjcyNw==',
            'Te': 'trailers'
        }

    def parse_resqonse(self, response: dict) -> bool:
        """
        解析resqonse包
        :return:
        """
        # links中包含了本次请求的链接和下一条请求的链接
        links: dict = response['links']
        # 如果存在下一条链接
        if links.__contains__('next'):
            data: list = response['data']
            for i in data:
                domain: str = i['id']
                self.result_domain.append(domain)
            logger.debug(f"virustotal current page：{self.page}")
            # 获取下一页的链接，每一页只能读取十条数据
            self.url = links['next']
            return True
        else:
            return False

    def send_request(self) -> Any:
        """
        请求接口，返回响应内容
        :return:
        """
        try:
            with Client(verify=False, headers=self.headers, timeout=10) as c:
                response = c.get(self.url)
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.debug(f"virustotal connect error！ Code： {response.status_code}")
                    # logger.debug(response.text)
                    return False
        except Exception as e:
            logger.error(f"{self.url} {e}")
            return False

    def get_domain(self) -> list:
        """
        https://www.virustotal.com/gui/
        获取子域名
        :return:
        """
        logger.info("Running virustotal...")
        while True:
            response = self.send_request()
            if not response:
                break
            elif self.parse_resqonse(response):
                self.page += 1
            else:
                logger.debug("virustotal crawl to the end！")
                break
            sleep(1)

        if self.result_domain:
            logger.info(f"Virustotal：{len(self.result_domain)} results found!")
            logger.debug(f"Virustotal：{self.result_domain}")
        return self.result_domain

    def run(self):
        pass
