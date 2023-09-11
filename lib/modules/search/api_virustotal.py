#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
文件描述：收集virustotal的子域名信息
"""
from time import sleep
from typing import Optional

from lib.modules.search.api_base import ApiBase
from lib.core.log import logger
from lib.utils.tools import match_subdomains


class Virustotal(ApiBase):

    def __init__(self, domain: str) -> None:
        super().__init__()
        self.domain: str = domain
        self.name: str = "Virustotal"
        self.result_domain: set = set()
        self.url: str = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?relationships=resolutions" \
                        f"&cursor=&limit=10"
        self.headers: dict = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
            'Content-Type': 'application/json',
            'X-Tool': 'vt-ui-main',
            'X-App-Version': 'v1x132x0',
            'Accept-Ianguage': 'en-US,en;q=0.9,es;q=0.8',
            'X-Vt-Anti-Abuse-Header': 'MTQ5NTc4NTM1OTItWkc5dWRDQmlaU0JsZG1scy0xNjY4MTQ5NzAxLjcyNw==',
            'Te': 'trailers'
        }

    def parse_resqonse(self, response_json: dict) -> Optional[str]:
        """解析resqonse包

        :return:
        """
        domain: str = self.domain
        # links中包含了本次请求的链接和下一条请求的链接
        links: dict = response_json['links']
        # 如果存在下一条链接
        if links.__contains__('next'):
            result_domain = match_subdomains(domain, str(response_json))
            self.result_domain = self.result_domain.union(result_domain)
            # 获取下一页的链接，每一页只能读取十条数据
            next_url = links['next']
            return next_url
        return

    def get_domain(self) -> set:
        """获取子域名数据

        :return:
        """
        name = self.name
        url = self.url
        logger.info(f"Running {name}...")

        try:
            response_json: Optional[dict] = self.send_request(url)
        except Exception as e:
            logger.error(f"[red]{name} connect error! {url} {e}[/red]")
            return self.result_domain

        next_url: Optional[str] = self.parse_resqonse(response_json)   # 获取下一页的链接
        page = 10  # 每页仅返回10条数据，这里设置最大返回200条数据
        for i in range(page):
            try:
                response_json: Optional[dict] = self.send_request(next_url)
            except Exception as e:
                logger.error(f"[red]{name} connect error! {url} {e}[/red]")
                break
            next_url: Optional[str] = self.parse_resqonse(response_json)  # 获取下一页的链接
            if not next_url:
                break
            sleep(1)

        logger.info(f"Virustotal：{len(self.result_domain)} results found!")
        return self.result_domain

    def run(self):
        pass
