#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：360 quake API接口调用
"""
from typing import Optional, Set

from lib.core.log import logger
from lib.modules.search.api_base import ApiBase
from lib.utils.tools import match_subdomains


class Quake(ApiBase):

    def __init__(self, query: str, domain: str) -> None:
        super().__init__()
        self.name: str = "Quake"
        self.domain: str = domain
        self.key: str = self.config['quake_key']
        self.url: str = f"https://quake.360.net/api/v3/search/quake_service"
        self.headers = {
            "X-QuakeToken": self.key,
            "Content-Type": "application/json"
        }
        self.size: int = self.config['quake_size']
        self.data = {
            "query": query,
            "size": self.size,
            "ignore_cache": False,
        }

    def get_domain(self,) -> set:
        """域名收集专用

        :return:
        """
        domain = self.domain
        name = self.name
        url = self.url
        logger.info(f"Running {name}...")
        try:
            response_json: Optional[dict] = self.send_request(url, method="post")
        except Exception as e:
            logger.error(f"[r]{name} connect error! {url} {e}[/r]")
            return self.result_domain

        if not response_json:
            return self.result_domain

        # 正则提取页面中域名
        self.result_domain: Set[str] = match_subdomains(domain, str(response_json))

        logger.info(f"{name}：{len(self.result_domain)} results found!")
        return self.result_domain

    def run(self):
        pass