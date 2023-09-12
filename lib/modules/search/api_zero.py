#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：零零信安 API接口调用
"""
from typing import Set, Optional

from lib.modules.search.api_base import ApiBase
from lib.core.log import logger
from lib.utils.tools import match_subdomains


class Zero(ApiBase):
    def __init__(self, query: str, domain: str) -> None:
        super().__init__()
        self.name = "Zero"
        self.key = self.config['zero_key']
        self.size: int = self.config['zero_size']  # 配置文件设定的最大检索值
        self.domain = domain    # 根域名
        self.page_size: int = 40   # 每页返回的最大检索数
        self.url: str = "https://0.zone/api/data/"
        self.data = {
            "query": query,
            "query_type": "site",
            "page": 1,
            "pagesize": self.page_size,
            "zone_key_id": self.key
        }

    def get_domain(self) -> Set[str]:
        """域名收集专用

        :return:
        """
        name = self.name
        domain: str = self.domain
        size: int = self.size
        page_size: int = self.page_size
        url = self.url
        logger.info(f"Running {name}...")

        # 先获取一页，看看检索出多少数据 #
        try:
            response_json: Optional[dict] = self.send_request(url, method="post")
        except Exception as e:
            logger.error(f"{name} connect error! {url} {e}")
            return self.result_domain

        if not response_json:
            return self.result_domain

        # 正则提取页面中域名
        self.result_domain: Set[str] = match_subdomains(domain, str(response_json))

        # 根据搜索出的检索量和设定配置，循环遍历页数 #
        try:
            total: int = int(response_json['total'])
            page: int = self.get_page(total, size, page_size)
            self.circular_process(page, url, domain, method="post")
        except Exception as e:
            logger.error(f"{response_json} {e}")

        logger.info(f"{name}：{len(self.result_domain)} results found!")
        return self.result_domain

    def run(self):
        pass
