#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：Hunter API接口调用
"""
from base64 import b64encode
from typing import Set, Optional

from lib.modules.search.api_base import ApiBase
from lib.core.log import logger
from lib.utils.tools import match_subdomains


class Hunter(ApiBase):
    def __init__(self, query: str, domain: str) -> None:
        super().__init__()
        self.name = "Hunter"
        self.key = self.config['hunter_key']
        self.query = query      # 查询参数
        self.domain = domain    # 根域名
        self.search: str = str(b64encode(query.encode("utf-8")), 'utf-8')   # base64编码的参数
        self.page_size: int = 20   # 每页返回的最大检索数
        self.size: int = self.config['hunter_size']     # # 配置文件设定的最大检索值
        self.url: str = (f"https://hunter.qianxin.com/openApi/search?api-key={self.key}&search={self.search}"
                         f"&page=[page]&page_size={self.page_size}&is_web=1&port_filter=false&status_code=0")

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
        new_url: str = url.replace("[page]", "1")
        try:
            response_json: Optional[dict] = self.send_request(new_url)
        except Exception as e:
            logger.error(f"{name} connect error! {url} {e}")
            return self.result_domain

        if not response_json:
            return self.result_domain

        # 正则提取页面中域名
        self.result_domain: Set['str'] = match_subdomains(domain, str(response_json))

        # 根据搜索出的检索量和设定配置，循环遍历页数 #
        try:
            total: int = response_json['data']['total']
            page: int = self.get_page(total, size, page_size)
            self.circular_process(page, url, domain)
        except Exception as e:
            logger.error(f"{response_json} {e}")

        logger.info(f"{name}：{len(self.result_domain)} results found!")
        logger.debug(f"{name}：{self.result_domain}")
        return self.result_domain

    def run(self):
        pass
