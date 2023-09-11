#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：binaryedge API接口调用
"""
from lib.modules.search.api_base import ApiBase


class Binaryedge(ApiBase):

    def __init__(self, domain: str) -> None:
        super().__init__()
        self.name: str = "Binaryedge"
        self.domain: str = domain
        self.key: str = self.config['binaryedge_key']
        self.url: str = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
        self.headers: dict = {
            'X-Key': self.key,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        }

