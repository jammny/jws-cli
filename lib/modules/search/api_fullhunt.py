#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：fullhunt API接口调用
"""
from lib.modules.search.api_base import ApiBase


class Fullhunt(ApiBase):

    def __init__(self, domain: str) -> None:
        super().__init__()
        self.name: str = "Fullhunt"
        self.domain: str = domain
        self.key: str = self.config['fullhunt_key']
        self.url: str = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
        self.headers = {
            'X-API-KEY': self.key,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        }

