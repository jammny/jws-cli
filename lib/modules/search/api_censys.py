#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：censys api 调用
"""
import base64
from lib.modules.search.api_base import ApiBase


class Censys(ApiBase):

    def __init__(self, domain: str) -> None:
        super().__init__()
        self.domain: str = domain
        self.censysID: str = self.config['censys_id']
        self.censysSecret: str = self.config['censys_secret']
        self.name: str = "Censys"
        self.url = f"https://search.censys.io/api/v2/certificates/search?per_page=100&virtual_hosts=EXCLUDE" \
                   f"&q={domain} "
        token = base64.b64encode(f"{self.censysID}:{self.censysSecret}".encode('utf-8')).decode('utf-8')
        self.headers = {
            'Authorization': f'Basic {token}',
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/110.0.0.0 Safari/537.36',
        }
