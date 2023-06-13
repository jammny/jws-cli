#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：模拟censys登录，搜索域名数据
"""
import base64

from lib.modules.sub.common import ApiBase
from lib.utils.tools import match_subdomains
from lib.core.settings import SUB_CONFIG


class Censys(ApiBase):
    def __init__(self, domain: str) -> None:
        super().__init__()
        self.censys_id: str = SUB_CONFIG['api_key']['censys_id']
        self.censys_secret: str = SUB_CONFIG['api_key']['censys_secret']
        if self.censys_id and self.censys_secret:
            self.key: str = "no null"
        self.name: str = "Censys"
        self.domain: str = domain
        self.url = f"https://search.censys.io/api/v2/certificates/search?per_page=100&virtual_hosts=EXCLUDE" \
                   f"&q={self.domain} "
        token = base64.b64encode(f"{self.censys_id}:{self.censys_secret}".encode('utf-8')).decode('utf-8')
        self.headers = {
            'Authorization': f'Basic {token}',
            'Accept': 'application/json',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/110.0.0.0 Safari/537.36',
        }

    def parse_response(self, response: dict):
        """解析响应包数据"""
        res = match_subdomains(self.domain, str(response))
        self.result_domain = list(res)


