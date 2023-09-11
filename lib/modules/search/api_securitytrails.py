#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：收集securitytrails的子域名信息
"""
from lib.modules.search.api_base import ApiBase
from lib.core.log import logger


class Securitytrails(ApiBase):

    def __init__(self, domain: str) -> None:
        super().__init__()
        self.name = "Securitytrails"
        self.key: str = self.config['securitytrails_key']
        self.domain: str = domain
        self.url: str = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false" \
                        f"&include_inactive=true"
        self.headers: dict = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
                "accept": "application/json",
                "APIKEY": self.key
            }

    def parse_response(self, domain, response_json):
        """解析响应数据

        :param domain:
        :param response_json:
        :return:
        """
        try:
            subdomains = response_json['subdomains']
            return set([f"{i}.{domain}" for i in subdomains])
        except:
            logger.error(f"Securitytrails parse response error. {response_json}")
            return set()
