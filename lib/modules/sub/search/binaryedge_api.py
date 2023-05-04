#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：binaryedge API接口调用
"""
from lib.core.settings import SUB_CONFIG
from lib.modules.sub.common import ApiBase


class Binaryedge(ApiBase):
    def __init__(self, domain) -> None:
        super().__init__()
        self.name = "Binaryedge"
        self.key: str = SUB_CONFIG['api_key']['binaryedge_key']
        self.url: str = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
        self.headers = {
            'X-Key': self.key,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        }

    def parse_response(self, response: dict):
        """
        解析响应包数据
        :return:
        """
        if response.__contains__('events'):
            data = response['events']
            for i in data:
                self.result_domain.append(i)
        else:
            # logger.debug(response)
            pass

