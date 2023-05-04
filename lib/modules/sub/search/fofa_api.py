#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：FOFA API接口调用
"""
from base64 import b64encode
from typing import Union

from lib.core.settings import SUB_CONFIG
from lib.utils.log import logger
from lib.utils.tools import domain_format

from ..common import ApiBase


class Fofa(ApiBase):
    def __init__(self, query: str) -> None:
        super().__init__()
        self.name = "Fofa"
        self.email: str = SUB_CONFIG['api_key']['fofa_email']
        self.key: str = SUB_CONFIG['api_key']['fofa_key']
        self.size: int = SUB_CONFIG['api_key']['fofa_size']
        self.qbase64: str = str(b64encode(query.encode("utf-8")), 'utf-8')  # fofa查询参数，base64编码
        self.url: str = f"https://fofa.info/api/v1/search/all?email={self.email}&key={self.key}&qbase64={self.qbase64}" \
                        f"&size={self.size}&fields=host,title,ip,port,protocol,domain"

    def parse_response(self, response: dict):
        """
        解析响应包数据
        :return:
        """
        if response['error']:
            logger.warning(f"Fofa Api is error！{response}")
        elif response['size'] == 0:
            logger.warning(f"No information related to the {response['query']} was found!")
        else:
            logger.info(f"FOFA Query：{response['query']} , {response['size']} results found!")
            for i in response['results']:
                self.result_domain.append(domain_format(i[0]))
            logger.debug(f"FOFA: {self.result_domain}")

    def parse_response2(self, response: dict):
        """
        解析响应包数据
        :return:
        """
        if response['error']:
            logger.warning(f"Fofa Api is error！{response}")
        elif response['size'] == 0:
            logger.warning(f"No information related to the {response['query']} was found!")
        else:
            logger.info(f"FOFA Query：{response['query']} , {response['size']} results found!")
            for i in response['results']:
                self.result_domain.append(i[0])
            logger.debug(f"FOFA: {self.result_domain}")

    def get_host(self, result):
        """
        获取host的值
        :param result:
        :return: list
        """
        res_host: list = [i['host'] for i in result]
        return res_host

    def run(self) -> list:
        """
        类执行入口,
        :return:
        """
        response: Union[dict, None] = self.send_request()
        if response:
            self.parse_response2(response)
        return self.result_domain
