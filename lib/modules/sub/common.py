#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 封装一些公共类
"""
from typing import Union
from httpx import Client

from lib.utils.log import logger


class ApiBase(object):
    """
    API模块父类
    """
    def __init__(self) -> None:
        self.name: str = ""
        self.key: str = ""
        self.url: str = ""
        self.result_domain: list = list()
        self.headers: dict = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        }

    def get_domain(self) -> list:
        """
        域名收集
        :return:
        """
        logger.info(f"Running {self.name} ...")
        # 判断key是否可用
        if not self.key:
            logger.warn(f"{self.name} api key is null!")
            return self.result_domain
        response: Union[dict, None] = self.send_request()
        if response:
            self.parse_response(response)

        logger.info(f"{self.name}：{len(self.result_domain)} results found!")
        logger.debug(self.result_domain)
        return self.result_domain

    def send_request(self) -> Union[dict, None]:
        """
        发送搜索请求
        """
        try:
            with Client(headers=self.headers, verify=False) as c:
                response = c.get(self.url)
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warn(f'{self.name} connect error！ Code: {response.status_code}')
                    # logger.debug(response.text)
                    return
        except Exception as e:
            logger.error(f"{self.url}, {e}")
            return

    def parse_response(self, response: dict):
        """
        解析响应包数据
        :return:
        """
        pass

