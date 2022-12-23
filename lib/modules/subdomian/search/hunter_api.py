#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：Hunter api接口调用
Hunter语法：

"""
from time import sleep
from random import choice
from base64 import b64encode

from httpx import Client

from lib.config.logger import logger
from lib.config.settings import USER_AGENTS, CONFIG_DATA


class Hunter:
    def __init__(self, query) -> None:
        self.name = "Hunter"
        self.key: str = CONFIG_DATA['hunter_key']
        self.query: str = query
        self.search: str = str(b64encode(self.query.encode("utf-8")), 'utf-8')
        self.url: str = 'https://hunter.qianxin.com/openApi/search'
        self.page: int = 1
        self.page_size: int = 100
        self.is_web: int = 1
        self.status_code: int = 200
        self.start_time: str = ""
        self.end_time: str = ""
        self.headers: dict = {"User-Agent": choice(USER_AGENTS)}
        self.result: list = []  # 存完整数据

    def parse_response(self, response) -> bool:
        """
        解析响应包数据
        :return:
        """
        if response['data']:
            total: str = response['data']['total']
            result: list = response['data']['arr']
            # 查询积分
            logger.debug(f"Hunter: {response['data']['rest_quota']}")
            self.result.extend(result)  # 把查询结果合并
            count: int = 100 * self.page
            # 遍历一下页数
            if int(total) > count:
                # 延迟1S
                sleep(1)
                self.page += 1
                return True
            else:
                return False
        else:
            # logger.debug(response)
            return False

    def send_request(self) -> bool | dict:
        """
        发送搜索请求并做子域匹配
        """
        params: dict = {'api-key': self.key, 'search': self.search, 'page': self.page, 'page_size': self.page_size,
                        'is_web': self.is_web}
        try:
            with Client(headers=self.headers, verify=False, params=params) as c:
                response = c.get(self.url)
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warn(f"Hunter connect error！ Code：{response.status_code}")
                    return False
        except Exception as e:
            logger.error(f"Hunter connect error! {e}")
            return False

    def get_domain(self) -> list:
        """
        自动化域名收集专用, domain_format 用于将host处理成域名格式
        :return:
        """
        logger.info("Running Hunter ...")
        # 判断key是否可用
        if not self.key:
            logger.warn(f"{self.name} api key error!")
            return []

        while True:
            response = self.send_request()
            if response:
                res = self.parse_response(response)
                if not res:
                    break

        result: list = [i['domain'] for i in self.result]
        if result:
            logger.info(f"Hunter Query：{self.query} , {len(result)} results found!")
            logger.debug(f"Hunter: {self.result}")
        return result

    def run(self):
        """
        类执行入口
        """
        pass
