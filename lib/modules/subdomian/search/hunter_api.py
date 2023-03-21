#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：Hunter API接口调用
"""
from time import sleep
from base64 import b64encode
from typing import Union
from dataclasses import dataclass

from httpx import Client

from lib.core.logger import logger
from lib.core.settings import CONFIG_DATA


@dataclass()
class Hunter(object):
    query: str

    name = "Hunter"
    key: str = CONFIG_DATA['hunter_key']
    url: str = 'https://hunter.qianxin.com/openApi/search'
    page: int = 1
    page_size: int = 100
    is_web: int = 1
    status_code: int = 200
    start_time: str = ""
    end_time: str = ""
    domain_result = list()  # 存完整数据

    def get_domain(self) -> list:
        """
        域名收集专用
        :return:
        """
        logger.info("Running Hunter ...")
        # 判断key是否为空
        if not self.key:
            logger.warning(f"{self.name} api key is null!")
            return list()

        while True:
            response_json = self.send_request()
            if response_json:
                res = self.parse_response(response_json)
                if not res:
                    break
            else:
                break

        result: list = [i['domain'] for i in self.domain_result]

        if result:
            logger.info(f"Hunter Query：{self.query} , {len(result)} results found!")
            logger.debug(f"Hunter: {result}")
        return result

    def send_request(self) -> Union[dict, None]:
        """
        发送搜索请求并做子域匹配
        """
        search: str = str(b64encode(self.query.encode("utf-8")), 'utf-8')
        params: dict = {'api-key': self.key, 'search': search, 'page': self.page, 'page_size': self.page_size,
                        'is_web': self.is_web}
        try:
            with Client(verify=False, params=params) as c:
                response = c.get(self.url)
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"Hunter connect error！ Code：{response.status_code}")
                    return
        except Exception as e:
            logger.error(f"Hunter connect error! {e}")
            return

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
            self.domain_result += result  # 把查询结果合并
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

    def run(self):
        """
        类执行入口
        """
        pass
