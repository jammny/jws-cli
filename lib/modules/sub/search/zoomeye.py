#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：ZoomEye API接口调用
"""
from typing import Union
from dataclasses import dataclass

from httpx import Client

from lib.core.settings import SUB_CONFIG
from lib.utils.log import logger
from lib.utils.tools import domain_format


@dataclass()
class ZoomEye(object):
    query: str  # 查询参数

    mail: str = SUB_CONFIG['api_key']['zoomeye_mail']
    password: str = SUB_CONFIG['api_key']['zoomeye_pass']
    domain_results = set()

    def send_request(self) -> Union[dict, None]:
        """
        ZoomEye 接口请求
        :return:
        """
        jwt: Union[str, None] = self.login()    # 获取用户jwt口令
        url: str = f'https://api.zoomeye.org/web/search?query={self.query}'
        if not jwt:  # 判断是否登陆成功
            return
        try:
            with Client(verify=False, timeout=10) as c:
                response = c.get(url, headers={'Authorization': 'JWT ' + jwt})
            if response.status_code == 200:
                return response.json()
            else:
                logger.debug(f"ZoomEye connect error! Code： {response.status_code}")
                return
        except Exception as e:
            logger.error(f"{url} {e}")
            return

    def login(self) -> Union[str, None]:
        """
        登陆获取用户token
        :return:
        """
        try:
            with Client(verify=False, timeout=10) as c:
                response = c.post(url='https://api.zoomeye.org/user/login',
                                  json={'username': self.mail, 'password': self.password})
                if response.status_code == 200:
                    data: dict = response.json()
                    access_token: str = data.get('access_token')
                    logger.debug("ZoomEye login success!")
                    return access_token
                else:
                    logger.warning("ZoomEye login failed!")
                    return
        except Exception as e:
            logger.error(f"ZoomEye login failed！{e}")
            return

    def get_domain(self) -> list:
        """
        域名收集调用
        :return: 返回包含域名的列表
        """
        logger.info("Running ZoomEye ...")
        response: Union[dict, None] = self.send_request()
        if response:
            self.parse_response(response)
        return list(self.domain_results)

    def parse_response(self, response: dict) -> None:
        """
        解析响应包数据
        :return:
        """
        for i in response['matches']:
            if i.__contains__('site'):
                self.domain_results.add(domain_format(i['site']))

        logger.info(f"ZoomEye Query：{self.query}, {len(self.domain_results)} results found!")
        logger.debug(f"ZoomEye Query：{self.domain_results}")

    def run(self):
        """
        类执行入口
        :return:
        """
        pass
