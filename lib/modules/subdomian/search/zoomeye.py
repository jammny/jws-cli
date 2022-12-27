#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：ZoomEye API接口调用
"""
from random import choice
from typing import Any

from httpx import Client

from lib.config.settings import USER_AGENTS, CONFIG_DATA
from lib.config.logger import logger

from lib.utils.format import domain_format


class ZoomEye:
    def __init__(self, query) -> None:
        self.mail: str = CONFIG_DATA['zoomeye_mail']
        self.password: str = CONFIG_DATA['zoomeye_pass']
        self.headers: dict = {"User-Agent": choice(USER_AGENTS)}
        self.query: str = query  # 查询参数
        self.url: str = f'https://api.zoomeye.org/web/search?query={query}'
        self.results: list = []

    def login(self) -> Any:
        """
        登陆获取用户token
        :return:
        """
        try:
            with Client(headers=self.headers, verify=False) as c:
                response = c.post(url='https://api.zoomeye.org/user/login',
                                  json={'username': self.mail, 'password': self.password})
                if response.status_code == 200:
                    data: dict = response.json()
                    access_token: str = data.get('access_token')
                    logger.debug("ZoomEye login success!")
                    return access_token
                else:
                    logger.warning("ZoomEye login failed!")
                    return False
        except Exception as e:
            logger.error(f"ZoomEye login failed！{e}")
            return False

    def parse_response(self, response: dict) -> None:
        """
        解析响应包数据
        :return:
        """
        for i in response['matches']:
            if i.__contains__('site'):
                self.results.append(domain_format(i['site']))
        logger.info(f"ZoomEye Query：{self.query}, {len(self.results)} results found!")
        logger.debug(f"ZoomEye Query：{self.results}")

    def send_request(self) -> Any:
        """
        ZoomEye 接口请求
        :return:
        """
        jwt = self.login()
        try:
            if jwt:  # 判断是否登陆成功
                with Client(headers=self.headers, verify=False) as c:
                    response = c.get(self.url, headers={'Authorization': 'JWT ' + jwt})
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.debug(f"ZoomEye connect error! Code： {response.status_code}")
                    return False
        except Exception as e:
            logger.error(f"{self.url} {e}")
            return False

    def get_domain(self):
        """
        域名收集调用,
        :return: 返回包含域名的列表
        """
        logger.info("Running ZoomEye ...")
        response = self.send_request()
        if response:
            self.parse_response(response)
        return self.results

    def run(self):
        """
        类执行入口
        :return:
        """
        pass
