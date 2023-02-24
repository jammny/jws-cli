#!/usr/bin/env python 
# -- coding:utf-8
"""
作者：jammny
文件描述：FOFA API接口调用
FOFA语法：

"""
from base64 import b64encode
from random import choice

from httpx import Client

from lib.core.settings import USER_AGENTS, CONFIG_DATA
from lib.core.logger import logger

from lib.utils.format import domain_format


class Fofa:
    def __init__(self, query):
        self.name = "Fofa"
        # fofa api key
        self.key: str = CONFIG_DATA['fofa_key']
        # fofa帐号
        self.email: str = CONFIG_DATA['fofa_email']
        # 返回的查询数量
        self.size: int = CONFIG_DATA['fofa_size']
        # fofa查询参数，base64编码
        self.qbase64: str = str(b64encode(query.encode("utf-8")), 'utf-8')
        self.headers: dict = {"User-Agent": choice(USER_AGENTS)}
        self.url: str = f"https://fofa.info/api/v1/search/all?email={self.email}&key={self.key}&qbase64={self.qbase64}"\
                        f"&size={self.size}&fields=host,title,ip,port,protocol,domain"
        self.results = []

    def get_host(self, result):
        """
        获取host的值
        :param result:
        :return: list
        """
        res_host: list = [i['host'] for i in result]
        return res_host

    def parse_response(self, response: dict) -> bool:
        """
        解析响应包数据
        :return:
        """
        if response['error']:
            logger.warning("Fofa Api is error！")
        elif response['size'] == 0:
            logger.warning(f"No information related to the {response['query']} was found!")
        else:
            logger.info(f"FOFA Query：{response['query']} , {response['size']} results found!")
            for i in response['results']:
                self.results.append(domain_format(i[0]))
            logger.debug(f"FOFA: {self.results}")
            return True
        return False

    def send_request(self) -> any:
        """
        fofa接口请求
        :return:
        """
        try:
            with Client(headers=self.headers, verify=False) as c:
                response = c.get(self.url)
            if response.status_code == 200:
                return response.json()
            else:
                logger.warn(f"Fofa connect error！ Code：{response.status_code}")
                return None
        except Exception as e:
            logger.error(f"{self.url} {e}")
            return None

    def get_domain(self) -> list:
        """
        用于域名收集
        :return: 返回列表
        """
        logger.info("Running Fofa ...")
        # 判断key是否可用
        if not self.key:
            logger.warn(f"{self.name} api key error!")
            return self.results

        response = self.send_request()
        if response:
            self.parse_response(response)

        return self.results

    def run(self):
        """
        类执行入口,
        :return:
        """
        response = self.send_request()
        return response
