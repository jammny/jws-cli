#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：谷歌搜索引擎的爬虫程序，基于谷歌镜像网站。
"""
from time import sleep
from typing import Any

from httpx import Client
from parsel import Selector

from lib.config.logger import logger


class Google:
    def __init__(self, domain: str):
        self.domain: str = domain
        self.query: str = f"site:{domain}"
        self.page: int = 0
        self.result_domain: list = []
        self.limit: int = 1000

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        selector = Selector(response)  # 创建Selector类实例
        # css选择器获取包含域名的链接
        res1: list = selector.css('a').css('span span ::text').getall()
        # 如果css选择器获取数据为空，返回False，终止循环
        if not res1:
            return False
        else:
            logger.debug(f"Google current page：{self.page // 10}")
            for i in res1:
                domain: str = i.split(" ›")[0]
                self.result_domain.append(domain)
            return True

    def google_req(self) -> Any:
        """
        请求接口，返回响应内容
        :return:
        """
        params: dict = {'q': self.query, 'start': self.page}
        headers: dict = {"User-Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"}
        url = "https://google.mirrors.pw/search"
        try:
            with Client(params=params, verify=False, headers=headers) as c:
                response = c.get(url)
                if response.status_code == 200:
                    return response.text
                else:
                    if response.text.__contains__("robots are known to use"):
                        logger.warn("遇到谷歌人机验证！")
                    else:
                        logger.debug(f"Google connect error！ Code： {response.status_code}")
                        # logger.debug(response.text)
                    return False
        except Exception as e:
            logger.error(f"{url} {e}")
            return False

    def get_domain(self):
        """
        获取域名
        :return:
        """
        logger.info("Running Google SE...")
        while True:
            response = self.google_req()
            if not response:
                # 网络异常
                break
            elif self.parse_resqonse(response):
                if self.page == self.limit:
                    logger.debug("Google 达到限制数，停止爬取！")
                    break
                self.page += 10
            else:
                logger.debug("Google crawl to the end！")
                break
            sleep(1)
        if self.result_domain:
            self.result_domain = list(set(self.result_domain))
            logger.info(f"Google SE：{len(self.result_domain)} results found!")
            logger.debug(f"Google SE：{self.result_domain}")
        return self.result_domain

    def run(self):
        """
        类统一入口
        :return:
        """
        pass
