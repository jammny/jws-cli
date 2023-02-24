#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：搜狗搜索引擎的爬虫程序
"""
from time import sleep
from typing import Any

from httpx import Client
from parsel import Selector

from lib.utils.format import domain_format

from lib.core.logger import logger


class Sogou:
    def __init__(self, domain: str):
        self.domain: str = domain
        self.query: str = f"site:{domain}"
        self.page: int = 1
        self.result_domain: list = []
        self.limit: int = 100
        self.url: str = "http://www.sogou.com/web"

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        selector = Selector(response)  # 创建Selector类实例
        # css选择器获取包含域名的链接
        res1: list = selector.css('div[class="citeurl"] span::text').getall()
        res2: list = selector.css('div[class="citeurl "] span::text').getall()
        res3: list = res1 + res2
        # 如果css选择器获取数据为空，返回False，终止循环
        if not res3:
            return False
        else:
            logger.debug(f"Sougou current page：{self.page}")
            for i in res3:
                if i.__contains__(self.domain):
                    domain: str = domain_format(i)
                    self.result_domain.append(domain)
            return True

    def sogou_req(self) -> Any:
        """
        请求接口，返回响应内容
        :return:
        """
        params: dict = {'query': self.query, "page": self.page}
        headers: dict = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}
        try:
            with Client(params=params, verify=False, headers=headers) as c:
                response = c.get(self.url)
                if response.status_code == 200:
                    return response.text
                elif response.status_code == 302:
                    logger.warn(f"遇到Sougou人机认证！")
                else:
                    logger.debug(f"Sougou connect error！ Code：{response.status_code}")
                    logger.debug(response.text)
                return False
        except Exception as e:
            logger.error(f"{self.url} {e}")
            return False

    def get_domain(self):
        """
        获取域名
        :return:
        """
        logger.info("Running Sogou SE...")
        while True:
            response = self.sogou_req()
            # 如果返回False，退出循环
            if not response:
                # 网络异常
                break
            elif self.parse_resqonse(response):
                if self.page == self.limit:
                    logger.debug("Sougou 达到限制数，停止爬取！")
                    break
                self.page += 1
            else:
                logger.debug("Sougou crawl to the end！")
                break
            sleep(1)

        if self.result_domain:
            # 去重
            self.result_domain = list(set(self.result_domain))
            logger.info(f"Sogou SE：{len(self.result_domain)} results found!")
            logger.debug(f"Sogou SE：{self.result_domain}")
        return self.result_domain

    def run(self):
        """
        类统一入口
        :return:
        """
        pass
