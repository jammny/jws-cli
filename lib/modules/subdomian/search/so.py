#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：360搜索引擎的爬虫程序
"""
from time import sleep
from typing import Any

from httpx import Client
from parsel import Selector

from lib.utils.format import domain_format

from lib.config.logger import logger


class So:
    def __init__(self, domain: str):
        self.domain: str = domain
        self.query: str = f"site:{domain}"
        self.page: int = 1  # 页数
        self.result_domain: list = []
        self.limit: int = 100  # 限制数量

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        selector = Selector(response)  # 创建Selector类实例
        # css选择器获取包含域名的链接
        res1: list = selector.css('p[class="g-linkinfo"] cite a::text').getall()
        # 下面规则是为了判断是否存在下一页
        res2: list = selector.css('a[id="snext"]').getall()
        if not res2:
            return False
        else:
            logger.debug(f"360 current page：{self.page}")
            for i in res1:
                domain: str = domain_format(i)
                self.result_domain.append(domain)
            return True

    def send_request(self) -> Any:
        """
        请求接口，返回响应内容
        :return:
        """
        url = "https://www.so.com/s"
        try:
            headers: dict = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}
            params: dict = {'q': self.query, "pn": self.page}
            with Client(params=params, verify=False, headers=headers, follow_redirects=True) as c:
                response = c.get(url)
                if response.status_code == 200:
                    return response.text
                else:
                    logger.debug(f"360so connect error！ Code： {response.status_code}")
                    # logger.debug(response.text)
        except Exception as e:
            logger.error(f"{url} {e}")
            return False

    def get_domain(self):
        """
        获取域名
        :return:
        """
        logger.info("Running 360so SE...")
        while True:
            response = self.send_request()
            # 如果返回None，退出循环
            if not response:
                break
            elif response.__contains__("访问异常页面"):
                logger.warn("遇到360人机验证！")
                break
            # 如果解析结果为False，退出循环。
            elif self.parse_resqonse(response):
                # 如果达到限制，退出循环
                if self.page == self.limit:
                    logger.debug("360so 达到限制数，停止爬取！")
                    break
                else:
                    self.page += 1
            else:

                logger.debug("360so crawl to the end！")
                break
            sleep(1)

        if self.result_domain:
            self.result_domain = list(set(self.result_domain))
            logger.info(f"360so SE：{len(self.result_domain)} results found!")
            logger.debug(f"360so SE：{self.result_domain}")
        return self.result_domain

    def run(self):
        """
        类统一入口
        :return:
        """
        pass
