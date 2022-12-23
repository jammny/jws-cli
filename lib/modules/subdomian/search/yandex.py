#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：搜狗搜索引擎的爬虫程序
"""
from time import sleep

from httpx import Client
from parsel import Selector

from lib.utils.format import domain_format

from lib.config.logger import logger


class Yandex:
    def __init__(self, domain: str):
        self.domain: str = domain
        self.query: str = f"site:{domain}"
        self.page: int = 0
        self.result_domain: list = []
        self.limit: int = 100

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        selector = Selector(response)  # 创建Selector类实例
        # css选择器获取包含域名的链接
        # res1: list = selector.css('a[class="link serp-item__title-link"]').xpath('@href').getall()
        res1: list = selector.css('b ::text').getall()
        # res2: list = selector.css('a[class="link pager__next"]').getall()
        # 如果css选择器获取数据为空，返回False，终止循环
        if res1:
            logger.debug(f"Yandex current page： {self.page + 1}")
            for i in res1:
                domain: str = domain_format(i)
                self.result_domain.append(domain)
            return True
        else:
            return False

    def yandex_req(self) -> str | bool:
        """
        请求接口，返回响应内容
        :return:
        """
        url = "https://yandex.com/search/"
        params: dict = {'text': self.query, "lr": 21431, 'redircnt': 667376625.1, 'p': self.page}
        headers: dict = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}
        try:
            with Client(params=params, verify=False, headers=headers) as c:
                response = c.get(url)
                if response.status_code == 200:
                    return response.text
                elif response.status_code == 302:
                    logger.warn(f'遇到Yandex人机认证！')
                    return False
                else:
                    logger.warn(f'Yandex connect error！ Code: {response.status_code}')
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
        logger.info("Running Yandex SE...")
        while True:
            response = self.yandex_req()
            if not response:
                # 网络异常
                break
            elif self.parse_resqonse(response):
                if self.page == self.limit:
                    logger.debug("Yandex 达到限制数，停止爬取！")
                    break
                else:
                    self.page += 1
            else:
                logger.debug("Yandex crawl to the end！")
                break
            sleep(1)
        if self.result_domain:
            # 去重
            self.result_domain = list(set(self.result_domain))
            logger.info(f"Yandex SE：{len(self.result_domain)} results found!")
            logger.debug(f"Yandex SE：{self.result_domain}")
        return self.result_domain

    def run(self):
        """
        类统一入口
        :return:
        """
        pass
