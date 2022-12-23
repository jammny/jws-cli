#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：Bing搜索引擎的爬虫程序
"""
from time import sleep
from typing import Any

from httpx import Client
from parsel import Selector

from lib.utils.format import domain_format

from lib.config.logger import logger


class Bing:
    def __init__(self, domain: str):
        self.domain: str = domain
        self.query: str = f"site:{domain}"
        # 页数
        self.page: int = 0
        self.result_domain: list = []
        # 限制数量
        self.limit: int = 1000

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        # 创建Selector类实例
        selector = Selector(response)
        # css选择器获取包含域名的链接
        res1: list = selector.css('cite').getall()
        res2 = [i.replace("<strong>", "").replace("</strong>", "").replace("<cite>", "").replace("</cite>", "") for i in res1]
        curr_page: str = selector.css('a[class="sb_pagS sb_pagS_bp b_widePag sb_bp"] ::text').get()

        # 如果列表为空
        if not res2:
            return False

        if int(curr_page) < (self.page // 10):
            return False
        else:
            logger.debug(f"Bing curreut page：{curr_page}")
            for i in res2:
                domain: str = domain_format(i)
                self.result_domain.append(domain)
            return True

    def send_request(self) -> Any:
        """
        请求接口，返回响应内容
        :return:
        """
        url = f"https://cn.bing.com/search?q={self.query}&first={self.page}"
        try:
            headers: dict = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
                "Referer": "https://cn.bing.com/"
            }
            with Client(verify=False, headers=headers) as c:

                response = c.get(url)
                if response.status_code == 200:
                    return response.text
                else:
                    logger.debug(f"Bing connect error！ Code：{response.status_code}")
                    # logger.debug(response.text)
                    return False
        except Exception as e:
            logger.error(f"{url} {e}")
            return False

    def get_domain(self) -> list:
        """
        获取域名
        :return:
        """
        logger.info("Running Bing SE...")
        while True:
            response = self.send_request()
            if not response:
                # 网络异常
                break
            elif self.parse_resqonse(response):
                # 如果达到限制，退出循环
                if self.page == self.limit:
                    logger.debug("Bing 达到限制数，停止爬取！")
                    break
                else:
                    self.page += 10
            else:
                logger.debug("Bing crawl to the end！")
                break
            sleep(1)
        if self.result_domain:
            # 去重
            self.result_domain = list(set(self.result_domain))
            logger.info(f"Bing SE：{len(self.result_domain)} results found!")
            logger.debug(f"Bing SE：{self.result_domain}")
        return self.result_domain

    def run(self):
        """
        类统一入口
        :return:
        """
        pass
