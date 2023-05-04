#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：百度搜索引擎的爬虫程序
"""
from ast import literal_eval
from time import sleep
from typing import Any

from httpx import Client
from parsel import Selector

from lib.utils.tools import domain_format
from lib.utils.log import logger


class Baidu:
    def __init__(self, domain: str) -> None:
        self.domain: str = domain
        self.query: str = f"site:{domain}"
        # 页数
        self.page: int = 0
        self.result_domain: list = []
        # 限制数量
        self.limit: int = 1000
        self.url = "http://m.baidu.com/s"

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        # 创建Selector类实例
        selector = Selector(response)
        # css选择器获取包含域名的链接
        res1: list = selector.css('div[class="c-result result"]').xpath('@data-log').getall()
        # 下面规则是为了判断是否存在下一页
        res2: list = selector.css('div[class="new-pagenav-right"] a').getall()
        res3: list = selector.css('i[class="c-icon icon-nextpage"]').getall()
        res4: list = res2 + res3
        if not res4:
            return False
        else:
            logger.debug(f"Baidu current page： {self.page // 10 + 1}")
            for i in res1:
                data: dict = literal_eval(i)
                domain: str = domain_format(data['mu'])
                self.result_domain.append(domain)
            return True

    def send_request(self) -> Any:
        """
        请求接口，返回响应内容
        :return:
        """
        try:
            params: dict = {'word': self.query, "pn": self.page}
            headers: dict = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"}
            with Client(params=params, verify=False, headers=headers) as c:
                response = c.get(self.url)
                if response.status_code == 200:
                    return response.text
                else:
                    if response.text.__contains__('https://wappass.baidu.com/static/captcha/tuxing.html'):
                        logger.warn("遇到百度人机验证！")
                    else:
                        logger.warn(f"Baidu connect error！ Code：{response.status_code}")
                        # logger.debug(response.text)
                    return False
        except Exception as e:
            logger.error(f"{self.url} {e}")
            return False

    def get_domain(self) -> list:
        """
        获取域名
        :return:
        """
        logger.info("Running Baidu SE...")
        while True:
            response = self.send_request()
            if not response:
                # 网络异常
                break
            elif self.parse_resqonse(response):
                if self.page == self.limit:
                    logger.warn("Baidu 达到限制数，停止爬取！")
                    break
                else:
                    self.page += 10
            else:
                logger.debug("Baidu crawl to the end！")
                break
            sleep(1)

        if self.result_domain:
            # 去重
            self.result_domain = list(set(self.result_domain))
            logger.info(f"Baidu SE：{len(self.result_domain)} results found!")
            logger.debug(f"Baidu SE：{self.result_domain}")
        return self.result_domain

    def run(self):
        """
        类统一入口
        :return:
        """
        pass
