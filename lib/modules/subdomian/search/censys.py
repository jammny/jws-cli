#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：模拟censys登录，搜索域名数据
"""
from time import sleep
from typing import Any

from httpx import Client
from parsel import Selector

from lib.utils.format import domain_format
from lib.core.logger import logger
from lib.core.settings import CONFIG_DATA


class Censys:
    def __init__(self, domain: str) -> None:
        self.domain: str = domain
        self.result_domain: list = []
        self.username: str = CONFIG_DATA['censys_username']
        self.password: str = CONFIG_DATA['censys_password']
        self.page: int = 1
        self.session_id: str = ''
        self.csrftoken: str = ''

    def get_csrftoken(self) -> Any:
        """
        登录接口
        :return:
        """
        try:
            # 获取session id 和 csrftoken
            with Client(verify=False, timeout=10) as c:
                response = c.get("https://censys.io/login")
                if response.status_code == 200:
                    session_id: str = c.cookies.get('search.censys.io.session.id')
                    csrftoken: str = self.parse_csrftoken(response.text)
                    self.session_id = session_id
                    self.csrftoken = csrftoken
                    return True
                else:
                    return False
        except Exception as e:
            logger.warning(e)
            return False

    def parse_csrftoken(self, response: str) -> str:
        """
        解析页面，获取csrftoken
        :param response:
        :return:
        """
        # 创建Selector类实例
        selector = Selector(response)
        csrftoken: str = selector.css('input[name="csrf_token"]').xpath('@value').get()
        return csrftoken

    def login_request(self) -> any:
        """
        登录请求
        :return:
        """
        url = "https://censys.io/login"
        try:
            cookies: dict = {'search.censys.io.session.id': self.session_id}
            data: dict = {
                'csrf_token': self.csrftoken,
                'came_from': f'https://search.censys.io/certificates?q={self.domain}',
                'page': self.page,
                'login': self.username,
                'password': self.password
            }
            with Client(verify=False, cookies=cookies, timeout=10) as c:
                response = c.post(url=url, data=data)
                if response.status_code == 302:
                    logger.debug('censys login success！')
                    return response.cookies
                else:
                    logger.warn(f'censys login error！')
                    # logger.debug(response.text)
                    return False
        except Exception as e:
            logger.warning(f"{url} {e}")
            return False

    def parse_resqonse(self, response: str) -> bool:
        """
        解析resqonse包
        :return:
        """
        # 创建Selector类实例
        selector = Selector(response)
        res: list = selector.css('span[class="SearchResult__metadata-value detail"] ::text').getall()
        if res:
            for i in res:
                if i.__contains__(self.domain):
                    domain: list = domain_format(i).replace(' ', '').split(',')
                    for d in domain:
                        if d.__contains__(self.domain):
                            self.result_domain.append(d)
            return True
        else:
            logger.debug("Censys crawl to the end！")
            return False

    def send_request(self, cookies) -> Any:
        """
        请求接口，返回响应内容
        :return:
        """
        url: str = f"https://search.censys.io/certificates/_search?q={self.domain}&page={self.page}"
        try:
            with Client(verify=False, cookies=cookies, timeout=10, follow_redirects=True) as c:
                response = c.get(url)
            if response.status_code == 200:
                return response.text
            else:
                logger.warn(f"Censys connect error！ Code: {response.status_code}")
                # logger.debug(response.text)
                return False
        except Exception as e:
            logger.warning(f"{url} {e}")
            return False

    def get_domain(self) -> list:
        """
        :return:
        """
        logger.info("Running Censys...")
        if self.get_csrftoken():
            # 如果登录失败
            cookies = self.login_request()
            if not cookies:
                return self.result_domain

            while True:
                response = self.send_request(cookies)
                if not response:
                    break
                elif self.parse_resqonse(response):
                    logger.debug(f"Censys current page: {self.page}")
                    self.page += 1
                else:
                    break
                sleep(1)

        if self.result_domain:
            logger.info(f"Censys：{len(self.result_domain)} results found!")
            logger.debug(f"Censys：{self.result_domain}")
        return self.result_domain

    def run(self):
        pass
