#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 内置的DNS数据源模块，爬取http://www.dnsdumpster.com/的数据。
"""
from typing import Union
from dataclasses import dataclass

from httpx import Client

from lib.utils.format import match_subdomains
from lib.core.logger import logger


@dataclass()
class Dnsdumpster(object):
    domain: str
    result_domain = set()
    url = f"https://dnsdumpster.com/"
    headers = {
        'Referer': 'https://dnsdumpster.com',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    def send_request(self) -> Union[str, None]:
        """
        请求接口，返回响应内容
        :return:
        """
        with Client(verify=False, timeout=10) as c:
            try:
                c.get(self.url)
                data = {
                    # 从返回的set-cookies中，拿到csrftoken
                    'csrfmiddlewaretoken': c.cookies.get('csrftoken'),
                    'targetip': self.domain,
                    'user': 'free'
                }
                response = c.post(self.url, headers=self.headers, data=data)
                if response.status_code == 200:
                    return response.text
                else:
                    logger.warning(f"dnsdumpster connect error！ Code： {response.status_code}")
                    # logger.debug(response.text)
                    return
            except Exception as e:
                logger.error(f"{self.url} {e}")
                return

    def run(self) -> list:
        """
        类执行入口
        :return:
        """
        logger.info("Running Dnsdumpster...")
        response: Union[str, None] = self.send_request()
        if response:
            self.result_domain = match_subdomains(self.domain, response)
        logger.info(f"Dnsdumpster：{len(self.result_domain)} results found!")
        logger.debug(f"Dnsdumpster：{self.result_domain}")
        return list(self.result_domain)


if __name__ == '__main__':
    Dnsdumpster('yineng.com.cn').run()
