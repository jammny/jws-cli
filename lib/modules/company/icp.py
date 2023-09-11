#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 利用多线程快速识别指纹信息。
"""

from httpx import Client
from parsel import Selector

from lib.core.log import logger
from lib.utils.tools import domain_format


class ICP(object):
    def __init__(self):
        pass

    def run(self, company_name):
        results = set()
        url = f"https://www.beianx.cn/search/{company_name}"
        try:
            with Client() as c:
                response = c.get(url)
            response_body = response.text
            selector = Selector(response_body)
            data_list: list = selector.css('table[class="table table-sm table-bordered table-hover"] a::text').getall()
            # print(data_list)
            for domain in data_list:
                if domain_format(domain):
                    # print(domain)
                    results.add(domain)
        except Exception as e:
            logger.error(f"[red]{url} {e}[/red]")

        logger.info(f"Target: {results} be found.")
        # print(results)
        return results