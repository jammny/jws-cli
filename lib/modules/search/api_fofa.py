#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：FOFA API接口调用
"""
from base64 import b64encode
from typing import Set, Optional

from rich.table import Table

from lib.modules.search.api_base import ApiBase
from lib.core.log import logger
from lib.utils.tools import match_subdomains

__all__ = ['Fofa']


def show_table(data) -> None:
    """表格展示数据

    :return:
    """
    if not data:
        return
    table = Table(title="fofa results", show_lines=False)
    table.add_column("host", justify="left", style="cyan", no_wrap=True)
    table.add_column("title", justify="left", style="magenta")
    table.add_column("ip", justify="left", style="red")
    table.add_column("port", justify="left", style="green")
    table.add_column("protocol", justify="left", style="green")
    for i in data:
        table.add_row(i[0], i[1], i[2], i[3], i[4])
    return


class Fofa(ApiBase):

    def __init__(self, query: str, domain: Optional[str] = None) -> None:
        super().__init__()
        self.name = "Fofa"
        self.domain: Optional[str] = domain
        self.email: str = self.config['fofa_email']
        self.key: str = self.config['fofa_key']
        self.size: str = self.config['fofa_size']
        self.query: str = query
        self.qbase64: str = str(b64encode(query.encode("utf-8")), 'utf-8')  # fofa查询参数，base64编码
        self.url: str = (f"https://fofa.info/api/v1/search/all?email={self.email}&key={self.key}&qbase64={self.qbase64}"
                         f"&size={self.size}&fields=host,title,ip,port,protocol,domain,banner")
        self.results: list = list()

    def get_domain(self,) -> set:
        """域名收集专用

        :return:
        """
        domain = self.domain
        name = self.name
        url = self.url
        logger.info(f"Running {name}...")
        try:
            response_json: Optional[dict] = self.send_request(url)
        except Exception as e:
            logger.error(f"{name} connect error! {url} {e}")
            return self.result_domain

        if not response_json:
            return self.result_domain

        # 正则提取页面中域名
        self.result_domain: Set['str'] = match_subdomains(domain, str(response_json))

        logger.info(f"{name}：{len(self.result_domain)} results found!")
        logger.debug(f"{name}：{self.result_domain}")
        return self.result_domain

    def run(self):
        url = self.url
        name = self.name

        try:
            fofa_results = self.send_request(url)
        except:
            logger.error(f"{name} connect error! Exit the task.")
            return list()

        # 判断返回的结果中是否存在error
        is_error: bool = fofa_results['error']
        if is_error:
            logger.error(f"Fofa Api error! {fofa_results}")
            return list()

        # 判断是否有数据 #
        results: list = fofa_results['results']
        if not results:
            logger.info(f"No information related to the {self.query} was found!")
            return list()

        show_table(results)
        return results
