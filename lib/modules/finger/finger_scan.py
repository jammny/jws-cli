#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 利用多线程快速识别指纹信息。
"""
import re
from codecs import lookup
from queue import Queue
from typing import ValuesView, Optional, List

from httpx import Client, Response
from rich.console import Console
from rich.table import Table
from tinydb import TinyDB, Query
from tinydb.table import Document
import pymmh3

from lib.core.settings import FINGER, SHOW_TABLE
from lib.core.log import logger
from lib.modules.waf.waf_scan import WAFScan
from lib.utils.thread import threadpool_task
from lib.modules.finger.Wappalyzer import Wappalyzer, WebPage


class FingerJScan(object):
    def __init__(self):
        self.db: TinyDB = TinyDB(f"{FINGER}")    # 初始化TinyDB对象
        self.query: Query = Query()    # 初始化查询
        self.keyword_db: List[Document] = self.db.search(self.query.method == 'keyword')    # 获取使用keyword方法的数据
        self.faviconhash_db: List[Document] = self.db.search(self.query.method == 'faviconhash')  # 获取使用hash方法的数据
        self.finger_results: list = list()   # 存储所有目标URL识别的结果
        self.cookies: dict = {
            'rememberMe': '1'
        }
        self.headers: dict = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        }

    def scan(self, queue_obj: Queue):
        """执行指纹扫描任务
        
        :param queue_obj: Queue 队列
        :return:
        """
        url: str = queue_obj.get()  # 从队列中获取目标url
        cms: set = set()  # 存储匹配到的cms数据
        cms_results: dict = dict()  # 一条完整的cms识别结果数据

        resp_data: Optional[dict] = self.send_request(url)

        if not resp_data:  # 如果目标访问失败就退出
            return

        body: str = resp_data['resp_body']
        header: ValuesView[str] = resp_data['resp_header']
        ico_hash: str = resp_data['ico_hash']
        # 先判断有没有faviconhash。如果有就匹配库中的指纹
        if ico_hash:
            cms_results['ico_hash'] = ico_hash

            icon_res: Optional[str] = self.resolver_icon(ico_hash)

            if icon_res:
                cms.add(icon_res)
        else:
            cms_results['ico_hash'] = ""
        keyword_res: str = self.resolver_keyword(header, body)
        if keyword_res:
            cms.add(keyword_res)

        url = resp_data['url']
        # 这里调用python-Wappalyzer #
        try:
            wappalyzer = Wappalyzer.latest()
            webpage = WebPage.new_from_url(url)
            wappalyzer_result: set = wappalyzer.analyze(webpage)
            cms = cms.union(wappalyzer_result)
        except Exception as e:
            pass

        # 调用WAF识别
        waf_result = WAFScan().finger(url)
        cms_results['waf'] = waf_result

        cms_results['cms'] = ", ".join(cms)
        cms_results['url'] = url
        re_title: list = re.findall(re.compile('<title>(.*?)</title>'), body)  # 正则获取网页titile
        cms_results['title'] = re_title[0] if re_title else ""
        cms_results['code'] = resp_data['status_code']

        self.finger_results.append(cms_results)

    def send_request(self, url: str) -> Optional[dict]:
        """发送请求，获取响应内容
        
        :param url: 目标url
        :return:
        """
        cookies: dict = self.cookies
        headers: dict = self.headers
        # 有时候我们可能需要扫描的列表中，只有IP+端口，这里可以自动补充http协议
        http_url, https_url = (f"http://{url}", f"https://{url}") if "http" not in url else (url, url)

        # 优先访问https #
        with Client(verify=False, follow_redirects=True, cookies=cookies, headers=headers, timeout=10) as client:
            try:
                response: Response = client.get(https_url)
                url: str = https_url
            except Exception as e:
                # 访问失败再访问http #
                try:
                    response: Response = client.get(http_url)  # 访问https
                    url: str = http_url
                except Exception as e:
                    return

        ico_hash: Optional[str] = self.get_icon_hash(url)  # 获取icon hash值
        response_data: dict = {
            'status_code': response.status_code,
            'resp_header': response.headers.values(),
            'resp_body': response.text,
            'ico_hash': ico_hash,
            'url': url
        }
        return response_data

    @staticmethod
    def get_icon_hash(url: str) -> Optional[str]:
        """通过直接拼接/favicon.ico的形式 去发现图标 并计算它的hash
        
        :param client: httpx.Client()
        :param url: 目标url
        :return:
        """
        try:
            with Client(verify=False, timeout=10) as client:
                response: Response = client.get(f"{url}/favicon.ico")
                if response.status_code == 200:
                    favicon: bytes = lookup('base64').encode(response.content)[0]
                    return str(pymmh3.hash(favicon))
                else:
                    # 直接拼接/favicon.ico 有时候并准确，可以思考一下怎么智能识别icon （需要优化）
                    return
        except Exception as e:
            logger.error(f"{url}/favicon.ico {e}")
            return

    def resolver_icon(self, ico_hash: str) -> Optional[str]:
        """解析内容 hash匹配指纹
        
        :param ico_hash: 目标iconhash
        :return:
        """
        for item in self.faviconhash_db:
            hash_rules: list = item['rules']
            if ico_hash == hash_rules[0]:   # hash一般只有一个
                return item['cms']
        return ""

    def resolver_keyword(self, header: ValuesView[str], body: str) -> str:
        """解析内容 keyword匹配指纹
        
        :param header: 响应头数据 collections.abc.ValuesView的泛型版本 可遍历数据
        :param body: 响应内容
        :return:
        """
        def match() -> str:
            for rule in keyword_rules:
                # 如果逻辑条件是or，且比较位置在body
                if condition == 'or' and location == 'body':
                    if rule in body:
                        return item['cms']
                    else:
                        continue
                # 如果逻辑条件是or，且比较位置在header
                elif condition == 'or' and location == 'header':
                    if rule in header:
                        return item['cms']
                    else:
                        continue
                # 如果逻辑条件是and，且比较位置在body
                elif condition == 'and' and location == 'body':
                    if rule not in body:   # 但凡有一个不匹配就结束循环
                        return ""
                    else:
                        continue
                # 如果逻辑条件是and，且比较位置在header
                elif condition == 'and' and location == 'header':
                    if rule not in header:
                        return ""
                    else:
                        continue
            return item['cms']    # 这里返回and成立的结果
        for item in self.keyword_db:
            keyword_rules: list = item['rules']
            location: str = item['location']
            condition: str = item['condition']
            result: str = match()
            if result != "":
                return result
        return ""

    def show_table(self) -> None:
        """表格展示数据
        
        :return:
        """
        data: list = self.finger_results
        if not data:
            return
        table = Table(title="finger results", show_lines=False)
        table.add_column("url", justify="left", style="cyan", no_wrap=True)
        table.add_column("title", justify="left", style="magenta")
        table.add_column("cms", justify="left", style="red")
        table.add_column("code", justify="left", style="green")
        table.add_column("ico_hash", justify="left", style="green")
        table.add_column("waf", justify="left", style="green")
        for i in data:
            table.add_row(i['url'], i['title'], i['cms'], str(i['code']), i['ico_hash'], i['waf'])
        console = Console()
        console.print(table)
        return

    def run(self, targets_list: List[str]) -> list:
        """这里利用多线程批量执行任务
        
        :param targets_list: 列表里面可是完整的URL链接，也可以是一个域名。
        :return:
        """
        logger.info(f"[g]| Current task: FingerScan | Target numbers: {len(targets_list)} | Fingerprints numbers:"
                    f" {len(self.db.all())} |[/g]")

        threadpool_task(task=self.scan, queue_data=targets_list)

        if SHOW_TABLE:
            self.show_table()

        logger.info(f"Effective collection quantity: {len(self.finger_results)}")
        return self.finger_results
