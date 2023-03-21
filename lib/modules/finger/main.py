#!/usr/bin/env python
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：简单实现一个web指纹识别工具。
"""
import time
from re import compile, findall
from random import choice
from codecs import lookup


from httpx import Client
from tinydb import TinyDB


from pymmh3 import hash

from lib.core.settings import FINGER, USER_AGENTS
from lib.core.logger import logger

from . import table
from ...utils.thread import threadpool_task, get_queue


class Finger:
    def __init__(self, target: list):
        # 目标列表
        self.target: list = target
        # 随机请求头
        self.headers: dict = {"User-Agent": choice(USER_AGENTS)}
        # shiro cookie测试
        self.cookies: dict = {'rememberMe': '1'}
        # 提取网页标题正则
        self.rex = compile('<title>(.*?)</title>')
        # 指纹数据库
        self.db = TinyDB(f"{FINGER}").all()
        # 用于保存url数据：['http://...','http://...']
        self.url: list = []
        # 用于存识别后的结果
        self.result: list = []

    def get_icon_hash(self, url) -> str:
        """
        获取网站的ico，并计算它的hash
        :param url:
        :return:
        """
        with Client(verify=False, follow_redirects=True) as c:
            try:
                response = c.get(f"{url}/favicon.ico")
                # 判断是否存在favicon.ico路径
                if response.status_code == 200:
                    look = lookup('base64')  # 创建编码器
                    favicon: bytes = look.encode(response.content)[0]
                    return str(hash(favicon))
                else:
                    # 未来加入智能识别ico
                    return ''
            except:
                return ''

    def resolver(self, data, item) -> str:
        """
        解析响应页面，识别指纹
        :return:
        """
        keyword = item['keyword']
        # 如果匹配方法是关键字
        if item['method'] == 'keyword':
            # 如果是匹配头部
            if item['location'] == "header":
                headers = ""
                for i in data['res_headers'].values():
                    headers = f'{headers}{i}'
                for k in keyword:
                    # 如果头部没有关键字
                    if k not in headers:
                        return ''
                return item['cms']
            # 如果是匹配身体
            if item['location'] == "body":
                res_body = data['res_body']
                for k in keyword:
                    # 如果匹配成功
                    if k not in res_body:
                        return ''
                return item['cms']
        # 如果匹配方法是ico哈希值
        elif item['method'] == 'faviconhash':
            ico_hash = data['ico_hash']
            for k in keyword:
                if ico_hash != k:
                    return ''
            # logger.debug(item)
            return item['cms']
        else:
            print('error', item['method'])
            return ''

    def webAlive(self, target: str):
        """
        网站存活探测
        :param target: 有可能是完整url，也有可能是域名。
        :return:
        """
        # 如果目标是域名
        if "http" not in target:
            http_url: str = f"http://{target}"
            https_url: str = f"https://{target}"
        # 如果目标是URL
        else:
            http_url: str = target
            https_url: str = target
        with Client(headers=self.headers, verify=False, cookies=self.cookies, follow_redirects=True, timeout=3) as c:
            # 先测试是否存在http，如果存在就不测https了，网站指纹大概率相同。
            try:
                response = c.get(http_url)
                return response
            except:
                # 有些http不能访问，只能访问https
                try:
                    response = c.get(https_url)
                    return response
                except Exception as e:
                    # logger.debug(f"{target} {e}")
                    return None

    def finger(self, queue):
        """
        多线程调用方法
        :param self:
        :param target:
        :return:
        """
        while not queue.empty():
            target: str = queue.get(timeout=4)
            # web存活探测
            response = self.webAlive(target)
            # 如果url不可访问，就直接退出
            if not response:
                return
            # 获取目标链接
            target_url: str = str(response.url)
            # 获取标题
            title_: list = findall(self.rex, response.text)
            if title_:
                title: str = title_[0]
            else:
                title: str = ""
            # 获取网站的ico hash
            ico_hash = self.get_icon_hash(target_url)
            data: dict = {
                'res_body': response.text,
                'res_headers': response.headers,
                'ico_hash': ico_hash,
            }
            # 解析指纹
            for item in self.db:
                cms = self.resolver(data, item)
                # 如果匹配到任意一个指纹就停下来
                if cms:
                    break
            tmp = {
                'url': target_url,
                'cms': cms,
                'title': title,
                'code': str(response.status_code),
                'ico_hash': ico_hash
            }
            self.result.append(tmp)
            logger.debug(tmp)

    def run(self) -> list:
        """
        类统一执行入口
        :return:
        """
        logger.info(f"Get the target number：{len(self.target)}")
        logger.info(f"Number of data fingerprints：{len(self.db)}")
        start_time = time.time()
        # 调用多线程
        queue_obj = get_queue(self.target)
        threadpool_task(task=self.finger, args=[queue_obj], thread_count=100)
        logger.info(f"Finger task finished! Total time：{time.time() - start_time}")
        logger.info(f"Effective collection quantity：{len(self.result)}")
        # 图表展示
        table.show_table(self.result)
        return self.result
