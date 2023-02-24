#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：爬取http代理链接
"""
from ast import literal_eval
from httpx import Client, stream
from rich.progress import Progress
from lib.core.logger import logger
from lib.core.settings import HTTP_PROXY
from lib.utils.thread import thread_task


class HttpProxy:
    def __init__(self):
        self.proxy_list: list = []  # 爬取到的代理
        self.available_proxy: list = []  # 可用的代理

    def check_proxy(self, queue, task, progress) -> None:
        """
        判断代理是否可用
        :return:
        """
        while not queue.empty():
            proxies: str = queue.get().rstrip('\n')
            url = "https://m.baidu.com/"
            try:
                with Client(proxies=proxies, verify=False) as c:
                    response = c.get(url)
                if response.status_code == 200:
                    logger.debug(f"发现可用代理：{proxies}")
                    self.available_proxy.append(proxies)
            except Exception as e:
                logger.debug(f"{proxies}{e}")
            finally:
                # 更新进度
                if not progress.finished:
                    progress.update(task, advance=1)

    def proxylist_proxy(self) -> None:
        """
        获取代理列表：http://proxylist.fatezero.org/proxy.list
        :return: 没有返回值
        """
        try:
            with stream("GET", "http://proxylist.fatezero.org/proxy.list") as r:
                for i in r.iter_lines():
                    data: dict = literal_eval(i.replace("null", '"null"'))
                    if not data['type'].__contains__("https"):
                        self.proxy_list.append(f"{data['type']}://{data['host']}:{data['port']}")
        except Exception as e:
            logger.warn(f"proxylist列表获取失败失败! {e}")

    def update(self) -> None:
        """
        代理更新
        :return:
        """
        logger.info("正在更新代理数据")
        self.proxylist_proxy()
        if not self.proxy_list:
            logger.error(f"代理更新失败!")
            return
        else:
            # 进度条
            with Progress() as progress:
                task = progress.add_task('[red]', total=len(self.proxy_list))
                thread_task(self.proxy_list, self.check_proxy, args=[task, progress])
            # 把结果写入文件
            with open(HTTP_PROXY, mode="w", encoding="utf-8") as f:
                f.writelines(f"{self.available_proxy}")
            logger.info(f"代理更新成功! 共发现有效代理数量：{len(self.available_proxy)}")
            logger.info(f"代理文件保存路径：{HTTP_PROXY}")

    def get_proxy(self) -> list:
        """
        获取本地代理列表文件，用于后续调用。
        :return:
        """
        try:
            with open(HTTP_PROXY, mode="r", encoding="utf-8") as f:
                proxy_list: list = literal_eval(f.readline())
                logger.debug(f"获取本地代理数量：{len(proxy_list)}")
                return proxy_list
        except Exception as e:
            logger.error(f"本地代理文件读取失败！ {HTTP_PROXY} {e}")
            return []
