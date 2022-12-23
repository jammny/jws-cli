#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
from time import time

from rich.progress import Progress

from lib.utils.thread import thread_task, get_queue
from lib.utils.nslookup import a_record

from lib.config.logger import logger
from lib.config.settings import SUBNAMES


class Brute:
    def __init__(self, target: str) -> None:
        # 获取目标域名
        self.target: str = target
        # 存爆破结果
        self.result: list = []
        # 存泛解析结果
        self.generic: list = []

    def generic_parsing(self) -> None:
        """
        检测域名泛解析
        :return:
        """
        domain: str = f"fucktest.{self.target}"
        try:
            # 如果能够成功解析出IP，说明存在泛解析
            ip: list = a_record(domain)
            # logger.warn(f"域名存在泛解析！默认忽略解析到{ip}的域名！")
            self.generic = ip
        except:
            # logger.debug(f"域名不存在泛解析！")
            pass

    def dns_resolver(self, queue, task, progress) -> None:
        """
        dns解析，多线程调用的方法
        :return:
        """
        while not queue.empty():
            domain: str = queue.get()
            try:
                ip: list = a_record(domain)
                if ip != self.generic:
                    self.result.append({'subdomain': domain, 'method': 'brute', 'ip': ip})
            except :
                # 抛出异常说明域名解析失败，pass
                pass
            finally:
                # 更新进度
                if not progress.finished:
                    progress.update(task, advance=1)

    def run(self) -> list:
        """
        子域名爆破，执行入口
        :return: 爆破结果
        """
        start = time()
        logger.info("Running Subdomain Brute...")
        # 读取一级字典
        with open(SUBNAMES, mode="r", encoding="utf-8") as f:
            data = f.readlines()
        # 清理 \n ， 并处理成 www.domain.com 格式
        domain: list = [f"{i.rstrip()}.{self.target}" for i in data]
        logger.info(f"Number of dictionary：{len(domain)}")
        # 检测泛解析
        self.generic_parsing()
        # 进度条
        with Progress() as progress:
            task = progress.add_task('[red]', total=len(domain))
            queue = get_queue(domain)
            thread_task(task=self.dns_resolver, thread_count=1000, args=[queue, task, progress])
        end = time()
        logger.info(f"Subdomain Brute: {len(self.result)} results found! Run time：{end - start}")
        logger.debug(self.result)
        return self.result
