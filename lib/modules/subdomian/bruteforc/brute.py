#!/usr/bin/env python 
# -*- coding : utf-8-*-
from time import time

from rich.progress import (
    BarColumn,
    Progress,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from lib.utils.thread import get_queue, threadpool_task
from lib.utils.nslookup import a_record

from lib.core.logger import logger


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
            # logger.warn(f"域名{self.target}存在泛解析！默认忽略解析到{ip}的域名！")
            self.generic = ip
        except:
            # logger.debug(f"域名{self.target}不存在泛解析！")
            pass

    def dns_resolver(self, queue, task, progress) -> None:
        """
        dns解析，多线程调用的方法
        :return:
        """
        while not queue.empty():
            domain: str = queue.get(timeout=4)
            if domain == u'end_tag':
                break
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

    def run(self, domain) -> list:
        """
        子域名爆破，执行入口
        :return: 爆破结果
        """
        start = time()
        # 检测泛解析
        self.generic_parsing()
        # 进度条
        progress = Progress(
            BarColumn(bar_width=40),
            "[progress.percentage]{task.percentage:>3.1f}%",
            # "•",
            # DownloadColumn(),
            # "•",
            TransferSpeedColumn(),
            "•",
            TimeRemainingColumn(),
        )
        with progress:
            task = progress.add_task('[red]', total=len(domain))
            queue_obj = get_queue(domain)
            threadpool_task(task=self.dns_resolver, args=[queue_obj, task, progress], thread_count=3000)
        end = time()
        logger.info(f"Subdomain Brute: {len(self.result)} results found! Run time：{end - start}")
        logger.debug(self.result)
        return self.result
