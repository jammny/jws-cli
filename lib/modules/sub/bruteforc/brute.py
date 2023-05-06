#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 子域名爆破模块，使用多线程的方式进行任务处理。
"""
from time import time

import dns.resolver
from rich.progress import Progress

from lib.utils.log import logger
from lib.utils.thread import threadpool_task
from lib.utils.tools import runtime_format


class Brute(object):
    def __init__(self):
        self.brute_results = []

    def resolve_domain(self, root_generic: list, progress, task, queue_obj):
        """

        :param root_generic:
        :param progress:
        :param task:
        :param queue_obj:
        :return:
        """
        try:
            domain = queue_obj.get()
            answers = dns.resolver.resolve(domain, 'A')
            ip: list = [str(rdata) for rdata in answers]
            if ip != root_generic:
                self.brute_results.append({
                    "subdomain": domain,
                    "method": "brute",
                    "ip": ip
                })
        except Exception as e:
            pass
        finally:
            # 进度条渲染
            progress.update(task, advance=1)

    def run(self, domain_list: list, root_generic: list, thread_num: int) -> list:
        """

        :param thread_num: 线程数
        :param domain_list: 待扫描的域名
        :param root_generic: 泛解析结果
        :return:
        """
        start = time()
        with Progress(transient=True) as progress:
            task = progress.add_task("[green]Processing...", total=len(domain_list))  # 定义一个进度条对象
            while not progress.finished:
                threadpool_task(task=self.resolve_domain, queue_data=domain_list,
                                task_args=(root_generic, progress, task,), thread_count=thread_num)
        end = time()
        run_time = runtime_format(start, end)
        logger.info(f"Subdomain Brute Scan: {len(self.brute_results)} results found! Total time：{run_time}")
        return self.brute_results
