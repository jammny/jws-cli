#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 子域名收集模块
"""
from queue import Queue
from typing import List, Set, Callable

from rich.table import Table

from lib.core.log import logger, console
from lib.core.settings import DNS_DATASETS_PATH, SHOW_TABLE
from lib.modules.sub.bruteforc.brute import Brute
from lib.modules.cdn.cdn_scan import CdnScan

from lib.modules.sub.custom import Custom
from lib.modules.sub.search import dns_zone_transfer_, dnsdumpster_, robtex_, virustotal_, censys_, securitytrails_, \
    fullhunt_, binaryedge_, hunter_, zoomeye_, fofa_, quake_, zero_
from lib.modules.sub.utils import get_dir_yaml, generic_parsing

from lib.utils.thread import threadpool_task


class SubScan(object):
    def __init__(self, brute_fuzzy: bool, engine: str) -> None:
        self.brute_fuzzy: bool = brute_fuzzy    # 是否开启爆破
        self.engine: str = engine    # 使用的爆破引擎
        self.passive_result: set = set()   # 存被动扫描数据
        self.valid_result = list()  # 存最终的域名存活数据
        self.brute_result = list()   # 存爆破数据
        self.root_generic = list()   # 存根域名泛解析的数据


    def check_domain_alive(self) -> None:
        """调用多线程的域名解析方法，判断域名存活, 并存储结果"""
        logger.info("Running domain validation...")
        targets_list: list = list(self.passive_result)
        result = CdnScan().run(targets_list)
        for i in result:
            if set(i['ip']) != set(self.root_generic):
                i['method'] = "passive"
                # i['ip'] = str(i['ip'])
                self.valid_result.append(i)
        logger.info(f"Subdomain Passive Scan: {len(self.valid_result)} results found!")

    def brute_(self, domain):
        """调用爆破模块

        :param domain: 目标域名
        :return:
        """
        brute_fuzzy: bool = self.brute_fuzzy
        engine: str = self.engine
        self.brute_result: List[dict] = Brute(engine).run(domain)
        if self.brute_result:
            self.remove_duplicate()  # 将被动收集和爆破收集的域名合并，去重复
            if brute_fuzzy:
                self.dnsgen_(domain)  # 利用字典进行域名置换
        return

    def dnsgen_(self, domain):
        """进行域名置换，发现更多潜在的子域名

        :param domain:
        :return:
        """
        engine = self.engine
        data: list = [i['subdomain'] for i in self.valid_result]
        if data:
            self.brute_result: List[dict] = Brute(engine).dnsgen_run(domain, data)
            if self.brute_result:
                self.remove_duplicate()  # 将被动收集和爆破收集的域名合并，去重复

    def remove_duplicate(self) -> None:
        """去掉重复的域名数据"""
        data: list = [i['subdomain'] for i in self.valid_result]
        for i in self.brute_result:
            if not i['subdomain'] in data:
                self.valid_result.append(i)

    def run_datasets(self, domain: str, queue_obj: 'Queue.queue') -> None:
        """多线程执行任务

        :param domain:
        :param queue_obj:
        :return:
        """
        datasets = queue_obj.get()
        c_result: Set['str'] = Custom(domain, datasets).run()
        self.passive_result = self.passive_result.union(c_result)

    def task_run(self, domain, queue_obj: 'Queue.queue') -> None:
        """多线程执行 内置API接口模块

        :param domain:
        :param queue_obj:
        :return:
        """
        task_name: Callable = queue_obj.get()
        result: set = task_name(domain)
        self.passive_result: set = self.passive_result.union(result)

    def show_table(self) -> None:
        """表格展示数据

        :return:
        """
        data: list = self.valid_result
        if not data:
            return
        table = Table(title="subdomain results", show_lines=False)
        table.add_column("subdomain", justify="left", style="cyan", no_wrap=True)
        table.add_column("ip", justify="left", style="magenta")
        table.add_column("cdn", justify="left", style="red")
        table.add_column("address", justify="left", style="green")
        table.add_column("method", justify="left", style="green")
        for i in data:
            table.add_row(i['subdomain'], str(i['ip']), i['cdn'], str(i['address']), i['method'])
        console.print(table)
        return

    def run(self, domain: str) -> list:
        """类统一执行入口
        
        :param domain: 目标域名
        :return:
        """
        # 获取DNS数据集的配置数据
        dns_datasets: list = get_dir_yaml(str(DNS_DATASETS_PATH))

        # 加载内置模块
        task_list: list = [
            dns_zone_transfer_, virustotal_, dnsdumpster_, robtex_,
            fofa_, zoomeye_, hunter_, binaryedge_, fullhunt_, securitytrails_, censys_, quake_, zero_
        ]

        modules_num = len(dns_datasets) + len(task_list)
        logger.info(f"[g]| Current task: SubScan | Target: {domain} | Loaded modules: {modules_num}"
                    f" | Brute Engine: {self.engine} | Brute Fuzzy: {self.brute_fuzzy} |[/g]")

        # 执行自定义的DNS数据集 #
        threadpool_task(task=self.run_datasets, queue_data=dns_datasets, task_args=(domain,), thread_count=30)

        # 执行内置的模块 #
        threadpool_task(task=self.task_run, queue_data=task_list, task_args=(domain,), thread_count=30)

        # 判断根域名是否存在泛解析
        self.root_generic = generic_parsing(domain)

        # 被动收集的域名存活验证
        self.check_domain_alive()

        # 爆破任务
        self.brute_(domain)

        if SHOW_TABLE:
            self.show_table()

        logger.info(f"Effective collection quantity：{len(self.valid_result)}")
        return self.valid_result
