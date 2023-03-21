#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 子域名收集模块
"""
import os
import socket
from time import time
from dataclasses import dataclass

import yaml
import tldextract
from rich.console import Console
from rich.table import Table

from lib.core.settings import DNS, SUBNAMES, SUBWORIDS
from lib.core.logger import logger
from lib.utils.nslookup import a_record
from lib.utils.thread import get_queue, threadpool_task

from .vulnerability.dns_zone_transfer import AXFR
from .bruteforc import brute, dnsgen
from .search import sogou, censys, zoomeye, bing, so, baidu, yandex, google, hunter_api, binaryedge_api, fofa_api, \
    fullhunt_api
from .intelligence import virustotal
from .dnsdatasets import robtex, dnsdumpster, securitytrails_api
from . import custom
from ...utils.format import runtime_format


@dataclass()
class Sub(object):
    target: str    # 获取目标域名

    passive_result = list()   # 存被动扫描数据
    brute_result = list()   # 存爆破数据
    valid_result = list()   # 存最终的域名存活数据
    root_generic = list()   # 存根域名泛解析的结果
    dnsgen_generic = list()   # 存一级域名泛解析结果

    def task_run(self, queue) -> None:
        """
        多线程任务执行入口
        :param queue:
        :return:
        """
        while not queue.empty():
            task = queue.get()
            task()

    def fofa_(self) -> None:
        """
        调用fofa api
        :return: ['xxx','xxx']
        """""
        query: str = f'domain="{self.target}" && protocol="http"'
        res: list = fofa_api.Fofa(query).get_domain()
        self.passive_result.extend(res)

    def zoomeye_(self) -> None:
        """
        调用zoomeye api
        :return:
        """
        query: str = f"hostname:{self.target}"
        res: list = zoomeye.ZoomEye(query).get_domain()
        self.passive_result.extend(res)

    def hunter_(self) -> None:
        """
        调用hunter api
        :return:
        """
        query: str = f'domain_suffix="{self.target}"'
        res: list = hunter_api.Hunter(query).get_domain()
        self.passive_result.extend(res)

    def securitytrails_(self) -> None:
        """
        Securitytrails API 域名收集
        :return: ['xxxx']
        """
        res: list = securitytrails_api.Securitytrails(self.target).get_domain()
        self.passive_result.extend(res)

    def fullhunt_(self) -> None:
        """
        fullhunt api 域名收集
        :return:
        """
        res: list = fullhunt_api.Fullhunt(self.target).get_domain()
        self.passive_result.extend(res)

    def binaryedge_api_(self) -> None:
        """
        binaryedge 域名收集
        :return:
        """
        res: list = binaryedge_api.Binaryedge(self.target).get_domain()
        self.passive_result.extend(res)

    def censys_(self) -> None:
        """
        censys 域名收集
        :return: ['xxxx']
        """
        res: list = censys.Censys(self.target).get_domain()
        self.passive_result.extend(res)

    def sougou_(self) -> None:
        """
        爬搜狗搜索引擎
        :return:['xxx','xxx']
        """
        res: list = sogou.Sogou(self.target).get_domain()
        self.passive_result.extend(res)

    def bing_(self) -> None:
        """
        爬Bing搜索引擎
        :return: ['xxx','xxx']
        """
        res: list = bing.Bing(self.target).get_domain()
        self.passive_result.extend(res)

    def baidu_(self) -> None:
        """
        爬baidu搜索引擎
        :return:['xxx','xxx']
        """
        res: list = baidu.Baidu(self.target).get_domain()
        self.passive_result.extend(res)

    def yandex_(self) -> None:
        """
        爬yandex搜索引擎
        :return:['xxx','xxx']
        """
        res: list = yandex.Yandex(self.target).get_domain()
        self.passive_result.extend(res)

    def google_(self) -> None:
        """
        爬google搜索引擎
        :return:['xxx','xxx']
        """
        res: list = google.Google(self.target).get_domain()
        self.passive_result.extend(res)

    def so_(self) -> None:
        """
        爬360搜索引擎
        :return:['xxx','xxx']
        """
        res: list = so.So(self.target).get_domain()
        self.passive_result.extend(res)

    def virustotal_(self) -> None:
        """
        virustotal收集模块
        :return: ['xxxx']
        """
        res: list = virustotal.Virustotal(self.target).get_domain()
        self.passive_result.extend(res)

    def robtex_(self) -> None:
        """
        robtex 域名收集
        :return: ['xxxx']
        """
        res: list = robtex.Robtex(self.target).get_domain()
        self.passive_result.extend(res)

    def dnsdumpster_(self) -> None:
        """
        dnsdumpster 域名收集
        :return: ['xxxx']
        """
        res: list = dnsdumpster.Dnsdumpster(self.target).run()
        self.passive_result.extend(res)

    def dns_zone_transfer_(self) -> None:
        """
        域传输漏洞检测
        :return:
        """
        res: list = AXFR(self.target).run()
        self.passive_result.extend(res)

    def get_datasets(self) -> list:
        """
        从目录中获取自定义DNS数据集的文件内容
        :return: 返回文件内容
        """
        yaml_files: list = list()
        # 遍历目录中的文件名
        for root, dirs, files in os.walk(DNS):
            for file in files:
                yaml_files.append(os.path.join(root, file))   # 将文件名添加到列表
        datasets: list = list()
        # 遍历文件内容
        for i in yaml_files:
            with open(i, mode='r', encoding='utf-8') as f:
                data: dict = yaml.safe_load(f.read())
                datasets.append(data)
        return datasets

    def run_datasets(self, queue):
        """
        多线程执行， 解析自定义数据集
        :param queue:
        :return:
        """
        while not queue.empty():
            dataset = queue.get()
            if dataset == u'end_tag':  # 接收到结束码，就结束
                break
            res: list = custom.Custom(self.target, dataset).run()
            self.passive_result.extend(res)

    def generic_parsing(self, target) -> None:
        """
        检测域名泛解析
        :return:
        """
        domain: str = f"fucktest.{target}"
        try:
            # 如果能够成功解析出IP，说明存在泛解析
            addr_info = socket.getaddrinfo(domain, None)
            self.root_generic: list = [addr[4][0] for addr in addr_info if ":" not in addr[4][0]]
            logger.warn(f"域名{target}存在泛解析！默认忽略解析到{self.root_generic}的域名！")
        except:
            pass

    def check_domain_alive(self):
        """
        判断域名存活
        :return:
        """
        logger.info("Running domain validation...")
        # 列表去重, 获取所以被动收集的内容
        passive_result: list = list(set(self.passive_result))
        queue = get_queue(passive_result)
        threadpool_task(task=self.domains_validation, args=[queue], thread_count=30)
        logger.info(f"Subdomain Passive: {len(self.valid_result)} results found!")

    def domains_validation(self, queue,) -> None:
        """
        主要验证被动收集的域名
        :return: 存货的域名
        """
        while not queue.empty():
            domain = queue.get()
            if domain == u'end_tag':  # 接收到结束码，就结束
                break
            try:
                ip = a_record(domain)
                # 忽视和泛解析相同的结果
                if ip and self.root_generic != ip:
                    self.valid_result.append({'subdomain': domain, 'method': 'passive', 'ip': ip})
            except:
                pass

    def brute_(self) -> None:
        """
        爆破模块
        :return: {'subdomain': 'xxx', 'method': 'brute', 'ip': ['xxxx']}
        """
        logger.info("Running Subdomain Brute...")
        # 读取一级字典, 清理\n，并拼接子域，处理成 www.domain.com 格式
        with open(SUBNAMES, 'r') as f:
            domains = [f"{line.strip()}.{self.target}" for line in f.readlines()]
        logger.info(f"Number of dictionary：{len(domains)}")
        self.brute_result = brute.Brute(self.target, domains, self.root_generic).run()
        # 将被动收集和爆破收集的域名合并，去重复
        self.remove_duplicate()

    def remove_duplicate(self) -> None:
        """
        去掉重复的域名数据
        :return:
        """
        data: list = [i['subdomain'] for i in self.valid_result]
        for i in self.brute_result:
            if not data.__contains__(i['subdomain']) and i['ip'] != self.root_generic:
                self.valid_result.append(i)

    def dnsgen_generic_parsing(self, queue):
        """
        多线程泛解析, 主要为了排除一级域名中存在泛解析的目标。
        :return:
        """
        while not queue.empty():
            domain = queue.get()
            if self.generic_parsing(domain):
                self.dnsgen_generic.append(domain)

    def dnsgen_(self):
        """
        进行域名置换，发现更多潜在的子域名
        :return:
        """
        logger.info("Running fuzz...")
        data: list = [i['subdomain'] for i in self.valid_result]
        # 一级域名泛解析筛选
        queue = get_queue(data)
        threadpool_task(self.dnsgen_generic_parsing, args=[queue], thread_count=10)
        # 读取置换用的字典
        with open(SUBWORIDS, mode='r', encoding='utf-8') as f:
            wordlist = f.read().splitlines()
        for d in self.dnsgen_generic:
            # 从发现的一级域名, 删除存在泛解析的数据
            if d in data:
                data.remove(d)
            # 从读取的置换字典中，删除存在泛解析的数据
            tmp = tldextract.extract(d).subdomain
            if tmp in wordlist:
                wordlist.remove(tmp)
        # 返回迭代器, 需要转成list
        domains = dnsgen.run(data, wordlist)
        domains: list = list(domains)
        logger.info(f"Generate the fuzz dictionary：{len(domains)}")
        # 因为之前爆破的数据已经合并了，所以这里可以覆盖掉原来的数据
        self.brute_result = brute.Brute(self.target, domains, self.root_generic).run()
        # 将原来的有效数据和置换爆破收集的域名合并，去重复
        self.remove_duplicate()

    def run(self, brute_status: bool) -> list:
        """
        类统一执行入口
        :param brute_status: 是否开启爆破
        :return: list
        """
        logger.info(f"Acquire scan target: {self.target}")
        start = time()
        task: list = [
            # 综合搜索引擎
            self.google_, self.so_, self.bing_, self.baidu_, self.yandex_, self.sougou_,
            # 网络空间搜索引擎
            self.censys_, self.fullhunt_, self.binaryedge_api_, self.fofa_, self.hunter_, self.zoomeye_,
            # 威胁情报
            self.virustotal_,
            # DNS数据集
            self.dnsdumpster_, self.securitytrails_, self.robtex_,
            # DNS域传输
            self.dns_zone_transfer_,
        ]
        datasets: list = self.get_datasets()
        logger.info(f"({len(task + datasets)}) modules were successfully loaded!")

        # 执行自定义的DNS数据集
        queue = get_queue(datasets)
        threadpool_task(task=self.run_datasets, args=[queue], thread_count=30)
        
        # 线程池执行内置的模块
        queue = get_queue(task)
        threadpool_task(task=self.task_run, args=[queue], thread_count=len(task))

        # 判断根域名是否存在泛解析
        self.generic_parsing(self.target)

        # 域名存活验证
        self.check_domain_alive()
        
        # 爆破任务
        if brute_status:
            self.brute_()
            # 利用字典进行域名置换
            self.dnsgen_()

        end = time()
        run_time = runtime_format(start, end)
        logger.info(f"Subdomain task finished! Total time：{run_time}")
        logger.info(f"Effective collection quantity：{len(self.valid_result)}")
        show_results(self.valid_result)   # 数据展示
        return self.valid_result


def show_results(data: list) -> None:
    """
    表格展示数据
    :param: data
    :return:
    """
    table = Table(title="subdomain results", show_lines=False)
    table.add_column("subdomain", justify="left", style="cyan", no_wrap=True)
    table.add_column("method", justify="left", style="magenta")
    table.add_column("ip", justify="left", style="red")
    for i in data:
        table.add_row(i['subdomain'], i['method'], str(i['ip']))
    console = Console()
    console.print(table)
