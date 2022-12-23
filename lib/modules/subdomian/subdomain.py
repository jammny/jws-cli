#!/usr/bin/env python
# -- coding:utf-8
"""
作者：jammny
文件描述：子域名收集模块
"""
import os
from queue import Queue
from time import time

import yaml
from colorama import Back

from lib.config.settings import console, DNS
from lib.config.logger import logger

from lib.utils.nslookup import a_record
from lib.utils.thread import thread_task, get_queue
from . import custom

from .bruteforc import brute

from .search import sogou, censys, zoomeye, bing, so, baidu, yandex, google, hunter_api, binaryedge_api, fofa_api, fullhunt_api

from .intelligence import virustotal
from .dnsdatasets import robtex, dnsdumpster, sitedossier, securitytrails_api


class Sub:
    def __init__(self, target) -> None:
        # 获取目标域名
        self.target: str = target
        # 存被动扫描数据
        self.passive_result: list = []
        # 存爆破数据
        self.brute_result: list = []
        # 存最终的域名存活数据
        self.valid_result: list = []
        # 存域名泛解析的结果
        self.generic: list = []

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
        :return:['xxx','xxx']
        """
        query: str = f"hostname:{self.target}"
        res: list = zoomeye.ZoomEye(query).get_domain()
        self.passive_result.extend(res)

    def hunter_(self) -> None:
        """
        调用hunter api
        :return:['xxx','xxx']
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
        :return: ['xxxx']
        """
        res: list = fullhunt_api.Fullhunt(self.target).get_domain()
        self.passive_result.extend(res)

    def binaryedge_api_(self) -> None:
        """
        binaryedge 域名收集
        :return: ['xxxx']
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

    def sitedossier_(self) -> None:
        """
        sitedossier 域名收集
        :return: ['xxxx']
        """
        res: list = sitedossier.Sitedossier(self.target).get_domain()
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
        res: list = dnsdumpster.Dnsdumpster(self.target).get_domain()
        self.passive_result.extend(res)

    def get_datasets(self):
        """
        从目录中获取自定义DNS数据集的文件内容
        :return: 返回文件内容
        """
        yaml_files = []
        # 遍历目录中的文件名
        for root, dirs, files in os.walk(DNS):
            for file in files:
                # 将文件名添加到列表
                yaml_files.append(os.path.join(root, file))

        datasets = []
        # 遍历文件内容
        for i in yaml_files:
            with open(i, mode='r', encoding='utf-8') as f:
                data = yaml.safe_load(f.read())
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
            res: list = custom.Custom(self.target, dataset).run()
            self.passive_result.extend(res)

    def brute_(self) -> None:
        """
        爆破模块
        :return: {'subdomain': 'xxx', 'method': 'brute', 'ip': ['xxxx']}
        """
        self.brute_result = brute.Brute(self.target).run()

    def generic_parsing(self) -> None:
        """
        检测域名泛解析
        :return:
        """
        domain = f"generictest.{self.target}"
        try:
            ip = a_record(domain)
            logger.warn(f"域名泛解析到IP：{ip}, 程序将自动忽略解析到该IP的域名")
            self.generic = ip
        except:
            logger.debug(f"域名不存在泛解析！")

    def domain_validation(self, queue) -> None:
        """
        主要验证被动收集的域名
        :return: 存货的域名
        """
        while not queue.empty():
            domain = queue.get()
            try:
                ip = a_record(domain)
                # 忽视和泛解析相同的结果
                if ip and self.generic != ip:
                    self.valid_result.append({'subdomain': domain, 'method': 'passive', 'ip': ip})
            except:
                pass

    def remove_duplicate(self) -> None:
        """
        去掉重复的域名数据
        :return:
        """
        data: list = [i['subdomain'] for i in self.valid_result]
        for i in self.brute_result:
            if not data.__contains__(i['subdomain']) and i['ip'] != self.generic:
                self.valid_result.append(i)

    def run(self, brute_status) -> list:
        """
        类统一执行入口
        :return:
        """
        start = time()
        logger.info(f"{Back.MAGENTA}执行任务：域名收集{Back.RESET}")
        task: list = [
            # 综合搜索引擎
            self.google_, self.so_, self.bing_, self.baidu_, self.yandex_, self.sougou_,
            # 网络空间搜索引擎
            self.censys_, self.fullhunt_, self.binaryedge_api_, self.fofa_, self.hunter_, self.zoomeye_,
            # 威胁情报
            self.virustotal_,
            # DNS数据集
            self.sitedossier_, self.robtex_, self.dnsdumpster_, self.securitytrails_,
        ]
        datasets: list = self.get_datasets()
        logger.info(f"({len(task + datasets)}) modules were successfully loaded!")

        # 先执行自定义的DNS数据集
        queue = get_queue(datasets)
        thread_task(task=self.run_datasets, args=[queue], thread_count=len(datasets))

        # 执行内置的模块
        queue = get_queue(task)
        thread_task(task=self.task_run, args=[queue], thread_count=len(task))

        # 判断是否存在域名泛解析
        self.generic_parsing()

        # 域名存活验证
        logger.info("Running domain validation...")
        # 列表去重, 获取所以被动收集的内容
        passive_result: list = list(set(self.passive_result))
        queue = get_queue(passive_result)
        thread_task(task=self.domain_validation, args=[queue])

        # 爆破任务
        if brute_status:
            self.brute_()

        # 将被动收集和爆破收集的域名合并，去重复
        self.remove_duplicate()

        end = time()
        logger.info(f"Subdomain task finished! Total time：{end - start}")
        logger.info(f"Effective collection quantity：{Back.RED}{len(self.valid_result)}{Back.RESET}")
        logger.debug(self.valid_result)
        console.print(self.valid_result)
        return self.valid_result
