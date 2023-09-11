#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 子域名爆破模块，使用多线程的方式进行任务处理。
"""
from typing import List, Set, Optional

import dns.resolver
from rich.progress import Progress

from lib.core.log import logger
from lib.core.settings import QQWRYPATH, SUBNAMES, SUBWORIDS, TMP
from lib.modules.cdn.cdn_scan import CdnScan
from lib.modules.sub.bruteforc import dnsgen
from lib.modules.sub.bruteforc.thirdparty import ksubdomain
from lib.modules.sub.utils import generic_parsing, get_subname
from lib.utils.thread import threadpool_task
from lib.modules.cdn.qqwry import QQwry
from lib.utils.tools import get_time


class Brute(object):
    def __init__(self, engine: str):
        self.engine: str = engine  # 扫描引擎
        self.qqwry: QQwry = QQwry()
        self.qqwry.load_file(str(QQWRYPATH))
        self.brute_result = []
        self.subdomain: set = set()
        self.dnsgen_generic_domain: set = set()  # 存一级域名泛解析数据

    def resolve_dns(self, progress, task, root_generic: list, queue_obj: 'Queue') -> None:
        """DNS解析IP

        :param task:
        :param progress:
        :param queue_obj:
        :param root_generic:
        :return:
        """
        try:
            hostname: str = queue_obj.get()
            answers = dns.resolver.resolve(hostname, 'A')
            ip: list = [str(rdata) for rdata in answers]
            if set(ip) != set(root_generic):  # 如果不是泛解析
                self.subdomain.add(hostname)
        except Exception as e:
            pass
        finally:
            progress.update(task, advance=1)
        return

    def thread_brute(self, domain: str, root_generic: List):
        """多线程爆破

        :return:
        """
        # 读取一级字典, 清理\n，并拼接子域，处理成 www.domain.com 格式
        with open(SUBNAMES, mode='r', encoding='utf-8') as f:
            domain_list: list = [f"{line.strip()}.{domain}" for line in f.readlines()]

        logger.info(f"Number of dictionary：{len(domain_list)}")

        with Progress(transient=True) as progress:
            task = progress.add_task("[red]Brute...", total=len(domain_list))
            threadpool_task(task=self.resolve_dns, queue_data=domain_list, thread_count=3000,
                            task_args=(progress, task, root_generic,))

        return

    def dnsgen_generic_parsing(self, queue_obj: 'Queue.queue'):
        """多线程泛解析, 主要为了排除一级域名中存在泛解析的目标

        :param queue_obj:
        :return:
        """
        domain = queue_obj.get()
        if generic_parsing(domain):
            self.dnsgen_generic_domain.add(domain)

    def dnsgen_run(self, domain, data):
        """

        :param domain:
        :param data:
        :return:
        """
        logger.info("Running dnsgen fuzz...")
        engine = self.engine
        dnsgen_generic_domain = self.dnsgen_generic_domain

        # 一级域名泛解析筛选 #

        threadpool_task(task=self.dnsgen_generic_parsing, queue_data=data, thread_count=30)
        logger.info(f"generic parsing domain name: {dnsgen_generic_domain}")

        # 读取置换用的字典 #
        with open(SUBWORIDS, mode='r', encoding='utf-8') as f:
            wordlist = f.read().splitlines()
        for d in list(dnsgen_generic_domain):
            # 从发现的一级域名, 删除存在泛解析的数据
            if d in data:
                data.remove(d)
            # 从读取的置换字典中，删除存在泛解析的数据
            tmp = get_subname(d)
            if tmp in wordlist:
                wordlist.remove(tmp)

        # 返回迭代器, 需要转成list #
        domains = dnsgen.run(data, wordlist, domain)
        domain_list: list = list(set(domains))
        logger.info(f"Generate the fuzz dictionary：{len(domain_list)}")

        if engine == "system":
            with Progress(transient=True) as progress:
                task = progress.add_task("[red]Brute...", total=len(domain_list))
                threadpool_task(task=self.resolve_dns, queue_data=domain_list, thread_count=3000,
                                task_args=(progress, task, [],))
        elif engine == "ksubdomain":
            # 把生成的字典写入目录 #
            p = f"{TMP}/{domain}/dnsgen.txt"
            with open(p, mode='w', encoding='utf-8') as f:
                f.writelines([f"{i}\n" for i in domain_list])
            self.subdomain: Set[str] = ksubdomain(p, domain)
        else:
            logger.error(f"Wrong brute engine: {engine}")
            return list()

        logger.info("Dnsgen fuzz finished.")
        if len(self.subdomain) > 1000:
            # 如果目标存在泛解析，且最终解析的数据超过1000，可能是误报数据
            logger.error(
                "Because the Domain names have universal resolution, and the result exceeded the threshold. "
                "Finally discard the brute result.")
        else:
            self.brute_result: List[dict] = CdnScan().run(target_list=list(self.subdomain))

        logger.info(f"Dnsgen：{len(self.brute_result)} results found!")

    def run(self, domain: str) -> List[dict]:
        """

        :param domain: 需要遍历的根域名
        :return:
        """
        engine: str = self.engine
        logger.info("Running Subdomain Brute...")

        # 先进行泛解析 #
        root_generic = generic_parsing(domain)
        if root_generic:
            logger.info(f"[y]The domain name is parsed to {root_generic}.[/y]")

        if engine == "system":
            self.thread_brute(domain, root_generic)
        elif engine == "ksubdomain":
            self.subdomain: Set[str] = ksubdomain(SUBNAMES, domain)
        else:
            logger.error(f"Wrong brute engine: {engine}")
            return list()

        if root_generic and len(self.subdomain) > 1000:
            # 如果目标存在泛解析，且最终解析的数据超过1000，可能是误报数据
            logger.error(
                "Because the Domain names have universal resolution, and the result exceeded the threshold. "
                "Finally discard the brute result.")
        else:
            self.brute_result: List[dict] = CdnScan().run(target_list=list(self.subdomain))

        logger.info(f"Brute：{len(self.brute_result)} results found!")
        return self.brute_result
