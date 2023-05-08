#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 子域名收集模块
"""
from queue import Queue
from time import time
from typing import Optional

import dns
import tldextract
from rich.console import Console
from rich.table import Table

from .vulnerability.dns_zone_transfer import AXFR
from .bruteforc import brute, dnsgen
from .search import sogou, censys, zoomeye, bing, so, baidu, yandex, google, hunter_api, binaryedge_api, fofa_api, \
    fullhunt_api
from .intelligence import virustotal
from .dnsdatasets import robtex, dnsdumpster, securitytrails_api
from .custom import Custom

from lib.core.settings import SUBNAMES, SUBWORIDS, DNS_PATH, SUB_CONFIG
from lib.utils.tools import runtime_format
from lib.utils.getfiles import get_yaml
from lib.utils.log import logger
from lib.utils.thread import threadpool_task
from lib.utils.dns_resolver import DnsResolver


class SubScan(object):
    def __init__(self,) -> None:
        self.brute_scan = SUB_CONFIG['brute_scan']
        self.brute_fuzzy = SUB_CONFIG['brute_fuzzy']
        self.brute_thread = SUB_CONFIG['brute_thread']

        self.target = None
        self.passive_result = list()   # 存被动扫描数据
        self.brute_result = list()   # 存爆破数据
        self.valid_result = list()   # 存最终的域名存活数据
        self.root_generic = list()   # 存根域名泛解析的结果
        self.dnsgen_generic = list()   # 存一级域名泛解析结果

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

    def run_datasets(self, queue_obj: Queue) -> None:
        """ 多线程执行， 解析自定义数据集
       
        :param queue_obj: Queue
        :return:
        """
        dataset = queue_obj.get()
        res: list = Custom(self.target, dataset).run()
        self.passive_result.extend(res)

    def generic_parsing(self, target) -> Optional[list]:
        """
        检测域名泛解析
        :return:
        """
        try:
            domain: str = f"fucktest.{target}"
            # 如果能够成功解析出IP，说明存在泛解析
            answers = dns.resolver.resolve(domain, 'A')
            ip: list = [str(rdata) for rdata in answers]
            logger.warning(f"{target} has universal resolution. Domain names resolved to {ip} are ignored by default.")
            return ip
        except:
            return

    def check_domain_alive(self):
        """
        判断域名存活
        :return:
        """
        logger.info("Running domain validation...")
        # 列表去重, 获取所以被动收集的内容
        passive_result: list = list(set(self.passive_result))
        dns_results = DnsResolver().run(passive_result)
        if dns_results:
            for data in dns_results:
                if self.target in data[0]:
                    self.valid_result.append({
                        'subdomain': data[0],
                        'method': 'passive',
                        'ip': data[1]
                    })
        logger.info(f"Subdomain Passive Scan: {len(self.valid_result)} results found!")

    def brute_(self) -> False:
        """调用爆破模块

        :return: 如果返回False，说明爆破结果无效
        """
        logger.info("Running Subdomain Brute...")
        # 读取一级字典, 清理\n，并拼接子域，处理成 www.domain.com 格式
        with open(SUBNAMES, 'r') as f:
            domains = [f"{line.strip()}.{self.target}" for line in f.readlines()]
        logger.info(f"Number of dictionary：{len(domains)}")
        self.brute_result = brute.Brute().run(domains, self.root_generic, self.brute_thread)
        if self.root_generic and len(self.brute_result) > 1000:
            # 如果存在泛解析，爆破数据超过1000的结果抛弃。
            self.brute_result = list()
            logger.warning(
                "Because the Domain names have universal resolution, and the result exceeded the threshold. "
                "Finally discard the brute result.")
            return False
        # 将被动收集和爆破收集的域名合并，去重复
        self.remove_duplicate()
        return True

    def remove_duplicate(self) -> None:
        """
        去掉重复的域名数据
        :return:
        """
        data: list = [i['subdomain'] for i in self.valid_result]
        for i in self.brute_result:
            if not data.__contains__(i['subdomain']) and set(i['ip']) != set(self.root_generic):
                self.valid_result.append(i)

    def dnsgen_generic_parsing(self, queue_obj: Queue):
        """
        多线程泛解析, 主要为了排除一级域名中存在泛解析的目标。
        :return:
        """
        domain = queue_obj.get()
        if self.generic_parsing(domain):
            self.dnsgen_generic.append(domain)

    def dnsgen_(self):
        """
        进行域名置换，发现更多潜在的子域名
        :return:
        """
        logger.info("Running dnsgen fuzz...")
        print(self.valid_result)
        data: list = [i['subdomain'] for i in self.valid_result]
        # 一级域名泛解析筛选
        threadpool_task(task=self.dnsgen_generic_parsing, queue_data=data)
        logger.debug(f"generic parsing domain name: {self.dnsgen_generic_parsing}")
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
        if domains:
            # 因为之前爆破的数据已经合并了，所以这里可以覆盖掉原来的数据
            self.brute_result = brute.Brute().run(domains, self.root_generic, self.brute_thread)
            # 将原来的有效数据和置换爆破收集的域名合并，去重复
            self.remove_duplicate()
        logger.info("Dnsgen fuzz finished.")

    def show_results(self,) -> None:
        """表格展示数据
        
        :return:
        """
        data: list = self.valid_result
        if not data:
            return
        table = Table(title="subdomain results", show_lines=False)
        table.add_column("subdomain", justify="left", style="cyan", no_wrap=True)
        table.add_column("method", justify="left", style="magenta")
        table.add_column("ip", justify="left", style="red")
        for i in data:
            table.add_row(i['subdomain'], i['method'], str(i['ip']))
        console = Console()
        console.print(table)

    def run(self, target: str) -> list:
        """类统一执行入口
        
        :param target: 目标域名
        :return: list
        """
        start = time()
        task: list = [
            self.google_, self.so_, self.bing_, self.baidu_, self.yandex_, self.sougou_,    # 综合搜索引擎
            self.censys_, self.fullhunt_, self.binaryedge_api_, self.fofa_, self.hunter_, self.zoomeye_,    # 网络空间搜索引擎
            self.virustotal_,   # 威胁情报
            self.dnsdumpster_, self.securitytrails_, self.robtex_,  # DNS数据集
            self.dns_zone_transfer_,    # DNS域传输
        ]
        datasets: list = get_yaml(str(DNS_PATH))
        if self.brute_scan:
            msg: str = f"Brute Scan:{self.brute_scan} | Brute Thread: {self.brute_thread} | Brute Fuzzy: {self.brute_fuzzy}"
        else:
            msg: str = f"Brute Scan:{self.brute_scan}"
        logger.info(f"Current task: SubScan | Target: {target} | Loaded modules: {len(task + datasets)} | {msg}")

        self.target: str = target    # 以前 self.target 用于获取目标域名，写了大量的 self.target 调用，懒得改了。
        threadpool_task(task=self.run_datasets, queue_data=datasets)    # 执行自定义的DNS数据集

        # 线程池执行内置的模块
        def task_run(queue_obj) -> None:
            queue_obj.get()()
        threadpool_task(task=task_run, queue_data=task)

        self.root_generic = self.generic_parsing(target)    # 判断根域名是否存在泛解析
        self.check_domain_alive()   # 域名存活验证

        # 爆破任务
        if self.brute_scan:
            if self.brute_() and self.brute_fuzzy:
                self.dnsgen_()  # 利用字典进行域名置换

        logger.info(f"Subdomain task finished! Total time：{runtime_format(start, time())}")
        logger.info(f"Effective collection quantity：{len(self.valid_result)}")
        self.show_results()
        return self.valid_result

