#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 
"""
from time import time

from rich.console import Console
from rich.table import Table

from lib.utils.log import logger
from .aqc import Aqc


class FirmScan(object):
    def show_icp(self, data):
        """表格展示ICP备案信息

        :param: data
        :return:
        """
        if not data:
            return
        table = Table(title="ICP Info", show_lines=False)
        table.add_column("domain", justify="left", style="cyan", no_wrap=True)
        table.add_column("homeSite", justify="left", style="magenta")
        table.add_column("siteName", justify="left", style="red")
        table.add_column("icpNo", justify="left", style="red")
        for i in data:
            table.add_row(str(i['domain']), str(i['homeSite']), str(i['siteName']), str(i['icpNo']))
        console = Console()
        console.print(table)

    def show_copyright(self, data):
        """

        :param data:
        :return:
        """
        if not data:
            return
        table = Table(title="Copyright Info", show_lines=False)
        table.add_column("softwareName", justify="left", style="cyan", no_wrap=True)
        table.add_column("batchNum", justify="left", style="magenta")
        table.add_column("softwareWork", justify="left", style="red")
        table.add_column("softwareType", justify="left", style="red")
        for i in data:
            table.add_row(str(i['softwareName']), str(i['batchNum']), str(i['softwareWork']), str(i['softwareType']))
        console = Console()
        console.print(table)

    def show_basicData(self, data):
        """

        :param data:
        :return:
        """
        if not data:
            return
        table = Table(title="BasicData Info", show_lines=False)
        table.add_column("entName", justify="left", style="cyan", no_wrap=True)
        table.add_column("openStatus", justify="left", style="magenta")
        table.add_column("legalPerson", justify="left", style="red")
        table.add_column("regCapital", justify="left", style="red")
        table.add_row(str(data['entName']), str(data['openStatus']), str(data['legalPerson']), str(data['regCapital']))
        console = Console()
        console.print(table)

    def show_investRecordData(self, data):
        """

        :param data:
        :return:
        """
        if not data:
            return
        table = Table(title="InvestRecordData Info", show_lines=False)
        table.add_column("entName", justify="left", style="cyan", no_wrap=True)
        table.add_column("legalPerson", justify="left", style="magenta")
        table.add_column("regRate", justify="left", style="red")
        table.add_column("regCapital", justify="left", style="red")
        for i in data:
            table.add_row(str(i['entName']), str(i['legalPerson']), str(i['regRate']), str(i['regCapital']))
        console = Console()
        console.print(table)

    def show_shareholdersData(self, data):
        """

        :param data:
        :return:
        """
        if not data:
            return
        table = Table(title="ShareholdersData Info", show_lines=False)
        table.add_column("pid", justify="left", style="cyan", no_wrap=True)
        table.add_column("name", justify="left", style="magenta")
        table.add_column("subRate", justify="left", style="red")
        table.add_column("subMoney", justify="left", style="red")
        for i in data:
            table.add_row(str(i['pid']), str(i['name']), str(i['subRate']), str(i['subMoney']))
        console = Console()
        console.print(table)

    def run(self, target_list):
        start: float = time()
        logger.info(f"Current task: FirmScan | Target numbers: {len(target_list)}")
        for target in target_list:
            logger.info(f"Current keyword: {target}")
            results = Aqc().run(target)
            self.show_basicData(results['basicData'])
            self.show_icp(results['icpInfo'])
            self.show_investRecordData(results['investRecordData'])
            self.show_shareholdersData(results['shareholdersData'])
            self.show_copyright(results['copyright'])
