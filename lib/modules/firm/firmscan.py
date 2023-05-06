#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 
"""
import pandas as pd

from rich.console import Console
from rich.table import Table

from lib.utils.log import logger
from .aqc import Aqc
from ...core.settings import REPORTS


class FirmScan(object):
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
        logger.info(f"Current task: FirmScan | Target numbers: {len(target_list)}")
        for target in target_list:
            logger.info(f"Current keyword: {target}")
            results = Aqc().run(target)
            if not results:
                logger.info(f"{target} information not found")
                return
            basicData = results['basicData']
            entName = basicData['entName']

            self.show_basicData(basicData)
            icpInfo = results['icpInfo']
            self.show_icp(icpInfo)
            copyright_ = results['copyright']
            self.show_copyright(copyright_)
            investRecordData = results['investRecordData']
            self.show_investRecordData(investRecordData)
            shareholdersData = results['shareholdersData']
            self.show_shareholdersData(shareholdersData)
            file = f"{REPORTS}/{entName}.xlsx"
            wirte_xlsx(file, basicData, icpInfo, copyright_, investRecordData, shareholdersData)
            logger.info(f"Output: {file}")


def wirte_xlsx(file, basicData, icpInfo, copyright_, investRecordData, shareholdersData):
    """

    :param entName:
    :param basicData:
    :param icpInfo:
    :param copyright_:
    :param investRecordData:
    :param shareholdersData:
    :return:
    """
    with pd.ExcelWriter(file) as writer:
        if basicData:
            entName = [basicData['entName']]
            openStatus = [basicData['openStatus']]
            legalPerson = [basicData['legalPerson']]
            regCapital = [basicData['regCapital']]
            scope = [basicData['scope']]
            res1 = {
                "企业名称": entName,
                "营业状态": openStatus,
                "法人": legalPerson,
                "注册资金": regCapital,
                "简介": scope,
            }
            pd.DataFrame(res1).to_excel(writer, sheet_name='基本信息', index=False)

        if icpInfo:
            domain = []
            siteName = []
            homeSite = []
            icpNo = []
            for i in icpInfo:
                domain.append(",".join(i['domain']))
                siteName.append(i['siteName'])
                homeSite.append(",".join(i['homeSite']))
                icpNo.append(i['icpNo'])
            res2 = {
                "域名": domain,
                "网站名": siteName,
                "主页": homeSite,
                "备案号": icpNo
            }
            pd.DataFrame(res2).to_excel(writer, sheet_name='ICP备案', index=False)

        if copyright_:
            softwareName = []
            batchNum = []
            softwareWork = []
            softwareType = []
            for i in copyright_:
                softwareName.append(i['softwareName'])
                batchNum.append(i['batchNum'])
                softwareWork.append(i['softwareWork'])
                softwareType.append(i['softwareType'])
            res3 = {
                "软件名": softwareName,
                "网站名": batchNum,
                "主页": softwareWork,
                "备案号": softwareType
            }
            pd.DataFrame(res3).to_excel(writer, sheet_name='软件著作信息', index=False)

        if investRecordData:
            entName = []
            legalPerson = []
            regRate = []
            regCapital = []
            for i in investRecordData:
                entName.append(i['entName'])
                legalPerson.append(i['legalPerson'])
                regRate.append(i['regRate'])
                regCapital.append(i['regCapital'])
            res4 = {
                "企业名称": entName,
                "法人": legalPerson,
                "控股比例": regRate,
                "投资资金": regCapital,
            }
            pd.DataFrame(res4).to_excel(writer, sheet_name='对外投资', index=False)

        if shareholdersData:
            pid = []
            name = []
            subRate = []
            subMoney = []
            for i in shareholdersData:
                pid.append(i['pid'])
                name.append(i['name'])
                subRate.append(i['subRate'])
                subMoney.append(i['subMoney'])
            res5 = {
                "PID": pid,
                "企业/个人": name,
                "持股比例": subRate,
                "投资资金": subMoney,
            }
            pd.DataFrame(res5).to_excel(writer, sheet_name='股东信息', index=False)