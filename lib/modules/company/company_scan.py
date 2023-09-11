#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 
"""
from typing import List

from lib.core.log import logger
from lib.modules.company.icp import ICP


class CompanyScan(object):
    def run(self, company_name) -> List[str]:
        logger.info(f"[g]| Current task: CompanyScan | Name: {company_name} |[/g]")
        results = ICP().run(company_name)
        return results
