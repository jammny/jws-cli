#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 
"""
from lib.core.log import logger
from lib.modules.company.aqc import Aqc


class CompanyScan(object):
    def run(self, target_list):
        logger.info(f"Current task: CompanyScan | Target numbers: {len(target_list)}")
        target = target_list[0]
        logger.info(f"Current keyword: {target}")
        results = Aqc().run(target)
        if not results:
            logger.info(f"{target} information not found")
            return
        return results
