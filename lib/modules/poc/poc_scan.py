#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 
"""
from lib.modules.poc.thirdparty import afrog
from lib.core.log import logger


class PocScan:
    def __init__(self, engine):
        self.engine = engine
        self.poc_results = []

    def run(self, targets_list: list, target=None):
        """

        :param target: 自动化扫描的时候，传入域名。
        :param targets_list:
        :return:
        """
        logger.info(f"Current task: PocScan | Target number: {len(targets_list)} | Engine: afrog")
        engine = self.engine
        if engine == "afrog":
            self.poc_results = afrog(targets_list, target)

        return self.poc_results
