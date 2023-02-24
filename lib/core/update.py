#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：
"""
from lib.core.logger import logger
from lib.core.settings import QQWRY

from lib.utils.qqwry import updateQQwry

from lib.core.proxy import HttpProxy


__all__ = ['Update', ]


class Update:
    def __init__(self):
        pass

    def update_proxy(self):
        """
        更新代理http_proxy.txt文件
        :return:
        """
        proxy = HttpProxy()
        proxy.update()

    def update_qqwry(self):
        """
        更新qqwry.dat文件
        :return:
        """
        result = updateQQwry(QQWRY)
        if result < 0:
            logger.error("qqwry.dat文件下载失败!")
        else:
            logger.info(f"qqwry.dat已更新: {QQWRY}")

    def run(self):
        self.update_proxy()
        self.update_qqwry()
        logger.warning("数据更新完毕！")
