#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： fofa调用程序
"""
from queue import Queue

from lib.modules.search.api_fofa import Fofa
from lib.core.log import logger
from lib.utils.thread import threadpool_task


class CidrFofa(object):
    def __init__(self):
        self.cidr_results = []

    def fofa_request(self, queue: Queue):
        """使用fofa api 来收集C段信息

        :return:
        """
        cidr = queue.get()
        query: str = f'ip="{cidr}"&&(protocol="http"||protocol="https")'
        fofa_results: dict = Fofa(query).run()
        tmp_results = [{"cidr": cidr, "host": item[2], "port": item[3], "protocol": item[4], "banner": item[6][:20]}
                       for item in fofa_results]
        self.cidr_results += tmp_results

    def run(self, cidr: list) -> list:
        """类执行入口

        :param cidr: 目标cidr格式的列表
        :return:
        """
        logger.info("Trying to use fofa.")
        threadpool_task(task=self.fofa_request, queue_data=cidr, thread_count=1)
        return self.cidr_results


if __name__ == "__main__":
    pass
