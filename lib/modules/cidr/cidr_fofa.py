#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： fofa调用程序
"""
from queue import Queue

from .cidr_table import show_table

from lib.modules.sub.search.fofa_api import Fofa

from lib.utils.log import logger
from lib.utils.thread import threadpool_task


class CidrFofa(object):
    def __init__(self):
        self.cidr_results = []

    def fofa_request(self, queue: Queue):
        """使用fofa api 来收集C段信息

        :return:
        """
        cidr = queue.get()
        logger.info(f"Scanner {cidr}...")
        query: str = f'ip="{cidr}"'
        response: dict = Fofa(query).send_request()
        if response['error']:
            logger.warning(f"Fofa Api is error！{response}")
        elif response['size'] == 0:
            logger.warning(f"No information related to the {response['query']} was found!")
        else:
            logger.info(f"FOFA Query：{response['query']} , {response['size']} results found!")
            results = response['results']
            tmp_results = [{"cidr": cidr, "ip": item[2], "port": item[3], "protocol": item[4]} for item in results]
            # show_table(tmp_results)
            self.cidr_results += tmp_results

    def run(self, cidr: list) -> list:
        """类执行入口

        :param cidr: 目标cidr格式的列表
        :return:
        """
        logger.info("trying to use fofa api...")
        threadpool_task(task=self.fofa_request, queue_data=cidr, thread_count=1)
        return self.cidr_results


if __name__ == "__main__":
    pass
