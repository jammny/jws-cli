#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： DNS解析
"""
import asyncio
from queue import Queue

import dns

from lib.utils.thread import threadpool_task


class DnsResolver(object):
    def __init__(self):
        self.dns_results = []

    def resolve_dns(self, queue_obj: Queue) -> None:
        try:
            hostname: str = queue_obj.get()
            answers = dns.resolver.resolve(hostname, 'A')
            ip: list = [str(rdata) for rdata in answers]
            self.dns_results.append((hostname, ip))
        except:
            pass

    def run(self, targets_list: list) -> list:
        threadpool_task(task=self.resolve_dns, queue_data=targets_list)
        return self.dns_results



class AsyncDnsResolver(object):
    """异步批量DNS解析, 在windwos系统下解析IP正常，在linux下解析会出现IPV6的格式。。。

    """
    async def resolve_dns(self, hostname):
        try:
            loop = asyncio.get_event_loop()
            result: list = await loop.getaddrinfo(hostname, 80, family=0, type=0, proto=0, flags=0)
            # print(hostname, result)
            return hostname, result
        except:
            return hostname, None

    async def main(self, domains):
        tasks = [asyncio.create_task(self.resolve_dns(hostname)) for hostname in domains]
        results = await asyncio.gather(*tasks)
        return results


if __name__ == "__main__":
    app = AsyncDnsResolver()
    targets = ['www.python.org', 'jammmny.com', 'baidu.com']
    print(asyncio.run(app.main(targets)))
