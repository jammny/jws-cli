#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：jammny
文件描述： ArchiveCrawl国内网络访问不了。
"""
import time

import cdx_toolkit

from lib.core.logger import logger
from lib.utils.format import match_subdomains


class ArchiveCrawl:
    def __init__(self, domain):
        self.domain = domain
        self.results = set()

    def get_domain(self):
        """

        :return:
        """
        cdx = cdx_toolkit.CDXFetcher(source='ia')
        url = f'*.{self.domain}/*'
        logger.debug(url, 'size estimate', cdx.get_size_estimate(url))
        for resp in cdx.iter(url, limit=50):
            if resp.data.get('status') not in ['301', '302']:
                # url = resp.data.get('url')
                # print(url + resp.text)
                res = match_subdomains(self.domain, resp.text)
                self.results.update(res)

    def run(self):
        logger.info("Running ArchiveCrawl...")
        s = time.time()
        self.get_domain()
        results = list(self.results)
        e = time.time()
        if results:
            logger.info(f"ArchiveCrawl：{len(results)} results found!")
            logger.debug(f"ArchiveCrawl：{results}")
            logger.debug(f"{e - s}")
        return results


if __name__ == '__main__':
    ArchiveCrawl("archive-it.org").run()
