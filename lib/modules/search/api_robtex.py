#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：通过robtex查询域名的dns解析记录，收集其中的域名信息。如果是['A', 'AAAA']记录，那么需要提取IP，然后再反查IP的域名解析。
"""
from time import sleep
from typing import Optional, Set

from lib.modules.search.api_base import ApiBase
from lib.core.log import logger
from lib.utils.tools import match_subdomains, match_ip


class Robtex(ApiBase):

    def __init__(self, domain: str) -> None:
        super().__init__()
        self.name: str = "Robtex"
        self.domain: str = domain
        self.result_domain: set = set()
        self.url: str = f"https://freeapi.robtex.com/pdns/forward/{self.domain}"

    def get_domain(self) -> Set[str]:
        """获取域名数据

        :return:
        """
        name: str = self.name
        domain: str = self.domain
        url: str = self.url
        logger.info(f"Running {name}...")

        try:
            response_body: Optional[str] = self.send_request(url, api=False)
        except Exception as e:
            logger.error(f"{name} connect error! {url} {e}")
            return self.result_domain

        if not response_body:
            return self.result_domain

        self.result_domain: Set[str] = match_subdomains(domain, response_body)

        # 提取IP地址 #
        ip_set: set = match_ip(response_body)
        if not ip_set:
            return self.result_domain

        for ip in ip_set:
            sleep(1)
            new_url = f"https://freeapi.robtex.com/pdns/reverse/{ip}"
            try:
                response_body: Optional[str] = self.send_request(url=new_url)
            except Exception as e:
                logger.error(f"{name} connect error! {new_url} {e}")
                break

            result_domain: Set[str] = match_subdomains(domain, response_body)
            self.result_domain = self.result_domain.union(result_domain)

        logger.info(f"{name}：{len(self.result_domain)} results found!")
        logger.debug(f"{name}：{self.result_domain}")
        return self.result_domain
