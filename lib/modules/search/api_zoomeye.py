#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述：ZoomEye API接口调用
"""
from typing import Optional, Set

from httpx import Client, Response

from lib.modules.search.api_base import ApiBase
from lib.core.log import logger
from lib.utils.tools import match_subdomains


class ZoomEye(ApiBase):
    def __init__(self, query: str, domain: str) -> None:
        super().__init__()
        self.name: str = "ZoomEye"
        self.query: str = query
        self.domain: str = domain
        self.page_size: int = 20    # 每页返回的最大检索数
        self.size: int = self.config['zoomeye_size']    # 配置文件设定的最大检索值

    def login(self) -> Optional[str]:
        """登陆获取用户token

        :return: 返回jwt信息
        """
        username: str = self.config['zoomeye_mail']
        password: str = self.config['zoomeye_pass']
        name: str = self.name
        url: str = "https://api.zoomeye.org/user/login"
        try:
            with Client(verify=False) as c:
                response: Response = c.post(url=url, json={
                    'username': username, 'password': password
                })
                if response.status_code == 200:
                    data: dict = response.json()
                    access_token: str = data.get('access_token')
                    logger.info(f"{name} login success!")
                    return access_token
                else:
                    logger.error(f"{name} login failed! {response} {response.text}")
                    return
        except Exception as e:
            logger.error(f"{name} login failed! {url} {e}")
            return

    def get_domain(self) -> Set[str]:
        """域名收集调用

        :return: 返回包含域名的列表
        """
        name = self.name
        domain: str = self.domain
        size: int = self.size
        page_size: int = self.page_size
        url: str = f"https://api.zoomeye.org/domain/search?q={domain}&type=1&page=[page]"  # [page] 用于动态修改页数
        logger.info(f"Running {name}...")

        # 获取用户jwt口令, 判断是否登陆成功 #
        jwt: Optional[str] = self.login()
        if not jwt:
            return self.result_domain
        else:
            self.headers['Authorization'] = f"JWT {jwt}"

        # 先获取一页，看看检索出多少数据 #
        new_url: str = url.replace("[page]", "1")
        try:
            response_json: Optional[dict] = self.send_request(new_url)
        except Exception as e:
            logger.error(f"{name} connect error! {url} {e}")
            return self.result_domain

        if not response_json:
            return self.result_domain

        # 正则提取页面中域名
        self.result_domain: Set['str'] = match_subdomains(domain, str(response_json))

        # 根据搜索出的检索量和设定配置，循环遍历页数 #
        try:
            total: int = response_json['total']
            page: int = self.get_page(total, size, page_size)
            self.circular_process(page, url, domain)
        except Exception as e:
            logger.error(f"{response_json} {e}")

        logger.info(f"{name}：{len(self.result_domain)} results found!")
        logger.debug(f"{name}：{self.result_domain}")
        return self.result_domain

    def run(self):
        pass
