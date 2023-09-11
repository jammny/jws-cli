#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 加载内置模块的函数
"""
from lib.modules.search.api_binaryedge import Binaryedge
from lib.modules.search.api_censys import Censys
from lib.modules.search.api_fofa import Fofa
from lib.modules.search.api_fullhunt import Fullhunt
from lib.modules.search.api_hunter import Hunter
from lib.modules.search.api_quake import Quake
from lib.modules.search.api_securitytrails import Securitytrails
from lib.modules.search.api_zero import Zero
from lib.modules.search.api_zoomeye import ZoomEye
from lib.modules.search.api_dnsdumpster import Dnsdumpster
from lib.modules.search.api_robtex import Robtex
from lib.modules.search.api_virustotal import Virustotal
from lib.modules.sub.vulnerability.dns_zone_transfer import AXFR


def dns_zone_transfer_(domain: str) -> set:
    """域传输漏洞检测"""
    return AXFR(domain).run()


def dnsdumpster_(domain: str) -> set:
    return Dnsdumpster(domain).get_domain()


def robtex_(domain: str) -> set:
    return Robtex(domain).get_domain()


def virustotal_(domain: str) -> set:
    return Virustotal(domain).get_domain()


def fofa_(domain: str) -> set:
    query: str = f'domain="{domain}"&&(protocol="http"||protocol="https")'
    return Fofa(query, domain).get_domain()


def zoomeye_(domain: str) -> set:
    return ZoomEye(query=f"{domain}", domain=domain).get_domain()


def hunter_(domain: str) -> set:
    return Hunter(query=f'domain.suffix="{domain}"&&(protocol="http"||protocol="https")', domain=domain).get_domain()


def binaryedge_(domain: str) -> set:
    return Binaryedge(domain).get_domain()


def securitytrails_(domain: str) -> set:
    return Securitytrails(domain).get_domain()


def fullhunt_(domain: str) -> set:
    return Fullhunt(domain).get_domain()


def censys_(domain: str) -> set:
    return Censys(domain).get_domain()


def quake_(domain: str) -> set:
    return Quake(query=f"domain: {domain} AND service: http", domain=domain).get_domain()


def zero_(domain: str) -> set:
    return Zero(query=f'url=={domain}&&(service=http||service=https)', domain=domain).get_domain()