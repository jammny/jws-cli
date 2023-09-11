#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 程序入口。
"""
from typer import Typer, Option

from lib.core.log import console
from lib.core.settings import BANNER
from lib.core.check import CheckAll, args_check
from lib.core.controller import Router
from lib.modules.company.company_scan import CompanyScan

app = Typer()


@app.command()
def main(
        target: str = Option(None, "--target", "-t", help="目标根域名/URL链接"),
        query: str = Option(None, "--query", "-q", help="空间搜索引擎语法"),
        file: str = Option(None, "--file", "-f", help="批量扫描, 多个目标之间需要换行分隔"),
        company: str = Option(None, "--company", "-c", help='企业全称：python jws-cli.py -c "企业全称" --auto'),

        auto: bool = Option(False, "--auto", help="自动化扫描: python jws-cli.py -t example.com --auto"),
        finger: bool = Option(False, "--finger",
                              help="WEB指纹识别: python jws-cli.py -t https://example.com --finger"),
        sub: bool = Option(False, "--sub",
                           help="子域名收集: python jws-cli.py -t example.com --sub [可选：--finger]"),
        port: bool = Option(False, "--port",
                            help="端口扫描: python jws-cli.py -t 192.168.2.1 --port [可选：--finger]"),
        cidr: bool = Option(False, "--cidr",
                            help="C端扫描: python jws-cli.py -t 192.168.2.1 --cidr [可选：--finger]"),
        poc: bool = Option(False, "--poc",
                           help="POC扫描: python jws-cli.py -t https://example.com --poc"),
        fofa: bool = Option(False, "--fofa",
                            help='FOFA搜集: python jws-cli.py -q "fofa语法" --fofa [可选：--poc]'),
) -> None:
    console.print(BANNER)  # 输出Banner图案
    targets_list: list = args_check(target, file, query, company)  # 返回需要扫描的目标列表
    check = CheckAll()
    check.run()   # 程序兼容性检测

    router = Router(targets_list)
    if query and fofa:
        Router.args_fofa(query, poc)  # fofa接口调用
    elif company and auto:
        domain_list = CompanyScan().run(company)
        if domain_list:
            r = Router(domain_list)
            r.args_auto()  # 自动化扫描
    elif auto:
        router.args_auto()  # 自动化扫描
    elif sub:
        router.args_sub(finger)   # 域名收集
    elif port:
        router.args_port(finger)  # 端口扫描
    elif cidr:
        router.args_cidr(finger)  # C段扫描
    elif finger:
        router.args_finger()  # 指纹识别
    elif poc:
        router.args_poc()  # POC扫描


if __name__ == "__main__":
    app()



