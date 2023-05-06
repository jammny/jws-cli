#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 程序入口。
"""
try:
    from typer import Exit, Typer, Option
    from rich import print
    from lib.core.controller import Router
    from lib.core.settings import BANNER
    from lib.utils.log import logger
    from lib.core.check import CheckAll
except NameError:
    import sys
    import os
    print("Lack of python dependencies, try automatic installation.")
    os.system("pip3 install -r requirements.txt")
    print("Now you can try restarting the program.")
    sys.exit(3)


def args_check(target: str, file: str, query: str) -> list:
    """参数检查

    :param target: 目标域名
    :param file: 本地文件
    :param query: fofa查询语句
    :raises typer.Exit: 没有必要参数 退出
    :raises typer.Exit: 如果文件为null 退出
    :return: 包含目标域名的列表
    """
    if not (target or file or query):
        print('You need to provide the args, enter "--help" for help!')
        raise Exit(code=1)
    # 文件读取目标
    if file:
        with open(file, mode='r', encoding='utf-8') as f:
            tmp: list = f.readlines()
            target_list: list = [i.rstrip("\n").replace(" ", "").rstrip("/") for i in tmp]  # 去掉多余的 \n 空格 /
        if not target_list:
            logger.error('The file is null!')
            raise Exit(code=1)
    else:
        target_list: list = [target.rstrip("/")]
    return target_list


if __name__ == "__main__":
    app = Typer()

    @app.command()
    def main(
            target: str = Option(None, "--target", "-t", help="扫描单个目标.", ),
            file: str = Option(None, "--file", "-f", help="从文件中读取目标.", ),
            query: str = Option(None, "--query", "-q", help="接口查询参数.", ),
            auto: bool = Option(False, "--auto", help="自动化扫描: python jws-cli.py -t example.com --auto"),
            sub: bool = Option(False, "--sub", help="子域名收集: python jws-cli.py -t example.com --sub"),
            finger: bool = Option(False, "--finger", help="指纹识别: python jws-cli.py -t https://example.com --finger"),
            cdn: bool = Option(False, "--cdn", help="CDN识别: python jws-cli.py -t example.com --cdn"),
            port: bool = Option(False, "--port", help="端口扫描: python jws-cli.py -t 127.0.0.1 --port"),
            cidr: bool = Option(False, "--cidr", help="C段扫描: python jws-cli.py -t 192.168.1.0/24 --cidr"),
            waf: bool = Option(False, "--waf", help="waf识别: python jws-cli.py -t https://example.com --waf"),
            dir_: bool = Option(False, "--dir", help="目录扫描: python jws-cli.py -t https://example.com --dir"),
            poc: bool = Option(False, "--poc", help="poc扫描: python jws-cli.py -t https://example.com --poc"),
            fofa: bool = Option(False, "--fofa", help="FOFA接口: python jws-cli.py -q [FOFA语法] --fofa --finger/--poc"),
    ) -> None:
        print(BANNER)  # 输出Banner图案
        target_list: list = args_check(target, file, query)  # 必要参数检测
        CheckAll().run()  # 程序兼容性检测
        if auto:
            Router.args_auto(target_list)  # 自动化扫描
        elif fofa:
            Router.args_fofa(query, finger, poc)  # fofa接口调用
        elif sub:
            Router.args_sub(target_list)  # 子域名收集
        elif finger:
            Router.args_finger(target_list)  # 指纹识别
        elif cdn:
            Router.args_cdn(target_list)  # CDN识别
        elif port:
            Router.args_port(target_list)  # 端口扫描
        elif cidr:
            Router.args_cidr(target_list)  # C段扫描
        elif waf:
            Router.args_waf(target_list)  # waf扫描
        elif dir_:
            Router.args_dir(target_list)  # 目录扫描
        elif poc:
            Router.args_poc(target_list)  # POC扫描
    app()
