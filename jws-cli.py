#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：https://github.com/jammny
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 程序入口。
"""
import sys

import typer
import colorama

from lib.core.controller import Option
from lib.core.settings import BANNER
from lib.core.logger import logger
from lib.core.check import CheckAll


if __name__ == "__main__":
    colorama.init(autoreset=True)  # 初始化
    app = typer.Typer()

    @app.command()
    def main(
            target: str = typer.Option(None, "--target", "-t", help="输入单个目标(必要参数).", ),
            file: str = typer.Option(None, "--file", "-f", help="从文件中读取目标(必要参数).", ),
            auto: bool = typer.Option(False, "--autoscan", "--auto", help="自动化扫描."),
            sub: bool = typer.Option(False, "--subdomain", "--sub", help="子域名收集."),
            brute: bool = typer.Option(False, "--brute", help="域名爆破模式."),
            finger: bool = typer.Option(False, "--finger", help="指纹识别."),
            cdn: bool = typer.Option(False, "--cdn", help="指纹识别."),
            port: bool = typer.Option(False, "--port", help="端口扫描."),
            cidr: bool = typer.Option(False, "--cidr", help="C段扫描."),
            waf: bool = typer.Option(False, "--waf", help="waf识别."),
            dir_: bool = typer.Option(False, "--dir", help="目录扫描."),
            poc: bool = typer.Option(False, "--poc", help="poc扫描."),
            xray: bool = typer.Option(False, "--xray", help="xray扫描."),
    ) -> None:
        # 输出Banner图案
        sys.stdout.write(BANNER)
        # 程序兼容性检测
        check = CheckAll()
        check.run()
        # 必要参数检测
        task = Option()
        if target is None and file is None:
            logger.error('You need to provide the target！')
            logger.warning('TIPS：Enter "--help" for help')
            raise typer.Exit(code=1)
        # 文件读取目标
        if file:
            with open(file, mode='r', encoding='utf-8') as f:
                tmp: list = f.readlines()
                # 去掉\n
                target_list: list = [i.rstrip("\n") for i in tmp]
            if target_list is []:
                logger.error('The file is null！')
                raise typer.Exit(code=1)
        else:
            target_list: list = [target]
        # 开始任务
        if auto:
            task.args_auto(target_list, brute)  # 自动化扫描
        elif sub:
            task.args_sub(target_list, brute)  # 子域名收集
        elif finger:
            task.args_finger(target_list)  # 指纹识别
        elif cdn:
            task.args_cdn(target_list)  # 指纹识别
        elif port:
            task.args_port(target_list)  # 端口扫描
        elif cidr:
            task.args_cidr(target_list)  # C段扫描
        elif waf:
            task.args_waf(target_list)  # waf扫描
        elif dir_:
            task.args_dir(target_list)  # 目录扫描
        elif poc:
            task.args_poc(target_list)  # POC扫描
        elif xray:
            task.args_xray(target_list)  # Xray扫描
    app()
