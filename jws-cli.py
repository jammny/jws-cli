#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 程序入口。
"""
import typer
from rich import print

from lib.core.controller import Option
from lib.core.settings import BANNER
from lib.utils.log import logger
from lib.core.check import CheckAll


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
        raise typer.Exit(code=1)
    # 文件读取目标
    if file:
        with open(file, mode='r', encoding='utf-8') as f:
            tmp: list = f.readlines()
            target_list: list = [i.rstrip("\n").replace(" ", "").rstrip("/") for i in tmp]   # 去掉多余的 \n 空格 /
        if not target_list:
            logger.error('The file is null!')
            raise typer.Exit(code=1)
    else:
        target_list: list = [target.rstrip("/")]
    return target_list


if __name__ == "__main__":
    app = typer.Typer()

    @app.command()
    def main(
            target: str = typer.Option(None, "--target", "-t", help="输入单个目标.", ),
            file: str = typer.Option(None, "--file", "-f", help="从文件中读取目标.", ),
            query: str = typer.Option(None, "--query", "-q", help="接口查询参数.", ),
            auto: bool = typer.Option(False, "--auto", help="自动化扫描."),
            sub: bool = typer.Option(False, "--sub", help="子域名收集."),
            finger: bool = typer.Option(False, "--finger", help="指纹识别."),
            cdn: bool = typer.Option(False, "--cdn", help="CDN识别"),
            port: bool = typer.Option(False, "--port", help="端口扫描."),
            cidr: bool = typer.Option(False, "--cidr", help="C段扫描."),
            waf: bool = typer.Option(False, "--waf", help="waf识别."),
            dir_: bool = typer.Option(False, "--dir", help="目录扫描."),
            poc: bool = typer.Option(False, "--poc", help="poc扫描."),
            fofa: bool = typer.Option(False, "--fofa", help="FOFA接口."),
    ) -> None:
        print(BANNER)   # 输出Banner图案
        target_list: list = args_check(target, file, query)  # 必要参数检测
        CheckAll().run()    # 程序兼容性检测
        if auto:
            Option.args_auto(target_list)  # 自动化扫描
        elif fofa:
            Option.args_fofa(query, finger, poc)  # fofa接口调用
        elif sub:
            Option.args_sub(target_list)  # 子域名收集
        elif finger:
            Option.args_finger(target_list)  # 指纹识别
        elif cdn:
            Option.args_cdn(target_list)  # CDN识别
        elif port:
            Option.args_port(target_list)  # 端口扫描
        elif cidr:
            Option.args_cidr(target_list)  # C段扫描
        elif waf:
            Option.args_waf(target_list)  # waf扫描
        elif dir_:
            Option.args_dir(target_list)  # 目录扫描
        elif poc:
            Option.args_poc(target_list)  # POC扫描
    app()
