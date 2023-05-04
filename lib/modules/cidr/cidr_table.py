#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 表格展示
"""
from rich.console import Console
from rich.table import Table


def show_table(tmp_results: list):
    """

    表格展示数据
    :return:
    """
    data = tmp_results
    table = Table(title="cdn results", show_lines=False)
    table.add_column("ip", justify="left", style="cyan", no_wrap=True)
    table.add_column("port", justify="left", style="magenta")
    table.add_column("protocol", justify="left", style="red")
    for i in data:
        table.add_row(i['ip'], i['port'], i['protocol'])
    console = Console()
    console.print(table)
