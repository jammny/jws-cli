#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：jammny
文件描述： 
"""
from rich.console import Console
from rich.table import Table


def show_table(data):
    """
    表格展示数据
    :param: data
    :return:
    """
    table = Table(title="ports results", show_lines=False)
    table.add_column("target", justify="left", style="cyan", no_wrap=True)
    table.add_column("port", justify="left", style="magenta")
    table.add_column("service", justify="left", style="red")
    table.add_column("banner", justify="left", style="red")
    for i in data:
        table.add_row(i['target'], (i['port']), i['service'], (i['banner']))
    console = Console()
    console.print(table)
