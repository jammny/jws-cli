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

    :return:
    """
    table = Table(title="finger results", show_lines=False)
    table.add_column("url", justify="left", style="cyan", no_wrap=True)
    table.add_column("title", justify="left", style="magenta")
    table.add_column("cms", justify="left", style="red")
    table.add_column("code", justify="left", style="green")
    table.add_column("ico_hash", justify="left", style="green")
    for i in data:
        table.add_row(i['url'], i['title'], i['cms'], i['code'], i['ico_hash'])
    console = Console()
    console.print(table)
