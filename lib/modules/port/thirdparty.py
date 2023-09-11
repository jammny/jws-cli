#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 
"""
import re
import subprocess
from typing import Set

from rich.progress import Progress

from lib.core.settings import THIRDPARTY_APP
from lib.core.log import logger


def nimscan(host) -> Set['int']:
    """调用nimscan完成全端口扫描"""
    logger.info("Running nimscan...")
    app = THIRDPARTY_APP['nimscan']
    command = f'ulimit -n 5500;{app} -i {host}'     # 默认扫全端口

    with Progress(transient=True) as progress:
        task = progress.add_task("[red]Scanning...", start=False, total=None)
        status, res = subprocess.getstatusoutput(command)
        progress.update(task, advance=100)

    open_port = set()
    if status == 0 and 'Open' in res:
        list_1 = res.split('==> ')
        for i in list_1:
            if 'Open' in i:
                a = re.sub("\x1b.*?m", '', i)
                b = re.sub("Open", '', a)
                c = b.split(' \n')[0]
                port = c.split(":")[1]
                open_port.add(int(port))
    return open_port
