#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 
"""
import subprocess
from typing import Set

from rich.progress import Progress

from lib.core.settings import THIRDPARTY_APP


def ksubdomain(dic, domain) -> Set[str]:
    """

    :param dic:
    :param domain:
    :return:
    """
    app = THIRDPARTY_APP['ksubdomain']
    command = f"{app} e -d {domain} -f {dic} -skip-wild --silent --only-domain"

    with Progress(transient=True) as progress:
        task = progress.add_task("[red]Brute...", start=False, total=None)
        status, result = subprocess.getstatusoutput(command)
        progress.update(task, advance=100)

    if status != 0:
        return set()

    subdomain: set = set(result.split("\n"))
    subdomain.discard('')
    return subdomain
