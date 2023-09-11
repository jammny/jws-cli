#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 
"""
from os import system

from pathlib import Path
from typing import Optional

from lib.core.settings import TMP, THIRDPARTY_APP
from lib.utils.encrypt import GetKey
from lib.utils.file import read_json_file, write_txt
from lib.core.log import logger


def make_dir(target: Optional[str]) -> tuple:
    """创建目录

    :param target: 自动化扫描时候的目标
    :return:
    """
    path_name: str = target if target else GetKey().random_key(5)
    new_path = TMP / path_name
    if not new_path.exists():
        Path.mkdir(new_path)
    return path_name, new_path


def afrog(target_list: list, target=None) -> list:
    """afrog漏洞扫描

    :param target_list: 待扫描的目标列表
    :param target: 自动化扫描时候的目标
    :return:
    """
    poc_results: list = []

    # 将需要扫描的URL写入指定目录下的txt文件，用于afrog读取 #
    path_name, new_path = make_dir(target)
    target_path: str = f"{new_path}/poc_targets.txt"
    write_status: bool = write_txt(target_path, target_list)

    if not write_status:
        return poc_results

    app: str = THIRDPARTY_APP['afrog']
    output: str = f"{new_path}/poc_afrog"
    command: str = f"{app} -T {target_path} -o {output}.html -j {output}.json"
    system(command)
    res: list = read_json_file(output)
    if res:
        afrog_results: list = read_json_file(output)
        logger.info(f"Output: {output}")
        for i in afrog_results:
            poc_results.append({
                'id': i['pocinfo']['id'],
                'name': i['pocinfo']['infoname'],
                'seg': i['pocinfo']['infoseg'],
                'url': i['fulltarget'],
                'description': i['pocinfo']['infodescription'],
            })
    return poc_results
