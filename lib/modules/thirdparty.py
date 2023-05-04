#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 第三方控制模块
"""
import json
from os import system
from pathlib import Path
from typing import Union

from lib.core.settings import TMP, MOD, DIR_CONFIG
from lib.utils.encrypt import GetKey
from lib.utils.log import logger

__all__ = ['afrog', 'ffuf', 'wafw00f']


def read_jsonfile(path: str) -> Union[list, dict, None]:
    """读json文件内容

    :param path: 文件路径
    :return:
    """
    try:
        with open(path, mode='r', encoding="utf-8") as f:
            json_data: Union[list, dict] = json.load(f)
        return json_data
    except:
        return


def make_dir(target: Union[str, None]) -> tuple:
    """创建目录

    :param target: 自动化扫描时候的目标
    :return:
    """
    path_name: str = target if target else GetKey().random_key(5)
    new_path: Path = TMP / path_name
    if not new_path.exists():
        Path.mkdir(new_path)
    return path_name, new_path


def write_file(path: str, data: list) -> bool:
    """写入目标文件

    :param path: 文件路径
    :param data: 写入数据
    :return:
    """
    try:
        with open(path, mode="w", encoding="utf-8") as f:
            f.write("\n".join(data))
        return True
    except Exception as e:
        logger.error(f"Output file write failure possible disk full. {e}")
        return False


def ffuf(target_list: list, target=None) -> list:
    """ffuf目录扫描

    :param target_list: 待扫描的目标列表
    :param target: 自动化扫描时候的目标
    :return:
    """
    dir_results: list = []
    args = ""
    mc = DIR_CONFIG['match_code']
    fc = DIR_CONFIG['filter_code']  # 响应中过滤HTTP状态码
    fl = DIR_CONFIG['filter_lines']  # 响应中过滤HTTP状态码
    threads = DIR_CONFIG['threads']  # 线程数
    fs = DIR_CONFIG['filter_size']
    fw = DIR_CONFIG['filter_world']
    fr = DIR_CONFIG['filter_regexp']
    if threads:
        args += f"-t {threads} "
    if mc:
        args += f"-mc {mc} "
    if fc:
        args += f"-fc {fc} "
    if fl:
        args += f"-fc {fl} "
    if fw:
        args += f"-fw {fw} "
    if fs:
        args += f"-fs {fs} "
    if fr:
        args += f"-fr {fr} "

    logger.info(
        f"Current task: DirScan | Target number: {len(target_list)} | Engine: ffuf(https://github.com/ffuf/ffuf)")
    path_name, new_path = make_dir(target)
    target_path = f"{new_path}/url_targets.txt"
    if write_file(target_path, target_list):
        output = f"{new_path}/dir_results.json"
        cmd = f"{MOD['ffuf']} -w {target_path}:URL -w db/dicc.txt:FUZZ -u URL/FUZZ -o {output} -v {args}"
        system(cmd)
        logger.info(f"Output: {output}")
        res: dict = read_jsonfile(output)
        if res:
            dir_results += res['results']
    return dir_results


def afrog(target_list: list, target=None) -> list:
    """afrog漏洞扫描

    :param target_list: 待扫描的目标列表
    :param target: 自动化扫描时候的目标
    :return:
    """
    poc_results: list = []
    logger.info(f"Current task: PocScan | Target number: {len(target_list)} | Engine: afrog("
                f"https://github.com/zan8in/afrog)")
    path_name, new_path = make_dir(target)
    target_path = f"{new_path}/url_targets.txt"
    if write_file(target_path, target_list):
        output: str = f"{new_path}/poc_results.json"
        cmd: str = f"{MOD['afrog']} -T {target_path} -o {new_path}/poc_results.html -json tmp/{path_name}/poc_results.json"
        system(cmd)
        logger.info(f"Output: {output}")
        res: list = read_jsonfile(output)
        if res:
            poc_results += read_jsonfile(output)
    return poc_results


def wafw00f(target_list: list, target=None) -> list:
    """

    :param target_list:
    :param target:
    :return:
    """
    waf_results: list = []
    logger.info(f"Current task: WafScan | Target number: {len(target_list)} | Engine: wafw00f("
                f"https://github.com/EnableSecurity/wafw00f)")
    path_name, new_path = make_dir(target)
    target_path = f"{new_path}/url_targets.txt"
    if write_file(target_path, target_list):
        output: str = f"{new_path}/waf_results.json"
        cmd: str = f"python {MOD['wafw00f']} -i {target_path} -o {new_path}/waf_results.json"
        system(cmd)
        logger.info(f"Output: {output}")
        res: list = read_jsonfile(output)
        if res:
            waf_results += read_jsonfile(output)
    return waf_results
