#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 生成报告核心代码
"""
from os import mkdir
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from tinydb import TinyDB

from lib.core.settings import REPORTS
from lib.core.settings import TMP
from lib.utils.encrypt import GetKey
from lib.utils.log import logger


def save_results(keyword: str, data: list, name=None):
    """保存扫描结果到tmp

    :param name:
    :param keyword:命名关键字
    :param data: 需要写入的数据
    :return:
    """
    if not name:
        name: str = f"{keyword}_{GetKey().random_key(5)}"
    Report(name).write_tmp(f'{keyword}_results', data)
    logger.info(f"Output files：{REPORTS}/{name}/{keyword}_results.txt")


class Report:
    def __init__(self, target):
        self.target = target

    def write_report(self, data):
        env = Environment(loader=FileSystemLoader('db'))
        template = env.get_template('template.html')
        with open(f"{REPORTS}/{self.target}.html", 'w', encoding="utf-8") as f:
            html_content = template.render(target=self.target, data=data)
            f.write(html_content)

    def db_insert(self, name, data, db):
        groups = db.table(name)
        for i in data:
            groups.insert(i)
        return groups.all()

    def db_select(self, db):
        """
        读取数据库中的所有数据
        :return:
        """
        groups = db.tables()
        return {i: db.table(i).all() for i in groups}

    def write_tmp(self, name, data):
        """
        将结果写入tmp， 供其他程序调用
        :return:
        """
        tmp_dir = Path(f"{TMP}/{self.target}")
        # 如果目录不存在就创建
        if not tmp_dir.exists():
            mkdir(tmp_dir)
        # 写入txt
        with open(f'{TMP}/{self.target}/{name}.txt', encoding="utf-8", mode="w") as f:
            f.write("\n".join(data))

    def html(self):
        db = TinyDB(f"{REPORTS}/{self.target}.json")
        groups = db.tables()
        data = {i: db.table(i).all() for i in groups}

        try:
            # 处理 waf_results 布尔值在html显示的问题
            for i in data['waf_results']:
                i['detected'] = str(i['detected'])
        except:
            pass

        # 将需要渲染的数据写入模板
        self.write_report(data)

    def run(self, name: str, data: list):
        db = TinyDB(f"{REPORTS}/{self.target}.json")
        # 将数据写入数据库
        self.db_insert(name, data, db)
