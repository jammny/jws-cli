#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述： 生成报告核心代码
"""
from os import mkdir
from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from tinydb import TinyDB

from lib.core.settings import REPORTS

from lib.core.settings import TMP


class Report:
    def __init__(self, target):
        self.target = target
        self.db = TinyDB(f"{REPORTS}/{target}.json")

    def write_report(self, data):
        env = Environment(loader=FileSystemLoader('db'))
        template = env.get_template('template.html')
        with open(f"{REPORTS}/{self.target}.html", 'w+') as f:
            html_content = template.render(target=self.target, data=data)
            f.write(html_content)

    def db_insert(self, name, data):
        groups = self.db.table(name)
        for i in data:
            groups.insert(i)
        return groups.all()

    def db_select(self):
        """
        读取数据库中的所有数据
        :return:
        """
        groups = self.db.tables()
        return {i: self.db.table(i).all() for i in groups}

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

    def run(self, name: str, data: list):
        # 将数据写入数据库
        self.db_insert(name, data)
        data = self.db_select()
        # 将需要渲染的数据写入模板
        self.write_report(data)
