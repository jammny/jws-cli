#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 生成报告核心代码
"""
from os import mkdir
from pathlib import Path
from typing import List

from jinja2 import Environment, FileSystemLoader

from tinydb import TinyDB
from tinydb.table import Document

from lib.core.settings import REPORTS
from lib.core.settings import TMP
from lib.utils.encrypt import GetKey
from lib.core.log import logger


class Report:
    def __init__(self, target: str = None):
        """

        :param target: 数据库名字
        """
        # 目录命名 #
        if target:
            self.target = target
        else:
            self.target = f"{GetKey().random_key(6)}"

        # 如果目录不存在就创建 #
        self.tmp_dir: Path = Path(f"{TMP}/{self.target}")
        if not self.tmp_dir.exists():
            mkdir(self.tmp_dir)

        # 初始化数据库
        self.db = TinyDB(f"{self.tmp_dir}/{self.target}.json")
        # logger.info(f"Output files：{self.tmp_dir}/{target}.json")

    def write_report(self, data):
        env = Environment(loader=FileSystemLoader('db'))
        template = env.get_template('report.html')
        with open(f"{REPORTS}/{self.target}.html", 'w', encoding="utf-8") as f:
            html_content = template.render(target=self.target, data=data)
            f.write(html_content)

    def db_insert(self, key_name: str, value: list) -> List[Document]:
        """写入数据

        :param key_name:
        :param value:
        :return:
        """
        db = self.db
        groups = db.table(key_name)
        for i in value:
            groups.insert(i)
        return groups.all()

    def db_select(self, db):
        """
        读取数据库中的所有数据
        :return:
        """
        groups = db.tables()
        return {i: db.table(i).all() for i in groups}

    def write_txt(self, file_name, data):
        """部分结果写入tmp供其他程序调用

        :param file_name: 文件名
        :param data: 文件内容
        :return:
        """
        # 写入txt #
        try:
            with open(f'{self.tmp_dir}/{file_name}.txt', encoding="utf-8", mode="w") as f:
                f.write("\n".join(data))
            logger.info(f"Output files：{self.tmp_dir}/{file_name}.txt")
        except Exception as e:
            logger.error(f"File write failure. {e}")

    def html(self):
        db = self.db
        groups = db.tables()
        data = {i: db.table(i).all() for i in groups}
        # 将需要渲染的数据写入模板 #
        self.write_report(data)

    def run(self, key_name: str, value: list):
        """

        :param key_name: 数据库的键
        :param value: 数据库的对应的值，这里传入需要写入的列表数据
        :return:
        """
        # 将数据写入数据库 #
        self.db_insert(key_name, value)
