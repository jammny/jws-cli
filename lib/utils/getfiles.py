#!/usr/bin python
# -*- encoding: utf-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 获取文件
"""
import yaml
import os


def get_yaml(file_path: str) -> list:
    """从目录中获取自定义DNS数据集的文件内容
    
    :return: 返回文件内容
    """
    # 遍历目录中的文件名
    yaml_files: list = list()
    for root, dirs, files in os.walk(file_path):
        for file in files:
            yaml_files.append(os.path.join(root, file))   # 将文件名添加到列表
    # 遍历文件内容
    context: list = list()
    for i in yaml_files:
        with open(i, mode='r', encoding='utf-8') as f:
            data: dict = yaml.safe_load(f.read())
            context.append(data)
    return context


if __name__ == '__main__':
    pass
