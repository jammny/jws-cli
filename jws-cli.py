#!/usr/bin/env python 
# -- coding:utf-8
"""
作者：jammny
文件描述： 命令行参数配置，程序入口。
"""
from sys import stdout, argv
from argparse import ArgumentParser
from os import system


def main():
    parser = ArgumentParser(description="tip：目标是做一款全自动化信息收集加漏洞扫描工具，解放双手，做回自己。 —— by jammny.")
    parser.add_argument("-t", nargs='?', const=True, type=str, dest="target", required=False, help="目标(必选参数)")
    parser.add_argument("--update", dest="update", action='store_true', required=False, help="更新数据")
    parser.add_argument("--auto", nargs='?', const=True, type=str, dest="auto", required=False, help="全自动化扫描")
    parser.add_argument("--sub", nargs='?', const=True, type=str, dest="sub", required=False, help="域名收集")
    parser.add_argument("--brute", dest="brute", action='store_true', required=False, help="域名爆破模式")
    parser.add_argument("--finger", nargs='?', const=True, type=str, dest="finger", required=False, help="指纹识别")
    parser.add_argument("--cdn", nargs='?', const=True, type=str, dest="cdn", required=False, help="CDN识别")
    parser.add_argument("--port", nargs='?', const=True, type=str, dest="port", required=False, help="端口扫描")
    parser.add_argument("--cidr", nargs='?', const=True, type=str, dest="cidr", required=False, help="C段扫描")
    parser.add_argument("--poc", nargs='?', const=True, type=str, dest="poc", required=False, help="POC漏洞扫描")
    parser.add_argument("--xray", nargs='?', const=True, type=str, dest="xray", required=False, help="xray网站扫描")
    '''
    parser.add_argument("--fofa", nargs='?', const=True, type=str, dest="fofa", required=False, help="fofa信息索引")
    parser.add_argument("--proxy", dest="proxy", action='store_true', required=False, help="可选：代理")
    '''
    args = parser.parse_args()
    # 输出Banner图案
    stdout.write(BANNER)
    # 程序兼容性检测
    CheckAll().run()
    if len(argv) == 1:
        logger.warning('TIPS：Enter "-h" for help')
        exit(0)
    Option(args.__dict__).run()


if __name__ == "__main__":
    try:
        from lib.config.settings import BANNER
        from lib.config.logger import logger
        from lib.core.check import CheckAll
        from lib.core.controller import Option
        from lib.config.settings import BANNER
        from lib.config.logger import logger
        from lib.core.check import CheckAll
        from colorama import init
        init(autoreset=True)
        main()
    except ModuleNotFoundError as e:
        moduleName: str = str(e).split("'")[1]
        print(f"{moduleName} module was not found!")
        print(f"Trying to install...")
        system("pip install -r requirements.txt")
