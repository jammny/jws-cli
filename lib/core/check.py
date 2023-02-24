import platform
from os import path, mkdir

from colorama import Fore
from httpx import Client

from lib.core.logger import logger
from lib.core.settings import REPORTS, MOD, VERSION, TMP


class CheckAll:
    """程序完整性检查"""

    def __init__(self):
        pass

    def py_check(self):
        """py版本检测"""
        py_version: str = platform.python_version()
        a: list = py_version.split('.')
        b: int = int(a[0])
        c: int = int(a[1])
        if b < 3 or c < 8:
            logger.error(f"此版本 ({py_version}) 不兼容, 版本至少需要 >= 3.8 (访问'https://www.python.org/downloads/')")
            exit(0)

    def report_check(self):
        """报告输出目录检测"""
        if not path.exists(REPORTS):
            mkdir(REPORTS)
        if not path.exists(TMP):
            mkdir(TMP)

    def update_check(self):
        """软件更新检测"""
        with Client(timeout=3, verify=False) as c:
            try:
                response = c.get("https://jammny.github.io/jws/version.txt")
                v = response.text.rstrip()
                if v != VERSION:
                    logger.info(f"New version: {VERSION} —> {Fore.RED}{v}{Fore.RESET} —> "
                                f"{Fore.MAGENTA}https://github.com/jammny/jws-cli{Fore.RESET}")
            except:
                pass

    def mod_check(self):
        """mod模块检测"""
        for i in MOD.values():
            if not path.isfile(i):
                logger.warn(f"缺少 {i} 文件")
                logger.warn(f"缺少第三方模块，可能将无法使用完整功能。")

    def run(self):
        logger.info("Checking for the program compatibility...")
        self.py_check()
        self.report_check()
        self.mod_check()
        logger.info("Checking for the latest version...")
        self.update_check()

