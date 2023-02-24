import logging
from sys import stdout

import coloredlogs


# 配置 logger
logging.basicConfig()
logger = logging.getLogger(name='mylogger')
coloredlogs.install(logger=logger)
logger.propagate = False

# 配置颜色
coloredFormatter = coloredlogs.ColoredFormatter(
    fmt='%(asctime)s %(filename)-8s:%(lineno)s  %(message)s',
    level_styles=dict(
        debug=dict(color='green'),
        info=dict(color='blue'),
        warning=dict(color='yellow', bright=True),
        error=dict(color='red', bold=True, bright=True),
        critical=dict(color='black', bold=True, background='red'),
    ),
    field_styles=dict(
        asctime=dict(color='green'),
        # filename=dict(color='white'),
        lineno=dict(color='white'),)
)

# 配置streamHandler
ch = logging.StreamHandler(stream=stdout)
ch.setFormatter(fmt=coloredFormatter)
logger.addHandler(hdlr=ch)
logger.setLevel(level=logging.DEBUG)

'''
# 日志输出格式
logging.addLevelName(logging.INFO, f" {Fore.BLUE}INFO{Fore.RESET}  ")
logging.addLevelName(logging.ERROR, f" {Fore.RED}ERROR{Fore.RESET} ")
logging.addLevelName(logging.WARNING, f" {Fore.YELLOW}WARN{Fore.RESET}  ")
logging.addLevelName(logging.DEBUG, f" {Fore.GREEN}DEBUG{Fore.RESET} ")

# 定义记录器
logger = logging.getLogger("jws.log")
# 定义处理器
logger_HANDLER = logging.StreamHandler(stdout)
# logger_HANDLER.setLevel(logging.INFO)
logger_HANDLER.setLevel(logging.DEBUG)

logger_file = logging.FileHandler(filename="jws.log", mode='w')
logger_file.setLevel(logging.DEBUG)

# 格式器
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s',
                              datefmt=f"{Fore.CYAN}%Y-%m-%d %H:%M:%S{Fore.RESET}")
formatter2 = logging.Formatter("%(asctime)s - %(name)s - %(levelname)-9s - "
                               "%(filename)-8s : %(lineno)s line - %(message)s", datefmt="%Y/%m/%d %H:%M:%S")

# 给处理器设置格式
logger_HANDLER.setFormatter(formatter)
logger_file.setFormatter(formatter2)

# 记录器设置处理器
logger.addHandler(logger_HANDLER)
logger.addHandler(logger_file)
'''