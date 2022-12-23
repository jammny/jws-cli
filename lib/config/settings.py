import os
import platform
import yaml
from rich.console import Console

console = Console(color_system='auto', style=None)

VERSION = "0.0.1"

BANNER: str = (
    "\033[1;31m\n"
    "   ___  _    _ _____        _____  _     _____ \n"
    "  |_  || |  | /  ___|      /  __ \| |   |_   _|\n"
    "    | || |  | \ `--. ______| /  \/| |     | |  \n"
    "    | || |/\| |`--. \______| |    | |     | |  \n"
    "/\__/ /\  /\  /\__/ /      | \__/\| |_____| |_ \n"
    "\____/  \/  \/\____/        \____/\_____/\___/ \n"
    "\n"
    f" \033[0m\033[1;34m jammny@fighter-team.cn    Version: {VERSION} \033[0m\n"
    "\n"
)


# 操作系统信息
OSNAME: str = platform.system()

# 当前工作目录
DIRNAME: str = os.getcwd()

# 指纹库数据
FINGER: str = os.path.join(DIRNAME, 'db/finger.json')

# 纯真ip数据库
QQWRY: str = os.path.join(DIRNAME, 'db/qqwry.dat')

# config.yaml配置数据
with open(os.path.join(DIRNAME, 'db/config.yaml'), mode="r", encoding="utf-8") as f:
    CONFIG_DATA = yaml.load(f.read(), Loader=yaml.FullLoader)

# 子域名爆破字典
SUBNAMES: str = os.path.join(DIRNAME, 'db/subnames.txt')

# POC目录
POC: str = os.path.join(DIRNAME, 'db/poc')

# 代理文件
HTTP_PROXY = os.path.join(DIRNAME, 'db/http_proxy.txt')

# 报告/结果输出路径
REPORTS: str = os.path.join(DIRNAME, 'reports')
TMP: str = os.path.join(DIRNAME, 'reports/tmp')

# dns 路径
DNS = os.path.join(DIRNAME, 'db/dns')

# 获取User-Agents
USER_AGENTS = CONFIG_DATA['user-agent']

# 第三方模块
MOD: dict = {
    "afrog": os.path.join(DIRNAME, 'thirdparty/afrog/afrog'),
}