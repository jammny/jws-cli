import os
import platform
import yaml
from rich.console import Console

console = Console(color_system='auto', style=None)

# 操作系统信息
OSNAME: str = platform.system()

# 当前工作目录
DIRNAME: str = os.getcwd()

# 指纹库数据
FINGER: str = os.path.join(DIRNAME, 'db/finger.json')

# 纯真ip数据库
QQWRY: str = os.path.join(DIRNAME, 'db/qqwry.dat')

with open(os.path.join(DIRNAME, 'db/config.yaml'), mode="r", encoding="utf-8") as f:
    # config.yaml配置数据
    CONFIG_DATA = yaml.load(f.read(), Loader=yaml.FullLoader)

# 版本信息
VERSION = CONFIG_DATA['version']

# logo信息
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


# 自动扫描配置
AUTO_SETTING: dict = CONFIG_DATA['auto_setting']

# 子域名模块
SUBNAMES: str = os.path.join(DIRNAME, 'db/subnames.txt')
SUBWORIDS: str = os.path.join(DIRNAME, 'db/subwords.txt')
DNS: str = os.path.join(DIRNAME, 'db/dns/test')

# 目录扫描模块
DICC: str = os.path.join(DIRNAME, 'db/dicc.txt')
DICC_CONFIG: str = os.path.join(DIRNAME, 'db/dirsearch.ini')

# CDN模块
CDN_KEY: str = CONFIG_DATA['cdn_key']

# 端口扫描
PORT: str = CONFIG_DATA['port']
PORT_THREAD: int = CONFIG_DATA['port_thread']
PORT_TIMEOUT: int = CONFIG_DATA['port_timeout']
PORT_METHOD: int = CONFIG_DATA['port_method']

# C段扫描
CIDR_METHOD: str = CONFIG_DATA['cidr_method']
CIDR_BLACKLIST: list = CONFIG_DATA['cidr_blacklist']

# POC模块
POC_ENGINE: str = CONFIG_DATA['poc_setting']
POC: str = os.path.join(DIRNAME, 'db/poc')

# 爬虫/代理模块
HTTP_PROXY = os.path.join(DIRNAME, 'db/http_proxy.txt')
USER_AGENTS = CONFIG_DATA['user-agent']

# 报告/结果输出
REPORTS: str = os.path.join(DIRNAME, 'reports')
TMP: str = os.path.join(DIRNAME, 'reports/tmp')

# 第三方模块
MOD: dict = {
    "afrog": os.path.join(DIRNAME, 'thirdparty/afrog/afrog'),
    "xray": os.path.join(DIRNAME, 'thirdparty/xray/xray'),
}
MOD_DIR: dict = {
    "xray_dir": os.path.join(DIRNAME, 'thirdparty/xray'),
}
