from sys import stdout
import logging

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
        filename=dict(color='white'),
        lineno=dict(color='white')
    )
)

# 配置streamHandler
ch = logging.StreamHandler(stream=stdout)
ch.setFormatter(fmt=coloredFormatter)
logger.addHandler(hdlr=ch)
logger.setLevel(level=logging.DEBUG)
