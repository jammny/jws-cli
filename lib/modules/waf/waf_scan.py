#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 
"""
import re
from time import time
from typing import Optional

from httpx import Client, Response
from pluginbase import PluginBase


from rich.console import Console
from rich.table import Table

from lib.core.log import logger
from lib.core.settings import WAF_PLUGINS, SHOW_TABLE
from lib.utils.thread import threadpool_task
from lib.utils.tools import runtime_format


class WAFScan(object):
    """WAF指纹识别"""
    def __init__(self):
        # 测试payload #
        self.xsstring = '<script>alert("XSS");</script>'  # XSS 测试payload
        self.sqlistring = "UNION SELECT ALL FROM information_schema AND ' or SLEEP(5) or '"  # sqli 测试payload
        self.lfistring = '../../../../etc/passwd'  # 文件读取
        self.rcestring = '/bin/cat /etc/passwd; ping 127.0.0.1; curl google.com'
        self.xxestring = '<!ENTITY xxe SYSTEM "file:///etc/shadow">]><pwn>&hack;</pwn>'
        # 请求头 #
        self.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,'
                      'application/signed-exchange;v=b3',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9',
            'DNT': '1',  # Do Not Track request header
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/78.0.3770.100 Safari/537.36',
            'Upgrade-Insecure-Requests': '1'
        }
        self.waf_results = list()   # 存储结果数据
        self.original_response = None    # 对目标进行访问，获取初始请求响应信息
        self.attackres_response = None      # 发送包含payload的请求，获取响应信息

    def send_request(self, url: str, params=None) -> Response:
        """发送http请求

        :param url:
        :param params:
        :return:
        """
        try:
            with Client(headers=self.headers, verify=False, follow_redirects=True) as c:
                response = c.get(url=url, params=params)
            return response
        except Exception as e:
            logger.error(f"{url} {e}")
            return

    def matchHeader(self, headermatch, attack=True) -> bool:
        """匹配响应头内容

        :param headermatch: Tuple(header, str)，第一个是头属性，第二个是值
        :param attack: 如果为False，就匹配原始请求
        :return: bool
        """
        response: 'Response' = self.attackres_response if attack else self.original_response
        header = headermatch[0]
        match = headermatch[1]
        header_dict = dict(response.headers)    # 获得响应头内容
        if header_dict and header_dict.__contains__(header) and re.search(match, header_dict[header], re.I):
            return True
        return False

    def matchStatus(self, statuscode: int, attack=True) -> bool:
        """匹配状态码

        :param statuscode: 状态码
        :param attack: 如果为False，就匹配原始请求
        :return:
        """
        response: 'Response' = self.attackres_response if attack else self.original_response
        if response.status_code == statuscode:
            return True
        return False

    def matchCookie(self, match, attack=True) -> bool:
        """匹配Cookie

        :param match:
        :param attack:
        :return:
        """
        return self.matchHeader(('Set-Cookie', match), attack=attack)

    def matchContent(self, regex, attack=True) -> bool:
        """正则匹配页面内容

        :param regex: 正则表达式
        :param attack: True, 需要匹配异常页面的信息
        :return: 匹配成功返回True
        """
        response: 'Response' = self.attackres_response if attack else self.original_response
        if re.search(regex, response.text, re.I):  # 需要在响应体中匹配多行上下文
            return True
        return False

    def matchReason(self, reason_str, attack=True):
        """匹配状态码对应的响应信息

        :param reason_str: “ok”、“Not Allowed”
        :param attack:True, 需要匹配异常页面的信息
        :return:
        """
        response: 'Response' = self.attackres_response if attack else self.original_response
        if response.reason_phrase == reason_str:
            return True
        return False

    def genericdetect(self, target: str) -> bool:
        """通用防护检测

        :param target: 目标url
        :return: 返回True说明，存在防护；否则，没有防护
        """
        response_1 = self.original_response

        # 如果修改User-Agent后，访问响应不同，说明目标存在一定的防护 #
        if self.headers.__contains__('User-Agent'):
            self.headers.pop('User-Agent')  # 删除 User-Agent
        response_2 = self.send_request(url=target)  # 这次是没有 User-Agent 的访问
        if not response_2:
            logger.info('Blocking is being done at connection/packet level.')
            return True
        if response_1.status_code != response_2.status_code:
            logger.info('Server returned a different response when request didn\'t contain the User-Agent header.')
            logger.info(f'response code : {response_1.status_code} -> {response_2.status_code}')
            return True

        # 测试XSS attack #
        response_xss = self.send_request(url=target+'/', params={'s': self.xsstring})
        if not response_xss:
            logger.info('Blocking is being done at connection/packet level.')
            return True
        if response_1.status_code != response_xss.status_code:
            logger.info('Server returned a different response when a XSS attack vector was tried.')
            logger.info(f'response code : {response_1.status_code} -> {response_xss.status_code}')
            return True

        # 测试 lfi attack #
        response_lfi = self.send_request(url=target+'/'+self.lfistring)
        if not response_lfi:
            logger.info('Blocking is being done at connection/packet level.')
            return True
        if response_1.status_code != response_lfi.status_code and response_lfi.status_code != 404:
            logger.info('Server returned a different response when a directory traversal was attempted.')
            logger.info(f'response code : {response_1.status_code} -> {response_lfi.status_code}')
            return True

        # 测试 sqli attack #
        response_sqli = self.send_request(url=target+'/', params={'s': self.sqlistring})
        if not response_sqli:
            logger.info('Blocking is being done at connection/packet level.')
            return True
        if response_1.status_code != response_sqli.status_code:
            logger.info('Server returned a different response when a SQLi was attempted.')
            logger.info(f'response code : {response_1.status_code} -> {response_sqli.status_code}')
            return True

        # 测试响应头server的变化 #
        normal_server, attack_response_server = '', ''
        attackres_response = self.attackres_response
        response_headers = dict(response_1.headers)
        attackres_response_headers = dict(attackres_response.headers)
        if response_headers.__contains__('server'):
            normal_server = response_headers['server']
        if attackres_response_headers.__contains__('server'):
            attack_response_server = attackres_response_headers['server']
        if attack_response_server != normal_server:
            logger.info('Server header changed, WAF possibly detected')
            logger.info(f'response server : {normal_server} -> {attack_response_server}')
            return True

        return False

    def load_plugins(self):
        """加载WAF插件"""
        # here = os.path.abspath(os.path.dirname(__file__))
        # get_path = partial(os.path.join, here)
        plugin_dir = str(WAF_PLUGINS)  # 插件目录
        plugin_base = PluginBase(package='plugins')
        plugin_source = plugin_base.make_plugin_source(searchpath=[plugin_dir], persist=True)
        plugin_dict = {}
        for plugin_name in plugin_source.list_plugins():
            plugin_dict[plugin_name] = plugin_source.load_plugin(plugin_name)
        return plugin_dict

    def buildResultRecord(self, url: str, waf_result: Optional[str]) -> dict:
        """生成dict类型的识别结果

        :param url:
        :param waf_result:
        :return:
        """
        result = {'url': url}
        if waf_result:
            result['detected'] = 'True'
            if 'generic' in waf_result:
                result['firewall'] = 'Generic'
                result['manufacturer'] = 'Unknown'
            else:
                result['firewall'] = waf_result.split('(')[0].strip()
                result['manufacturer'] = waf_result.split('(')[1].replace(')', '').strip()
        else:
            result['detected'] = 'False'
            result['firewall'] = 'None'
            result['manufacturer'] = 'None'
        return result

    def scan(self, queue_obj: 'queue.Queue'):
        """扫描方法

        :param queue_obj: queue.Queue 队列中放url
        :return:
        """
        target = queue_obj.get()  # 获取目标url
        # 对目标进行访问，获取初始请求响应信息 #
        self.original_response = self.send_request(url=target)
        if not self.original_response:   # 如果目标访问失败，就直接退出
            logger.error(f"{target} connect error!")
            return

        # 第一次试探性的测试WAF, 发送三种测试payload #
        self.attackres_response = self.send_request(url=target+'/', params={
            'a': self.xsstring,
            'b': self.sqlistring,
            'c': self.lfistring
        })
        
        if not self.attackres_response:  # 如果目标访问失败，就直接退出
            logger.info('Blocking is being done at connection/packet level.')
            self.waf_results.append(self.buildResultRecord(target, 'generic'))  # 攻击请求失败的话，大概率有WAF
            return

        # 初始化插件数据 #
        waf_detections_rules = dict()
        plugin_dict = self.load_plugins()
        for plugin_module in plugin_dict.values():
            waf_detections_rules[plugin_module.NAME] = plugin_module.is_waf     # {"插件名": "插件方法"}

        # 调用插件方法 #
        waf = list()
        for name in waf_detections_rules.keys():
            if waf_detections_rules[name](self):  # 调用插件的iswaf方法，传入参数“self”，匹配成功为True，否为False
                waf.append(name)
                break  # 匹配到就退出

        if waf:  # 如果匹配到指纹
            logger.info(f'[+] The site {target} is behind WAF: {waf}')
            for name in waf:
                self.waf_results.append(self.buildResultRecord(target, name))
        else:
            if self.genericdetect(target):
                self.waf_results.append(self.buildResultRecord(target, 'generic'))
            else:
                self.waf_results.append(self.buildResultRecord(target, None))
        return

    def show_table(self) -> None:
        """表格展示数据"""
        data: list = self.waf_results
        if not data:
            return
        table = Table(title="WAF results", show_lines=False)
        table.add_column("url", justify="left", style="cyan", no_wrap=True)
        table.add_column("detected", justify="left", style="magenta")
        table.add_column("firewall", justify="left", style="red")
        table.add_column("manufacturer", justify="left", style="green")
        for i in data:
            table.add_row(i['url'], str(i['detected']), i['firewall'], i['manufacturer'])
        console = Console()
        console.print(table)
        return

    def finger(self, url: str):
        """finger识别时候调用接口，识别一条url

        :param url: 需要识别的链接
        :return: waf的名字
        """
        threadpool_task(self.scan, [url], thread_count=1)
        return self.waf_results[0]['firewall']

    def run(self, target_list):
        """类的统一执行入口

        :param auto:
        :param target_list: ['url目标', '']
        :return:
        """
        start = time()
        logger.info(f"Current task: WAFScan | Target number: {len(target_list)}")
        threadpool_task(self.scan, target_list)

        if SHOW_TABLE:
            self.show_table()

        logger.info(f"WAF scan task finished! Total time：{runtime_format(start, time())}")
        return self.waf_results
