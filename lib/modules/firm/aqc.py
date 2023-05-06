#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 利用多线程快速识别指纹信息。
"""

from typing import Optional

from httpx import Client
import json
from ast import literal_eval

from lib.utils.log import logger


class Aqc(object):
    def __init__(self):
        self.headers = {
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/98.0.4758.80 Safari/537.36 Edg/98.0.1108.43',
            'Accept': 'text/html, application/xhtml+xml, image/jxr, */*',
            'Referer': 'https://aifanfan.baidu.com/',
            'Connection': 'close',
        }

    def get_pid(self, target) -> Optional[str]:
        """默认选择第一个搜索结果的PID值

        :param target:
        :return:
        """
        url = f'https://aiqicha.baidu.com/s?q={target}&t=0'
        try:
            with Client(verify=False) as c:
                response = c.get(url=url, headers=self.headers)
            list_1: list = response.text.split('window.pageData = ')
            list_2: list = list_1[1].split(';\n        window.isSpider = null')
            result: dict = json.loads(list_2[0])
            # print(result['result']['resultList'])
            pid: str = result['result']['resultList'][0]['pid']
            return pid
        except Exception as e:
            logger.error(f"{url}, {e}")
            return

    def processing_data(self, resp) -> tuple:
        """

        :param resp:
        :return:
        """
        res = literal_eval(resp.text)  # 数据类型转换
        d = res['data']
        return d['list'], d['pageCount']

    def send_req(self, url, pid):
        """

        :param url:
        :param pid:
        :return:
        """
        results = []
        try:
            with Client(verify=False, headers=self.headers) as c:
                response = c.get(url=f'{url}{pid}&p=1')
                data, pageCount = self.processing_data(response)
                results += data
                if pageCount > 1:
                    for i in range(2, pageCount + 1):
                        response = c.get(url=f'{url}{pid}&p={i}')
                        data, pageCount = self.processing_data(response)
                        results += data
                return results
        except Exception as e:
            logger.error(f"{e}")
            return

    def icp_info(self, pid):
        """ICP备案信息

        :param pid: 企业pid值
        :return:
        """
        url = f'https://aiqicha.baidu.com/detail/icpinfoAjax?pid='
        return self.send_req(url, pid)

    def copyright_info(self, pid):
        """软件著作权

        :param pid: 企业pid值
        :return:
        """
        url = f'https://aiqicha.baidu.com/detail/copyrightAjax?size=10&pid='
        return self.send_req(url, pid)

    def intellectual_property(self, pid):
        """知识产权信息

        :param pid: 企业pid值
        :return:
        """
        url = f'https://aiqicha.baidu.com/detail/intellectualPropertyAjax?pid={pid}'
        try:
            with Client(verify=False, headers=self.headers) as c:
                response = c.get(url=url)
                results = literal_eval(response.text)  # 数据类型转换
                return results['data']
        except Exception as e:
            logger.error(f"{url}, {e}")
            return None

    def basic_data(self, pid):
        """企业基础信息

        :param pid: 企业pid值
        :return:
        """
        url = f'https://aiqicha.baidu.com/detail/basicAllDataAjax?pid={pid}'
        try:
            with Client(verify=False) as c:
                response = c.get(url=url, headers=self.headers)
                results = response.json()  # 数据类型转换
                data = results['data']
                basicData = data['basicData']  # 企业信息
                shareholdersData = data['shareholdersData']['list']  # 股东信息
                investRecordData = data['investRecordData']['list']  # 对外投资
                return basicData, shareholdersData, investRecordData
        except Exception as e:
            logger.error(f"{url}, {e}")
            return None, None, None

    def run(self, target):
        """爱企查爬虫程序执行入口

        :param target:
        :return:
        """
        pid: str = self.get_pid(target)
        icpInfo = self.icp_info(pid)
        copyright_ = self.copyright_info(pid)
        basicData, shareholdersData, investRecordData = self.basic_data(pid)
        return {
            'pid': pid,
            'icpInfo': icpInfo,
            'copyright': copyright_,
            'basicData': basicData,
            'shareholdersData': shareholdersData,
            'investRecordData': investRecordData
        }


if __name__ == '__main__':
    aqc = Aqc()
    print(aqc.run("脸萌"))
