#!/usr/bin/env python
'''
Copyright (C) 2022, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

NAME = 'AliYunDun (Alibaba Cloud Computing)'


def is_waf(self):
    if self.matchContent(r'阿里云 Web应用防火墙'):
        return True

    if self.matchContent(r'很抱歉，由于您访问的URL有可能对网站造成安全威胁，您的访问被阻断。'):
        return True

    if self.matchContent(r'error(s)?\.aliyun(dun)?\.(com|net)?'):
        return True

    if self.matchContent(r'alicdn\.com\/sd\-base\/static\/\d{1,2}\.\d{1,2}\.\d{1,2}\/image\/405\.png'):
        return True

    if self.matchContent(r'Sorry, your request has been blocked as it may cause potential threats to the server\'s security.'):
        return True

    return False
