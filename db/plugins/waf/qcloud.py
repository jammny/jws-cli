#!/usr/bin/env python
'''
Copyright (C) 2022, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

NAME = 'Qcloud (Tencent Cloud)'


def is_waf(self):
    if self.matchContent(r'腾讯云Web应用防火墙'):
        return True

    if self.matchContent(r'https://imgcache.qq.com/qcloud/security/static/imgs/attackIntercept.svg') \
            and self.matchStatus(403):
        return True

    return False
