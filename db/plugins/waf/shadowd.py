#!/usr/bin/env python
'''
Copyright (C) 2022, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

NAME = 'Shadow Daemon (Zecure)'


def is_waf(self):
    if self.matchContent(r"<h\d{1}>\d{3}.forbidden<.h\d{1}>"):
        return True

    if self.matchContent(r"request forbidden by administrative rules"):
        return True

    return False
