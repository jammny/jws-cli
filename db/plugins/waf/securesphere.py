#!/usr/bin/env python
'''
Copyright (C) 2022, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

NAME = 'SecureSphere (Imperva Inc.)'


def is_waf(self):
    if self.matchContent(r'<(title|h2)>Error'):
        return True

    if self.matchContent(r'The incident ID is'):
        return True

    if self.matchContent(r"This page can't be displayed"):
        return True

    if self.matchContent(r'Contact support for additional information'):
        return True

    return False
