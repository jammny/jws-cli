#!/usr/bin/env python
'''
Copyright (C) 2022, WAFW00F Developers.
See the LICENSE file for copying permission.
'''

NAME = 'SquidProxy IDS (SquidProxy)'


def is_waf(self):
    if self.matchHeader(('Server', r'squid(/[0-9\.]+)?')):
        return True

    if self.matchContent(r'Access control configuration prevents your request'):
        return True

    return False
