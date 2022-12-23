#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
作者：jammny
文件描述： 
"""
import random
import string


class GetKey:
    def __init__(self):
        pass

    def random_key(self, length):
        """
        获取随机n1
        :param length:
        :return:
        """
        numOfNum = random.randint(1, length - 1)
        numOfLetter = length - numOfNum
        slcNum = [random.choice(string.digits) for i in range(numOfNum)]
        slcLetter = [random.choice(string.ascii_letters) for i in range(numOfLetter)]
        slcChar = slcNum + slcLetter
        random.shuffle(slcChar)
        getPwd = ''.join([i for i in slcChar])
        return getPwd
