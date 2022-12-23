#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：
"""
from threading import Thread
from queue import Queue
from typing import Callable


def thread_task(task: Callable, args: list, thread_count: int = 100):
    """
    多线程任务
    :param task: 需要多线程执行的任务
    :param thread_count: 默认线程数100
    :param args: 需要传一个list，[queue,b]
    :return:
    """
    # 添加线程任务
    thread_pool: list = [Thread(target=task, args=args) for _ in range(thread_count)]
    # 开始线程
    for i in range(thread_count):
        thread_pool[i].start()
    # 结束线程
    for i in range(thread_count):
        thread_pool[i].join()


def get_queue(data: list):
    """
    创建一个queue用来配合多线程。
    :return
    """
    queue = Queue()
    for i in data:
        queue.put(i)
    return queue



