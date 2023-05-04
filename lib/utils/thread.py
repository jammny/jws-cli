#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
前言：切勿将本工具和技术用于网络犯罪，三思而后行！
文件描述： 文件描述：线程池封装。
"""
from queue import Queue
from typing import Callable
from concurrent.futures import ThreadPoolExecutor


def threadpool_task(task: Callable, queue_data: list, thread_count: int = 100, task_args: tuple = ()):
    """
    线程池模板
    :param task: 需要执行的多线程任务
    :param queue_data: 需要添加到队列的数据
    :param thread_count: 并发数
    :param task_args:  除了Queue之外的的参数
    :return
    """
    queue_obj: Queue = Queue(maxsize=0)
    for i in queue_data:
        queue_obj.put(i)
    args: tuple = task_args + (queue_obj,)
    with ThreadPoolExecutor(max_workers=thread_count) as pool:
        for _ in range(queue_obj.qsize()):
            futrue = pool.submit(lambda p: task(*p), args)
            # futrue.add_done_callback(done)    # 回调函数
