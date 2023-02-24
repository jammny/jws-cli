#!/usr/bin/env python 
# -*- coding : utf-8-*-
# coding:unicode_escape
"""
作者：jammny
文件描述：
"""
import time
import subprocess
import threading
from queue import Queue
from typing import Callable
from concurrent.futures import ThreadPoolExecutor
from sys import stdout, platform


def get_queue(data: list):
    """
    创建一个生产队列用来配合多线程。
    :param: data 需要放入队列的数据
    :return
    """
    queue_obj = Queue(maxsize=0)
    for i in data:
        queue_obj.put(i)
    return queue_obj


def thread_task(task: Callable, args: list, thread_count: int = 100):
    """
    线程类模板
    :param task: 需要多线程执行的任务
    :param thread_count: 默认线程数100
    :param args: 需要传一个list，[queue,b]
    :return:
    """
    # 定义一个存放线程类的列表。
    tasks: list = [threading.Thread(target=task, args=args) for _ in range(thread_count)]
    # 开始线程
    for i in tasks:
        i.start()
    # 开始线程
    for i in tasks:
        i.join()

def threadpool_task(task: Callable, args: list, thread_count):
    """
    线程池模板
    :param task: 需要多线程执行的任务
    :param args: 参数列表[]
    :param thread_count 线程数
    """
    pool = ThreadPoolExecutor(max_workers=thread_count)
    for _ in range(thread_count):
        futrue = pool.submit(lambda p: task(*p), args)
        # 回调函数
        # futrue.add_done_callback(done)
    pool.shutdown()


def ping(queue):
    while not queue.empty():
        ip = queue.get(timeout=3)
        # 判断系统环境
        if 'win' in platform:
            command = f'ping -n 1 {ip}'
        else:
            command = f'ping -c 1 {ip}'
        s, res = subprocess.getstatusoutput(command)
        if "TTL" in res or "ttl" in res:
            stdout.write(f"{ip} is up \n")
        else:
            stdout.write(f"{ip} is not up \n")


if __name__ == '__main__':
    start_time = time.time()
    targets = ["127.0.0.1", "192.168.0.2", "192.168.0.1", "192.168.0.3"]
    q = get_queue(targets)
    # 线程
    thread_task(task=ping, args=[q], thread_count=4)
    # 线程池
    threadpool_task(task=ping, args=[q], thread_count=3)
    print(f"用时：{time.time() - start_time}")
