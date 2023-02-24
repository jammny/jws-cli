import multiprocessing
import subprocess
from typing import Callable


def get_queue(data: list):
    """
    创建一个生产队列用来配合多线程。
    :param: data 需要放入队列的数据
    :return
    """
    queue = multiprocessing.Manager().Queue()
    # 提交任务
    for i in data:
        queue.put(i)
    # 添加任务结束标记
    for i in range(4):
        queue.put(None)
    return queue


def process_task(task: Callable, args: tuple, process_count: int = 3):
    """
    线程类模板
    :param task: 需要多线程执行的任务
    :param process_count: 默认进程数10
    :param args: 需要传一个list，(queue,)
    :return:
    """
    # 定义一个存放进程类的列表。
    process_list = [multiprocessing.Process(target=task, args=args) for i in range(process_count)]
    # 开始进程
    for i in process_list:
        i.start()
    # 进程堵塞
    for i in process_list:
        i.join()


def processpool_task(task: Callable, args: tuple, process_count: int = 3):
    """
    线程池模板
    :param task: 需要多线程执行的方法
    :param args: 传入方法的参数
    :param process_count 进程数
    """
    # 创建进程池和队列
    pool = multiprocessing.Pool(process_count)
    # 启动进程池中的进程
    for i in range(process_count):
        pool.apply_async(task, args=args)
    # 等待所有进程完成
    pool.close()
    pool.join()


def ping(queue):
    while True:
        ip = queue.get()
        if ip is None:
            break
        command = f'ping -c 1 {ip}'
        s, res = subprocess.getstatusoutput(command)
        if "TTL" in res or "ttl" in res:
            print(f"{ip} is up")
        else:
            print(f"{ip} is not up")


if __name__ == '__main__':
    targets = ["127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"]
    queue = get_queue(targets)
    # processpool_task(task=ping, args=(queue,), process_count=3)
    # process_task(task=ping, args=(queue,), process_count=3)
