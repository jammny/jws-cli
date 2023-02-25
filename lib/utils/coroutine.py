import time
import socket
import eventlet

# 打补丁
eventlet.monkey_patch(socket=True)


def get_eventlet_queue(data):
    queue = eventlet.Queue()
    for i in data:
        queue.put(i)
    return queue


def coroutinepool_task(task, data, thread_count: int, task_args: tuple):
    """
    :params: args_list [(host, queue)]

    """
    queue = get_eventlet_queue(data)
    args = task_args + (queue, )
    pool = eventlet.GreenPool(thread_count)
    # 循环创建协程并加入协程池
    for _ in range(queue.qsize()):
        pool.spawn_n(task, *args)
    # 等待所有协程执行完毕
    pool.waitall()


# 扫描端口的函数
def scan_port(host, queue):
    try:
        port = queue.get()
        # 创建套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 设置超时时间
        sock.settimeout(3)
        # 连接主机和端口
        res = sock.connect_ex((host, port))
        # 关闭套接字
        sock.close()
        if res == 0:
            # 打印端口信息
            print(f'Port {port} is open')
    except:
        pass


if __name__ == "__main__":
    s = time.time()
    host = '120.48.47.193'
    thread_num = 1000
    data = [i for i in range(1, 65535)]
    task_args = (host, )
    coroutinepool_task(scan_port, data, thread_num, task_args)
    print(time.time() - s)
