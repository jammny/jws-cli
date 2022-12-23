import array
import bisect
import socket
import urllib
from typing import Tuple, Union
import struct
import urllib.request
import zlib
from lib.config.logger import logger

__all__ = ['QQwry', 'updateQQwry']


def int3(data, offset):
    return data[offset] + (data[offset + 1] << 8) + \
           (data[offset + 2] << 16)


def int4(data, offset):
    return data[offset] + (data[offset + 1] << 8) + \
           (data[offset + 2] << 16) + (data[offset + 3] << 24)


class QQwry:
    def __init__(self) -> None:
        self.clear()

    def clear(self) -> None:
        '''清空加载的数据，再次调用.load_file()时不必执行.clear()。'''
        self.idx1 = None
        self.idx2 = None
        self.idxo = None

        self.data = None
        self.index_begin = -1
        self.index_end = -1
        self.index_count = -1

        self.__fun = None

    def load_file(self, filename: Union[str, bytes], loadindex: bool = False) -> bool:
        '''加载qqwry.dat文件。成功返回True，失败返回False。
        参数filename可以是qqwry.dat的文件名（str类型），也可以是bytes类型的文件内容。'''
        self.clear()

        if type(filename) == bytes:
            self.data = buffer = filename
            filename = 'memory data'
        elif type(filename) == str:
            # read file
            try:
                with open(filename, 'br') as f:
                    self.data = buffer = f.read()
            except Exception as e:
                logger.error('%s open failed：%s' % (filename, str(e)))
                self.clear()
                return False

            if self.data == None:
                logger.error('%s load failed' % filename)
                self.clear()
                return False
        else:
            self.clear()
            return False

        if len(buffer) < 8:
            logger.error('%s load failed, file only %d bytes' %
                         (filename, len(buffer))
                         )
            self.clear()
            return False

        # index range
        index_begin = int4(buffer, 0)
        index_end = int4(buffer, 4)
        if index_begin > index_end or \
                (index_end - index_begin) % 7 != 0 or \
                index_end + 7 > len(buffer):
            logger.error('%s index error' % filename)
            self.clear()
            return False

        self.index_begin = index_begin
        self.index_end = index_end
        self.index_count = (index_end - index_begin) // 7 + 1

        if not loadindex:
            logger.info('%s %s bytes, %d segments. without index.' %
                        (filename, format(len(buffer), ','), self.index_count)
                        )
            self.__fun = self.__raw_search
            return True

        # load index
        self.idx1 = array.array('L')
        self.idx2 = array.array('L')
        self.idxo = array.array('L')

        try:
            for i in range(self.index_count):
                ip_begin = int4(buffer, index_begin + i * 7)
                offset = int3(buffer, index_begin + i * 7 + 4)

                # load ip_end
                ip_end = int4(buffer, offset)

                self.idx1.append(ip_begin)
                self.idx2.append(ip_end)
                self.idxo.append(offset + 4)
        except:
            logger.error('%s load index error' % filename)
            self.clear()
            return False

        logger.info('%s %s bytes, %d segments. with index.' %
                    (filename, format(len(buffer), ','), len(self.idx1))
                    )
        self.__fun = self.__index_search
        return True

    def __get_addr(self, offset):
        # mode 0x01, full jump
        mode = self.data[offset]
        if mode == 1:
            offset = int3(self.data, offset + 1)
            mode = self.data[offset]

        # country
        if mode == 2:
            off1 = int3(self.data, offset + 1)
            c = self.data[off1:self.data.index(b'\x00', off1)]
            offset += 4
        else:
            c = self.data[offset:self.data.index(b'\x00', offset)]
            offset += len(c) + 1

        # province
        if self.data[offset] == 2:
            offset = int3(self.data, offset + 1)
        p = self.data[offset:self.data.index(b'\x00', offset)]

        return c.decode('gb18030', errors='replace'), \
               p.decode('gb18030', errors='replace')

    def lookup(self, ip_str: str) -> Union[Tuple[str, str], None]:
        '''查找IP地址的归属地。
           找到则返回一个含有两个字符串的元组，如：('国家', '省份')
           没有找到结果，则返回一个None。'''
        ip = struct.unpack(">I", socket.inet_aton(ip_str.strip()))[0]

        try:
            return self.__fun(ip)
        except:
            if not self.is_loaded():
                logger.error('Error: qqwry.dat not loaded yet.')
            else:
                raise

    def __raw_search(self, ip):
        l = 0
        r = self.index_count

        while r - l > 1:
            m = (l + r) // 2
            offset = self.index_begin + m * 7
            new_ip = int4(self.data, offset)

            if ip < new_ip:
                r = m
            else:
                l = m

        offset = self.index_begin + 7 * l
        ip_begin = int4(self.data, offset)

        offset = int3(self.data, offset + 4)
        ip_end = int4(self.data, offset)

        if ip_begin <= ip <= ip_end:
            return self.__get_addr(offset + 4)
        else:
            return None

    def __index_search(self, ip):
        posi = bisect.bisect_right(self.idx1, ip) - 1

        if posi >= 0 and self.idx1[posi] <= ip <= self.idx2[posi]:
            return self.__get_addr(self.idxo[posi])
        else:
            return None

    def is_loaded(self) -> bool:
        '''是否已加载数据，返回True或False。'''
        return self.__fun != None

    def get_lastone(self) -> Union[Tuple[str, str], None]:
        '''返回最后一条数据，最后一条通常为数据的版本号。
           没有数据则返回一个None。
           如：('纯真网络', '2020年9月30日IP数据')'''
        try:
            offset = int3(self.data, self.index_end + 4)
            return self.__get_addr(offset + 4)
        except:
            return None


def updateQQwry(filename: Union[str, None]) -> Union[int, bytes]:
    """
    1.当参数filename是str类型时，表示要保存的文件名。
       成功后返回一个正整数，是文件的字节数；失败则返回一个负整数。

    2.当参数filename是None时，函数直接返回qqwry.dat的文件内容（一个bytes对象）。
       成功后返回一个bytes对象；失败则返回一个负整数。
       这里要判断一下返回值的类型是bytes还是int。
    """

    def get_fetcher():
        # no proxy
        proxy = urllib.request.ProxyHandler({})
        # opener
        opener = urllib.request.build_opener(proxy)

        def open_url(file_name, url):
            # request对象
            headers = {
                'User-Agent': 'Mozilla/3.0 (compatible; Indy Library)',
                'Host': 'update.cz88.net'
            }
            req = urllib.request.Request(url, headers=headers)

            try:
                # r是HTTPResponse对象
                r = opener.open(req, timeout=60)
                dat = r.read()
                if not dat:
                    raise Exception('文件大小为零')
                return dat
            except Exception as e:
                logger.error('下载%s时出错: %s' % (file_name, str(e)))
                return None

        return open_url

    fetcher = get_fetcher()

    # download copywrite.rar
    url = 'http://update.cz88.net/ip/copywrite.rar'
    data = fetcher('copywrite.rar', url)
    if not data:
        return -1

    # extract infomation from copywrite.rar
    if len(data) <= 24 or data[:4] != b'CZIP':
        logger.error('解析copywrite.rar时出错')
        return -2

    version, unknown1, size, unknown2, key = \
        struct.unpack_from('<IIIII', data, 4)
    if unknown1 != 1:
        logger.error('解析copywrite.rar时出错')
        return -2

    # download qqwry.rar
    url = 'http://update.cz88.net/ip/qqwry.rar'
    data = fetcher('qqwry.rar', url)
    if not data:
        return -3

    if size != len(data):
        logger.error('qqwry.rar文件大小不符合copywrite.rar的数据')
        return -4

    # decrypt
    head = bytearray(0x200)
    for i in range(0x200):
        key = (key * 0x805 + 1) & 0xff
        head[i] = data[i] ^ key
    data = head + data[0x200:]

    # decompress
    try:
        data = zlib.decompress(data)
    except:
        logger.error('解压缩qqwry.rar时出错')
        return -5

    if filename == None:
        return data
    elif type(filename) == str:
        # save to file
        try:
            with open(filename, 'wb') as f:
                f.write(data)
            return len(data)
        except:
            logger.error('保存到最终文件时出错')
            return -6
    else:
        logger.error('保存到最终文件时出错')
        return -6