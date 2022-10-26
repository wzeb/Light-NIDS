"""
聚合单位：
src_IP：
    不同IP，二元组数量
     五元组数量

src_ip  dst_ip , Denoted Chaneel
    五元组数量

src_ip,port  dst_ip,port， 协议号,  Denoted Socket
    正向包间隔
######################################################################

公有特征：
    1. 正向包数量
    2. 反向包数量
    3. 正向包长度均值
    4. 反向包长度均值
    5. 正向包长度标准差
    6. 反向包长度标准差

特征产生触发条件：
    Cache 中 packet 出队时，如果未触发过检查
"""
import os
from math import sqrt
import dpkt
from MyPacket import MyPacket, get_mypacket_from_dpkt_packet
import numpy as np


def getPacketKey(pkt: MyPacket, dir: bool):
    """
    :param pkt: MyPacket
    :param dir: direction of pkt, true: fwd
    :return: key of 1_tuple, 2_tuple, 4_tuple, 5_tuple
    """
    k_one = pkt.ip.src
    k_two = pkt.ip.src + ',' + pkt.ip.dst
    k_four = pkt.ip.src + ',' + str(pkt.sport) + ',' + pkt.ip.dst + ',' + str(pkt.dport)
    k_five = k_four + ',' + str(pkt.ip.protocol)
    if not dir:
        k_one = pkt.ip.dst
        k_two = pkt.ip.dst + ',' + pkt.ip.src
        k_four = pkt.ip.dst + ',' + str(pkt.dport) + ',' + pkt.ip.src + ',' + str(pkt.sport)
        k_five = k_four + ',' + str(pkt.ip.protocol)
    return k_one, k_two, k_five


def get5tupleKey(pkt: MyPacket, dir: bool):
    """
    :param pkt: MyPacket
    :param dir: direction of pkt, true: fwd
    :return: key of 5_tuple
    """
    k_five = pkt.ip.src + ',' + str(pkt.sport) + ',' + pkt.ip.dst + ',' + str(pkt.dport) + ',' + str(pkt.ip.protocol)
    if not dir:
        k_five = pkt.ip.dst + ',' + str(pkt.dport) + ',' + pkt.ip.src + ',' + str(pkt.sport) + ',' + str(pkt.ip.protocol)
    return k_five

'''
class Welford:
    """
    Welford algorithm to O(1) maintain pkt_cnt, pkt_len_avg, pkt_len_stddev
    """
    def __init__(self):
        self.num = 0
        self.mean = 0
        self.sum = 0

    def addValue(self, val):
        self.num += 1
        delta = val - self.mean
        self.mean += delta / self.num
        self.sum += (val - self.mean) * delta

    def deleteValue(self, val):
        self.num -= 1
        if self.num == 0:
            self.__init__()
            return
        delta = val - self.mean
        mean = self.mean - delta / self.num
        self.sum -= (val - mean) * delta
        self.mean = mean

    def get_var(self):
        """
        :return: 样本方差 (∑(x-m)²)/(n-1)
        """
        if self.num <= 0 :
            return 0
        return self.sum / self.num

    def get_stddev(self):
        """
        :return: 标准差
        """
        return sqrt(self.get_var())

    def get_mean(self):
        return self.mean

    def get_num(self):
        return self.num
'''

class Welford:
    """
    Naive algorithm to verify Welford algorithm
    """
    def __init__(self):
        self.cache = []

    def addValue(self, val):
        self.cache.append(val)

    def deleteValue(self, val):
        if val != self.cache[0]:
            print('error  error error  error error  error error  error !!!!')
        self.cache.pop(0)

    def get_var(self):
        sum = 0
        if len(self.cache) <= 0:
            return 0
        for val in self.cache:
            sum += val
        mean = sum / len(self.cache)
        rt = 0
        for val in self.cache:
            rt += (val - mean) ** 2
        return rt / len(self.cache)

    def get_stddev(self):
        return sqrt(self.get_var())

    def get_mean(self):
        if len(self.cache) == 0 :
            return 0
        sum = 0
        for val in self.cache:
            sum += val
        return sum / len(self.cache)

    def get_num(self):
        return len(self.cache)


"""
显示一个 pcap文件中所有不同的IP
"""
def PrintIP(file_in):
    file_in = file_in + '.pcap'
    if not os.path.exists(file_in):
        print('file:"' + file_in + '" not exits.')
        return
    pcap = dpkt.pcap.Reader(open(file_in, mode='rb'))
    IPs = []
    cnt_tmp = 0
    for ts, buf in pcap:
        pkt = get_mypacket_from_dpkt_packet(ts, buf)
        ip = pkt.ip.src
        if ip not in IPs:
            IPs.append(ip)
        ip = pkt.ip.dst
        if ip not in IPs:
            IPs.append(ip)
        IPs.sort()
    for a in IPs:
        print(a)

