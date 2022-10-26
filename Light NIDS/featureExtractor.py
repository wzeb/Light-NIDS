import os

from txt2packets import *
from tools import *
from MyPacket import *
import time
import numpy as np

Statistics_VEC_SIZE = 21 * 50000
Mat_VEC_SIZE = 3 * 32 * 32 * 500
Hash = [16] * 2000
Lens = [60, 66, 67, 68, 69, 70, 74, 75, 78, 81, 87, 91, 110, 1474, 1514]
for i in range(15):
    Hash[Lens[i]] = i + 1

class Features:
    def __init__(self):
        self.fwd_welford = Welford()    # maintain common 6 features
        self.bwd_welford = Welford()
        """ 
        for each tuple, cal categories number of sub-tuple
        """
        self.num_2tuple = 0     # for IP
        self.num_5tuple = 0     # for IP, <src_ip, dst_ip>
        """
        matrix for sequence feature
        """
        self.mat = [0] * (32*32)    # -16 ~ 16
        self.X = 16
        self.XX = 16



    def addValue(self, len: int, dir: bool):
        if dir:
            self.fwd_welford.addValue(len)
            #Y = min(32, len // 100 + 17)
            Y = Hash[len] + 16
            self.mat[32 * (self.X - 1) + Y - 1] += 1
        else:
            self.bwd_welford.addValue(len)
            #Y = min(16, len // 100 + 1)
            Y = Hash[len]
            self.mat[32 * (self.X - 1) + Y - 1] += 1
        self.X = Y

    def deleteValue(self, len: int, dir: bool):
        if dir:
            self.fwd_welford.deleteValue(len)
            #Y = min(32, len // 100 + 17)
            Y = Hash[len] + 16
            self.mat[32 * (self.XX - 1) + Y - 1] -= 1
        else:
            self.bwd_welford.deleteValue(len)
            #Y = min(16, len // 100 + 1)
            Y = Hash[len]
            self.mat[32 * (self.XX - 1) + Y - 1] -= 1
        self.XX = Y


class FeaturesGenerator:
    def __init__(self):
        self.features_dict = dict()

    def addPacket(self, pkt: MyPacket, dir: bool):
        k_1tuple, k_2tuple, k_5tuple = getPacketKey(pkt, dir)
        """
            detect: if a new tuple come, then accumulate to it's ancestor tuples
        """
        if k_5tuple not in self.features_dict:
            self.features_dict[k_5tuple] = Features()
            f_5tuple = self.features_dict[k_5tuple]
            if k_2tuple not in self.features_dict:
                self.features_dict[k_2tuple] = Features()
                f_2tuple = self.features_dict[k_2tuple]
                if k_1tuple not in self.features_dict:
                    self.features_dict[k_1tuple] = Features()
                    f_1tuple = self.features_dict[k_1tuple]
                else:
                    f_1tuple = self.features_dict[k_1tuple]
                f_1tuple.num_2tuple += 1
            else:
                f_1tuple = self.features_dict[k_1tuple]
                f_2tuple = self.features_dict[k_2tuple]
            f_1tuple.num_5tuple += 1
            f_2tuple.num_5tuple += 1
        else:
            f_1tuple = self.features_dict[k_1tuple]
            f_2tuple = self.features_dict[k_2tuple]
            f_5tuple = self.features_dict[k_5tuple]
        """
        exec Welford algorithm to maintain common features
        """
        f_5tuple.addValue(pkt.len, dir)
        f_2tuple.addValue(pkt.len, dir)
        f_1tuple.addValue(pkt.len, dir)

    def deletePacket(self, pkt: MyPacket, dir: bool):
        k_1tuple, k_2tuple, k_5tuple = getPacketKey(pkt, dir)
        f_1tuple = self.features_dict[k_1tuple]
        f_2tuple = self.features_dict[k_2tuple]
        f_5tuple = self.features_dict[k_5tuple]
        f_1tuple.deleteValue(pkt.len, dir)
        f_2tuple.deleteValue(pkt.len, dir)
        f_5tuple.deleteValue(pkt.len, dir)
        """
        if no packet belong to tuple-T exists, delete Features-member of T, and accumulate T's ancestor tuples -1
        """
        if f_5tuple.fwd_welford.get_num() + f_5tuple.bwd_welford.get_num() == 0:
            f_2tuple.num_5tuple -= 1
            f_1tuple.num_5tuple -= 1
            self.features_dict.pop(k_5tuple)
            if f_2tuple.fwd_welford.get_num() + f_2tuple.bwd_welford.get_num() == 0:
                f_1tuple.num_2tuple -= 1
                self.features_dict.pop(k_2tuple)
                if f_1tuple.fwd_welford.get_num() + f_1tuple.bwd_welford.get_num() == 0:
                    self.features_dict.pop(k_1tuple)

    """
    return 2 Vec: 21 Statistics and Mat[3 * 32*32]
    """
    def getFeatures(self, pkt, dir):
        k_1tuple, k_2tuple, k_5tuple = getPacketKey(pkt, dir)
        f_1tuple = self.features_dict[k_1tuple]
        f_2tuple = self.features_dict[k_2tuple]
        f_5tuple = self.features_dict[k_5tuple]
        return [f_2tuple.num_5tuple, f_1tuple.num_5tuple, f_1tuple.num_2tuple,
                f_1tuple.fwd_welford.get_num(),   f_1tuple.bwd_welford.get_num(),
                f_1tuple.fwd_welford.get_mean(),  f_1tuple.bwd_welford.get_mean(),
                f_1tuple.fwd_welford.get_stddev(), f_1tuple.bwd_welford.get_stddev(),
                f_2tuple.fwd_welford.get_num(),   f_2tuple.bwd_welford.get_num(),
                f_2tuple.fwd_welford.get_mean(),  f_2tuple.bwd_welford.get_mean(),
                f_2tuple.fwd_welford.get_stddev(), f_2tuple.bwd_welford.get_stddev(),
                f_5tuple.fwd_welford.get_num(),   f_5tuple.bwd_welford.get_num(),
                f_5tuple.fwd_welford.get_mean(),  f_5tuple.bwd_welford.get_mean(),
                f_5tuple.fwd_welford.get_stddev(), f_5tuple.bwd_welford.get_stddev(),
                ], f_1tuple.mat + f_2tuple.mat + f_5tuple.mat


def extract_features_from_pcap(file_in, file_out, window_size, left, right, ip_vec, save_Statistics, save_matrix):
    file_in = file_in + '.txt'
    if not os.path.exists(file_in):
        print('file:"' + file_in + '" not exits.')
        return
    print('reading "' + file_in + '" and get packets.')

    if save_Statistics:
        f = open(file_out + '_statistics.txt', 'w')
        f.close()
    if save_matrix:
        f = open(file_out + '_mat.txt', 'w')
        f.close()

    """
    pcap = dpkt.pcap.Reader(open(file_in, mode='rb'))
    cnt_tmp = 0
    for ts, buf in pcap:
        cnt_tmp += 1
        if cnt_tmp <= left:
            continue
        elif cnt_tmp > right:
            break
        pkt = get_mypacket_from_dpkt_packet(ts, buf)
        packets.append(pkt)
    """
    #count = []

    packets = txt2mypkts(file_in, right)
    cache = []
    trigger = dict()
    feature_generator = FeaturesGenerator()
    statistics_vec = np.empty(Statistics_VEC_SIZE, dtype='float')
    mat_vec = np.empty(Mat_VEC_SIZE, dtype='int')
    statistics_vec_cnt = 0
    mat_vec_cnt = 0
    extracting_time = 0
    features_num = 0
    copy_time = 0
    for packet in packets:
        cache.append(packet)
        if packet.ip.src in ip_vec:     #ip_vec: 需要检查的IP集合
            #count.append(packet.len)
            feature_generator.addPacket(packet, True)
            k_five = get5tupleKey(packet, True)
            if k_five not in trigger:
                trigger[k_five] = packet.timeStamp
        if packet.ip.dst in ip_vec:
            #count.append(packet.len)
            feature_generator.addPacket(packet, False)
            k_five = get5tupleKey(packet, False)
            if k_five not in trigger:
                trigger[k_five] = packet.timeStamp
        while packet.timeStamp - cache[0].timeStamp >= window_size:
            time_begin = time.time()
            pkt = cache[0]
            cache.pop(0)
            if pkt.ip.src in ip_vec:
                k_five = get5tupleKey(pkt, True)
                if k_five in trigger:
                    if trigger[k_five] == pkt.timeStamp:
                        """ head-pkt has trigger of getting a feature-vec """
                        Statistics, Mat = feature_generator.getFeatures(pkt, True)
                        trigger.pop(k_five)
                        """ put features to already-allocated array """
                        time1 = time.time()
                        for val in Statistics:
                            statistics_vec[statistics_vec_cnt] = val
                            statistics_vec_cnt += 1
                        for val in Mat:
                            mat_vec[mat_vec_cnt] = val
                            mat_vec_cnt += 1
                        copy_time += time.time() - time1
                feature_generator.deletePacket(pkt, True)
            extracting_time += time.time() - time_begin

            """ dump features vec to file """
            if statistics_vec_cnt == Statistics_VEC_SIZE:
                if save_Statistics:
                    f = open(file_out + '_statistics.txt', 'a+')
                    np.savetxt(f, statistics_vec.reshape((-1, 21)))
                    f.close()
                statistics_vec_cnt = 0
                features_num += Statistics_VEC_SIZE / 21
            if mat_vec_cnt == Mat_VEC_SIZE:
                if save_matrix:
                    f = open(file_out + '_mat.txt', 'a+')
                    np.savetxt(f, mat_vec.reshape((-1, 3 * 32 * 32)), fmt='%d')
                    f.close()
                mat_vec_cnt = 0

            time_begin = time.time()
            if pkt.ip.dst in ip_vec:
                k_five = get5tupleKey(pkt, False)
                if k_five in trigger:
                    if trigger[k_five] == pkt.timeStamp:
                        """ head-pkt has trigger of getting a feature-vec """
                        Statistics, Mat = feature_generator.getFeatures(pkt, False)
                        trigger.pop(k_five)
                        """ put features to already-allocated array """
                        time1 = time.time()
                        for val in Statistics:
                            statistics_vec[statistics_vec_cnt] = val
                            statistics_vec_cnt += 1
                        for val in Mat:
                            mat_vec[mat_vec_cnt] = val
                            mat_vec_cnt += 1
                        copy_time += time.time() - time1
                feature_generator.deletePacket(pkt, False)
            extracting_time += time.time() - time_begin

            """ dump features vec to file """
            if statistics_vec_cnt == Statistics_VEC_SIZE:
                if save_Statistics:
                    f = open(file_out + '_statistics.txt', 'a+')
                    np.savetxt(f, statistics_vec.reshape((-1, 21)))
                    f.close()
                statistics_vec_cnt = 0
                features_num += Statistics_VEC_SIZE / 21
            if mat_vec_cnt == Mat_VEC_SIZE:
                if save_matrix:
                    f = open(file_out + '_mat.txt', 'a+')
                    np.savetxt(f, mat_vec.reshape((-1, 3*32*32)), fmt='%d')
                    f.close()
                mat_vec_cnt = 0

    if save_Statistics:
        f = open(file_out + '_statistics.txt', 'a+')
        statistics_vec = statistics_vec[0:statistics_vec_cnt]
        np.savetxt(f, statistics_vec.reshape((-1, 21)))
        f.close()
    if save_matrix:
        f = open(file_out + '_mat.txt', 'a+')
        mat_vec = mat_vec[0:mat_vec_cnt]
        np.savetxt(f, mat_vec.reshape((-1, 3 * 32 * 32)), fmt='%d')
        features_num += statistics_vec_cnt / 21
        f.close()

    print('packets_cnt: ' + str(len(packets)))
    print('windows: ' + str(window_size))
    print('feature instances: ' + str(features_num))
    print('use time: ' + str(extracting_time))
    print('copy_time: ' + str(copy_time))
    #return count
