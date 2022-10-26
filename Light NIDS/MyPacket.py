#!/usr/bin/env python
# -*- coding:utf-8 -*-
# @Time     : 2021/5/8 14:39
# @Author   : Chongbo Wei
# @File     : packets.py
# @Software : PyCharm

import dpkt
from dpkt.utils import *
from dpkt.ethernet import *
from scapy.all import *


def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

"""
###########################  Ether Header 'type' ########################
ETH_CRC_LEN = 4
ETH_HDR_LEN = 14
ETH_LEN_MIN = 64  # minimum frame length with CRC
ETH_LEN_MAX = 1518  # maximum frame length with CRC
ETH_MTU = (ETH_LEN_MAX - ETH_HDR_LEN - ETH_CRC_LEN)
ETH_MIN = (ETH_LEN_MIN - ETH_HDR_LEN - ETH_CRC_LEN)
# Ethernet payload types - http://standards.ieee.org/regauth/ethertype
ETH_TYPE_UNKNOWN = 0x0000
ETH_TYPE_EDP = 0x00bb  # Extreme Networks Discovery Protocol
ETH_TYPE_PUP = 0x0200  # PUP protocol
ETH_TYPE_IP = 0x0800  # IP protocol
ETH_TYPE_ARP = 0x0806  # address resolution protocol
ETH_TYPE_AOE = 0x88a2  # AoE protocol
ETH_TYPE_CDP = 0x2000  # Cisco Discovery Protocol
ETH_TYPE_DTP = 0x2004  # Cisco Dynamic Trunking Protocol
ETH_TYPE_REVARP = 0x8035  # reverse addr resolution protocol
ETH_TYPE_8021Q = 0x8100  # IEEE 802.1Q VLAN tagging
ETH_TYPE_8021AD = 0x88a8  # IEEE 802.1ad
ETH_TYPE_QINQ1 = 0x9100  # Legacy QinQ
ETH_TYPE_QINQ2 = 0x9200  # Legacy QinQ
ETH_TYPE_IPX = 0x8137  # Internetwork Packet Exchange
ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol
ETH_TYPE_PPP = 0x880B  # PPP
ETH_TYPE_MPLS = 0x8847  # MPLS
ETH_TYPE_MPLS_MCAST = 0x8848  # MPLS Multicast
ETH_TYPE_PPPoE_DISC = 0x8863  # PPP Over Ethernet Discovery Stage
ETH_TYPE_PPPoE = 0x8864  # PPP Over Ethernet Session Stage
ETH_TYPE_LLDP = 0x88CC  # Link Layer Discovery Protocol
ETH_TYPE_TEB = 0x6558  # Transparent Ethernet Bridging
ETH_TYPE_PROFINET = 0x8892  # PROFINET protocol

###################################################################################
# Protocol (ip_p) - http://www.iana.org/assignments/protocol-numbers
IP_PROTO_IP = 0  # dummy for IP
IP_PROTO_HOPOPTS = IP_PROTO_IP  # IPv6 hop-by-hop options
IP_PROTO_ICMP = 1  # ICMP
IP_PROTO_IGMP = 2  # IGMP
IP_PROTO_GGP = 3  # gateway-gateway protocol
IP_PROTO_IPIP = 4  # IP in IP
IP_PROTO_ST = 5  # ST datagram mode
IP_PROTO_TCP = 6  # TCP
IP_PROTO_CBT = 7  # CBT
IP_PROTO_EGP = 8  # exterior gateway protocol
IP_PROTO_IGP = 9  # interior gateway protocol
IP_PROTO_BBNRCC = 10  # BBN RCC monitoring
IP_PROTO_NVP = 11  # Network Voice Protocol
IP_PROTO_PUP = 12  # PARC universal packet
IP_PROTO_ARGUS = 13  # ARGUS
IP_PROTO_EMCON = 14  # EMCON
IP_PROTO_XNET = 15  # Cross Net Debugger
IP_PROTO_CHAOS = 16  # Chaos
IP_PROTO_UDP = 17  # UDP
IP_PROTO_MUX = 18  # multiplexing
IP_PROTO_DCNMEAS = 19  # DCN measurement
IP_PROTO_HMP = 20  # Host Monitoring Protocol
IP_PROTO_PRM = 21  # Packet Radio Measurement
IP_PROTO_IDP = 22  # Xerox NS IDP
IP_PROTO_TRUNK1 = 23  # Trunk-1
IP_PROTO_TRUNK2 = 24  # Trunk-2
IP_PROTO_LEAF1 = 25  # Leaf-1
IP_PROTO_LEAF2 = 26  # Leaf-2
IP_PROTO_RDP = 27  # "Reliable Datagram" proto
IP_PROTO_IRTP = 28  # Inet Reliable Transaction
IP_PROTO_TP = 29  # ISO TP class 4
IP_PROTO_NETBLT = 30  # Bulk Data Transfer
IP_PROTO_MFPNSP = 31  # MFE Network Services
IP_PROTO_MERITINP = 32  # Merit Internodal Protocol
IP_PROTO_SEP = 33  # Sequential Exchange proto
IP_PROTO_3PC = 34  # Third Party Connect proto
IP_PROTO_IDPR = 35  # Interdomain Policy Route
IP_PROTO_XTP = 36  # Xpress Transfer Protocol
IP_PROTO_DDP = 37  # Datagram Delivery Proto
IP_PROTO_CMTP = 38  # IDPR Ctrl Message Trans
IP_PROTO_TPPP = 39  # TP++ Transport Protocol
IP_PROTO_IL = 40  # IL Transport Protocol
IP_PROTO_IP6 = 41  # IPv6
IP_PROTO_SDRP = 42  # Source Demand Routing
IP_PROTO_ROUTING = 43  # IPv6 routing header
IP_PROTO_FRAGMENT = 44  # IPv6 fragmentation header
IP_PROTO_RSVP = 46  # Reservation protocol
IP_PROTO_GRE = 47  # General Routing Encap
IP_PROTO_MHRP = 48  # Mobile Host Routing
IP_PROTO_ENA = 49  # ENA
IP_PROTO_ESP = 50  # Encap Security Payload
IP_PROTO_AH = 51  # Authentication Header
IP_PROTO_INLSP = 52  # Integated Net Layer Sec
IP_PROTO_SWIPE = 53  # SWIPE
IP_PROTO_NARP = 54  # NBMA Address Resolution
IP_PROTO_MOBILE = 55  # Mobile IP, RFC 2004
IP_PROTO_TLSP = 56  # Transport Layer Security
IP_PROTO_SKIP = 57  # SKIP
IP_PROTO_ICMP6 = 58  # ICMP for IPv6
IP_PROTO_NONE = 59  # IPv6 no next header
IP_PROTO_DSTOPTS = 60  # IPv6 destination options
IP_PROTO_ANYHOST = 61  # any host internal proto
IP_PROTO_CFTP = 62  # CFTP
IP_PROTO_ANYNET = 63  # any local network
IP_PROTO_EXPAK = 64  # SATNET and Backroom EXPAK
IP_PROTO_KRYPTOLAN = 65  # Kryptolan
IP_PROTO_RVD = 66  # MIT Remote Virtual Disk
IP_PROTO_IPPC = 67  # Inet Pluribus Packet Core
IP_PROTO_DISTFS = 68  # any distributed fs
IP_PROTO_SATMON = 69  # SATNET Monitoring
IP_PROTO_VISA = 70  # VISA Protocol
IP_PROTO_IPCV = 71  # Inet Packet Core Utility
IP_PROTO_CPNX = 72  # Comp Proto Net Executive
IP_PROTO_CPHB = 73  # Comp Protocol Heart Beat
IP_PROTO_WSN = 74  # Wang Span Network
IP_PROTO_PVP = 75  # Packet Video Protocol
IP_PROTO_BRSATMON = 76  # Backroom SATNET Monitor
IP_PROTO_SUNND = 77  # SUN ND Protocol
IP_PROTO_WBMON = 78  # WIDEBAND Monitoring
IP_PROTO_WBEXPAK = 79  # WIDEBAND EXPAK
IP_PROTO_EON = 80  # ISO CNLP
IP_PROTO_VMTP = 81  # Versatile Msg Transport
IP_PROTO_SVMTP = 82  # Secure VMTP
IP_PROTO_VINES = 83  # VINES
IP_PROTO_TTP = 84  # TTP
IP_PROTO_NSFIGP = 85  # NSFNET-IGP
IP_PROTO_DGP = 86  # Dissimilar Gateway Proto
IP_PROTO_TCF = 87  # TCF
IP_PROTO_EIGRP = 88  # EIGRP
IP_PROTO_OSPF = 89  # Open Shortest Path First
IP_PROTO_SPRITERPC = 90  # Sprite RPC Protocol
IP_PROTO_LARP = 91  # Locus Address Resolution
IP_PROTO_MTP = 92  # Multicast Transport Proto
IP_PROTO_AX25 = 93  # AX.25 Frames
IP_PROTO_IPIPENCAP = 94  # yet-another IP encap
IP_PROTO_MICP = 95  # Mobile Internet Ctrl
IP_PROTO_SCCSP = 96  # Semaphore Comm Sec Proto
IP_PROTO_ETHERIP = 97  # Ethernet in IPv4
IP_PROTO_ENCAP = 98  # encapsulation header
IP_PROTO_ANYENC = 99  # private encryption scheme
IP_PROTO_GMTP = 100  # GMTP
IP_PROTO_IFMP = 101  # Ipsilon Flow Mgmt Proto
IP_PROTO_PNNI = 102  # PNNI over IP
IP_PROTO_PIM = 103  # Protocol Indep Multicast
IP_PROTO_ARIS = 104  # ARIS
IP_PROTO_SCPS = 105  # SCPS
IP_PROTO_QNX = 106  # QNX
IP_PROTO_AN = 107  # Active Networks
IP_PROTO_IPCOMP = 108  # IP Payload Compression
IP_PROTO_SNP = 109  # Sitara Networks Protocol
IP_PROTO_COMPAQPEER = 110  # Compaq Peer Protocol
IP_PROTO_IPXIP = 111  # IPX in IP
IP_PROTO_VRRP = 112  # Virtual Router Redundancy
IP_PROTO_PGM = 113  # PGM Reliable Transport
IP_PROTO_ANY0HOP = 114  # 0-hop protocol
IP_PROTO_L2TP = 115  # Layer 2 Tunneling Proto
IP_PROTO_DDX = 116  # D-II Data Exchange (DDX)
IP_PROTO_IATP = 117  # Interactive Agent Xfer
IP_PROTO_STP = 118  # Schedule Transfer Proto
IP_PROTO_SRP = 119  # SpectraLink Radio Proto
IP_PROTO_UTI = 120  # UTI
IP_PROTO_SMP = 121  # Simple Message Protocol
IP_PROTO_SM = 122  # SM
IP_PROTO_PTP = 123  # Performance Transparency
IP_PROTO_ISIS = 124  # ISIS over IPv4
IP_PROTO_FIRE = 125  # FIRE
IP_PROTO_CRTP = 126  # Combat Radio Transport
IP_PROTO_CRUDP = 127  # Combat Radio UDP
IP_PROTO_SSCOPMCE = 128  # SSCOPMCE
IP_PROTO_IPLT = 129  # IPLT
IP_PROTO_SPS = 130  # Secure Packet Shield
IP_PROTO_PIPE = 131  # Private IP Encap in IP
IP_PROTO_SCTP = 132  # Stream Ctrl Transmission
IP_PROTO_FC = 133  # Fibre Channel
IP_PROTO_RSVPIGN = 134  # RSVP-E2E-IGNORE
IP_PROTO_RAW = 255  # Raw IP packets
IP_PROTO_RESERVED = IP_PROTO_RAW  # Reserved
IP_PROTO_MAX = 255'

# TCP control flags
TH_FIN = 0x01  # end of data
TH_SYN = 0x02  # synchronize sequence numbers
TH_RST = 0x04  # reset connection
TH_PUSH = 0x08  # push
TH_ACK = 0x10  # acknowledgment number set
TH_URG = 0x20  # urgent pointer set
TH_ECE = 0x40  # ECN echo, RFC 3168
TH_CWR = 0x80  # congestion window reduced
TH_NS = 0x100  # nonce sum, RFC 3540
"""

class MyPacket:
    def __init__(self):
        self.timeStamp: float = 0.0
        self.len: int = -1
        self.hasEther = False
        self.hasARP = False
        self.hasIP = False
        self.hasTCP = False
        self.hasUDP = False
        self.hasDNS = False
        self.ether = self.Ethernet()
        self.ip = self.IP()
        self.tcp = self.TCP()
        self.udp = self.UDP()
        self.sport = -1
        self.dport = -1

    class Ethernet:
        def __init__(self):
            self.src = 'Unknown'
            self.dst = 'Unknown'
            self.type = -1

        def set(self, src: str, dst: str, type: int):

            self.src = src
            self.dst = dst
            self.type = type

        def getAttributes(self):
            return self.src + ',' + self.dst + ',' + str(self.type)
            # return [self.src, self.dst, self.type]

    class IP:
        def __init__(self):
            self.version = -1
            self.protocol = -1
            self.src = 'Unknown'
            self.dst = 'Unknown'

        def set(self, version: int, protocol: int, src: str, dst: str):
            self.version = version
            self.protocol = protocol
            self.src = src
            self.dst = dst

        def getAttributes(self):
            return str(self.version) + ',' + str(self.protocol) + ',' + str(self.src) + ',' + str(self.dst)

    class TCP:
        def __init__(self):
            self.sport = -1
            self.dport = -1
            """
            self.seq = -1
            self.ack = -1
            self.flags = ''
            """

        def set(self, sport: int, dport: int):
            self.sport = sport
            self.dport = dport
            """
            self.seq = seq
            self.ack = ack
            self.flags = flags
            """

        def getAttributes(self):
            return str(self.sport) + ',' + str(self.dport) # + ',' + str(self.seq) + ',' + str(self.ack) + ',' + str(self.flags)

    class UDP:
        def __init__(self):
            self.sport = -1
            self.dport = -1

        def set(self, sport: int, dport: int):
            self.sport = sport
            self.dport = dport

        def getAttributes(self):
            return str(self.sport) + ',' + str(self.dport)
            # return [self.sport, self.dport]

    def dpkt_Packet2MyPacket(self, ts, buf):
        self.timeStamp = ts
        self.len = len(buf)
        self.hasEther = True
        eth = dpkt.ethernet.Ethernet(buf)
        self.ether.set(mac_addr(eth.src), mac_addr(eth.dst), eth.type)
        if isinstance(eth.data, dpkt.ip.IP):
            self.hasIP = True
            ip = eth.data
            self.ip.set(ip.v, ip.p, inet_to_str(ip.src), inet_to_str(ip.dst))
            if isinstance(ip.data, dpkt.tcp.TCP):
                self.hasTCP = True
                tcp = ip.data
                self.sport = tcp.sport
                self.dport = tcp.dport
                self.tcp.set(tcp.sport, tcp.dport) #, tcp.seq, tcp.ack, tcp.flags)
            elif isinstance(ip.data, dpkt.udp.UDP):
                self.hasUDP = True
                udp = ip.data
                self.sport = udp.sport
                self.dport = udp.dport
                self.udp.set(udp.sport, udp.dport)

    def encod2arr(self):
        boolCode = 0
        if self.hasEther:
            boolCode |= 1
        if self.hasARP:
            boolCode |= 2
        if self.hasIP:
            boolCode |= 4
        if self.hasTCP:
            boolCode |= 8
        if self.hasUDP:
            boolCode |= 16
        if self.hasDNS:
            boolCode |= 32
        return str(self.timeStamp) + ',' + str(self.len) + ',' + str(boolCode) + ',' + \
               self.ether.getAttributes() + ',' + self.ip.getAttributes() + ',' + \
               self.tcp.getAttributes() + ',' + self.udp.getAttributes()

    def decoder(self, str):
        str = str.strip().strip('\n').strip('\r').strip('\r\n')
        arr = str.split(',')
        self.timeStamp = float(arr[0])
        self.len = int(arr[1])
        boolCode = int(arr[2])
        self.hasEther = boolCode & 1
        self.hasARP = boolCode & 2
        self.hasIP = boolCode & 4
        self.hasTCP = boolCode & 8
        self.hasUDP = boolCode & 16
        self.hasDNS = boolCode & 32
        cnt = 3
        if self.hasEther:
            self.ether.set(arr[cnt], arr[cnt+1], int(arr[cnt+2]))
            cnt += 3
        if self.hasIP:
            self.ip.set(int(arr[cnt]), int(arr[cnt+1]), arr[cnt+2], arr[cnt+3])
            cnt += 4
        if self.hasTCP:
            self.tcp.set(int(arr[cnt]), int(arr[cnt+1])) #, int(arr[cnt+2]), int(arr[cnt+3]), arr[cnt+4])
            self.sport = self.tcp.sport
            self.dport = self.tcp.dport
            cnt += 2
        if self.hasUDP:
            self.udp.set(int(arr[cnt]), int(arr[cnt+1]))
            self.sport = self.udp.sport
            self.dport = self.udp.dport

    def showInfo(self):
        print('timestamp: ' + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timeStamp)))

def get_mypacket_from_dpkt_packet(timestamp, buf):
    rt = MyPacket()
    rt.dpkt_Packet2MyPacket(timestamp, buf)
    return rt
