import struct
import socket

#formats of packets
#ethernet header
#smac:dmac:ethtyp
ETH_HDR = '!6s6sH'
#ipv4 header
#ver_ihl:tos:len:ident:flag_fo:ttl:proto:checksum:sip:dip
IPV4_HDR = '!ssHHHssHII'
#ipv4 packet hdr fields
IPV4_VERIHL = 0
IPV4_TOS = 1
IPV4_LEN = 2
IPV4_IDENT = 3
IPV4_FLAG_FO = 4
IPV4_TTL = 5
IPV4_PROTO = 6
IPV4_CHKSUM = 7
IPV4_SIP = 8
IPV4_DIP = 9

def unpack_ethernet(packet):
    return struct.unpack_from(ETH_HDR,buffer(packet),0)

#check for vlan hdr not implemented yet...
def unpack_ipv4(packet,hdr_field = None):
    if hdr_field == None:
        return struct.unpack_from(IPV4_HDR,buffer(packet),14)
    else:
        return struct.unpack_from(IPV4_HDR,buffer(packet),14)[hdr_field]

def ip2int(addr):                                                               
    return struct.unpack("!I", socket.inet_aton(addr))[0]                       


def int2ip(addr):                                                               
    return socket.inet_ntoa(struct.pack("!I", addr))      
