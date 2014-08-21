# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import struct
from binascii import hexlify
from array import *

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_str
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import ipv4,ipv6,ethernet,icmp,arp,icmpv6

from ryu.ofproto import nx_match
from ryu.ofproto import ether
import convert
 
LOG = logging.getLogger('ryu.app.simple_switch')

# TODO: we should split the handler into two parts, protocol
# independent and dependant parts.

# TODO: can we use dpkt python library?

# TODO: we need to move the followings to something like db


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.port_to_ip = {}
        self.port_to_switch_mac = {}
        self.port_to_ipv6 = {}

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        wildcards &= ~ofproto_v1_0.OFPFW_DL_DST

        match = datapath.ofproto_parser.OFPMatch(
            wildcards, in_port, 0, dst,
            0, 0, 0, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    '''
    def _binary_to_ipv6_format(self,binary):
        
        h = hexlify(binary)
        return int(h[0:8],16),int(h[8:16],16),int(h[16:24],16),int(h[24:32],16)
    '''   
    def find_packet(self,msg,target):
        pkt = Packet(array('B',msg.data))          
        for packet in pkt:
            if isinstance(packet,array):
                pass
            else:
                if packet.protocol_name==target:
                    target_packet=packet
                    return target_packet 
                else:
                    pass
        print "cann't find target_packet!\n"
        return None

    def _to_command(self,table,command):
        return table << 8 | command 

    def  nx_ipv6_add_flow(self,dp,rule,actions):
        command = self._to_command(0, dp.ofproto.OFPFC_ADD)  

        #actions = []
        #actions.append(dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_NORMAL)) 

        _rule = nx_match.ClsRule()
        _rule.set_dl_type(ether.ETH_TYPE_IPV6)

        _rule.set_ipv6_dst(rule.get('ipv6_dst',''))
        _rule.set_ipv6_src(rule.get('ipv6_src',''))


        flow_mod = dp.ofproto_parser.NXTFlowMod(datapath=dp,
            cookie=0, command=command, idle_timeout=0, hard_timeout=0,
            priority=0x1, buffer_id=0xffffffff,
            out_port=dp.ofproto.OFPP_NONE,
            flags=0, rule=_rule, actions=actions)
        dp.send_msg(flow_mod)
       
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port  = msg.in_port
        datapath = msg.datapath
        ofproto = datapath.ofproto
        dpid = datapath.id
        print 'mac_to_port',self.mac_to_port,'\n'       
        self.mac_to_port.setdefault(dpid, {})
        print 'mac_to_port',self.mac_to_port,'\n'
       
        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
        LOG.info("packet in %s %s %s %s",
                 dpid, haddr_to_str(src), haddr_to_str(dst), msg.in_port)

        if _eth_type == ether.ETH_TYPE_ARP:
            #if dst in self.port_to_switch_mac[dpid]:
            arp_pkt = self.find_packet(msg,'arp')
            if arp_pkt != None:
                dst_ip = arp_pkt.dst_ip
                src_ip = arp_pkt.src_ip
                
                self.port_to_ip.setdefault(dpid,{})
                self.port_to_ip[dpid][in_port] = (src_ip & 0Xffffff00) + 0xfe

                if dst_ip == self.port_to_ip[dpid][in_port]:
                    src_mac = self.port_to_switch_mac[dpid][in_port]
                
                    e = ethernet.ethernet(src,self.port_to_switch_mac[dpid][in_port],ether.ETH_TYPE_ARP)
                    if arp_pkt.opcode == arp.ARP_REQUEST:
                        opcode = arp.ARP_REPLY 
                    #else:
                        #opcode = arp.ARP_REV_REPLY
                    a = arp.arp(hwtype = 1,proto = 0x0800, hlen = 6, plen = 4, opcode = opcode,
                        src_mac = src_mac,src_ip = arp_pkt.dst_ip,
                        dst_mac = arp_pkt.src_mac, dst_ip = arp_pkt.src_ip)
                    p = Packet()
                    p.add_protocol(e)
                    p.add_protocol(a) 
                    p.serialize()             
                                    
                    datapath.send_packet_out(in_port=ofproto_v1_0.OFPP_NONE,actions=[datapath.ofproto_parser.OFPActionOutput(in_port)],data=p.data)

                    print "arp request packet's dst_mac is ",haddr_to_str(self.port_to_switch_mac[dpid][in_port])
                    


        
        if _eth_type == ether.ETH_TYPE_IP:
            ip_pkt = self.find_packet(msg,'ipv4')
            #to judge if the ip packet contains icmp protocol
            #print 'lee 0'
            if ip_pkt.proto == 1:
                icmp_pkt = self.find_packet(msg,'icmp')
                if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    ip_src = ip_pkt.src
                    ip_dst = ip_pkt.dst

                    echo_id = icmp_pkt.data.id
                    echo_seq = icmp_pkt.data.seq
                    echo_data = bytearray(icmp_pkt.data.data)

                    icmp_data = icmp.echo(id_=echo_id,seq=echo_seq,data=echo_data)
                    
                    self.port_to_ip.setdefault(dpid, {})
                    #mask is 24 bit
                    self.port_to_ip[dpid][in_port] = (ip_src & 0Xffffff00) + 0xfe
                    #print 'lee 1'
                    if self.port_to_ip[dpid][in_port] == ip_dst:
                        #send a echo reply packet  
                        ether_dst = src
                        ether_src = self.port_to_switch_mac[dpid][in_port]
                        e = ethernet.ethernet(ether_dst,ether_src,ether.ETH_TYPE_IP)
                        #csum calculation should be paied attention
                        #ic = icmp.icmp(type_= 0,code=0,csum=0,data=icmp_pkt.data)
                        i = ipv4.ipv4(version=4,header_length=5,tos=0,total_length=0,
                            identification=0,flags=0x000,offset=0,ttl=64,proto=1,csum=0,src=ip_dst,
                            dst=ip_src,option=None)

                        ic = icmp.icmp(type_= 0,code=0,csum=0,data=icmp_data)
                        p = Packet()
                        p.add_protocol(e)
                        p.add_protocol(i)
                        p.add_protocol(ic) 
                        p.serialize()                       
                        datapath.send_packet_out(in_port=ofproto_v1_0.OFPP_NONE,actions=[datapath.ofproto_parser.OFPActionOutput(in_port)],data=p.data)
                        print 'send a ping replay'                        
                    else:
                        pass
        
        if _eth_type == ether.ETH_TYPE_IPV6:
            ipv6_pkt = self.find_packet(msg,'ipv6')
            #don't care about ipv6's extention header
            icmpv6_pkt = self.find_packet(msg,'icmpv6')
            if icmpv6_pkt != None:
                if icmpv6_pkt.type_ == icmpv6.ND_NEIGHBOR_SOLICIT:

                    self.port_to_ipv6.setdefault(dpid,{})
                    #self.port_to_ipv6[dpid][in_port]=hexlify(((ipv6_pkt.src & (1<<128))-(1<<64)) + (1<<64) - 2)
                    self.port_to_ipv6[dpid][in_port]=struct.pack('!4I',0x100000,0x0,0xffffffff,0xfffffffd)
                    
                    if icmpv6_pkt.data.dst == self.port_to_ipv6[dpid][in_port]:
                           
                        #send a ND_NEIGHBOR_REPLY packet
                        ether_dst = src
                        ether_src = self.port_to_switch_mac[dpid][in_port]
                        e = ethernet.ethernet(ether_dst,ether_src,ether.ETH_TYPE_IPV6)
                        
                        ic6_data_data = icmpv6.nd_option_la(hw_src=self.port_to_switch_mac[dpid][in_port],data=None)
                        #res = 3 or 7
                        ic6_data = icmpv6.nd_neighbor(res=3,dst=icmpv6_pkt.data.dst,type_=icmpv6.nd_neighbor.ND_OPTION_TLA,length=1,data=ic6_data_data)
                        ic6 = icmpv6.icmpv6(type_=icmpv6.ND_NEIGHBOR_ADVERT,code=0,csum=0,data=ic6_data)  
                        #payload_length
                        i6 = ipv6.ipv6(version= 6,traffic_class=0,flow_label=0,payload_length=32,nxt=58,hop_limit=255,
                            src=icmpv6_pkt.data.dst,dst=ipv6_pkt.src) 
                        p = Packet()
                        p.add_protocol(e)
                        p.add_protocol(i6)
                        p.add_protocol(ic6) 
                        p.serialize() 
                        datapath.send_packet_out(in_port=ofproto_v1_0.OFPP_NONE,actions=[datapath.ofproto_parser.OFPActionOutput(in_port)],data=p.data)
                        print 'send a NA packet'
                        
                
                if icmpv6_pkt.type_ == icmpv6.ICMPV6_ECHO_REQUEST:
                    if self.port_to_ipv6[dpid].has_key(in_port):
                       
                    #print hexlify(self.port_to_ipv6[dpid][in_port])
                    #print 'ipv6_pkt.dst is',hexlify(ipv6_pkt.dst)
                    #print 'ipv6_pkt.dst is',hexlify(ipv6_pkt.dst)                  
                        if ipv6_pkt.dst == self.port_to_ipv6[dpid][in_port]:
                            ether_dst = src
                            ether_src = self.port_to_switch_mac[dpid][in_port]
                            e = ethernet.ethernet(ether_dst,ether_src,ether.ETH_TYPE_IPV6)
                            ic6_data = icmpv6_pkt.data
                            ic6 = icmpv6.icmpv6(type_=icmpv6.ICMPV6_ECHO_REPLY,code=0,csum=0,data=ic6_data)
                            i6 = ipv6.ipv6(version= 6,traffic_class=0,flow_label=0,payload_length=64,nxt=58,hop_limit=64,
                                src=ipv6_pkt.dst,dst=ipv6_pkt.src)
                            p = Packet()
                            p.add_protocol(e)
                            p.add_protocol(i6)
                            p.add_protocol(ic6) 
                            p.serialize() 
                            datapath.send_packet_out(in_port=ofproto_v1_0.OFPP_NONE,actions=[datapath.ofproto_parser.OFPActionOutput(in_port)],data=p.data)
                            print 'send a ping6 reply packet'


                                        
                    

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            if _eth_type == ether.ETH_TYPE_IP:
                self.add_flow(datapath, msg.in_port, dst, actions)        
            #add a ipv6 flow table pay attention ipv6_flow entry only be added once when ipv4 flow entry is added       
            elif _eth_type == ether.ETH_TYPE_IPV6:

                '''
                # judge if src and dst addr is special 
                # eg: src [0,0,0,0] dst begin with 0xff01 or 0x ff02 
                if ipv6_src == [0,0,0,0] or ipv6_dst[0]&0xff010000 == 0xff010000 or ipv6_dst[0]&0xff020000 == 0xff020000:
                    print 'ipv6 reserved address\n' 
                #elif ipv6_dst[0]&0xfe800000 == 0xfe800000:
                #    print 'ipv6 dst address is Link-Local address'
                else:
                '''     
                
                ipv6_pkt = self.find_packet(msg,'ipv6')
                #ipv6_src=struct.pack('!4I',self._binary_to_ipv6_format(ipv6_packet.src))
                #ipv6_dst=struct.pack('!4I',self._binary_to_ipv6_format(ipv6_packet.dst))
                ipv6_src = convert.bin_to_ipv6_arg_list(ipv6_pkt.src)
                ipv6_dst = convert.bin_to_ipv6_arg_list(ipv6_pkt.dst)
                """
                ipv6_src = struct.pack('!4I',int(hexlify(ipv6_pkt.src)[0:8],16),int(hexlify(ipv6_pkt.src)[8:16],16),int(hexlify(ipv6_pkt.src)[16:24],16),int(hexlify(ipv6_pkt.src)[24:32],16))
                ipv6_dst = struct.pack('!4I',int(hexlify(ipv6_pkt.dst)[0:8],16),int(hexlify(ipv6_pkt.dst)[8:16],16),int(hexlify(ipv6_pkt.dst)[16:24],16),int(hexlify(ipv6_pkt.dst)[24:32],16))
                """   
                rule={'ipv6_src':ipv6_src,'ipv6_dst':ipv6_dst}
                self.nx_ipv6_add_flow(datapath,rule,actions)
                print 'add a ipv6 flow entry'  
            else:
                pass
          
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)                 
        
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self,ev):

        msg = ev.msg
        dpid = msg.datapath_id
        self.port_to_switch_mac.setdefault(dpid,{})
        dp_ports = msg.ports 
        for k,v in dp_ports.items():
            self.port_to_switch_mac[dpid][k] = v.hw_addr
        print 'ports initialize\n'        


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.port_to_switch_mac[dpid][port_no] = msg.desc.hw_addr
            LOG.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            if self.port_to_switch_mac.has_key(dpid):
                if self.port_to_switch_mac[dpid].has_key(port_no):
                    del self.port_to_switch_mac[dpid][port_no]
            LOG.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            LOG.info("port modified %s", port_no)
        else:
            LOG.info("Illeagal port state %s %s", port_no, reason)   
