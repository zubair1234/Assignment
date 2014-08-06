__author__ = 'wiman'

from Multicast import Multicast

'''
multi = Multicast()
multi._organized_process()
print multi.wrotten_ports
'''

from ryu.ofproto import ofproto_v1_3
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.lib.packet import ethernet, ipv4, udp
from ryu.lib.packet import packet
from ryu.ofproto import ether

class Proto(object):
    ETHER_IP = 0x800
    ETHER_ARP = 0x806
    IP_UDP = 17
    IP_TCP = 6
    TCP_HTTP = 80
    UDP_DNS = 53

def init_mac_ip(switches_num):
    mac2ip = []
    for i in range(switches_num):
        mac2ip.append([])
    mac2ip[0].append('00:00:00:00:00:01')
    mac2ip[0].append('10.0.0.1')
    mac2ip[2].append('00:00:00:00:00:06')
    mac2ip[2].append('10.0.0.6')
    mac2ip[3].append('00:00:00:00:00:07')
    mac2ip[3].append('10.0.0.7')
    mac2ip[6].append('00:00:00:00:00:0d')
    mac2ip[6].append('10.0.0.13')
    mac2ip[9].append('00:00:00:00:00:14')
    mac2ip[9].append('10.0.0.20')
    return mac2ip


class Controllerinterface(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(Controllerinterface, self).__init__(*args, **kwargs)
        multi = Multicast()
        multi._organized_process()
        self.mac_ip = init_mac_ip(multi.switches)
        self.ports = multi.wrotten_ports
        self.head_switch = multi.head
        self.proxy_port = multi.proxy_port
        self.group_port = multi.group_port
        print self.mac_ip
        #print self.ports

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath = datapath, priority = priority, match = match, instructions = inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        topo_id = dp.id - 1
        #print topo_id
        if topo_id == self.head_switch:                                     # source node
            # add the flow from proxy_port -> group_port
            actions = [ofp_parser.OFPActionOutput(self.group_port)]
            match = ofp_parser.OFPMatch(in_port=self.proxy_port)
            self.add_flow(dp, 2, match, actions)

            data = None
            if msg.buffer_id == ofp.OFP_NO_BUFFER:
                data = msg.data
            out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=self.proxy_port,
                                          actions=actions, data=data)
            dp.send_msg(out)

            buckets = []
            for port in self.ports[topo_id]:
                actions = [ofp_parser.OFPActionOutput(port)]
                buckets.append(ofp_parser.OFPBucket(weight=0, watch_port=0, watch_group=0, actions=actions))

            req = ofp_parser.OFPGroupMod(datapath=dp, command=ofp.OFPFC_ADD,
                                         type_=ofp.OFPGT_ALL, group_id=0, buckets=buckets)
            dp.send_msg(req)
            match = ofp_parser.OFPMatch(in_port=self.group_port)
            actions = [ofp_parser.OFPActionGroup(0)]
            self.add_flow(dp, 2, match, actions)
        else:
            pkt = packet.Packet(msg.data)
            eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
            if eth_pkt.ethertype != Proto.ETHER_IP:
                return
            ip_pkt = pkt.get_protocols(ipv4.ipv4)[0]
            if ip_pkt.proto != Proto.IP_UDP:
                return

            if len(self.ports[topo_id]) >= 1: # multicast
                #match = ofp_parser.OFPMatch()
                for port in self.ports[topo_id]:
                    pkt = packet.Packet(msg.data)
                    if port <= 2:  #reform packets
                        eth_pkt = pkt.get_protocols(ethernet.ethernet)[0]
                        ip_pkt = pkt.get_protocols(ipv4.ipv4)[0]
                        udp_pkt = pkt.get_protocols(udp.udp)[0]
                        eth_src = eth_pkt.src
                        eth_dst = self.mac_ip[topo_id][0]
                        ipv4_src = ip_pkt.src
                        ipv4_dst = self.mac_ip[topo_id][1]
                        udp_srcport = udp_pkt.src_port
                        udp_dstport = udp_pkt.dst_port
                        p = self.redefine_udp_packet(eth_src, eth_dst, ipv4_src, ipv4_dst, udp_srcport, udp_dstport, pkt.__getitem__(3))
                        out = ofp_parser.OFPPacketOut(datapath= dp,actions=[ofp_parser.OFPActionOutput(port)],
                                                      in_port=1, buffer_id=0xffffffff, data=p.data)
                        dp.send_msg(out)
                    else:
                        msg_cpy = msg.data
                        req = ofp_parser.OFPPacketOut(
                        datapath = dp,
                        actions = [ofp_parser.OFPActionOutput(port)],
                        in_port = 1,
                        buffer_id = 0xffffffff,
                        data = msg_cpy
                        )
                        dp.send_msg(req)

    #reform the packets

    def redefine_udp_packet(self, eth_src, eth_dst, ipv4_src, ipv4_dst, inport, outport, data):
        ethertype = 0x800 #ether.ETH_TYPE_8021Q
        eth_packet = ethernet.ethernet(eth_dst, eth_src, ethertype)
        ip_packet = ipv4.ipv4(4, 5, 0, 0, 0, 0, 0, 255, 17, 0, ipv4_src, ipv4_dst)
        udp_packet = udp.udp(inport, outport, 0, 0)
        p = packet.Packet()
        p.add_protocol(eth_packet)
        p.add_protocol(ip_packet)
        p.add_protocol(udp_packet)
        p.add_protocol(data)
        p.serialize()
        return p

