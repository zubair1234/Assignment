import array
import time
import ConfigParser

import interceptor
import probe

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.lib.packet.dhcp import options
from ryu.lib.packet.udp import udp
from ryu.lib import addrconv

DHCP_SERVER_OUT_PORT = -1
DHCP_SERVER_DISCOVERED = False
DHCP_SERVER_FLOW = False
WAN_OUT_PORT = -1
WAN_ROUTER_DISCOVERED = False
DB_CONNECTION_LIVE = False

class Carrier(app_manager.RyuApp):
        
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    global i, pr
    i = interceptor.Interceptor()
    pr = probe.Probe()

    def __init__(self, *args, **kwargs):
        super(Carrier, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #Let's start implementing some configuration file support
        config = ConfigParser.RawConfigParser()
        configFileName = '/root/binaries/ryu/ryu/app/carrier/carrier.cfg'
        self.logger.info("[ADMIN] (Carrier) Loading configuration file [%s]" % (configFileName))
        config.read(configFileName)
        #controller identifier
        self.CONTROLLER_MAC = config.get('global', 'CONTROLLER_MAC')
        #anonymous unicast addressing
        self.CONTROLLER_SPECIAL_IP = config.get('global', 'CONTROLLER_SPECIAL_IP')
        self.CONTROLLER_SPECIAL_MAC = config.get('global', 'CONTROLLER_SPECIAL_MAC')
        #get information about the router
        self.ROUTER_IP = config.get('global', 'ROUTER_IP')
        self.ROUTER_MAC = config.get('global', 'ROUTER_MAC')
        #get information about known AAA services
        self.DHCP_SERVER_MAC = config.get('aaa', 'DHCP_SERVER_MAC')
        
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("[ADMIN] switch_features_handler(self, ev)")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)


    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def switch_enter_handler(self, ev):
        global DB_CONNECTION_LIVE
        self.logger.info("[ADMIN] switch_enter_handler(self, ev)")
        dp = ev.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        if ev.state == MAIN_DISPATCHER:
            self.logger.info("Switch entered: %s", dp.id)
            i.discover_dhcp_server(dp,ofproto,parser)  
            self.discover_router(dp,ofproto,parser)
            DB_CONNECTION_LIVE = pr.connect()
        elif ev.state == DEAD_DISPATCHER:
            if dp.id is None:
                return
            self.logger.info("Switch left: %s", dp.id)

    
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst)
        datapath.send_msg(mod)


    def delete_flow(self, datapath, priority, match): 
        self.logger.info("[ADMIN] delete_flow(self, '%s', '%s', '%s')", datapath, priority, match)
        ofproto = datapath.ofproto 
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,priority=priority, match=match)
        datapath.send_msg(mod)
    
    
    def discover_router(self, datapath, ofproto, parser):
        ##arp for the router first, to learn its out port
        ##form the ARP req
        a_hwtype = 1
        a_proto = ether.ETH_TYPE_IP
        a_hlen = 6
        a_plen = 4
        a_opcode = 1 #request1
        a_srcMAC = self.CONTROLLER_SPECIAL_MAC
        a_srcIP = self.CONTROLLER_SPECIAL_IP
        a_dstMAC = self.ROUTER_MAC
        a_dstIP = self.ROUTER_IP
        p = packet.Packet()
        e = ethernet.ethernet(a_dstMAC,a_srcMAC,ether.ETH_TYPE_ARP)
        a = arp.arp(a_hwtype,a_proto,a_hlen,a_plen,a_opcode,a_srcMAC,a_srcIP,a_dstMAC,a_dstIP)
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        #send packet out
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=p.data)
        datapath.send_msg(out)
        dpid = datapath.id
        self.logger.info("packet out dpid:'%s' src:'%s' dst:'%s' out_port:'OFPP_FLOOD'", dpid, self.CONTROLLER_SPECIAL_MAC, self.ROUTER_MAC)
        self.logger.info("[ADMIN] Attempting to discover WAN router... ")
    
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global DHCP_SERVER_OUT_PORT
        global DHCP_SERVER_DISCOVERED
        global DHCP_SERVER_FLOW
        global WAN_OUT_PORT
        global WAN_ROUTER_DISCOVERED
        global DB_CONNECTION_LIVE

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        protocols = i.get_protocols(pkt)

        eth = protocols['ethernet']
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        
        self.logger.info("packet in dpid:'%s' src:'%s' dst:'%s' in_port:'%s'", dpid, eth.src, eth.dst, in_port)
        
        if DB_CONNECTION_LIVE:
            ## check if MAC is in database (basic DB function test)
            ## or if it's a control mac address
            db_check = pr.authenticator_get_token_id(str(eth.src))
            if db_check != None or str(eth.src) == self.CONTROLLER_MAC or str(eth.src) == self.ROUTER_MAC or str(eth.src) == self.DHCP_SERVER_MAC:
                # if we get here then the mac address associated with this
                # packet is in fact in safe
                self.logger.info("[ADMIN] Client '%s' is valid!", eth.src)   
                if db_check != None:
                    self.logger.info("[ADMIN] Client '%s' is a customer in database!", eth.src)
            else:
                ## else we have no awareness about who is trying to send this packet through our 
                ## BRAS - drop it on the floor
                self.logger.info("[ADMIN] Client '%s' is not a valid client!", eth.src)
                return
                
        d_pkt = packet.Packet(array.array('B', msg.data)) # detailed packet
        
        #dhcp_d = i.detect_dhcp_discover(pkt)
        dhcp_o = i.detect_dhcp_offer(pkt)
        #dhcp_r = i.detect_dhcp_request(pkt)
        dhcp_a = i.detect_dhcp_ack(pkt)
        dhcp_nak = i.detect_dhcp_nak(pkt)
        #dhcp_dec = i.detect_dhcp_decline(pkt)
        dhcp_rel = i.detect_dhcp_release(pkt)

##############################################################        
        if eth.src == self.DHCP_SERVER_MAC and not DHCP_SERVER_DISCOVERED:
            DHCP_SERVER_OUT_PORT = in_port
            self.logger.info("[ADMIN] Discovered the local DHCP server source port on local bridge -> port %s",DHCP_SERVER_OUT_PORT)
            self.mac_to_port[dpid][eth.src] = in_port
            DHCP_SERVER_DISCOVERED = True
            
            #add all client -> server control flows once
            if DHCP_SERVER_FLOW == False:      
                ## add control flows for dhcp messages
                self.logger.info("[ADMIN] Add DHCP control flows between DHCP Server and all clients")
                actions = [parser.OFPActionOutput(DHCP_SERVER_OUT_PORT)]
                match = parser.OFPMatch(eth_dst='ff:ff:ff:ff:ff:ff', eth_type=0x0800, ip_proto=17, udp_src=68, udp_dst=67)
                self.add_flow(datapath,200,match,actions)
                match = parser.OFPMatch(eth_dst=eth.src, eth_type=0x0800, ip_proto=17, udp_src=68, udp_dst=67) #eth_dst = DHCP server
                self.add_flow(datapath,200,match,actions)
                DHCP_SERVER_FLOW = True
        
##############################################################        
        if eth.src == self.ROUTER_MAC and not WAN_ROUTER_DISCOVERED:
            WAN_OUT_PORT = in_port
            self.logger.info("[ADMIN] Discovered the WAN accessible port on local bridge -> port %s",WAN_OUT_PORT)
            self.mac_to_port[dpid][eth.src] = in_port
            WAN_ROUTER_DISCOVERED = True
            
##############################################################        
        #if dhcp_d and DHCP_SERVER_DISCOVERED:
            ## broadcast from client to server
            ## forward the discovery to the server 
            ## dhcp discovery will not be seen by ryu as these
            ## packets already match existing control flows
        
##############################################################       
        if dhcp_o and DHCP_SERVER_DISCOVERED:
            ## direct from server to client
            ## forward the ack to the client as a flow doesn't
            ## yet exist for this
            protocols = i.get_protocols(pkt) 
            ipv4 = protocols['ipv4']
            self.logger.info("[ADMIN] [DHCPO] DHCP Offer of '%s' sent from DHCP server to client destination MAC: '%s'", ipv4.dst, eth.dst)
            
            if eth.dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][eth.dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            data = None
            
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
            self.logger.info("dhcp_o -> packet out dpid:'%s' out_port:'%s'", datapath.id, in_port)
            datapath.send_msg(out)

##############################################################
        #if dhcp_r and DHCP_SERVER_DISCOVERED:
            ## broadcast from client to server
            ## forward the request to the server 
            ## dhcp request will not be seen by ryu as these
            ## packets already match existing control flows
            
##############################################################
        if dhcp_a and DHCP_SERVER_DISCOVERED:
            ## direct from server to client
            ## forward the ack to the client as a flow doesn't
            ## yet exist for this
            protocols = i.get_protocols(pkt) 
            ipv4 = protocols['ipv4']
            self.logger.info("[ADMIN] [DHCPA] DHCP Ack sent from DHCP server to client destination MAC: '%s'", eth.dst)

            if eth.dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][eth.dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            data = None
            
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
            self.logger.info("dhcp_a -> packet out dpid:'%s' out_port:'%s'", datapath.id, in_port)
            datapath.send_msg(out)
            
            ## create WAN-accessible flows here
            ## client --> WAN
            self.logger.info("[ADMIN] Adding WAN-accessible flow for client '%s'", eth.dst)
            actions = [parser.OFPActionOutput(WAN_OUT_PORT)]    
            match = parser.OFPMatch(in_port=self.mac_to_port[dpid][eth.dst], eth_src=eth.dst)
            self.add_flow(datapath, 100, match, actions)
            
            ## WAN --> client
            self.logger.info("[ADMIN] Adding WAN-->Client flow") 
            actions = [parser.OFPActionOutput(self.mac_to_port[dpid][eth.dst])]
            match = parser.OFPMatch(eth_dst=eth.dst)
            self.add_flow(datapath,101,match,actions)

            
##############################################################            
        if dhcp_nak and DHCP_SERVER_DISCOVERED:
            ## broadcast from server to client
            ## forward the nack to the client as a flow doesn't
            ## yet exist for this
            if eth.dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][eth.dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            data = None
            
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=in_port, actions=actions, data=data)
            self.logger.info("dhcp_nak -> packet out dpid:'%s' out_port:'%s'", datapath.id, in_port)
            datapath.send_msg(out)
            
##############################################################
        ##if dhcp_dec and DHCP_SERVER_DISCOVERED:
            ## broadcast from client to server
            ## forward the decline to the server 
            ## dhcp declines will not be seen by ryu as these
            ## packets already match existing control flows
            

 ##############################################################           
        if dhcp_rel and DHCP_SERVER_DISCOVERED:
            ## direct packet to server from client
            ## remove any WAN-accessible flows here
            self.logger.info("[ADMIN] dhcp_rel Removing temporary flows between WAN and client '%s'", eth.dst)
            ## client --> WAN
            match = parser.OFPMatch(in_port=self.mac_to_port[dpid][eth.dst],eth_src=eth.dst)
            self.delete_flow(datapath,100,match)
            
            ## WAN --> client
            match = parser.OFPMatch(eth_dst=eth.dst)
            self.delete_flow(datapath,101,match)
