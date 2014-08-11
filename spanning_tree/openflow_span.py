
import logging
import json

from ryu.topology.switches import Switches
from ryu.topology import api
import networkx as nx
#from ryu.topology import event 
from ryu.base import app_manager
from ryu.controller import ofp_event 
from ryu.controller.handler import MAIN_DISPATCHER , CONFIG_DISPATCHER , DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.controller.controller import Datapath
from ryu.lib.packet import packet, ethernet, arp
from ryu.ofproto import ether
from ryu.lib import ofctl_v1_3
from ryu.app.ofctl import service
from ryu.lib import mac as mac_lib
from ryu.lib import addrconv
from ryu.topology import event
from ryu.lib.port_no import port_no_to_str
from ryu.controller import handler
from ryu.controller import dpset
from ryu.lib import stplib
from ryu.lib.dpid import dpid_to_str
ARP = arp.arp.__name__
LOG = logging.getLogger(__name__)

class configuration(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    #_CONTEXTS = { 'dpset' : dpset.DPSet, }
 
    
    
    def __init__(self, *args, **kwargs):
        super(configuration, self).__init__(*args, **kwargs)
        self.mac_table={}
        self.mac_to_port= {}
        self.graph =nx.Graph()
        self.do_once=0
        self.switch_list={} # required for storing topology 
        self.links={}  # Required for storing topology
    
    def create_link_edge(self,vertex1,vertex2):
        self.graph.add_edge(vertex1,"link",vertex2)
        #edge2 = self.graph.edges.get(edge.eid)
        #assert edge == edge2
        #edge2.save
    
    
    
    def create_switch(self):
        for index,switch in enumerate(self.switch_list):
	     #  dpid_str = format_dpid_str(dpid_to_str(switch.dp.id))
	     # self.switches.append({'state':'active','dpid':dpid_str,'type':'switch'})
	       graph.add_node('dpid',dpid_str,{'state':'active','dpid':dpid_str,'type':'switch'})
	     #  self.switch_vertices.append(v)
    
    def create_switch_to_switch_links(self):
        for link in self.links:
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            src_dpid = format_dpid_str(dpid_to_str(link.src.dpid))
            dst_dpid = format_dpid_str(dpid_to_str(link.dst.dpid))
            src_port_id = src_dpid + str(src_port)
            dst_port_id = dst_dpid + str(dst_port)
            src_port_vertex  = self.get_unique_port_vertex(src_port_id)
            dst_port_vertex  = self.get_unique_port_vertex(dst_port_id)
            self.create_link_edge(src_port_vertex,dst_port_vertex)
            
            
    def create_topology_vertices(self):
        self.switch_list = ryu.topology.api.get_all_switch(self)
        self.links = ryu.topology.api.get_all_link(self)
        self.create_switch()
        self.create_port_vertices()
        self.create_device_vertices()
        self.create_port_to_switch_edges()
        self.create_port_to_device_edges()
        self.create_switch_to_switch_links()
        
        
        
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
         
        msg=ev.msg
        datapath = msg.datapath
        print ( 'Features_Handler ' )
        ofproto = datapath.ofproto 
        of_parser = datapath.ofproto_parser
        priority_arp = 1
        priority_icmp = 3
        priority_mac = 4
        cookie = 1 
        dpid = datapath.id 
    
        if dpid == 2:
           
           match = of_parser.OFPMatch( in_port =1 , arp_op = 1, eth_type = 0x0806, eth_dst='ff:ff:ff:ff:ff:ff', arp_tpa = '10.0.0.2')
           out_port = 2          
           actions = []
           actions.append (of_parser.OFPActionSetField(eth_src='00:00:00:00:00:01'))
           actions.append (of_parser.OFPActionOutput(out_port)) 
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_mac, match=match,instructions=inst)
           datapath.send_msg(out)


           match = of_parser.OFPMatch ( in_port = 1, eth_type = 0x0800 ,ip_proto=1,icmpv4_type = 8, ipv4_src='10.0.0.1', ipv4_dst='10.0.0.2')
           out_port = 2
           actions = []
           actions.append (of_parser.OFPActionOutput(out_port))
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_mac, match=match,instructions=inst)
           datapath.send_msg(out)


          ######################################################################## 
           match = of_parser.OFPMatch ( eth_type = 0x0806 ,arp_op = 2, eth_dst='00:00:00:00:00:01' )
           out_port = 1
           actions=[]
           actions.append (of_parser.OFPActionOutput(out_port))
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_mac, match=match,instructions=inst)
           datapath.send_msg(out)

           match = of_parser.OFPMatch ( eth_type = 0x0800 ,ip_proto=1,icmpv4_type = 0 , ipv4_dst='10.0.0.1')
           out_port = 1
           actions=[]
           actions.append (of_parser.OFPActionOutput(out_port))
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_mac, match=match,instructions=inst)
           datapath.send_msg(out)

           match = of_parser.OFPMatch( in_port =1 , arp_op = 1, eth_type = 0x0806, eth_dst='ff:ff:ff:ff:ff:ff')
           
           out_port = 3
           actions=[]
           actions.append (of_parser.OFPActionOutput(out_port))
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=3, match=match,instructions=inst)
           datapath.send_msg(out)
           
          

           #######################################################################

           match = of_parser.OFPMatch ( in_port = 1, eth_type = 0x0800 ,ip_proto=1,icmpv4_type = 8, ipv4_src='10.0.0.1')
           out_port = 3
           actions = []
           actions.append (of_parser.OFPActionOutput(out_port))
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=2, match=match,instructions=inst)
           datapath.send_msg(out)

           match = of_parser.OFPMatch ( in_port = 3, eth_type = 0x0800 ,ip_proto=1,icmpv4_type = 0 ,ipv4_dst='10.0.0.1') #icmp=0 reply
           out_port = 1
           actions = []
           actions.append (of_parser.OFPActionOutput(out_port))
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=2, match=match,instructions=inst)
           datapath.send_msg(out)           

 
           #########################################################################

        if dpid == 1:
           match = of_parser.OFPMatch( in_port =1 , arp_op = 1, eth_type = 0x0806, eth_dst='ff:ff:ff:ff:ff:ff')
           out_port = 2
           actions = [of_parser.OFPActionOutput(out_port)]
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_arp, match=match,instructions=inst)
           datapath.send_msg(out)

           match = of_parser.OFPMatch( in_port =1 , eth_type = 0x0800,ip_proto=1,icmpv4_type = 8)
           out_port = 2
           actions = [of_parser.OFPActionOutput(out_port )]
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_arp, match=match,instructions=inst)
           datapath.send_msg(out)


           match = of_parser.OFPMatch( in_port =2 )
           out_port = 1
           actions = [of_parser.OFPActionOutput(out_port )]
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_arp, match=match,instructions=inst)
           datapath.send_msg(out)

        if dpid == 3:
           match = of_parser.OFPMatch( in_port = 3 ,  arp_op = 1, eth_type = 0x0806, eth_dst='ff:ff:ff:ff:ff:ff', arp_tpa='10.0.0.3')
           actions = [of_parser.OFPActionOutput(1) ]
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_arp, match=match,instructions=inst)
           datapath.send_msg(out)
           
           match = of_parser.OFPMatch( in_port = 3 ,  arp_op = 1, eth_type = 0x0806, eth_dst='ff:ff:ff:ff:ff:ff', arp_tpa='10.0.0.4')
           actions = [of_parser.OFPActionOutput(2) ]
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_arp, match=match,instructions=inst)
           datapath.send_msg(out)

           match = of_parser.OFPMatch( arp_op = 2, eth_type = 0x0806 )
           actions = [of_parser.OFPActionOutput(3) ]
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=1, match=match,instructions=inst)
           datapath.send_msg(out)

           match = of_parser.OFPMatch( in_port =3 , eth_type = 0x0800,ip_proto=1,icmpv4_type = 8)
           actions = [of_parser.OFPActionOutput(1) ]
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_arp, match=match,instructions=inst)
           datapath.send_msg(out)

           match = of_parser.OFPMatch( eth_type = 0x0800,ip_proto=1,icmpv4_type = 0)
           actions = [of_parser.OFPActionOutput(3) ]
           inst = [of_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
           out = of_parser.OFPFlowMod(datapath=datapath, priority=priority_arp, match=match,instructions=inst)
           datapath.send_msg(out)

           


    @set_ev_cls(ofp_event.EventOFPPacketIn,[ MAIN_DISPATCHER, DEAD_DISPATCHER])
    def packet_in_handler(self, ev):
       
       #sw_list  = get_switch(self, 1)
       #sw_list = api.get_all_switch(self)
       # sw_list_body =json.dumps([ switch.to_dict() for switch in sw_list]) 
       #print('sw_list_body {}'.format(sw_list_body))
       
       #link_list = api.get_all_link(self)
       #link_list_body = json.dumps([ link.to_dict() for link in link_list ])
       #print('link_list_body {}'.format(link_list_body))

       #link_self = api.get_link(self,1)  ## dpid
       #link_body = json.dumps([ link.to_dict() for link in link_self ])
       #print('link_body {}'.format(link_body))

       #link_self = api.get_link(self,2)  ## dpid
       #link_body = json.dumps([ link.to_dict() for link in link_self ])
       #print('link_body {}'.format(link_body))
       
       #link_self = api.get_link(self,3)  ## dpid
       #link_body = json.dumps([ link.to_dict() for link in link_self ])
       #print('link_body {}'.format(link_body))


       msg = ev.msg                     # object which describes the openflow messages must 
       datapath = msg.datapath          # instance that describes and openflowswitch datapath must 
       #print ('Coming from')            # how can i know about the datapath?
       ofproto = datapath.ofproto       # of proto is an instance of the function inhereted by datapath it basically export openflow modules
       parser = datapath.ofproto_parser # encoding and decoding of openflow messages version ?
       in_port = msg.match['in_port']
       out_port = ofproto.OFPP_FLOOD
                                        # always used for Openflow protocols  
       data=msg.data                                 #buffer_id=msg.buffer_id
       actions = [parser.OFPActionOutput(out_port,0)] # prepare openflow messages ofproto_parser OFPxxx (xxx is message) 
       
       out = parser.OFPPacketOut(datapath=datapath,buffer_id = ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=data)
       datapath.send_msg(out)

       Stp.packet_in_handler


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self,ev):
       msg=ev.msg
       reason=msg.reason
       dp=msg.datapath
       ofpport = msg.desc

       Switches.port_status_handler
       print('yes')

       #sw_list  = get_switch(self, 1)
       sw_list = api.get_all_switch(self)
       sw_list_body =json.dumps([ switch.to_dict() for switch in sw_list])
       print('sw_list_body {}'.format(sw_list_body))

       link_list = api.get_all_link(self)
       link_list_body = json.dumps([ link.to_dict() for link in link_list ])
       print('link_list_body {}'.format(link_list_body))


    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER,DEAD_DISPATCHER])
    def state_change_handler(self, ev):
      
       dp=ev.datapath
       assert dp is not None
       LOG.debug(dp)
       
       sw_list = api.get_all_switch(self)
       sw_list_body =json.dumps([ switch.to_dict() for switch in sw_list])
       print('sw_list_body {}'.format(sw_list_body))
       
       link_list = api.get_all_link(self)
       link_list_body =json.dumps([link.to_dict() for link in link_list])
       print ('link_list_body {}' .format(link_list_body))
       Switches.state_change_handler
   
    @handler.set_ev_cls(event.EventPortModify)
    def port_modify_handler(self, ev):
       LOG.debug(ev)


