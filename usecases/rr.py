 
import thread
import logging
import json
import time

from ryu.topology import switches , event , api
from ryu.base import app_manager
from ryu.controller import ofp_event 
from ryu.controller.handler import MAIN_DISPATCHER , CONFIG_DISPATCHER , DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp
from ryu.ofproto import ether
from ryu.lib import ofctl_v1_3
from ryu.app.ofctl import service
from ryu.lib import mac as mac_lib
from ryu.lib import addrconv
from ryu.lib.port_no import port_no_to_str
from ryu.controller import handler
from ryu.controller import dpset
from ryu.lib import stplib
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from ryu.lib.ofctl_v1_3 import get_flow_stats,get_port_stats
from switch import Port , Switch
import algorithm

import matplotlib.pyplot as plt
from networkx.readwrite import json_graph 
import networkx as nx


ARP = arp.arp.__name__
LOG = logging.getLogger(__name__)

def format_dpid_str(dpid_str):
        dpid_str = ':'.join([dpid_str[i:i + 2] for i in range(0, len(dpid_str), 2)])
        return dpid_str

def hex2decimal(hex):
    i = int(hex, 16)
    return str(i)

def getPeriodicStats(dp):
    """show periodic stats on screen

    :param dp: the datapath from which the stats shall be shown for network debugging and Malicious attacks """
    waiters = {}
    while True:
        get_flow_stats(dp, waiters)
        get_port_stats(dp, waiters)
        time.sleep(1)


class configuration(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION ,ofproto_v1_2.OFP_VERSION, ofproto_v1_0.OFP_VERSION]
    #The contexts are necessary for some events and resources.
    _CONTEXTS = { 'switches': switches.Switches}  # used for EventLinkAdd
                   
    
    
    def __init__(self, *args, **kwargs):
        super(configuration, self).__init__(*args, **kwargs)
        self.mac_table={}
        self.mac_to_port= {}
        self.graph =nx.Graph() # Graph plotting
        self.do_once=0
        self.switch_list={} # required for storing nodes in topology 
        self.links={}  # Required for storing links in topology   
        self.mst =[] # stores minimum spanning tree path
        self.dpid_to_switch={}
        self.sw_list_body=[]
        self.link_list_body ={}
        self.routing_algo = algorithm.Dijkstra(self.dpid_to_switch)
        self.ports = []
        self.paths = []

    def add_link(self):
       """Add links to the topology graph 
        Extracts link information stored in link dictionary

        important fields:
        link.src.dpid
        link.dst.dpid """
       
       for link in self.links :
         
               
               src_port = link.src.port_no
               dst_port = link.dst.port_no
               src_dpid = format_dpid_str(dpid_to_str(link.src.dpid))
               dst_dpid = format_dpid_str(dpid_to_str(link.dst.dpid))
               src_port_id = src_dpid + str(src_port)
               dst_port_id = dst_dpid + str(dst_port)
             
#               e = ((link.src.dpid , link.src.port_no) , (link.dst.dpid , link.dst.port_no))
               self.graph.add_edge(link.src.dpid , link.dst.dpid)
#               self.graph.add_edge(*e)
               print(self.graph.edges())

    def add_switch(self):
        """Add switches to the topology graph
        Extracts switches information stored in switch_list dictionary

        important fields:
        switch.dp.id """
        print('self.sw_list_body {}'.format(self.sw_list_body))
 


        
        for index,switch in enumerate( self.switch_list):
#            dpid = format_dpid_str(dpid_to_str(switch.dp.id))
            self.graph.add_node(switch.dp.id)
            dpid=switch.dp.id
  
 
#            dpid = hex2decimal(switch['ports']['dpid'])            
#            self.graph.add_node(switch['ports']['dpid'])
        
#            for node in switch["ports"]:
#                dpid = hex2decimal(node['dpid'])
#               self.graph.add_node(dpid)
        print(self.graph.nodes())
        nx.draw(self.graph)
        plt.show()


    def create_spanning_tree(self):
        """Builds and display topology graph and that run minimum spanning tree algorithm

        important fields:
        self.switch_list: Nodes are extracted and stored in dictionary from the LLDP based topology 
        self.links: links are extracted and stored in dictionary from the LLDP based topology
        self.add_switch: function is called to build topology graph and add nodes
        self.add_link: function is called to add link to the topology
        self.mst : minimum spanning tree is created and path is stored in the dictionary"""

        self.switch_list = api.get_all_switch(self)
        self.links = api.get_all_link(self)
        self.sw_list_body =json.dumps([ switch.to_dict() for switch in self.switch_list])
        
        
        self.add_switch()  
        self.add_link()
        nx.draw(self.graph)
        plt.show()

        self.mst = nx.minimum_spanning_tree(self.graph)
        print self.mst
        print(self.mst.nodes())
        print(self.mst.edges())
        nx.draw(self.mst)
        plt.show()
        
        x = nx.connected_components(self.mst)
        print x      
        
 #       shortest_path1=nx.shortest_path(self.mst,2)
 #       print shortest_path1
 #       shortest_path2=nx.shortest_path(self.mst,1,3)
#        print shortest_path2
#        shortest_path3 = nx.shortest_path(self.mst,1,2)
#        print shortest_path3          

        return self.mst

    def shortest_path(self, dpid):
        
        shortest_path = []
        shortest_path = nx.shortest_path(self.mst,dpid)
        
        print shortest_path

        return shortest_path          

    def deploy_flow_entry(self, datapath, switch_list, match): 
       """ Function required for adding Flows in the switch 
       """
       
       ofproto = datapath.ofproto
       parser = datapath.ofproto_parser
       priority_mac = 4
 #     switch_list = [ 1 ,2 ,3]
       
       length = len(self.mst)
       print length
       print 'fuckeeeeeeeeeeeeeeeeeer'
       print self.mst
       if length == 3:
           for i in xrange(length-1):
               this_switch = switch_list[i]
               next_switch = switch_list[i + 1]
               print this_switch
               print next_switch
               outport_no = 5
               print 'for fuck sake'


           actions = [datapath.ofproto_parser.OFPActionOutput(outport_no)]

           inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                          actions)]
           out = parser.OFPFlowMod(datapath=datapath, priority=30, match=match,instructions=inst)
        
#           datapath.send_msg(out)
           datapath.send_msg(out)
           LOG.info('Flow entry deployed to %s', this_switch)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
       """ A Function that describes the switch features. 
           This will be used to install proactive flows in the switch
       """

       msg=ev.msg
       datapath = msg.datapath
       print ( 'Features_Handler ' ) 
       parser = datapath.ofproto_parser
       priority_arp = 1
       priority_icmp = 3
       priority_mac = 4
       cookie = 1 
       dpid = datapath.id 
   

    @set_ev_cls(ofp_event.EventOFPPacketIn,[ MAIN_DISPATCHER, DEAD_DISPATCHER])
    def packet_in_handler(self, ev):
       """A Function that deals with Packet in event.Minimum spanning tree is created and calculated
          from the extracted topology for the very first time.Handler  will be modifed for installation of Flow rules 
       """

       if self.do_once == 0:
            time.sleep(1)
            self.create_spanning_tree()
            self.do_once = 1

       msg = ev.msg                    
       datapath = msg.datapath          
       ofproto = datapath.ofproto       
       parser = datapath.ofproto_parser
       in_port = msg.match['in_port'] 
       
       pkt = packet.Packet(msg.data)
       eth = pkt.get_protocol(ethernet.ethernet)

       dst = eth.dst
       src = eth.src

       dpid = datapath.id
       self.shortest_path(dpid)
 
       print('packet_in: dpid {} src {} dst {}'.format(dpid,src,dst))

       self.mac_to_port.setdefault(dpid, {})
       
       self.mac_to_port[dpid][src] = in_port

       if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
       
  
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
       
    def port_status_handler(self,ev):
       """Handler used to handle port status
           Displays the topology and port information in case of Port modfictation event 
       """
       msg=ev.msg
       reason=msg.reason
       dp=msg.datapath
       ofpport = msg.desc
       port_no = msg.desc.port_no
       ofproto = dp.ofproto
       if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
	    pass
       elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
	    pass
       elif reason == ofproto.OFPPR_MODIFY:

            self.logger.info("port modified %s", port_no)
	    
       else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
	    pass


 
       sw_list = api.get_all_switch(self)
       sw_list_body =json.dumps([ switch.to_dict() for switch in sw_list])
       print('sw_list_body {}'.format(sw_list_body))

       link_list = api.get_all_link(self)
       link_list_body = json.dumps([ link.to_dict() for link in link_list ])
       print('link_list_body {}'.format(link_list_body))

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER,DEAD_DISPATCHER])
    def state_change_handler(self, ev):                                 ## to do add flow in switch enter hander and switch leave handler
         """Update topology graph when a switch enters or leaves.
         ev -- datapath event and all of it's fields

         important fields:
         ev.dp.id: dpid that is joining or leaving
         ev.enter is true if the datapath is entering and false if it is leaving
         """

         
         dp=ev.datapath
#         ports = ev.datapath.ports
         ofproto = dp.ofproto
         parser = dp.ofproto_parser   


                          
         assert dp is not None
         if dp.id is None:
            return
 

         if ev.state == MAIN_DISPATCHER:

            match = parser.OFPMatch()
            switch_list = []
            for i in self.dpid_to_switch:
               switch_list.append(i)

            self.deploy_flow_entry(dp,switch_list,match)

            if not self.graph.has_node(dp.id):
#             dpid = format_dpid_str(dpid_to_str(dp.id))
              self.graph.add_node(dp.id)
              thread.start_new(getPeriodicStats, (dp,))
              self.logger.info('Switch %s added to the topology', str(dp.id))
#             for port in ev.datapath.ports: 
#                  ports = []
#                  ports=dp.ports
#                  out_port = ports[port][0] 
#                  print out_port
#                  print 'fuck'
#                  actions =[]
#              actions = [parser.OFPActionOutput(out_port)]
#              self.add_flow( dp ,0 ,match , actions)
                   

         elif ev.state == DEAD_DISPATCHER:
            if dp.id is None:
                return
            if self.graph.has_node(dp.id):
              self.graph.remove_node(dp.id)
              self.logger.info('Switch %s removed from the topology',
                              str(dp.id))

         nx.draw(self.graph)
         plt.show()


         LOG.debug(dp)         
# INSTALL DEFAULT FLOW

    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    
    def switch_enter_handler(self, event):
        # very strangely, EventSwitchEnter happens after 
        # EventOFPSwitchFeatures sometimes

        dpid = event.switch.dp.id
        try:
            s = self.dpid_to_switch[dpid]
        except KeyError:
            s = Switch(event.switch.dp)
            self.dpid_to_switch[dpid] = s
            self.routing_algo.topology_last_update = time.time()
            print self.routing_algo.topology_last_update 
        print self.dpid_to_switch
#        self._pre_install_flow_entry(s)
    
    def _update_port_link(self, dpid, port):
        switch = self.dpid_to_switch[dpid]
        p = switch.ports.get(port.port_no, None)
        if p:
            p.peer_switch_dpid = port.peer_switch_dpid
            p.peer_port_no = port.peer_port_no
        else:
            switch.ports[port.port_no] = port

        peer_switch = self.dpid_to_switch[port.peer_switch_dpid]
        switch.peer_to_local_port[peer_switch] = port.port_no
        print switch.peer_to_local_port           
        print 'fuck u florian'

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, event):
        try:
            del self.dpid_to_switch[event.switch.dp.id]
            self.routing_algo.topology_last_update = time.time()
        except KeyError:
            pass    

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_handler(self, ev):
        """Add new links to the topology graph
        ev -- LinkAdd event and all of it's fields.

        important fields:
        ev.link.src: tuple (srcdpid, srcport)
        ev.link.dst: tuple (dstdpid, dstport)"""
        src = ev.link.src
        dst = ev.link.dst


        src_port = Port(port = ev.link.src, peer = ev.link.dst)
        dst_port = Port(port = ev.link.dst, peer = ev.link.src)
        self._update_port_link(src_port.dpid, src_port)
        self._update_port_link(dst_port.dpid, dst_port)
        self.routing_algo.topology_last_update = time.time()


        if src.dpid is None or dst.dpid is None:
            return
        
        if not self.graph.has_edge(src.dpid, dst.dpid):
            self.graph.add_edge(src.dpid, dst.dpid)
            self.graph[src.dpid][dst.dpid][src.dpid] = src.port_no
            self.graph[src.dpid][dst.dpid][dst.dpid] = dst.port_no
            self.logger.info('Link Detected, topology so far: %s',
                         str(self.graph.edges()))     
            nx.draw(self.graph)
            plt.show()
            print src.port_no
            print dst.port_no
            self.mst = nx.minimum_spanning_tree(self.graph)
            print self.mst
            print(self.mst.nodes())
            print(self.mst.edges())
            nx.draw(self.mst)
            plt.show()

       
    def _delete_link(self, port):
        try:
            switch = self.dpid_to_switch[port.dpid]
            p = switch.ports[port.port_no]
        except KeyError:
            return

        p.peer_switch_dpid = None
        p.peer_port_no = None
        print 'fuck u raumer'

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete(self, ev):
        
        """Delete links to the topology graph
        ev -- LinkDelete event and all of it's fields.

        important fields:
        ev.link.src: tuple (srcdpid, srcport)
        ev.link.dst: tuple (dstdpid, dstport)"""
        src = ev.link.src
        dst = ev.link.dst

        try:
            switch_1 = self.dpid_to_switch[ev.link.src.dpid]
            switch_2 = self.dpid_to_switch[ev.link.dst.dpid]
            del switch_1.peer_to_local_port[switch_2]
            del switch_2.peer_to_local_port[switch_1]
        except KeyError:
            return

        self._delete_link(ev.link.src)
        self._delete_link(ev.link.dst)
        self.routing_algo.topology_last_update = time.time()        
        

        if src.dpid is None or dst.dpid is None:
             return
        if self.graph.has_edge(src.dpid, dst.dpid):  
        
           self.graph.remove_edge(src.dpid, dst.dpid)
           self.logger.info('Link Removed, topology so far: %s',
                          str(self.graph.edges()))
           nx.draw(self.graph)
           plt.show()
           self.mst = nx.minimum_spanning_tree(self.graph)
           print self.mst
           print(self.mst.nodes())
           print(self.mst.edges())
           nx.draw(self.mst)
           plt.show()


    @set_ev_cls(event.EventPortAdd)
    def port_add_handler(self, event):
        port = Port(event.port)
        switch = self.dpid_to_switch[port.dpid]
        switch.ports[port.port_no] = port
#        witch.update_from_config(self.switch_cfg)
        self.routing_algo.topology_last_update = time.time()


    @handler.set_ev_cls(event.EventPortModify)
    def port_modify_handler(self, ev):         
        """Handler that logs port modifiction messages"""

        LOG.debug(ev)


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        """Handler that monitors the number of packets flowing from a particular flow. Can be used for attack forensic"""

        msg = ev.msg
        dp = msg.datapath
        print "Flows on datapath ", dp.id
        flows = msg.body
        i = 1
        for flow in flows:
            print "Flow %d" % i
            print "Hard timeout: %d, Idle timeout: %d" % (flow.hard_timeout, flow.idle_timeout)
            print "Flow packet count: %d" % flow.packet_count
            print "Flow duration: %d" % flow.duration_sec
            print "Flow match:", flow.match
            print "Actions:", flow.instructions[0].actions
            i += 1
        print "\n"
        print self.dpid_to_switch



    @set_ev_cls(event.EventPortDelete)
    def port_delete_handler(self, event):
        port = Port(event.port)
        try:
            switch = self.dpid_to_switch[port.dpid]
            del switch.ports[port.port_no]
            self.routing_algo.topology_last_update = time.time()
        except KeyError:
            pass

     
