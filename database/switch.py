import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from bulbs.titan import Graph,Config
import ryu.topology.api
import time

'''Table mapping devices to switch ports'''
switch_port_to_host = {
                's1-eth1':'00:00:00:00:00:01',
                's4-eth1':'00:00:00:00:00:04',
                's2-eth1':'00:00:00:00:00:02',
                's5-eth1':'00:00:00:00:00:05',
                's3-eth1':'00:00:00:00:00:03',
                's6-eth1':'00:00:00:00:00:06'
               };

'''Helper function to format dpid_str''' 
def format_dpid_str(dpid_str):
	dpid_str = ':'.join([dpid_str[i:i + 2] for i in range(0, len(dpid_str), 2)])
	return dpid_str

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.do_once = 0
        self.switch_list = {}
        self.links = {}
        '''formatted data for the vertices'''             
       	self.switches = [] 
        self.ports = [] 
        self.devices = [] 
        '''Graph vertices on Titan Db'''
        self.switch_vertices = []
        self.port_vertices = []
        self.device_vertices = []
        config = Config('http://192.168.241.192:8182/graphs/graph')
        self.g = Graph()

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    '''Function to create vertices for the switches in the topology.key for switch vertices in the "formatted dpid"'''
    def create_switch_vertices(self):
        for index,switch in enumerate(self.switch_list):
	       dpid_str = format_dpid_str(dpid_to_str(switch.dp.id))
	       self.switches.append({'state':'active','dpid':dpid_str,'type':'switch'})
	       v = self.g.vertices.get_or_create('dpid',dpid_str,{'state':'active','dpid':dpid_str,'type':'switch'})
	       self.switch_vertices.append(v)
	else:
	    self.display_list(self.switches)
 
    '''Function to create port vertices for the switch ports in the topology.key for port vertices is the "formatted port_id"'''
    def create_port_vertices(self):
        for index,switch in enumerate(self.switch_list):
	 	    for port in switch.ports:
                        desc = port.name
                        hw_addr = port.hw_addr
                        state = 'active'
                        port_state = 1
                        number = port.port_no
                        dpid_s = format_dpid_str(dpid_to_str(port.dpid))
                        port_id = dpid_s + str(number)
                        self.ports.append({'desc':desc,'port_id':port_id,'state':state,'port_state':port_state,'number':number,'type':'port'})
                        v = self.g.vertices.get_or_create('port_id',port_id,{'desc':desc,'port_id':port_id,'state':state,'port_state':port_state,'number':number,'type':'port'})
                        self.port_vertices.append(v)
	else:
		    self.display_list(self.ports)
    
    '''Function to create device vertices in the topology.key for device vertices is the "dl_addr"'''
    def create_device_vertices(self):
        for value in switch_port_to_host.values():
            self.devices.append({'state':'active','dl_addr':value,'type':'device'})
            v = self.g.vertices.get_or_create('dl_addr',value,{'state':'active','dl_addr':value,'type':'device'})
            self.device_vertices.append(v)
        else:
            self.display_list(self.devices)	

    '''Helper function to retrieve unique switch vertex using key'''
    def get_unique_switch_vertex(self,dpid_str):
        return self.g.vertices.index.get_unique( "dpid", dpid_str) 	

    '''Helper function to retrieve unique port vertex using key'''
    def get_unique_port_vertex(self, port_id_str):
        return self.g.vertices.index.get_unique( "port_id", port_id_str)
 
    '''Helper function to retrieve unique device vertex using key'''
    def get_unique_device_vertex(self,dl_addr_str):
        return self.g.vertices.index.get_unique( "dl_addr", dl_addr_str)	

    '''Helper function to create an outgoing edge from vertex1 to vertex2'''	
    def create_outgoing_edge(self,vertex1,vertex2):
        edge = self.g.edges.create(vertex1,"out",vertex2)
        edge2 = self.g.edges.get(edge.eid)
        assert edge == edge2
        edge2.save	

    '''Helper function to create an incoming edge from vertex1 to vertex2'''
    def create_incoming_edge(self,vertex1,vertex2):
        edge = self.g.edges.create(vertex1,"in",vertex2)
        edge2 = self.g.edges.get(edge.eid)
        assert edge == edge2
        edge2.save
    
    '''Helper function to create an "link" edge from vertex1 to vertex2'''
    def create_link_edge(self,vertex1,vertex2):
        edge = self.g.edges.create(vertex1,"link",vertex2)
        edge2 = self.g.edges.get(edge.eid)
        assert edge == edge2
        edge2.save

    def get_unique_incoming_vertex(self,vertex):
        v_list = vertex.inV()
        for v in v_list:
            in_vert = v 
        return in_vert

    def is_connected(self,portA, portB):
    	return portA.both("link").retain([portB]).hasNext()

    '''function to create port to switch edges''' 
    def create_port_to_switch_edges(self):
        for port in self.ports:
            for switch in self.switches:
                dpid_str = switch["dpid"]
                port_id_str = port["port_id"]
                if port_id_str[0:len(port_id_str)-1] == dpid_str:
                    sw_vertex = self.get_unique_switch_vertex(dpid_str)
                    port_vertex = self.get_unique_port_vertex(port_id_str)
                    #print('Creating edge between {} and {}'.format(dpid_str,port_id_str))
                    self.create_outgoing_edge(sw_vertex,port_vertex)
				
    '''function to create port to device edges'''
    def create_port_to_device_edges(self):
        for port in self.ports:
            desc_str = port["desc"]
            port_id_str = port["port_id"]
            for value in switch_port_to_host.keys():
                if desc_str == value:
                    port_vertex  = self.get_unique_port_vertex(port_id_str)
                    device_vertex = self.get_unique_device_vertex(switch_port_to_host[value])
                    #print('Creating edge between {} and {}'.format(port_id_str,switch_port_to_host[value]))
                    self.create_outgoing_edge(port_vertex,device_vertex)
    
    '''function to create links between relavent switch ports'''
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
        self.create_switch_vertices()
        self.create_port_vertices()
        self.create_device_vertices()
        self.create_port_to_switch_edges()
        self.create_port_to_device_edges()
        self.create_switch_to_switch_links()

    def display_list(self,lst):
        for l in lst:
            #print l
            pass

    
    def compute_path(self,src,dst,datapath):
        src_node = self.get_unique_device_vertex(src)	
        dst_node = self.get_unique_device_vertex(dst)	
        src_node_port = self.get_unique_incoming_vertex(src_node)
        dst_node_port = self.get_unique_incoming_vertex(dst_node)
        dst_switch = self.get_unique_incoming_vertex(dst_node_port)
        src_switch = self.get_unique_incoming_vertex(src_node_port)
        dst_sw_port_list = dst_switch.outV()
        src_sw_port_list = src_switch.outV()
        print('COMPUTE PATH src mac {} dst mac {} switch dpid {}'.format(src,dst,datapath.id))

        
        for port in dst_sw_port_list:
                if port != dst_node_port:
                    dst_sw_other_ports = port
        for port in src_sw_port_list:
            if port != src_node_port:
                src_sw_other_ports = port


        MatchSrcMac = src
        MatchDstMac = dst
        src_switch_dpid = src_switch.dpid
        dst_switch_dpid = dst_switch.dpid
        src_port = src_node_port.number
        dst_port = dst_node_port.number 		
        data_path_summary = str(src_port) + '/' + src_switch_dpid + '/' + str(src_sw_other_ports.number) + ',' + str(dst_sw_other_ports.number) + '/' + dst_switch_dpid + '/' + str(dst_port)

        flow = self.g.vertices.get_or_create('MatchDstMac',dst,
                          {'MatchSrcMac':src,'MatchDstMac':dst,
                           'src_switch_dpid':src_switch_dpid,
                           'dst_switch_dpid':dst_switch_dpid,
                           'data_path_summary':data_path_summary,
                           'type':'flow',
                           'user_state':'FE_USER_MODIFY'})

        #create flow entries for source switch
        if src_switch_dpid == format_dpid_str(dpid_to_str(datapath.id)): 
            switch_dpid = src_switch_dpid
            actionOutputPort = src_sw_other_ports.number
            MatchInPort = src_port
            switch_dpid_port = (switch_dpid + str(MatchInPort))
            print('CREATING flow entry for src switch dpid {} dst MAC addr {} and KEY {}'.format(src_switch_dpid,dst,switch_dpid_port))

            #creating flow_entry node for src switch	
            fe1 = self.g.vertices.get_or_create('switch_dpid_port',switch_dpid_port,
                          {'actionOutputPort':actionOutputPort,
                           'switch_dpid_port':switch_dpid_port,
                           'switch_dpid':switch_dpid,
                           'switch_state':'FE_SWITCH_UPDATED',
                           'matchInPort': MatchInPort,
                           'type': 'flow_entry',
                           'user_state':'FE_USER_ADD',
                           'actions': {'type':'ACTION_OUTPUT', 'action':{'port':actionOutputPort, 'maxLen':0}}}) 
            
            switch_dpid = src_switch_dpid
            actionOutputPort = src_port
            MatchInPort = src_sw_other_ports.number
            switch_dpid_port = (switch_dpid + str(MatchInPort))
            print('CREATING flow entry for src switch dpid {} dst MAC addr {} and KEY {}'.format(src_switch_dpid,dst,switch_dpid_port))
            
            #creating flow_entry node for src switch	
            fe2 = self.g.vertices.get_or_create('switch_dpid_port',switch_dpid_port,
                          {'actionOutputPort':actionOutputPort,
                           'switch_dpid_port':switch_dpid_port,
                           'switch_dpid':switch_dpid,
                           'switch_state':'FE_SWITCH_UPDATED',
                           'matchInPort': MatchInPort,
                           'type': 'flow_entry',
                           'user_state':'FE_USER_ADD',
                           'actions': {'type':'ACTION_OUTPUT', 'action':{'port':actionOutputPort, 'maxLen':0}}}) 

            switch_list = self.g.vertices.index.lookup(dpid=switch_dpid)
            for sw in switch_list:
                sw_vertex = sw
        
        #create flow entries for dst switch
        if dst_switch_dpid == format_dpid_str(dpid_to_str(datapath.id)):
            switch_dpid = dst_switch_dpid
            actionOutputPort = dst_node_port.number
            MatchInPort = dst_sw_other_ports.number
            switch_dpid_port = (switch_dpid + str(MatchInPort))
            print('CREATING flow entry for dst switch dpid {} dst MAC addr {} and KEY {}'.format(dst_switch_dpid,dst,switch_dpid_port))
        
            #create flow_entry node for dst switch
            fe1 = self.g.vertices.get_or_create('switch_dpid_port',switch_dpid_port,
                          {'actionOutputPort':actionOutputPort,
                           'switch_dpid_port':switch_dpid_port,
                           'switch_dpid':switch_dpid,
                           'switch_state':'FE_SWITCH_UPDATED',
                           'matchInPort': MatchInPort,
                           'type': 'flow_entry',
                           'user_state':'FE_USER_ADD',
                           'actions': {'type':'ACTION_OUTPUT', 'action':{'port':actionOutputPort, 'maxLen':0}}}) 

            switch_dpid = dst_switch_dpid
            actionOutputPort = dst_sw_other_ports.number
            MatchInPort = dst_node_port.number
            switch_dpid_port = (switch_dpid + str(MatchInPort))
            print('CREATING flow entry for dst switch dpid {} dst MAC addr {} and KEY {}'.format(dst_switch_dpid,dst,switch_dpid_port))
            
            #create flow_entry node for dst switch
            fe2 = self.g.vertices.get_or_create('switch_dpid_port',switch_dpid_port,
                          {'actionOutputPort':actionOutputPort,
                           'switch_dpid_port':switch_dpid_port,
                           'switch_dpid':switch_dpid,
                           'switch_state':'FE_SWITCH_UPDATED',
                           'matchInPort': MatchInPort,
                           'type': 'flow_entry',
                           'user_state':'FE_USER_ADD',
                           'actions': {'type':'ACTION_OUTPUT', 'action':{'port':actionOutputPort, 'maxLen':0}}}) 
        
            switch_list = self.g.vertices.index.lookup(dpid=switch_dpid)
            for sw in switch_list:
                sw_vertex = sw
       
        #self.g.scripts.update('/home/karthik/Projects/ryu_extras/rexster-console-2.3.0/is_connected.groovy')   # add file to scripts index
        #script = self.g.scripts.get('isConnected')     # get a function by its name
        #params = dict(portA=flow,portB=fe1)       # put function params in dict
        #items = self.g.gremlin.query(script, params)
        self.create_outgoing_edge(flow,fe1)
        self.create_outgoing_edge(flow,fe2)
        self.create_outgoing_edge(fe1,sw_vertex)	
        self.create_outgoing_edge(fe2,sw_vertex)	
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
	
        if self.do_once == 0:
            time.sleep(1)
            self.create_topology_vertices()
            self.do_once = 1


        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        if dst not in switch_port_to_host.values():
            return
            
        if src not in switch_port_to_host.values():
            return
        
        self.compute_path(src,dst,datapath)
        dpid = datapath.id
        print('packet_in: dpid {} src {} dst {}'.format(dpid,src,dst))
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        
        fe_key = format_dpid_str(dpid_to_str(datapath.id)) + str(msg.in_port)
        fe_list = self.g.vertices.index.lookup(switch_dpid_port=fe_key)
        for fe in fe_list:
            print('flow entries for switch {} has output port {} action {}'.format(fe.switch_dpid,fe.actionOutputPort,fe.actions))
            outport = fe.actionOutputPort
        
        actions = [datapath.ofproto_parser.OFPActionOutput(outport)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            #self.logger.info("port added %s", port_no)
	    pass
        elif reason == ofproto.OFPPR_DELETE:
            #self.logger.info("port deleted %s", port_no)
	    pass
        elif reason == ofproto.OFPPR_MODIFY:
            #self.logger.info("port modified %s", port_no)
	    pass
        else:
            #self.logger.info("Illeagal port state %s %s", port_no, reason)
	    pass
    
