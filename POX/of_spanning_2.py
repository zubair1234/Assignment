#https://github.com/yonatang/networks-pa1/blob/master/pox/samples/of_learning_switch_spanning_tree.py


""" 
OpenFlow Exercise - Sample File
This file was created as part of the course Advanced Workshop in IP Networks
in IDC Herzliya.

This code is based on the official OpenFlow tutorial code.

This code implements the switch with spanning tree exercise 
"""
import utils 
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet      import ethernet
from pox.lib.packet.lldp          import lldp, chassis_id, port_id, end_tlv
from pox.lib.packet.lldp          import ttl
from threading import Lock
from datetime import datetime

log = core.getLogger()

class Discovery:
    '''
    This class learn the network topology, and saves it in the DataModel class
    its sends periodic (every DISCOVERY_INTERVAL ) LLDP packets to all connected switches, and updated the topology accordingly
    in addition its also remove links from the graph when they didn't been active for the X seconds or an indication for link loss occours  
    '''
    __metaclass__ = utils.SingletonType
  
    LLDP_DST_ADDR  = '\x01\x80\xc2\x00\x00\x0e'
    DISCOVERY_INTERVAL = 1
    REMOVE_EXPIRED_INTERVAL = 3

    def __init__(self):
        '''
        Constructor
        '''        
        self.connected_switches = []
        self.discovery_timer = utils.Timer(Discovery.DISCOVERY_INTERVAL, self._send_discovery_packets, [], True)
        self.remove_expired_timer = utils.Timer(Discovery.REMOVE_EXPIRED_INTERVAL, self._remove_expired_links, [], True)
        self.graph = DataModel()
        self.handlers = []
        self.change_lock = Lock()
    
    def _remove_expired_links(self):
        expired_links=self.graph.get_expired_links()
        if len(expired_links) > 0:
            #log.debug('Discovery: removing %i expired links %s' %(len(expired_links),expired_links)) 
            for (a,port1,b,port2) in expired_links:
                if self.graph.link_is_dead(a, port1, b, port2):
                    log.debug('Link is removed due to [timeout]: (%i %i)<->(%i %i)' % (a,port1,b,port2))
            self._tree_changed()
    
    def _send_discovery_packets(self):
        '''
            sends discovery packets to all connected switches
        '''
        #log.debug('Discovery: sending LLDP to %i connected switches' % (len(self.connected_switches)) )        
        for switch_event in self.connected_switches:
            self._send_LLDP_to_switch(switch_event)

    def _send_LLDP_to_switch(self,event):
        '''
        sending lldp packet to all of a switch ports        
        :param event: the switch ConnectionUp Event
        '''
        dst = Discovery.LLDP_DST_ADDR
        for p in event.ofp.ports:
            if p.port_no < of.OFPP_MAX:  # @UndefinedVariable
                # Build LLDP packet
                src = str(p.hw_addr)
                port = p.port_no

                lldp_p = lldp() # create LLDP payload
                ch_id=chassis_id() # Add switch ID part
                ch_id.fill(ch_id.SUB_LOCAL,bytes(hex(long(event.dpid))[2:-1])) # This works, the appendix example doesn't
                #ch_id.subtype=chassis_id.SUB_LOCAL
                #ch_id.id=event.dpid
                lldp_p.add_tlv(ch_id)
                po_id = port_id() # Add port ID part
                po_id.subtype = 2
                po_id.id = str(port)
                lldp_p.add_tlv(po_id)
                tt = ttl() # Add TTL
                tt.ttl = 1
                lldp_p.add_tlv(tt)
                lldp_p.add_tlv(end_tlv())
                
                ether = ethernet() # Create an Ethernet packet
                ether.type = ethernet.LLDP_TYPE # Set its type to LLDP
                ether.src = src # Set src, dst
                ether.dst = dst
                ether.payload = lldp_p # Set payload to be the LLDP payload
                
                # send LLDP packet
                pkt = of.ofp_packet_out(action = of.ofp_action_output(port = port))
                pkt.data = ether
                event.connection.send(pkt)  
            
    def _handle_ConnectionUp(self, event):
        '''
        Will be called when a switch is added.
        save the connection event in self.connected_switches 
        Use event.dpid for switch ID, and event.connection.send(...) to send messages to the switch.
        '''
        self.connected_switches.append(event)
        self.set_LLDP_rule(event.connection)
        log.debug('Discovery: switch %i connected'%(event.dpid))
        self.graph.switch_is_up(event.dpid)
        
    def set_LLDP_rule(self,connection):
        '''
        set a flow rule in the switch
        to pass all LLDP packets to the controller
        '''
        # should i delete old rules ?
                
        fm = of.ofp_flow_mod()
        fm.match.dl_type = ethernet.LLDP_TYPE
        fm.match.dl_dst = Discovery.LLDP_DST_ADDR

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=of.OFPP_CONTROLLER)  # @UndefinedVariable
        fm.actions.append(action)
        # Send message to switch
        connection.send(fm)
        
    def _handle_ConnectionDown(self, event):
        '''
        Will be called when a switch goes down. Use event.dpid for switch ID.
        '''
        event_to_delete = [up_event for up_event in self.connected_switches if up_event.dpid == event.dpid][0]
        self.connected_switches.remove(event_to_delete)
        log.debug('Discovery: switch %i disconnected'%(event.dpid))
        
        removed_links=self.graph.switch_is_down(event.dpid)
        for (s1,p1,s2,p2) in removed_links:
            log.debug('Link is removed due to [switch %i is down]: (%i %i)<->(%i %i)' % (event.dpid,s1,p1,s2,p2))
        self._tree_changed()
        
    def _handle_PortStatus(self, event):
        '''
        Will be called when a link changes. Specifically, when event.ofp.desc.config is 1, it means that the link is down. Use event.dpid for switch ID and event.port for port number.
        '''
        dpid=event.dpid
        port=event.port
        if event.ofp.desc.config == 1:
            log.debug('[switch %i]: port %i was disconnected'%(dpid, port))
            links = self.graph.get_all_links_for_switch_and_port(dpid, port)
            for (s1,p1,s2,p2) in links:
                if self.graph.link_is_dead(s1, p1, s2, p2):
                    log.debug('Link is removed due to [port closed]: (%i %i)<->(%i %i)' % (s1,p1,s2,p2))
            if (len(links)>0):
                self._tree_changed()
            
                
    def _handle_PacketIn(self, event):
        '''
        Will be called when a packet is sent to the controller. Same as in the previous part. Use it to find LLDP packets (event.parsed.type == ethernet.LLDP_TYPE) and update the topology according to them.
        '''
        if event.parsed.type != ethernet.LLDP_TYPE:
            return
        
        pkt = event.parsed
        lldp_p = pkt.payload
        ch_id = lldp_p.tlvs[0]
        po_id = lldp_p.tlvs[1]
        src_dpid = int(ch_id.id)
        src_port = int(po_id.id)
        #log.debug("Received a LLDP packet on switch %i from %i" % (event.dpid,src_dpid))
        if self.graph.link_is_alive( src_dpid, src_port, event.dpid, event.port):
            #a new link
            log.debug("New link was found: (%i %i)<->(%i %i)" % (src_dpid,src_port,event.dpid,event.port))
        
        self._tree_changed()
            
        
    def register_tree_change(self,handler):
        '''
        Add a listener for topology change event
        '''
        self.handlers.append(handler)

    def _tree_changed(self):
        '''
        Will notify handlers which links are allowed and which links are forbidden
        '''
        self.change_lock.acquire()
        try:
            allowed=self.graph.get_all_allowed_links()
            forbidden=self.graph.get_all_forbidden_links()
            to_add=self.graph.get_enteries_to_add()
            to_remove=self.graph.get_enteries_to_remove()
            for handler in self.handlers:
                handler.handle(allowed,forbidden)
            
            for (s1,p1,s2,p2) in to_add:
                self.graph.enteries_added(s1, p1, s2, p2)
                
            for (s1,p1,s2,p2) in to_remove:
                self.graph.enteries_removed(s1, p1, s2, p2)
        finally:    
            self.change_lock.release()
            
###########################################################################################################################
#
# Data model classes
#
###########################################################################################################################
class LinkData:
    def __init__(self, port1, port2):
        self.last_sync = datetime.now()
        self.port1 = port1
        self.port2 = port2
        self.is_link_allowed = True
        self.has_entry = False

class SwitchData:
    def __init__(self):
        self.uf_rank = 0
        self.uf_parent = None

class DataModel:
    def __init__(self):
        self.graph = utils.Graph()

    """Should be called whenever an indication received, that a new switch is up"""
    def switch_is_up(self, switch_id):
        self.graph.add_node(switch_id, SwitchData())
        
    """Should be called whenever an indication received, that a switch is down.
    Returns the list of links that were removed"""
    def switch_is_down(self, switch_id):
        removed_links = []
        if switch_id in self.graph.nodes:
            self.graph.remove_node(switch_id)
            to_delete = []
            for (a,b) in self.graph.edges:
                if a == switch_id or b == switch_id:
                    to_delete.append((a,b))
            for (a,b) in to_delete:
                data = self.graph.edges[(a,b)]
                removed_links.append(a,data.port1,b,data.port2)
                self.graph.delete_edge(a, b)
            self.update_spanning_tree()
        return removed_links

    """Should be called whenever an indication received, that a link is down.
    Returns True if this link wasn't already dead"""
    def link_is_dead(self, s1_id, port1, s2_id, port2):
        link = self.graph.get_edge(s1_id, s2_id)
        if link != None and self.__check_ports(link, port1, port2):
            self.graph.delete_edge(s1_id, s2_id)
            self.update_spanning_tree()
            return True
        else:
            return False
              
    """Should be called whenever an indication received, that a link between two switches is alive.
    Returns True if this is a new link"""
    def link_is_alive(self, s1_id, port1, s2_id, port2):
        link = self.graph.get_edge(s1_id, s2_id)
        if link == None:
            link = LinkData(port1, port2)
            self.graph.add_edge(s1_id, s2_id, link)
            self.update_spanning_tree()
            return True
        else:
            link.last_sync = datetime.now()
            return False
            
    def get_all_links_for_switch_and_port(self,s_id,port):
        res = []
        for (a,b) in self.graph.edges:
            data = self.graph.edges[(a,b)]
            if (a==s_id) and (data.port1==port):
                res.append((a,data.port1,b,data.port2))
            if (b==s_id) and (data.port2==port):
                res.append((a,data.port1,b,data.port2))
        return res

    """Returns all the links which haven't shown life signs for more than 6 seconds.
       This method should be called from a different thread every 3 seconds.
       Each returned link should result with two entries removal.
       Also, link_is_dead() should be called for each returned link."""
    def get_expired_links(self):
        res = []
        now = datetime.now()
        for (a,b) in self.graph.edges:
            data = self.graph.edges[(a,b)]
            diff = now - data.last_sync
            if diff.seconds > 6:
                res.append((a,data.port1,b,data.port2))
        return res

    def __check_ports(self, link, port1, port2):
        return (link.port1 == port1 and link.port2 == port2) or (link.port1 == port2 and link.port2 == port1)

    """Should be called after a switches table entry is removed by the controller.
       Both entries on both sides of the link should be removed before calling this method"""
    def enteries_removed(self, s1_id, port1, s2_id, port2):
        link = self.graph.get_edge(s1_id, s2_id)
        if self.__check_ports(link, port1, port2):
            link.has_entry = False

    """Should be called after a switches table entry is added by the controller.
       Both entries on both sides of the link should be added before calling this method"""
    def enteries_added(self, s1_id, port1, s2_id, port2):
        link = self.graph.get_edge(s1_id, s2_id)
        if self.__check_ports(link, port1, port2):
            link.has_entry = True

    """Indicates whether a link is a part of the spanning tree, and is allowed to be used."""
    def is_link_allowed(self, s1_id, port1, s2_id, port2):
        link = self.graph.get_edge(s1_id, s2_id)
        return (link.is_link_allowed and self.__check_ports(link, port1, port2))
 
    """Returns all allowed links. Might be unuseful."""
    def get_all_allowed_links(self):
        res = []
        for (a,b) in self.graph.edges:
            data = self.graph.edges[(a,b)]
            if self.is_link_allowed(a, data.port1, b, data.port2):
                res.append((a,data.port1,b,data.port2))
        return res

    """Returns all forbidden links. Might be unuseful."""
    def get_all_forbidden_links(self):
        res = []
        for (a,b) in self.graph.edges:
            data = self.graph.edges[(a,b)]
            if not self.is_link_allowed(a, data.port1, b, data.port2):
                res.append((a,data.port1,b,data.port2))
        return res

    """Returns all the links that are forbidden, and the relevant entries haven't been removed yet by the controller."""
    def get_enteries_to_remove(self):
        res = []
        for (a,b) in self.graph.edges:
            data = self.graph.edges[(a,b)]
            if not self.is_link_allowed(a, data.port1, b, data.port2) and data.has_entry:
                res.append((a,data.port1,b,data.port2))
        return res

    """Returns all the links that are allowed, and the relevant entries haven't been added yet by the controller."""
    def get_enteries_to_add(self):
        res = []
        for (a,b) in self.graph.edges:
            data = self.graph.edges[(a,b)]
            if self.is_link_allowed(a, data.port1, b, data.port2) and not data.has_entry:
                res.append((a,data.port1,b,data.port2))
        return res

    """Updates the spanning tree. There is no need to call it, as it is called automatically in specific methods."""
    def update_spanning_tree(self):
        for v in self.graph.nodes:
            data = self.graph.nodes[v]
            utils.UnionFind.make_set(data)
        for (a,b) in self.graph.edges:
            data = self.graph.edges[(a,b)]
            data.is_link_allowed = False;
        for (a,b) in self.graph.edges:
            data1 = self.graph.nodes[a]
            data2 = self.graph.nodes[b]
            data = self.graph.edges[(a,b)]
            if utils.UnionFind.find(data1) != utils.UnionFind.find(data2):
                data.is_link_allowed = True;
                utils.UnionFind.union(data1, data2)
                
    def filter_forbidden_links(self, list_of_links):
        res = []
        for (a,port1,b,port2) in list_of_links:
            if self.is_link_allowed(a, port1, b, port2):
                res.append((a,port1,b,port2))
        return res
    
###########################################################################################################################
#
# The spanning tree switch
#
###########################################################################################################################            
class Switch (object):
    """
    A Switch object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__ (self, connection):
        self.connection = connection
        # This maps ethernet address to a port
        self.ports = {}
        # The discovery singleton
        self.discovery=Discovery()
        # This holds the forbidden links (links that are not part of the spanning tree)
        self.forbidden_ports=[]
        
        # This binds our PacketIn event listener
        connection.addListeners(self)
        # This binds the discovery PacketIn event listener
        connection.addListeners(self.discovery)
        # This binds the switch to topology changes
        self.discovery.register_tree_change(self)
        

    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """
  
        packet = event.parsed # Packet is the original L2 packet sent by the switch
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
    
        packet_in = event.ofp # packet_in is the OpenFlow packet sent by the switch
    
        self.act_like_switch(packet, packet_in)
    
    def remove_flow_rule(self, dst_eth, port):
        """
        Remove every flow rule that matched the dl_dst=dst_eth, excluding LLDP-forwarding-to-controller rule 
        """
        flow_msg=of.ofp_flow_mod()
        flow_msg.match.dl_dst=dst_eth
        flow_msg.command=of.OFPFC_DELETE
        self.connection.send(flow_msg)
        #After removing a flow rule, add back the "forward LLDP packet to controller" rule 
        self.discovery.set_LLDP_rule(self.connection)
        log.debug('[switch %i] flow record removed: match[dl_dst=%s] -> out_port=%i' % (self.connection.dpid, dst_eth, port))
        
    def _flood(self, packet_in):
        
        ports=self.connection.features.ports
        
        buffer_id = packet_in.buffer_id
        raw_data = packet_in.data
        in_port=packet_in.in_port
        msg=of.ofp_packet_out()
        if buffer_id != -1 and buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if raw_data is None:
                # No raw_data specified -- nothing to send!
                return
            msg.data = raw_data
            
        for port in ports:
            port_no=port.port_no
            # do not flood backwards, do not flood the controller and do not flood over links that are not part of the spanning tree
            if (port_no < of.OFPP_MAX) and (port_no != in_port) and (port_no not in self.forbidden_ports):
                #print '[switch %i] (flooding) adding action from in_port=%i to out_port=%i' % (self.connection.dpid, in_port,port_no)
                action = of.ofp_action_output(port = port_no)
                msg.actions.append(action)
        
        self.connection.send(msg)
    
    def handle(self, allowed_links, forbidden_links):
        """
        Implement the topology-change handler 
        """
        dpid=self.connection.dpid
        new_forbidden_ports=[]
        new_allowed_ports=[]
        
        for (s1,p1,s2,p2) in forbidden_links:
            #Learn about all forbidden links that are relevant to this switch
            if (s1==dpid):
                new_forbidden_ports.append(p1)
            if (s2==dpid):
                new_forbidden_ports.append(p2)
        
        for (s1,p1,s2,p2) in allowed_links:
            #Learn about all allowed links that are relevant to this switch
            if (s1==dpid):
                new_allowed_ports.append(p1)
            if (s2==dpid):
                new_allowed_ports.append(p2)
        
        
                
        for port in new_forbidden_ports:
            if port not in self.forbidden_ports:
                # this is a new forbidden port
                log.debug("[switch %i] spanning tree disabled port %i" % (dpid,port))
                
                for (eth,e_port) in self.ports.items():
                    # flow rule exists, remove it
                    if e_port==port:
                        self.remove_flow_rule(eth, port)

        for port in new_allowed_ports:
            if port in self.forbidden_ports:
                # this is a new allowed link. just log it
                log.debug("[switch %i] spanning tree enabled port %i" % (dpid,port))
                        
        self.forbidden_ports=new_forbidden_ports
                
        
    def act_like_switch(self, packet, packet_in):
        """
        Implement switch-like behavior
        """
        eth_src = packet.src
        eth_dst = packet.dst
        buffer_id = packet_in.buffer_id
        raw_data = packet_in.data
        in_port = packet_in.in_port
        
        # don't act on LLDP packets at all
        if packet.type == ethernet.LLDP_TYPE:
            return
        
        # don't act on packet that comes from a forbidden link 
        if in_port in self.forbidden_ports:
            return
        
        # packet came from unexpected port
        if (eth_src in self.ports) and (self.ports[eth_src] != packet_in.in_port):
            self.remove_flow_rule(eth_src, self.ports[eth_src])
        
        # learn locally about the port for this Ethernet address port
        # don't add a rule yet, because we need to filter packets by the in_port as well
        self.ports[eth_src] = packet_in.in_port
        
        if eth_dst in self.ports:
            # we know everything in order to set the flowtable rule now
            out_port = self.ports[eth_dst]
            msg = of.ofp_flow_mod()
            msg.match.dl_dst = eth_dst
            msg.match.in_port = in_port
            msg.match.dl_src = eth_src
            log.debug('[switch %i] flow record added: match[in_port=%i,dl_src=%s,dl_dst=%s] -> out_port=%i' % (self.connection.dpid, in_port, eth_src, eth_dst, out_port))
            msg.in_port = in_port
            if buffer_id != -1 and buffer_id is not None:
                # We got a buffer ID from the switch; use that
                msg.buffer_id = buffer_id
            else:
                # No buffer ID from switch -- we got the raw data
                if raw_data is None:
                    # No raw_data specified -- nothing to send!
                    return
                msg.data = raw_data
        
            # Add an action to send to the specified port
            action = of.ofp_action_output(port = out_port)
            msg.actions.append(action)
        
            # Send message to switch
            self.connection.send(msg)
        else:
            log.debug('[switch %i] flooding packet [dl_src=%s,dl_dst=%s,in_port=%i]' % (self.connection.dpid, eth_src, eth_dst, in_port))
            self._flood(packet_in)
                  
            
        

def launch ():
    """
    Starts the component
    """
    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Switch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
