""" Authors: Golan Parashi 032158008, Avi Lachmish 025292194, Dudu Ben Ari 031377179 """

from utils import SingletonType, Timer, UnionFind
from collections import namedtuple, defaultdict
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.core import core
import time


log = core.getLogger()
EventContinue = (False, False)
EventHalt = (True, False)


class Tutorial(object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__(self, connection):
        self.connection = connection
        self._mac_to_in_port = dict()

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # This binds our _handle_port_authorization_changed event listener
        self._discovery_component = core.discovery
        self._discovery_component.add_port_authorization_listener(self.connection.dpid, self)
        self._unauthorized_ports = dict()

    def _handle_port_authorization_changed(self, dpid, port_no, authorized):
        """ called when port authorization was changed during spanning tree calculation """

        # we are only interested in ports that belongs to this switch
        if dpid != self.connection.dpid:
            return

        if authorized:
            # port is authorized
            self._unauthorized_ports.pop(port_no, None)
        else:
            # port is not authorized any more
            self._unauthorized_ports[port_no] = None

            # remove what what we have already learnt on the un-authorized port
            self._mac_to_in_port = {mac: in_port for mac, in_port in self._mac_to_in_port.iteritems()
                                    if in_port != port_no}

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """

        packet = event.parsed  # Packet is the original L2 packet sent by the switch
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # packet_in is the OpenFlow packet sent by the switch

        self.act_like_switch(packet, packet_in)

    def send_packet(self, buffer_id, raw_data, out_port, in_port):
        """
        Sends a packet out of the specified switch port.
        If buffer_id is a valid buffer on the switch, use that. Otherwise,
        send the raw data in raw_data.
        The "in_port" is the port number that packet arrived on.  Use
        OFPP_NONE if you're generating this packet.
        """
        # We tell the switch to take the packet with id buffer_if from in_port
        # and send it to out_port
        # If the switch did not specify a buffer_id, it must have specified
        # the raw data of the packet, so in this case we tell it to send
        # the raw data
        msg = of.ofp_packet_out()
        msg.in_port = in_port
        if buffer_id != of.NO_BUFFER and buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if raw_data is None:
                # No raw_data specified -- nothing to send!
                return
            msg.data = raw_data

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def act_like_switch(self, packet, packet_in):
        """
        Implement switch-like behavior -- if destination is know, send only to the learnt port, otherwise, flood (send
        all packets to all ports besides the input port).
        """

        dpid = self.connection.dpid

        log.debug('act_like_switch: dpid={}, type={}, {}.{} -> {}'
                  .format(dpid, packet.type, packet.src, packet_in.in_port, packet.dst))

        # check if we already know this src
        known_in_port = self._mac_to_in_port.get(packet.src, None)
        if known_in_port:
            # check whether src incoming port was changed
            if known_in_port != packet_in.in_port:
                log.info('src in_port was changed: dpid={}, src={} known in_port={}, new in_port={}'
                         .format(dpid, packet.src, known_in_port, packet_in.in_port))

                self._uninstall_flows(dpid, packet)

                if packet_in.in_port not in self._unauthorized_ports:
                    log.debug('Learning: dpid={}, {} via port {}'.format(dpid, packet.src, packet_in.in_port))
                    self._mac_to_in_port[packet.src] = packet_in.in_port
                else:
                    log.debug('Not learning un-authorized port: dpid={}, in_port={}'.format(dpid, packet_in.in_port))
        else:
            if packet_in.in_port not in self._unauthorized_ports:
                # new authorized src.in_port - learn it
                log.debug('Learning: dpid={}, {} via port {}'.format(dpid, packet.src, packet_in.in_port))
                self._mac_to_in_port[packet.src] = packet_in.in_port
            else:
                log.debug('Not learning un-authorized port: dpid={}, in_port={}'.format(dpid, packet_in.in_port))

        # check if we know in which port the destination is connected to
        known_in_port = self._mac_to_in_port.get(packet.dst, None)
        if known_in_port:
            # install new rule: dst via in_port
            self._install_flow(dpid, packet, packet_in, dst_port=known_in_port)
        else:
            # we do not know in which port destination is connected if at all
            log.debug('Flooding packet: dpid={}, type={}, src={} port={} -> dst={} port={}'
                      .format(dpid, packet.type, packet.src, packet_in.in_port, packet.dst, of.OFPP_FLOOD))

            self.send_packet(packet_in.buffer_id, packet_in.data, of.OFPP_FLOOD, packet_in.in_port)

        log.debug('act_like_switch: finished: dpid={}'.format(dpid))

    def _install_flow(self, dpid, packet, packet_in, dst_port):
        """ Installing rule in switch. Rule is from any source to specific destination and src_port via dst_port """

        log.debug('Installing flow: dpid={}, match={{ dst:{}, in_port:{} }} output via port {}'
                  .format(dpid, packet.dst, packet_in.in_port, dst_port))

        msg = of.ofp_flow_mod()
        msg.match.dl_dst = packet.dst
        msg.match.in_port = packet_in.in_port
        msg.actions.append(of.ofp_action_output(port=dst_port))

        # also send the packet...
        if packet_in.buffer_id != of.NO_BUFFER and packet_in.buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = packet_in.buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if packet_in.data:
                msg.data = packet_in.data

        self.connection.send(msg)

        log.debug('Sending: dpid={}, {}.{} -> {}.{}'.format(dpid, packet.src, packet_in.in_port, packet.dst, dst_port))

    def _uninstall_flows(self, dpid, packet):
        """ Un-installing all rules to specific destination. """

        log.debug('Un-installing flow: dpid={}, match={{ dst:{} }} delete'
                  .format(dpid, packet.src))

        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        msg.match.dl_dst = packet.src

        self.connection.send(msg)


class LLDPMessageBroker(object):
    """ Sends out LLDP discovery packets to all switch neighbours """

    LLDPRawMessage = namedtuple("LLDPMessage", ('dpid', 'port_num', 'raw_lldp_packet'))

    def __init__(self, round_time=1):
        """
        round_time: time in seconds that all LLDP packets must be sent to all neighbours. it can be
                    equals to link timeout at maximum.
        """

        # hold packets that needs to be sent to neighbours.
        self._neighbours_queue = list()

        # hold packets that needs to be sen
        self._send_round_time = round_time

        self._timer = None

        # register for switch events
        core.listen_to_dependencies(self)

    def _handle_openflow_ConnectionUp(self, event):
        """ monitor switch up """

        self._remove_switch(event.dpid, set_timer=False)

        ports = [(port.port_no, port.hw_addr) for port in event.ofp.ports]

        for port_num, port_addr in ports:
            self._add_port(event.dpid, port_num, port_addr, set_timer=False)

        self._set_timer()

    def _handle_openflow_ConnectionDown(self, event):
        """ monitor switch down """

        self._remove_switch(event.dpid)

    def _handle_openflow_PortStatus(self, event):
        """ monitor switch ports """

        if event.added or (event.modified and event.ofp.desc.config == 0):
            self._add_port(event.dpid, event.port, event.ofp.desc.hw_addr)
        elif event.deleted or (event.modified and event.ofp.desc.config == 1):
            self._remove_port(event.dpid, event.port)

    def _remove_switch(self, dpid, set_timer=True):
        self._neighbours_queue = [p for p in self._neighbours_queue if p.dpid != dpid]

        if set_timer:
            self._set_timer()

    def _remove_port(self, dpid, port_num, set_timer=True):
        if port_num >= of.OFPP_MAX:
            return

        self._neighbours_queue = [p for p in self._neighbours_queue if p.dpid != dpid or p.port_num != port_num]

        if set_timer:
            self._set_timer()

    def _add_port(self, dpid, port_num, port_addr, set_timer=True):
        if port_num >= of.OFPP_MAX:
            return

        self._remove_port(dpid, port_num, set_timer=False)

        lldpPacket = self._create_lldp_packet(dpid, port_num, port_addr)
        self._neighbours_queue.append(LLDPMessageBroker.LLDPRawMessage(dpid, port_num, lldpPacket))

        if set_timer:
            self._set_timer()

    def _set_timer(self):
        if self._timer:
            self._timer.stop()

        self._timer = None
        neighbours_count = len(self._neighbours_queue)

        if neighbours_count != 0:
            per_packet_interval = self._send_round_time / float(neighbours_count)
            self._timer = Timer(per_packet_interval, self._timer_handler, recurring=True)

    def _timer_handler(self):
        """ Sending LLDP packets to next neighbour. """

        if len(self._neighbours_queue) > 0:
            item = self._neighbours_queue.pop(0)
            core.openflow.sendToDPID(item.dpid, item.raw_lldp_packet)

            # re-insert the packet for next round
            self._neighbours_queue.append(item)

    def _create_lldp_packet(self, dpid, port_num, port_addr):
        """ Creating LLDP packet """

        chassis_id = pkt.chassis_id(subtype=pkt.chassis_id.SUB_CHASSIS, id=str(dpid))

        port_id = pkt.port_id(subtype=pkt.port_id.SUB_PORT, id=str(port_num))

        ttl = pkt.ttl(ttl=1)

        lldp_packet = pkt.lldp()
        lldp_packet.tlvs.append(chassis_id)
        lldp_packet.tlvs.append(port_id)
        lldp_packet.tlvs.append(ttl)
        lldp_packet.tlvs.append(pkt.end_tlv())

        eth = pkt.ethernet(type=pkt.ethernet.LLDP_TYPE)
        eth.src = port_addr
        eth.dst = pkt.ETHERNET.LLDP_MULTICAST
        eth.payload = lldp_packet

        po = of.ofp_packet_out(action=of.ofp_action_output(port=port_num))
        po.data = eth.pack()
        return po.pack()


class PortAuthorizer(object):
    class Vertex(object):
        def __init__(self, label):
            self.label = label

    def __init__(self):
        # listeners for port authorization change events
        #
        # map: dpid-> list(listener)
        # listener must implement:  def _handle_port_authorization_changed(self, port_no, authorized)
        self._listeners = defaultdict(list)

        # map: switch->port_num->flood_state
        self._former_port_valid_status = defaultdict(lambda: defaultdict(lambda: None))

    def add_listener(self, dpid, listener):
        self._listeners[dpid].append(listener)

    def _handle_openflow_ConnectionUp(self, event):
        self._former_port_valid_status.clear()

    def topology_changed(self, active_links):
        spt = self._spt_from_topology(active_links)

        self._update_switch_from_spt(spt, active_links)

    def _spt_from_topology(self, active_links):
        # v is a set of switches and e is adjacency matrix of the form: src_switch->(dst_switch->port_on_src) which
        # means that src_switch is connected to dst_switch via port_on_src which is located in src_switch.
        G = self._graph_from_topology(active_links)

        # build spanning tree from topology graph.
        # spt is a map: src_switch->set of (dst_switch, port_num) tuple
        spt = self._spt_from_graph(G)

        return spt

    def _graph_from_topology(self, active_links):
        def get_opposite_link(link):
            return Discovery.Link(link[2], link[3], link[0], link[1])

        # edges is adjacency matrix of the form: src_switch->(dst_switch->port_on_src) which
        # means that src_switch is connected to dst_switch via port_on_src which is located in src_switch.
        edges = defaultdict(lambda: defaultdict(lambda: list()))
        switches = set()

        # build edges from all discovered links
        for link in active_links:
            switches.update([link.dpid1, link.dpid2])
            edges[link.dpid1][link.dpid2].append(link)

        # remove links which are not valid in both directions. we need only valid full duplex links so our Tutorial
        # object will learn source of packets correctly
        for src_switch in switches:
            for dst_switch in switches:
                # ignoring same switch
                if src_switch is dst_switch:
                    continue

                # check if src_switch is connected to dst_switch
                if dst_switch not in edges[src_switch]:
                    continue

                # if two switches are connected via several ports, we select only one of them.
                # if we already chose one, there is no need to continue.
                if not isinstance(edges[src_switch][dst_switch], list):
                    continue

                # filter non full duplex links - links that are active in both directions
                is_opposite_link_valid = False
                for link in edges[src_switch][dst_switch]:
                    # check that the link [dst_switch][src_switch] is active
                    if get_opposite_link(link) in active_links:
                        # if two switches are connected via several ports, select only one of them
                        edges[src_switch][dst_switch] = link.port1
                        edges[dst_switch][src_switch] = link.port2
                        is_opposite_link_valid = True
                        break

                # remove links which are only valid for one direction
                if not is_opposite_link_valid:
                    del edges[src_switch][dst_switch]
                    if src_switch in edges[dst_switch]:
                        # also delete the opposite link
                        del edges[dst_switch][src_switch]

        return switches, edges

    def _spt_from_graph(self, G):
        """
        create spt for the graph using Kruskal's algorithm using disjoint sets and tree based
        union-find data structure
        """
        V, E = G

        #map: src_switch->set of (dst_switch, port_num) tuple
        spt = defaultdict(set)

        # map: dpid->set(Vertex(v))
        V = [PortAuthorizer.Vertex(v) for v in V]

        # starting with each switch(vertex) in it own set
        [UnionFind.make_set(v) for v in V]

        switch_map = {v.label: v for v in V}

        if len(switch_map.keys()) > 0:
            for src_switch, edges in E.iteritems():
                for dst_switch, src_port in edges.iteritems():
                    # get the sets where the switches are in
                    src_switch_set = switch_map[src_switch]
                    dst_switch_set = switch_map[dst_switch]

                    # can we add this edge safely without causing a loop?
                    if UnionFind.find(src_switch_set) != UnionFind.find(dst_switch_set):
                        # edge connects disjoint sets - unite the sets
                        UnionFind.union(src_switch_set, dst_switch_set)

                        # update spt with both direction edges
                        spt[src_switch].add((dst_switch, src_port))
                        spt[dst_switch].add((src_switch, E[dst_switch][src_switch]))

        return spt

    def _update_switch_from_spt(self, spt, active_links):
        # spt is a map: src_switch->set of (dst_switch, port_num) tuple

        for src_switch, edges_set in spt.iteritems():
            con = core.openflow.getConnection(src_switch)

            # check that we have a valid connection to the switch
            if not con:
                continue

            # modify switch port's flood flag and remove flows containing invalid ports according spt.
            # ports in spt are enabled for flooding, others are disabled.
            switch_ports_in_spt = [e[1] for e in edges_set]

            for p in con.ports.itervalues():
                if p.port_no >= of.OFPP_MAX:
                    continue

                is_port_valid_for_flood = is_port_valid = p.port_no in switch_ports_in_spt

                #we always enable flooding for ports that are connected to hosts
                if not is_port_valid_for_flood and \
                        self._is_port_not_connected_to_switch(active_links, src_switch, p.port_no):
                    is_port_valid_for_flood = True

                # make modification to port only if state was changed
                if self._former_port_valid_status[src_switch][p.port_no] != is_port_valid:
                    self._former_port_valid_status[src_switch][p.port_no] = is_port_valid

                    if is_port_valid:
                        log.debug('Port enabled by spanning tree: dpid={}, port={}'.format(src_switch, p.port_no))
                    else:
                        log.debug('Port disabled by spanning tree: dpid={}, port={}'.format(src_switch, p.port_no))

                        log.debug('Un-installing flows containing disabled port: dpid={}, match={{ out_port:{} }}'
                                  ' delete'.format(src_switch, p.port_no))

                        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE, out_port=p.port_no)
                        con.send(msg)

                    if is_port_valid_for_flood:
                        log.debug('flooding enabled for port: dpid={}, port={}'.format(src_switch, p.port_no))
                    else:
                        log.debug('flooding disabled for port: dpid={}, port={}'.format(src_switch, p.port_no))

                    # send port modification message to switch configuring its flood flag
                    config = 0 if is_port_valid_for_flood else of.OFPPC_NO_FLOOD
                    msg = of.ofp_port_mod(port_no=p.port_no, hw_addr=p.hw_addr, mask=of.OFPPC_NO_FLOOD, config=config)
                    con.send(msg)

                    # notify all listeners (e.g: Tutorial objects) that port authorization has changed
                    for listener in self._listeners[src_switch]:
                        listener._handle_port_authorization_changed(src_switch, p.port_no, is_port_valid)

    def _is_port_not_connected_to_switch(self, active_links, dpid, port):
        """ check if a port is not connected to another switch """

        for link in active_links:
            if (dpid, port) == (link.dpid1, link.port1):
                return False
            if (dpid, port) == (link.dpid2, link.port2):
                return False

        return True


class Discovery(object):
    __metaclass__ = SingletonType

    LINK_TIMEOUT = 6                 # number of second before link is considered as invalid
    LINK_TIMEOUT_CHECK_INTERVAL = 3  # number of seconds till the next invalid link check is performed

    Link = namedtuple("Link", ("dpid1", "port1", "dpid2", "port2"))

    def __init__(self):
        self._discovered_links = dict()  # maps from discovered link to time stamp
        self._lldpBroker = LLDPMessageBroker()
        self._port_authorizer = PortAuthorizer()

        # listen to events with high priorit so we get them before all others
        core.listen_to_dependencies(self, listen_args={'openflow': {'priority': 0xffffffff}})

        Timer(Discovery.LINK_TIMEOUT_CHECK_INTERVAL, self._remove_expired_links, recurring=True)

    def add_port_authorization_listener(self, dpid, listener):
        self._port_authorizer.add_listener(dpid, listener)

    def _handle_openflow_ConnectionUp(self, event):
        """ Will be called when a switch is added. """

        # forward event to port authorizer so it can do its thing
        self._port_authorizer._handle_openflow_ConnectionUp(event)

        self._install_flow_direct_lldp_packets_to_controller(event.connection)

    def _handle_openflow_ConnectionDown(self, event):
        """ Will be called when a switch goes down. """

        # Delete all links on this switch
        downLinks = [link for link in self._discovered_links if event.dpid in [link.dpid1, link.dpid2]]

        for link in downLinks:
            log.debug('Existing link is removed: ({}, {}) -> ({}, {}), reason=switch is down, dpid={}'
                      .format(link.dpid1, link.port1, link.dpid2, link.port2, event.dpid))

        self._remove_links(downLinks)

    def _handle_openflow_PortStatus(self, event):
        """ monitor switch ports """

        if event.deleted or (event.modified and event.ofp.desc.config == 1):
            downLinks = [link for link in self._discovered_links
                         if (event.dpid, event.port) in [(link.dpid1, link.port1), (link.dpid2, link.port2)]]

            for link in downLinks:
                log.debug('Existing link is removed: ({}, {}) -> ({}, {}), reason=port is down, dpid={}, port={}'
                          .format(link.dpid1, link.port1, link.dpid2, link.port2, event.dpid, event.port))

            self._remove_links(downLinks)

    def _handle_openflow_PacketIn(self, event):
        """ Will be called when a packet is sent to the controller. """
        lldp_pkt = event.parsed

        # we handle only LLDP packets
        if lldp_pkt.effective_ethertype != pkt.ethernet.LLDP_TYPE or lldp_pkt.dst != pkt.ETHERNET.LLDP_MULTICAST:
            return EventContinue

        # parse LLDP packet: extract sender dpid and sender port
        lldp_p = lldp_pkt.payload
        ch_id = lldp_p.tlvs[0]
        po_id = lldp_p.tlvs[1]
        r_dpid = int(ch_id.id)
        r_port = int(po_id.id)

        # log.debug('_handle_openflow_PacketIn-> got LLDP packet: type={}, dpid={}, packet: dpid={}, port={}'
        #           .format(event.parsed.type, event.dpid, r_dpid, r_port))

        if (event.dpid, event.port) == (r_dpid, r_port):
            log.warning('Port received its own LLDP packet: dpid={}, port={} - ignoring'
                        .format(event.dpid, event.port))
            return EventHalt

        # add link or update link time stamp
        link = Discovery.Link(r_dpid, r_port, event.dpid, event.port)

        if link not in self._discovered_links:
            log.info('New link found: ({}, {}) -> ({}, {})'.format(link.dpid1, link.port1, link.dpid2, link.port2))

            self._discovered_links[link] = time.time()
            # update ports on switches
            self._port_authorizer.topology_changed(self._discovered_links.keys())
        else:
            # in any case, update the time stamp
            self._discovered_links[link] = time.time()

        # do not pass LLDP packet to switch
        return EventHalt

    def _remove_links(self, links):
        for link in links:
            del self._discovered_links[link]

        # update ports on switches
        self._port_authorizer.topology_changed(self._discovered_links.keys())

    def _remove_expired_links(self):
        """ Remove apparently dead links """
        now = time.time()

        expired = [link for link, ts in self._discovered_links.iteritems() if ts + Discovery.LINK_TIMEOUT < now]
        if len(expired) > 0:
            for link in expired:
                log.debug('Existing link is removed: ({}, {}) -> ({}, {}), reason=not found for long time '
                          .format(link.dpid1, link.port1, link.dpid2, link.port2))

            self._remove_links(expired)

    def _install_flow_direct_lldp_packets_to_controller(self, connection):
        log.debug('Installing flow to direct LLDP messages to controller: dpid={}, match={{ type:{}, dst:{} }}'
                  'output via port {}'
                  .format(connection.dpid, pkt.ethernet.LLDP_TYPE, pkt.ETHERNET.LLDP_MULTICAST, of.OFPP_CONTROLLER))

        # make sure LLDP packets are sent to the controller so we can handle it
        match = of.ofp_match(dl_type=pkt.ethernet.LLDP_TYPE, dl_dst=pkt.ETHERNET.LLDP_MULTICAST)
        msg = of.ofp_flow_mod()
        msg.priority = 65000
        msg.match = match
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))

        connection.send(msg)


def launch():
    """ Starts the component """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)

    core.register('discovery', Discovery())
    core.openflow.addListenerByName("ConnectionUp", start_switch)
