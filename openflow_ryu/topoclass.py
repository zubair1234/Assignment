import logging
import struct
import time
import json
import array
import socket

from ryu.topology import event
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.exception import RyuException
from ryu.lib import hub
from netgraph import NetGraph
from ryu.lib.mac import DONTCARE_STR, haddr_to_str
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from ryu.lib.port_no import port_no_to_str
from ryu.lib.packet import packet, ethernet, lldp, arp
from ryu.ofproto.ether import ETH_TYPE_LLDP, ETH_TYPE_ARP
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import nx_match
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_3_parser
import redis
import cPickle as pickle
import of_utils
rdb = redis.StrictRedis(db=1)

LOG = logging.getLogger(__name__)






class Port(object):
    # This is data class passed by EventPortXXX
    def __init__(self, dpid, ofproto, ofpport):
        super(Port, self).__init__()

        self.dpid = dpid
        self._ofproto = ofproto
        self._config = ofpport.config
        self._state = ofpport.state

        self.port_no = ofpport.port_no
        self.hw_addr = ofpport.hw_addr
        self.name = ofpport.name

    def is_reserved(self):
        return self.port_no > self._ofproto.OFPP_MAX

    def is_down(self):
        return (self._state & self._ofproto.OFPPS_LINK_DOWN) > 0 \
            or (self._config & self._ofproto.OFPPC_PORT_DOWN) > 0

    def is_live(self):
        # NOTE: OF1.2 has OFPPS_LIVE state
        #       return (self._state & self._ofproto.OFPPS_LIVE) > 0
        return not self.is_down()

    def to_dict(self):
        return {'dpid': dpid_to_str(self.dpid),
                'port_no': port_no_to_str(self.port_no),
                'hw_addr': haddr_to_str(self.hw_addr),
                'name': self.name.rstrip('\0')}

    # for Switch.del_port()
    def __eq__(self, other):
        return self.dpid == other.dpid and self.port_no == other.port_no

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.dpid, self.port_no))

    def __str__(self):
        LIVE_MSG = {False: 'DOWN', True: 'LIVE'}
        return 'Port<dpid=%s, port_no=%s, %s>' % \
            (self.dpid, self.port_no, LIVE_MSG[self.is_live()])


class Switch(object):
    # This is data class passed by EventSwitchXXX
    def __init__(self, dp):
        super(Switch, self).__init__()

        self.dp = dp
        self.ports = []

    def add_port(self, ofpport):
        port = Port(self.dp.id, self.dp.ofproto, ofpport)
        if not port.is_reserved():
            self.ports.append(port)

    def del_port(self, ofpport):
        self.ports.remove(Port(ofpport))

    def to_dict(self):
        d = {'dpid': dpid_to_str(self.dp.id),
             'ports': [port.to_dict() for port in self.ports]}
        return d

    def __str__(self):
        msg = 'Switch<dpid=%s, ' % self.dp.id
        for port in self.ports:
            msg += str(port) + ' '

        msg += '>'
        return msg


class Link(object):
    # This is data class passed by EventLinkXXX
    def __init__(self, src, dst):
        super(Link, self).__init__()
        self.src = src
        self.dst = dst

    def to_dict(self):
        d = {'src': self.src.to_dict(),
             'dst': self.dst.to_dict()}
        return d

    # this type is used for key value of LinkState
    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.src, self.dst))

    def __str__(self):
        return 'Link: %s to %s' % (self.src, self.dst)


class PortState(dict):
    # dict: int port_no -> OFPPort port
    # OFPPort is defined in ryu.ofproto.ofproto_v1_X_parser
    def __init__(self):
        super(PortState, self).__init__()

    def add(self, port_no, port):
        self[port_no] = port

    def remove(self, port_no):
        del self[port_no]

    def modify(self, port_no, port):
        self[port_no] = port


class PortData(object):
    def __init__(self, is_down, lldp_data):
        super(PortData, self).__init__()
        self.is_down = is_down
        self.lldp_data = lldp_data
        self.timestamp = None
        self.sent = 0

    def lldp_sent(self):
        self.timestamp = time.time()
        self.sent += 1

    def lldp_received(self):
        self.sent = 0

    def lldp_dropped(self):
        return self.sent

    def clear_timestamp(self):
        self.timestamp = None

    def set_down(self, is_down):
        self.is_down = is_down

    def __str__(self):
        return 'PortData<live=%s, timestamp=%s, sent=%d>' \
            % (not self.is_down, self.timestamp, self.sent)


class PortDataState(dict):
    # dict: Port class -> PortData class
    # slimed down version of OrderedDict as python 2.6 doesn't support it.
    _PREV = 0
    _NEXT = 1
    _KEY = 2

    def __init__(self):
        super(PortDataState, self).__init__()
        self._root = root = []          # sentinel node
        root[:] = [root, root, None]    # [_PREV, _NEXT, _KEY]
                                        # doubly linked list
        self._map = {}

    def _remove_key(self, key):
        link_prev, link_next, key = self._map.pop(key)
        link_prev[self._NEXT] = link_next
        link_next[self._PREV] = link_prev

    def _append_key(self, key):
        root = self._root
        last = root[self._PREV]
        last[self._NEXT] = root[self._PREV] = self._map[key] = [last, root,
                                                                key]

    def _prepend_key(self, key):
        root = self._root
        first = root[self._NEXT]
        first[self._PREV] = root[self._NEXT] = self._map[key] = [root, first,
                                                                 key]

    def _move_last_key(self, key):
        self._remove_key(key)
        self._append_key(key)

    def _move_front_key(self, key):
        self._remove_key(key)
        self._prepend_key(key)

    def add_port(self, port, lldp_data):
        if port not in self:
            self._prepend_key(port)
            self[port] = PortData(port.is_down(), lldp_data)
        else:
            self[port].is_down = port.is_down()

    def lldp_sent(self, port):
        port_data = self[port]
        port_data.lldp_sent()
        self._move_last_key(port)
        return port_data

    def lldp_received(self, port):
        self[port].lldp_received()

    def move_front(self, port):
        port_data = self.get(port, None)
        if port_data is not None:
            port_data.clear_timestamp()
            self._move_front_key(port)

    def set_down(self, port):
        is_down = port.is_down()
        port_data = self[port]
        port_data.set_down(is_down)
        port_data.clear_timestamp()
        if not is_down:
            self._move_front_key(port)
        return is_down

    def get_port(self, port):
        return self[port]

    def del_port(self, port):
        del self[port]
        self._remove_key(port)

    def __iter__(self):
        root = self._root
        curr = root[self._NEXT]
        while curr is not root:
            yield curr[self._KEY]
            curr = curr[self._NEXT]

    def clear(self):
        for node in self._map.itervalues():
            del node[:]
        root = self._root
        root[:] = [root, root, None]
        self._map.clear()
        dict.clear(self)

    def items(self):
        'od.items() -> list of (key, value) pairs in od'
        return [(key, self[key]) for key in self]

    def iteritems(self):
        'od.iteritems -> an iterator over the (key, value) pairs in od'
        for k in self:
            yield (k, self[k])


class LinkState(dict):
    # dict: Link class -> timestamp
    def __init__(self):
        super(LinkState, self).__init__()
        self._map = {}

    def get_peer(self, src):
        return self._map.get(src, None)

    def update_link(self, src, dst):
        link = Link(src, dst)

        self[link] = time.time()
        self._map[src] = dst

        # return if the reverse link is also up or not
        rev_link = Link(dst, src)
        return rev_link in self

    def link_down(self, link):
        del self[link]
        del self._map[link.src]

    def rev_link_set_timestamp(self, rev_link, timestamp):
        # rev_link may or may not in LinkSet
        if rev_link in self:
            self[rev_link] = timestamp

    def port_deleted(self, src):
        dst = self.get_peer(src)
        if dst is None:
            raise KeyError()

        link = Link(src, dst)
        rev_link = Link(dst, src)
        del self[link]
        del self._map[src]
        # reverse link might not exist
        self.pop(rev_link, None)
        rev_link_dst = self._map.pop(dst, None)

        return dst, rev_link_dst



class LLDPPacket(object):
    # make a LLDP packet for link discovery.

    CHASSIS_ID_PREFIX = 'dpid:'
    CHASSIS_ID_PREFIX_LEN = len(CHASSIS_ID_PREFIX)
    CHASSIS_ID_FMT = CHASSIS_ID_PREFIX + '%s'

    PORT_ID_STR = '!I'      # uint32_t
    PORT_ID_SIZE = 4

    class LLDPUnknownFormat(RyuException):
        message = '%(msg)s'

    @staticmethod
    def lldp_packet(dpid, port_no, dl_addr, ttl):
        pkt = packet.Packet()

        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = dl_addr
        ethertype = ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)

        tlv_chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=LLDPPacket.CHASSIS_ID_FMT %
            dpid_to_str(dpid))

        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_PORT_COMPONENT,
                                  port_id=struct.pack(
                                      LLDPPacket.PORT_ID_STR,
                                      port_no))

        tlv_ttl = lldp.TTL(ttl=ttl)
        tlv_end = lldp.End()

        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        lldp_pkt = lldp.lldp(tlvs)
        pkt.add_protocol(lldp_pkt)

        pkt.serialize()
        return pkt.data

    @staticmethod
    def lldp_parse(data):
        pkt = packet.Packet(data)
        eth_pkt = pkt.next()
        assert type(eth_pkt) == ethernet.ethernet

        lldp_pkt = pkt.next()
        if type(lldp_pkt) != lldp.lldp:
            raise LLDPPacket.LLDPUnknownFormat()

        tlv_chassis_id = lldp_pkt.tlvs[0]
        if tlv_chassis_id.subtype != lldp.ChassisID.SUB_LOCALLY_ASSIGNED:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id subtype %d' % tlv_chassis_id.subtype)
        chassis_id = tlv_chassis_id.chassis_id
        if not chassis_id.startswith(LLDPPacket.CHASSIS_ID_PREFIX):
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id format %s' % chassis_id)
        src_dpid = str_to_dpid(chassis_id[LLDPPacket.CHASSIS_ID_PREFIX_LEN:])

        tlv_port_id = lldp_pkt.tlvs[1]
        if tlv_port_id.subtype != lldp.PortID.SUB_PORT_COMPONENT:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id subtype %d' % tlv_port_id.subtype)
        port_id = tlv_port_id.port_id
        if len(port_id) != LLDPPacket.PORT_ID_SIZE:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id %d' % port_id)
        (src_port_no, ) = struct.unpack(LLDPPacket.PORT_ID_STR, port_id)

        return src_dpid, src_port_no



class OFFabric(app_manager.RyuApp):
    DEFAULT_TTL = 120  # unused. ignored.
    LLDP_PACKET_LEN = len(LLDPPacket.lldp_packet(0, 0, DONTCARE_STR, 0))
    LLDP_SEND_GUARD = .05
    LLDP_SEND_PERIOD_PER_PORT = .9
    TIMEOUT_CHECK_PERIOD = 5.
    MSG_CHECK_PERIOD = 5.
    LINK_TIMEOUT = TIMEOUT_CHECK_PERIOD * 2
    LINK_LLDP_DROP = 5

    def __init__(self, *args, **kwargs):
        super(OFFabric, self).__init__(*args, **kwargs)
        self.name = 'offabric'
        self.dps = {}                 # datapath_id => Datapath class
        self.port_state = {}          # datapath_id => ports
        self.ports = PortDataState()  # Port class -> PortData class
        self.links = LinkState()      # Link class -> timestamp
        self.is_active = True
        try:
            self.mac_table = pickle.loads(rdb.get('mac_table_pickled'))
            LOG.info('init mac_table from redis')
        except:
            self.mac_table = None
        if not self.mac_table:
            self.mac_table = dict()
            LOG.error('cant find mac_table id redis')
        try:
            self.arp_table = pickle.loads(rdb.get('arp_table_pickled'))
            LOG.info('init arp_table from redis')
        except:
            self.arp_table = None
        if not self.arp_table:
            self.arp_table = dict()
            LOG.error('cant find arp_table in redis')
        self.graph_map = dict()
        self.graph_ports = dict()
        

        self.link_discovery = True
        if self.link_discovery:
            self.install_flow = True
            self.explicit_drop = True
            self.lldp_event = hub.Event()
            self.link_event = hub.Event()
            self.threads.append(hub.spawn(self.lldp_loop))
            self.threads.append(hub.spawn(self.link_loop))
        self.listen_for_msg = True
        if self.listen_for_msg:
            self.msg_event = hub.Event()
            self.threads.append(hub.spawn(self.msg_loop))

    def close(self):
        self.is_active = False
        if self.link_discovery:
            self.lldp_event.set()
            self.link_event.set()
            self.msg_event.set()
            hub.joinall(self.threads)

    def _register(self, dp):
        assert dp.id is not None
        assert dp.id not in self.dps

        self.dps[dp.id] = dp
        self.port_state[dp.id] = PortState()
        for port in dp.ports.values():
            self.port_state[dp.id].add(port.port_no, port)

    def _unregister(self, dp):
        if dp.id in self.dps:
            del self.dps[dp.id]
            del self.port_state[dp.id]

    def _get_switch(self, dpid):
        if dpid in self.dps:
            switch = Switch(self.dps[dpid])
            for ofpport in self.port_state[dpid].itervalues():
                switch.add_port(ofpport)
            return switch

    def _get_port(self, dpid, port_no):
        switch = self._get_switch(dpid)
        if switch:
            for p in switch.ports:
                if p.port_no == port_no:
                    return p

    def _port_added(self, port):
        lldp_data = LLDPPacket.lldp_packet(
            port.dpid, port.port_no, port.hw_addr, self.DEFAULT_TTL)
        self.ports.add_port(port, lldp_data)
        # LOG.debug('_port_added dpid=%s, port_no=%s, live=%s',
        #           port.dpid, port.port_no, port.is_live())

    def _link_down(self, port):
        try:
            dst, rev_link_dst = self.links.port_deleted(port)
        except KeyError:
            # LOG.debug('key error. src=%s, dst=%s',
            #           port, self.links.get_peer(port))
            return
        link = Link(port, dst)
        self.send_event_to_observers(event.EventLinkDelete(link))
        if rev_link_dst:
            rev_link = Link(dst, rev_link_dst)
            self.send_event_to_observers(event.EventLinkDelete(rev_link))
        self.ports.move_front(dst)


    ####################################
    #@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        print(msg.in_port)
        pkt = packet.Packet(array.array('B',msg.data))
        for p in pkt:
            print(p)
            if p.protocol_name == 'arp':
                print(p.src_ip)
                print(p.src_mac)
            
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        out = ofp_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        #dp.send_msg(out)
    ############################################
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        assert dp is not None

        if ev.state == MAIN_DISPATCHER:
            self._register(dp)
            switch = self._get_switch(dp.id)
            LOG.debug('register %s', switch)
            self.send_event_to_observers(event.EventSwitchEnter(switch))

            if not self.link_discovery:
                return

            if self.install_flow:
                ofproto = dp.ofproto
                ofproto_parser = dp.ofproto_parser

                # TODO:XXX need other versions
                if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
                    rule = nx_match.ClsRule()
                    rule.set_dl_dst(lldp.LLDP_MAC_NEAREST_BRIDGE)
                    rule.set_dl_type(ETH_TYPE_LLDP)
                    actions = [ofproto_parser.OFPActionOutput(
                        ofproto.OFPP_CONTROLLER, self.LLDP_PACKET_LEN)]
                    dp.send_flow_mod(
                        rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
                        idle_timeout=0, hard_timeout=0, actions=actions)
#                elif ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
#                    match = ofproto_v1_3_parser.OFPMatch(dl_type=ETH_TYPE_LLDP, dl_dst= lldp.LLDP_MAC_NEAREST_BRIDGE)
#                    actions = [ofproto_v1_3_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, self.LLDP_PACKET_LEN)]
#                    mod = ofproto_v1_3_parser.OFPFlowMod(
#                       datapath=dp, match=match, cookie=0,
#                       command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, actions=actions)
#                    dp.send_msg(mod)
                    #rule = nx_match.ClsRule()
                    #rule.set_dl_dst(lldp.LLDP_MAC_NEAREST_BRIDGE)
                    #rule.set_dl_type(ETH_TYPE_LLDP)
                    #actions = [ofproto_parser.OFPActionOutput(
                    #    ofproto.OFPP_CONTROLLER, self.LLDP_PACKET_LEN)]
                    #dp.send_flow_mod(
                    #    rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
                    #    idle_timeout=0, hard_timeout=0, actions=actions)

                else:
                    LOG.error('cannot install flow. unsupported version. %x',
                              dp.ofproto.OFP_VERSION)

            for port in switch.ports:
                if not port.is_reserved():
                    self._port_added(port)
            self.lldp_event.set()

        elif ev.state == DEAD_DISPATCHER:
            # dp.id is None when datapath dies before handshake
            if dp.id is None:
                return
            switch = self._get_switch(dp.id)
            self._unregister(dp)
            LOG.debug('unregister %s', switch)
            self.send_event_to_observers(event.EventSwitchLeave(switch))

            if not self.link_discovery:
                return

            for port in switch.ports:
                if not port.is_reserved():
                    self.ports.del_port(port)
                    self._link_down(port)
            self.lldp_event.set()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        dp = msg.datapath
        ofpport = msg.desc

        if reason == dp.ofproto.OFPPR_ADD:
            #LOG.debug('A port was added.' +
            #          '(datapath id = %s, port number = %s)',
            #          dp.id, ofpport.port_no)
            self.port_state[dp.id].add(ofpport.port_no, ofpport)
            self.send_event_to_observers(
                event.EventPortAdd(Port(dp.id, dp.ofproto, ofpport)))

            if not self.link_discovery:
                return

            port = self._get_port(dp.id, ofpport.port_no)
            if port and not port.is_reserved():
                self._port_added(port)
                self.lldp_event.set()

        elif reason == dp.ofproto.OFPPR_DELETE:
            #LOG.debug('A port was deleted.' +
            #          '(datapath id = %s, port number = %s)',
            #          dp.id, ofpport.port_no)
            self.port_state[dp.id].remove(ofpport.port_no)
            self.send_event_to_observers(
                event.EventPortDelete(Port(dp.id, dp.ofproto, ofpport)))

            if not self.link_discovery:
                return

            port = self._get_port(dp.id, ofpport.port_no)
            if port and not port.is_reserved():
                self.ports.del_port(port)
                self._link_down(port)
                self.lldp_event.set()

        else:
            assert reason == dp.ofproto.OFPPR_MODIFY
            #LOG.debug('A port was modified.' +
            #          '(datapath id = %s, port number = %s)',
            #          dp.id, ofpport.port_no)
            self.port_state[dp.id].modify(ofpport.port_no, ofpport)
            self.send_event_to_observers(
                event.EventPortModify(Port(dp.id, dp.ofproto, ofpport)))

            if not self.link_discovery:
                return

            port = self._get_port(dp.id, ofpport.port_no)
            if port and not port.is_reserved():
                if self.ports.set_down(port):
                    self._link_down(port)
                self.lldp_event.set()

    @staticmethod
    def _drop_packet(msg):
        buffer_id = msg.buffer_id
        if buffer_id == msg.datapath.ofproto.OFP_NO_BUFFER:
            return

        dp = msg.datapath
        # TODO:XXX
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            dp.send_packet_out(buffer_id, msg.in_port, [])
        else:
            LOG.error('cannot drop_packet. unsupported version. %x',
                      dp.ofproto.OFP_VERSION)

    def controller_send(self,dp,dport,data):
        actions = [dp.ofproto_parser.OFPActionOutput(dport)]
        dp.send_packet_out(actions=actions, data=data)

    def install_flow_dmac(self,dp,sport,dport,dmac,actions = None):
        actions = [dp.ofproto_parser.OFPActionOutput(dport)]
        ofproto = dp.ofproto
        match = dp.ofproto_parser.OFPMatch(in_port=sport, dl_dst= dmac)
        mod = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=100, hard_timeout=200,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        dp.send_msg(mod)

    def install_flow_dip(self,dp,sport,dport,dip,actions = None):
#        actions = [dp.ofproto_parser.OFPActionSetNwSrc(sip),
        actions = [ dp.ofproto_parser.OFPActionOutput(dport)]
        ofproto = dp.ofproto
        match = dp.ofproto_parser.OFPMatch(in_port=sport,dl_type=0x0800, nw_dst = dip)
        mod = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, match=match, cookie=0,
            command=ofproto.OFPFC_MODIFY, idle_timeout=100, hard_timeout=200,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        dp.send_msg(mod)




    def create_arp_response(self,srcip,srcmac,dstip):
        arp_pkt = packet.Packet()
        src = self.arp_table[dstip][2]
        dst = srcmac
        ethertype = ETH_TYPE_ARP
        eth_packet = ethernet.ethernet(dst,src,ethertype)
        arp_pkt.add_protocol(eth_packet)
        arp_packet = arp.arp(src_mac = src,dst_mac = dst, dst_ip = srcip,
                             src_ip = dstip, opcode = arp.ARP_REPLY)
        arp_pkt.add_protocol(arp_packet)
        arp_pkt.serialize()
        return arp_pkt.data

    def create_graph_map(self):
        for link in self.links._map:
            if not link.dpid in self.graph_map:
                self.graph_map[link.dpid] = dict()
            if not link.dpid in self.graph_ports:
                self.graph_ports[link.dpid] = dict()
            self.graph_map[link.dpid][self.links._map[link].dpid] = 1
            self.graph_ports[link.dpid][self.links._map[link].dpid] = link.port_no
        rdb.set('fabric_map',json.dumps(self.graph_map))
        return True


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        if not self.link_discovery:
            return

        msg = ev.msg
        dp = msg.datapath
        pkt = packet.Packet(array.array('B',msg.data))
        for p in pkt:
            try:
                p.protocol_name
                #ipv6 bug... TODO
            except:
                return
            if  p.protocol_name == 'lldp':
                try:
                    src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
                except LLDPPacket.LLDPUnknownFormat as e:
                    print('lldp miss')
                    # This handler can receive all the packtes which can be
                    # not-LLDP packet. Ignore it silently
                    return
                dst_dpid = msg.datapath.id
                dst_port_no = msg.in_port
        
                src = self._get_port(src_dpid, src_port_no)
                if not src or src.dpid == dst_dpid:
                    return
                try:
                    self.ports.lldp_received(src)
                except KeyError:
                    # There are races between EventOFPPacketIn and
                    # EventDPPortAdd. So packet-in event can happend before
                    # port add event. In that case key error can happend.
                    # LOG.debug('lldp_received: KeyError %s', e)
                    pass
                
                self.create_graph_map()
                dst = self._get_port(dst_dpid, dst_port_no)
                if not dst:
                    return
                #graph for spf
                old_peer = self.links.get_peer(src)
                # LOG.debug("Packet-In")
                # LOG.debug("  src=%s", src)
                # LOG.debug("  dst=%s", dst)
                # LOG.debug("  old_peer=%s", old_peer)
                if old_peer and old_peer != dst:
                    old_link = Link(src, old_peer)
                    self.send_event_to_observers(event.EventLinkDelete(old_link))
        
                link = Link(src, dst)
                if not link in self.links:
                    self.send_event_to_observers(event.EventLinkAdd(link))
                if not self.links.update_link(src, dst):
                    # reverse link is not detected yet.
                    # So schedule the check early because it's very likely it's up
                    self.ports.move_front(dst)
                    self.lldp_event.set()
                if self.explicit_drop:
                    self._drop_packet(msg)
            if p.protocol_name == 'arp':
                #dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
                dst, src, _eth_type = of_utils.unpack_ethernet(msg.data)
                src_ip_addr = p.src_ip
                dst_ip_addr = p.dst_ip
                src_mac_addr = src
                host_dpid = dp.id
                host_port = msg.in_port
                if(not src_ip_addr in self.arp_table or
                   self.arp_table[src_ip_addr] != (host_dpid,host_port,
                                                   src_mac_addr)):
                    self.arp_table[src_ip_addr] = (host_dpid,host_port,
                                                   src_mac_addr)
                    rdb.set('arp_table',json.dumps(self.arp_table))
                    rdb.set('arp_table_pickled',pickle.dumps(self.arp_table))
                if(not src_mac_addr in self.mac_table or
                   self.mac_table[src_mac_addr] != (host_dpid,host_port)):
                    self.mac_table[src_mac_addr] = (host_dpid,host_port)
                    rdb.set('mac_table',json.dumps(self.mac_table))
                    rdb.set('mac_table_pickled',pickle.dumps(self.mac_table))
                if(dst_ip_addr in self.arp_table):
                    print('response')
                    arp_pkt = self.create_arp_response(src_ip_addr,
                                                       src_mac_addr,dst_ip_addr)
                    actions = [dp.ofproto_parser.OFPActionOutput(host_port)]
                    dp.send_packet_out(actions=actions, data=arp_pkt)

                    
                self._drop_packet(msg)
                return
            #testing, everything thru the contoller
            if p.protocol_name == 'ipv4':
                if p.dst in self.arp_table:
                    dip = of_utils.unpack_ipv4(msg.data, of_utils.IPV4_DIP)
                    proto = p.proto
                    dmac = self.arp_table[p.dst][2]
                    sport = msg.in_port
                    if self.arp_table[p.dst][0] == dp.id:
                        print('same sw')
                        dport = self.arp_table[p.dst][1]
                        self.install_flow_dmac(dp,sport,dport,dmac)
                        #self._drop_packet(msg)
                        self.controller_send(dp,dport,msg.data)
                        return
                    dst_dpid = self.arp_table[p.dst][0]
                    dst_dp = self.dps[dst_dpid]
                    dst_port = self.arp_table[p.dst][1]
                    met, topo, topo_ecmp = NetGraph.SrcDst_SPF_ECMP(self.graph_map,dp.id,dst_dpid)
                    print(topo)
                    print(topo_ecmp)
                    cntr = len(topo) 
                    prev_node = dp
                    while cntr >= 1: 
                        dport = self.graph_ports[prev_node.id][topo[cntr]]
#                        self.install_flow_dmac(prev_node,sport,dport,dmac)
                        self.install_flow_dip(prev_node,sport,dport,dip)
                        sport = self.graph_ports[topo[cntr]][prev_node.id]
                        prev_node = self.dps[topo[cntr]]
                        cntr -= 1
                    #self.install_flow_dmac(prev_node,sport,self.mac_table[dmac][1],dmac)
                    self.install_flow_dip(prev_node,sport,self.arp_table[p.dst][1],dip)
                    print(p)
                    #self._drop_packet(msg)
                    self.controller_send(dst_dp,dst_port,msg.data)
                self._drop_packet(msg)
                return
            if(p.protocol_name != 'arp' and p.protocol_name != 'lldp'
               and p.protocol_name != 'ethernet'):
                print(p)
                
 
            
        
    def send_lldp_packet(self, port):
        try:
            port_data = self.ports.lldp_sent(port)
        except KeyError as e:
            # ports can be modified during our sleep in self.lldp_loop()
            # LOG.debug('send_lldp: KeyError %s', e)
            return
        if port_data.is_down:
            return

        dp = self.dps.get(port.dpid, None)
        if dp is None:
            # datapath was already deleted
            return

        # LOG.debug('lldp sent dpid=%s, port_no=%d', dp.id, port.port_no)
        # TODO:XXX
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            actions = [dp.ofproto_parser.OFPActionOutput(port.port_no)]
            dp.send_packet_out(actions=actions, data=port_data.lldp_data)
        else:
            LOG.error('cannot send lldp packet. unsupported version. %x',
                      dp.ofproto.OFP_VERSION)

    def lldp_loop(self):
        while self.is_active:
            self.lldp_event.clear()

            now = time.time()
            timeout = None
            ports_now = []
            ports = []
            for (key, data) in self.ports.items():
                if data.timestamp is None:
                    ports_now.append(key)
                    continue

                expire = data.timestamp + self.LLDP_SEND_PERIOD_PER_PORT
                if expire <= now:
                    ports.append(key)
                    continue

                timeout = expire - now
                break

            for port in ports_now:
                self.send_lldp_packet(port)
            for port in ports:
                self.send_lldp_packet(port)
                hub.sleep(self.LLDP_SEND_GUARD)      # don't burst

            if timeout is not None and ports:
                timeout = 0     # We have already slept
            # LOG.debug('lldp sleep %s', timeout)
            self.lldp_event.wait(timeout=timeout)

    def link_loop(self):
        while self.is_active:
            self.link_event.clear()

            now = time.time()
            deleted = []
            for (link, timestamp) in self.links.items():
                # LOG.debug('%s timestamp %d (now %d)', link, timestamp, now)
                if timestamp + self.LINK_TIMEOUT < now:
                    src = link.src
                    if src in self.ports:
                        port_data = self.ports.get_port(src)
                        # LOG.debug('port_data %s', port_data)
                        if port_data.lldp_dropped() > self.LINK_LLDP_DROP:
                            deleted.append(link)

            for link in deleted:
                self.links.link_down(link)
                # LOG.debug('delete %s', link)
                self.send_event_to_observers(event.EventLinkDelete(link))

                dst = link.dst
                rev_link = Link(dst, link.src)
                if rev_link not in deleted:
                    # It is very likely that the reverse link is also
                    # disconnected. Check it early.
                    expire = now - self.LINK_TIMEOUT
                    self.links.rev_link_set_timestamp(rev_link, expire)
                    if dst in self.ports:
                        self.ports.move_front(dst)
                        self.lldp_event.set()

            self.link_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)

    def msg_loop(self):
        while self.is_active:
            self.msg_event.clear()
            cntrl_msg = rdb.get('cntrl_msg')
            rdb.set('cntrl_msg', '')
            if(cntrl_msg):
                print(cntrl_msg)
            self.msg_event.wait(timeout=self.MSG_CHECK_PERIOD)


    @set_ev_cls(event.EventSwitchRequest)
    def switch_request_handler(self, req):
        # LOG.debug(req)
        dpid = req.dpid

        switches = []
        if dpid is None:
            # reply all list
            for dp in self.dps.itervalues():
                switches.append(self._get_switch(dp.id))
        elif dpid in self.dps:
            switches.append(self._get_switch(dpid))

        rep = event.EventSwitchReply(req.src, switches)
        self.reply_to_request(req, rep)

    @set_ev_cls(event.EventLinkRequest)
    def link_request_handler(self, req):
        # LOG.debug(req)
        dpid = req.dpid

        if dpid is None:
            links = self.links
        else:
            links = [link for link in self.links if link.src.dpid == dpid]
        rep = event.EventLinkReply(req.src, dpid, links)
        self.reply_to_request(req, rep)


def get_switch(app, dpid=None):
    rep = app.send_request(event.EventSwitchRequest(dpid))
    return rep.switches


def get_all_switch(app):
    return get_switch(app)


def get_link(app, dpid=None):
    rep = app.send_request(event.EventLinkRequest(dpid))
    return rep.links


def get_all_link(app):
    return get_link(app)
