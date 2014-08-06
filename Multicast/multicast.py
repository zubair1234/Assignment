__author__ = 'mkuai'

from Fileoperation import Fileoperation
from Paths import Paths
from Distancegraph import Distancegraph
from Determinepaths import Determinepaths
from Generaterouting import Generaterouting
#from Arppath import Arppath

#Organize all the processes, and transfer the port result to the ryu controller
#Then, we start the service; we believe the process can achieve our perspectives

class Multicast:
    def __init__(self):
        self.wrotten_ports = []
        self.head = 0
        self.proxy_port = 0
        self.group_port = 0
        self.switches = 0

    def _organized_process(self):
        file = Fileoperation()
        file._process_files("Topology", "Ports", "Request")    #read all the configure file
        self.switches = file.m_switch_number
        #self.source_ip = file.ip_src
        paths = Paths()
        paths._shortest_path_tree(file.receivers, file.graph)
        distance_graph = Distancegraph()
        distance_graph._minimal_spanning_tree(file.receivers, paths.path_sets)
        distance_graph._restore_paths(paths.path_sets)
        determine_path =Determinepaths()
        determine_path._src_to_multitree(file.m_switch_number, distance_graph.paths, file.graph, file.sender)
        generate_routing = Generaterouting()
        generate_routing._write_ports(file.m_total_number, distance_graph.paths, determine_path.multi_head, file.ports)
        self.wrotten_ports = generate_routing.map_ports
        self.proxy_port = generate_routing.proxy_port
        self.group_port = generate_routing.group_port
        self.head = generate_routing.head_switch
        #arp_path = Arppath()
        #arp_path._install_arp_path(file.m_total_number, file.ports, determine_path.src_to_multi)
        #print self.wrotten_ports
