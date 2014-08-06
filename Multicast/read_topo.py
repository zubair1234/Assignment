__author__ = 'mkuai'

class Fileoperation:
    def __init__(self):
        self.m_switch_number = 0
        self.m_host_number = 0
        self.m_total_number = 0
        self.ip_src = ''
        self.sender = 0               #python instantiate problem
        self.graph = []
        self.ports = []
        self.receivers = []
        return

    def _read_topo(self, filename = "Topology"):
        with open(filename, 'r') as file:
            self.m_switch_number, self.m_host_number = [int (x) for x in file.readline().split()]
            self.m_total_number = self.m_host_number + self.m_switch_number
            for line in file:
                self.graph.append([int(x) for x in line.split()])
        file.close()
        return

    def _read_ports(self, filename = "Ports"):
        with open(filename, 'r') as file:
            for line in file:
                self.ports.append([int(x) for x in line.split()])
        file.close()
        return

    def _read_request(self, filename = "Request"):
        with open(filename, 'r') as file:
            tmp = [int (x) for x in file.readline().split()]
            self.sender = tmp[0]
            for line in file:
                self.receivers = [int (x) for x in line.split()]
        file.close()
        return

    def _read_ip_source(self, filename = "IP_Source"):
        with open(filename, 'r') as file:
            ip_tmp = file.readline().split('\n')
            self.ip_src = ip_tmp[0]
        file.close()
        return

    def _process_files(self, topo, ports, request):
        self._read_topo(topo)
        self._read_ports(ports)
        self._read_request(request)
