__author__ = 'mkuai'

#This class is to generate the routing command among these links

class Generaterouting:
    def __init__(self):
        self.proxy_port = 0
        self.group_port = 0
        self.head_switch = 0
        self.total_num = 0
        self.map = []
        self.edgeset = []
        self.map_link = []
        self.map_ports = []
        return

    def _gene_route_comm(self, num, paths, head):
        self.total_num = num
        for i in range(num):
            line = [0 for j in range(num)]
            self.map.append(line)
        for i in range(len(paths)):
            j = 1
            while j < len(paths[i]):
                u = paths[i][j-1]
                v = paths[i][j]
                self.map[u][v] = 1
                self.map[v][u] = 1
                j += 1
        #print self.map
        #when all the destination nodes is included in the set, we terminate the search
        nodes = [0 for i in range(num)]
        prev_nodes = []
        post_nodes = []
        prev_nodes.append(head)

        while prev_nodes.__len__() > 0:
            while prev_nodes.__len__() > 0:
                u = prev_nodes[0]
                del prev_nodes[0]
                nodes[u] = 1
                for i in range(num):
                    if self.map[u][i] == 1 and nodes[i] != 1:
                        self.edgeset.append((u, i))
                        post_nodes.append(i)
            prev_nodes = post_nodes
        #print self.edgeset
        '''
        j = 2                             #This is the uni-routing
        while j < len(src_to_multi):
            u = src_to_multi[j-1]
            v = src_to_multi[j]
            self.edgeset.append((u, v))
            j += 1

        j = len(src_to_multi) - 1         #This is the bi-routing; we should avoid a lot of arp broadcast, so it is reasonable to bi-route
        while j > 0:
            u = src_to_multi[j]
            v = src_to_multi[j-1]
            self.edgeset.append((u, v))
            j -= 1
        '''
        return

    def _write_nodes(self, num, paths, head):
        self._gene_route_comm(num, paths, head)
        for i in range(self.total_num):
            line = [0 for j in range(self.total_num)]
            self.map_link.append(line)
        for u, v in self.edgeset:
            self.map_link[u][v] = 1
        print self.map_link
        return

    def _write_ports(self, num, paths, head, ports_dic):
        self.head_switch = head
        self._write_nodes(num, paths, head)
        self.map_ports = [[] for i in range(num)]
        for i in range(num):
            for j in range(num):
                if self.map_link[i][j] == 1:
                    self.map_ports[i].append(ports_dic[i][j])
        print self.map_ports
        self._add_ports(head)
        return

    #Actually, this path is independent of the multicast tree.
    #def _write_arp_path(self, src_to_multi):
    def _add_ports(self, head):
        with open("IP_Source", 'r') as file:
            self.proxy_port, self.group_port = [int (x) for x in file.readline().split()]
        file.close()
        self.map_ports[head].append(self.proxy_port)
