_author__ = 'mkuai'

from sets import Set

#generate distance graph and construct minimal spanning tree on this map
class Distancegraph:
    def __init__(self):
        self.m_distance_graph = []
        self.nodeNum = 0
        self.recNodes = []
        self.total_cost = 0
        self.treeEdges = []
        self.paths = []
        return

    #generate a distance graph with recNodeSet and pathSets
    def _generate_distance_graph(self, recNodeset, pathSet):
        self.recNodes = recNodeset[:]
        self.nodeNum = len(recNodeset)
        self.m_distance_graph = [[] for i in range(self.nodeNum)]
        for i in range(self.nodeNum):
            for node in recNodeset:
                self.m_distance_graph[i].append(pathSet[node][i][1])

        print self.m_distance_graph                                           #store the distance graph
        return

    #when recNodeset == treeNodes, return the mst                              kruskal algorithm
    def _minimal_spanning_tree(self, recNodeset, pathSet):
        self._generate_distance_graph(recNodeset, pathSet)
        #nodeSets = recNodeset[:]                                               #copy the nodeset
        #total_cost = 0
        treeNodes = Set([])
        nodeSets = Set(range(self.nodeNum))
        edges = [(self.m_distance_graph[u][v], u, v) for u in range(self.nodeNum) for v in range(self.nodeNum)]
        edges.sort()
        print edges
        #treeEdges = []
        for W, u, v in edges:
            if u not in treeNodes or v not in treeNodes:
                if u not in treeNodes:
                    treeNodes.add(u)
                    nodeSets.remove(u)
                if v not in treeNodes:
                    treeNodes.add(v)
                    nodeSets.remove(v)
                self.treeEdges.append((u, v))
                self.total_cost += W
                if nodeSets.__eq__(Set([])):
                    break
        print self.treeEdges
        print self.total_cost
        return

    #restore the path in the original graph
    def _restore_paths(self, pathSet):
        for u, v in self.treeEdges:
            src = self.recNodes[u]
            self.paths.append(pathSet[src][v][2])
        print self.paths
        return
