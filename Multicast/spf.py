__author__ = 'mkuai'

class Paths:
    def __init__(self):
        self.max_int = 10000
        self.path_sets = {}

    # if dst == -1 return all the shortest paths
    # else return host->src to dst shortest path
    def _uni_path(self, graph, src = 0, dst = -1):
        nodeNum = len(graph)
        distTosrc = [self.max_int for i in range(nodeNum)]
        distTosrc[src] = 0

        nonvisNodes = [0 for i in range(nodeNum)]
        prevNodes = [-1 for i in range(nodeNum)]

        while True:
            i = 0
            while i < nodeNum:
                if nonvisNodes[i] == 1:
                    i += 1
                    continue
                else:
                    break
            if i == nodeNum:                     # dst == -1 return the shortest path tree
                return prevNodes
            minDist = distTosrc[i]                # take the first nodes as the potential minimal distance
            minIndex = i
            for i in range(nodeNum):
                if distTosrc[i] < minDist and nonvisNodes[i] == 0:
                    minDist = distTosrc[i]
                    minIndex = i

            if (minIndex == dst or distTosrc[minIndex] == self.max_int):              # end the search; return the path
                uni_path = []
                if distTosrc[minIndex] == self.max_int:
                    return uni_path
                else:
                    uni_path.append(dst)
                    while prevNodes[minIndex] != -1:
                        uni_path.append(prevNodes[minIndex])
                        minIndex = prevNodes[minIndex]
                    uni_path.reverse()
                    return uni_path

            nonvisNodes[minIndex] = 1                                                 # visit the node

            for i in range(nodeNum):
                if graph[minIndex][i] == 1 and nonvisNodes[i] == 0:
                    if graph[minIndex][i] + distTosrc[minIndex] < distTosrc[i]:
                        distTosrc[i] = graph[minIndex][i] + distTosrc[minIndex]
                        prevNodes[i] = minIndex

    #generate shortest path tree with prevNodes
    def _shortest_path_tree(self, nodeSet, graph):
        for node in nodeSet:
            preNodeSet = self._uni_path(graph, node, dst = -1)
            items = []
            for element in nodeSet:
                value = []
                if element == node:
                    value.append(element)                                                   #destination node  0
                    value.append(self.max_int)                                              #length of path    1
                    value.append([])                                                        #path set          2
                    items.append(value)
                else:
                    value.append(element)
                    path = []
                    dstnode = element
                    path.append(element)                                       #destination node
                    while preNodeSet[dstnode] != -1:
                        path.append(preNodeSet[dstnode])
                        dstnode = preNodeSet[dstnode]
                    path.reverse()
                    value.append(len(path))                                    #length of path
                    value.append(path)                                         #path
                    items.append(value)
            self.path_sets[node] = items
        return                                                                #self.path_sets
