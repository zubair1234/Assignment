__author__ = 'mkuai'

from Paths import Paths
from sets import Set

#This class determine the multicast tree and routing path

class Determinepaths:
    def __init__(self):
        self.switches = Set()
        self.multi_head = 0
        self.src_to_multi = []                                         #source node direct to the multicast tree
        return

    #In this process, I use breadth-first algorithm to locate the head of multicast tree,and return a source-head path
    def _head_multi_tree(self, num, paths, graph, src):
        switches_tmp = Set([])
        prev_que = []
        post_que = []
        for i in range(len(paths)):
            switches_tmp = switches_tmp | Set(paths[i])
        for x in switches_tmp:
            if x < num:
                self.switches.add(x)
        #prev_que.put(src, False)
        #interSet = Set()
        prev_que.append(src)
        visSwitch = [0 for i in range(num)]
        flag = 0
        while len(prev_que) > 0:                                      # If the graph is connected, finally, we can locate a node
            while len(prev_que) > 0:
                u = prev_que[0]
                del prev_que[0]
                for i in range(num):
                    if graph[i][u] == 1 or graph[u][i] == 1:
                        if visSwitch[i] == 0:
                            post_que.append(i)
                            visSwitch[i] = 1
                interSet = Set(post_que) & self.switches
                if len(interSet) > 0:
                    flag = 1
                    break
            if flag == 1:
                break
            prev_que = post_que
        self.multi_head = interSet.pop()
        #print self.multi_head
        return

    def _src_to_multitree(self, num, paths, graph, src):                     #the difficulties are to set all the routing command effectively
        pt = Paths()
        self._head_multi_tree(num, paths, graph, src)
        self.src_to_multi = pt._uni_path(graph, src, self.multi_head)
        #print self.src_to_multi
        return
