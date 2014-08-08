#!/usr/bin/python

def ecmp_path_recursion(graph, node, result_graph, cntr_dict):
    if node:
        if len(graph[node]) == 1:
            result_graph[cntr_dict[0]] = (node, graph[node][0])
            node  = graph[node][0]
            cntr_dict[0] += 1
            print(cntr_dict[0])
            ecmp_path_recursion(graph,node,result_graph,cntr_dict)
        if len(graph[node]) > 1:
            for node2 in graph[node]:
                result_graph[cntr_dict[0]] = (node,node2)
                cntr_dict[0] += 1
                print(cntr_dict[0])
                ecmp_path_recursion(graph,node2,result_graph,cntr_dict)

class NetGraph(object):
    @staticmethod
    def SingleSPF(graph_dict, src_node): 
        SPF_INFINITY = 16000000
        distance_dict = dict()
        previous_node = dict()
        unvisited_set = set()
        nodes = graph_dict.keys()
        for node in nodes:
            if node == src_node:
                distance_dict[node] = 0
            else:
                distance_dict[node] = SPF_INFINITY
            previous_node[node] = None
            unvisited_set.add(node)
        
        while unvisited_set:
            minimal_distance = SPF_INFINITY
            closest_node = None
            for node in nodes:
                if node in unvisited_set:
                    if distance_dict[node] <= minimal_distance:
                        minimal_distance = distance_dict[node]
                        closest_node = node
            
            unvisited_set.remove(closest_node)
            if distance_dict[closest_node] == SPF_INFINITY:
                break

            for neighbor in graph_dict[closest_node].keys():
                if neighbor in unvisited_set:
                    path_len = distance_dict[closest_node] + int(graph_dict[closest_node][neighbor])
                    if path_len < distance_dict[neighbor]:
                        distance_dict[neighbor] = path_len
                        previous_node[neighbor] = closest_node
        return distance_dict, previous_node

    @staticmethod
    def SingleSPF_ECMP(graph_dict, src_node): 
        SPF_INFINITY = 16000000
        ecmp_cntr = 1
        distance_dict = dict()
        previous_node = dict()
        unvisited_set = set()
        nodes = graph_dict.keys()
        for node in nodes:
            if node == src_node:
                distance_dict[node] = 0
            else:
                distance_dict[node] = SPF_INFINITY
            previous_node[node] = None
            unvisited_set.add(node)
        
        while unvisited_set:
            minimal_distance = SPF_INFINITY
            closest_node = None
            for node in nodes:
                if node in unvisited_set:
                    if distance_dict[node] <= minimal_distance:
                        minimal_distance = distance_dict[node]
                        closest_node = node
            
            unvisited_set.remove(closest_node)
            if distance_dict[closest_node] == SPF_INFINITY:
                break

            for neighbor in graph_dict[closest_node].keys():
                if neighbor in unvisited_set:
                    path_len = distance_dict[closest_node] + int(graph_dict[closest_node][neighbor])
                    if path_len <= distance_dict[neighbor]:
                        distance_dict[neighbor] = path_len
                        if previous_node[neighbor]:
                            previous_node[neighbor+"-e"+str(ecmp_cntr)] = closest_node
                            ecmp_cntr += 1
                        else:
                            previous_node[neighbor] = closest_node
        return distance_dict, previous_node

    @staticmethod
    def SrcDst_SPF_ECMP(graph_dict, src_node, dst_node): 
        SPF_INFINITY = 16000000
        ecmp_cntr = 1
        distance_dict = dict()
        previous_node = dict()
        previous_node2 = dict()
        unvisited_set = set()
        nodes = graph_dict.keys()
        for node in nodes:
            if node == src_node:
                distance_dict[node] = 0
            else:
                distance_dict[node] = SPF_INFINITY
            previous_node[node] = None
            previous_node2[node] = list()
            unvisited_set.add(node)
        
        while unvisited_set:
            minimal_distance = SPF_INFINITY
            closest_node = None
            for node in nodes:
                if node in unvisited_set:
                    if distance_dict[node] <= minimal_distance:
                        minimal_distance = distance_dict[node]
                        closest_node = node
            
            unvisited_set.remove(closest_node)
            if closest_node == dst_node:
                break
            if distance_dict[closest_node] == SPF_INFINITY:
                break

            for neighbor in graph_dict[closest_node].keys():
                if neighbor in unvisited_set:
                    path_len = distance_dict[closest_node] + int(graph_dict[closest_node][neighbor])
                    if path_len <= distance_dict[neighbor]:
                        distance_dict[neighbor] = path_len
                        previous_node[neighbor] = closest_node
                        previous_node2[neighbor].append(closest_node)
        path_cntr = 1
        srcdst_path = dict()
        srcdst_path2 = dict()
        path_node = dst_node
        #w/o mpath
        while previous_node[path_node]:
            srcdst_path[path_cntr] = path_node
            path_node = previous_node[path_node]
            path_cntr += 1
        path_node = dst_node
        path_cntr = dict()
        path_cntr[0] = 1
        ecmp_path_recursion(previous_node2,path_node,srcdst_path2,path_cntr)
        print(srcdst_path2)   
       
        return distance_dict[dst_node], srcdst_path, srcdst_path2




if __name__ == '__main__':
    net_descr = dict()
    net_descr['a'] = dict()
    net_descr['b'] = dict()
    net_descr['c'] = dict()
    net_descr['d'] = dict()
    net_descr['a']['b'] = 1
    net_descr['a']['c'] = 2
    net_descr['b']['a'] = 7
    net_descr['b']['c'] = 1
    net_descr['b']['d'] = 3
    net_descr['c']['a'] = 10
    net_descr['c']['b'] = 1
    net_descr['c']['d'] = 2
    net_descr['d']['c'] = 6
    net_descr['d']['b'] = 7
    for key in net_descr.keys():
        res = NetGraph.SingleSPF(net_descr,key)
        print(res)
    print('##########')
    res = NetGraph.SrcDst_SPF_ECMP(net_descr,'a','d')
    print(res)
