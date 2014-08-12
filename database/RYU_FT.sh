#! /bin/bash

if [ $1 -eq 0 ]
then 
    sudo ovs-vsctl set-controller s1 "tcp:192.168.241.132:6633"
    sudo ovs-vsctl set-controller s2 "tcp:192.168.241.132:6633"
    sudo ovs-vsctl set-controller s3 "tcp:192.168.241.132:6633" 
    sudo ovs-vsctl set-controller s4 "tcp:192.168.241.132:6633" 
    sudo ovs-vsctl set-controller s5 "tcp:192.168.241.132:6633" 
    sudo ovs-vsctl set-controller s6 "tcp:192.168.241.132:6633" 
else
    sudo ovs-vsctl set-controller s1 "tcp:192.168.241.128:6633"
    sudo ovs-vsctl set-controller s2 "tcp:192.168.241.128:6633"
    sudo ovs-vsctl set-controller s3 "tcp:192.168.241.128:6633" 
    sudo ovs-vsctl set-controller s4 "tcp:192.168.241.128:6633" 
    sudo ovs-vsctl set-controller s5 "tcp:192.168.241.128:6633" 
    sudo ovs-vsctl set-controller s6 "tcp:192.168.241.128:6633" 
fi
