#!/bin/sudo /bin/sh

if [ -z "$1" ];  then
    echo "Usage: $0 [interface_name]"
    exit 1
fi

echo "Setting interface $1.."

modprobe dummy

ip link add $1 type dummy

ip addr add 192.168.1.100/24 brd + dev $1

sysctl -w net.ipv6.conf.$1.disable_ipv6=1

ifconfig $1 multicast

ip link set dev $1 up

route add -net 239.0.0.0 netmask 255.0.0.0 $1

ip link show $1
