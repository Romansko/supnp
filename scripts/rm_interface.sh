#!/bin/sudo /bin/sh

if [ -z "$1" ];  then
    echo "Usage: $0 [interface_name]"
    exit 1
fi

echo "Removing interface $1.."

sudo ip link delete $1 type dummy

sudo rmmod dummy
