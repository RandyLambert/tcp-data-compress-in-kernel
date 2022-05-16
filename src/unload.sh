#!/bin/bash
set -x

IFNAME=$1
# sudo tc qdisc del dev $IFNAME ingress
sudo tc filter del dev $IFNAME egress
sudo tc qdisc del dev $IFNAME clsact
sudo rm /sys/fs/bpf/classification
