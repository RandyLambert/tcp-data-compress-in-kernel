#!/bin/bash
set -x

IFNAME=$1
sudo tc qdisc add dev $IFNAME clsact
sudo tc filter add dev $IFNAME egress bpf object-pinned /sys/fs/bpf/classification
