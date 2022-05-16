#!/bin/bash
set -x

# Detach and unload the bpf_sockops_v4 program
sudo bpftool cgroup detach /sys/fs/cgroup sock_ops pinned /sys/fs/bpf/bpf_tcpoptionstoa
sudo rm /sys/fs/bpf/bpf_tcpoptionstoa

# Delete the map
# sudo rm /sys/fs/bpf/sock_ops_map
