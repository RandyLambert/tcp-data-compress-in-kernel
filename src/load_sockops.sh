#!/bin/bash

# enable debug output for each executed command, to disable: set +x
set -x

# exit if any command fails
set -e

# Mount the bpf filesystem
# sudo mount -t bpf bpf /sys/fs/bpf/

# Compile the bpf_sockops program
# clang -std=gnu89 -O2 -target bpf -c bpf_sockops.bpf.c -o bpf_sockops.bpf.o

# Load and attach the bpf_sockops program
# sudo bpftool prog load bpf_sockops.bpf.o /sys/fs/bpf/bpf_sockops
sudo bpftool cgroup attach /sys/fs/cgroup sock_ops pinned /sys/fs/bpf/bpf_tcpoptionstoa
# Extract the id of the sockhash map used by the bpf_sockops program
# This map is then pinned to the bpf virtual file system


# MAP_ID=$(sudo bpftool prog show pinned /sys/fs/bpf/bpf_sockops | grep -o -E 'map_ids [0-9]+' | cut -d ' ' -f2-)
# sudo bpftool map pin id $MAP_ID /sys/fs/bpf/sock_ops_map
