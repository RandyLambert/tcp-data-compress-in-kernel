#!/bin/bash
set -x

sudo firewall-cmd --zone=public --add-port=1234/tcp --permanent 
sudo firewall-cmd --zone=public --add-port=12345/tcp --permanent 
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports 
