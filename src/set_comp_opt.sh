PORT=$1
LOCAL_OPTS=$2
echo $PORT > /proc/sys/net/ipv4/tcp_compression_ports
# echo 1234,12345 > /proc/sys/net/ipv4/tcp_compression_ports

echo $LOCAL_OPTS > /proc/sys/net/ipv4/tcp_compression_local
# echo 1 > /proc/sys/net/ipv4/tcp_compression_local
