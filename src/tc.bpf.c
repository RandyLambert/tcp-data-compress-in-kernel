//#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

#include <bits/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tc.h"

#define COMP_SOCKET_SIZE 65535
#ifndef FORCE_READ
#define FORCE_READ(X) (*(volatile typeof(X)*)&X)
#endif
int port;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sock_key);
	__type(value, unsigned int);
	__uint(max_entries, COMP_SOCKET_SIZE);
} send_bytes SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, struct sock_key);
// 	__type(value, unsigned int);
// 	__uint(max_entries, COMP_SOCKET_SIZE);
// } recv_bytes SEC(".maps");

static inline int is_hello(struct __sk_buff *skb, __u64 nh_off) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct iphdr *iph = data + nh_off;

  if (iph + 1 > data_end) {
    return 0;
  }

  if (iph->protocol != IPPROTO_TCP) {
    return 0;
  }
  __u32 tcp_hlen = 0;
  __u32 ip_hlen = 0;
  __u32 poffset = 0;
  __u32 plength = 0;
  __u32 ip_total_length = iph->tot_len;

  ip_hlen = iph->ihl << 2;

  if (ip_hlen < sizeof(*iph)) {
    return 0;
  }

  struct tcphdr *tcph = data + nh_off + sizeof(*iph);

  if (tcph + 1 > data_end) {
    return 0;
  }

  tcp_hlen = tcph->doff << 2;

  poffset = ETH_HLEN + ip_hlen + tcp_hlen;
  plength = ip_total_length - ip_hlen - tcp_hlen;
  if (plength >= 7) {
    char p[7] = {0};
    int i = 0;
    int ret = bpf_skb_load_bytes(skb, poffset, p, 6);
    	if (ret) {
			// bpf_printk("bpf_skb_load_bytes failed: %d\n", ret);
			return TC_ACT_OK;
		}
    if(p[0] == 'H' && p[1] == 'e'){
      bpf_printk("p = %s,plength = %u, len = %u\n",p, plength, skb->len - poffset);
      p[4] = 'U';
      
      ret = bpf_skb_store_bytes(skb, poffset, p, 6, 0);
    	if (ret) {
			bpf_printk("bpf_skb_store_bytes failed: %d\n", ret);
			return TC_ACT_OK;
		}
    }

    int *value;
    if ((p[0] == 'H') && (p[1] == 'e') && (p[2] == 'l') && (p[3] == 'l')) {
      return 1;
    }
  }

  return 0;
}

static inline void extract_key4_from_ops(struct iphdr *iph,struct tcphdr *tcph, struct sock_key *key) {
    key->daddr = bpf_htonl(iph->daddr);
    key->saddr = bpf_htonl(iph->saddr);
    key->dport = bpf_htonl(tcph->dest) >> 16;
    key->sport = bpf_htonl(tcph->source) >> 16;
    key->family = 1;
}

static inline void add_socket_len(struct __sk_buff *skb,__u64 nh_off) {

  struct sock_key key = {};

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct iphdr *iph = data + nh_off;

    if (iph + 1 > data_end) {
      return ;
    }

    if (iph->protocol != IPPROTO_TCP) {
      return ;
    }
    __u32 tcp_hlen = 0;
    __u32 ip_hlen = 0;
    __u32 poffset = 0;
    __u32 plength = 0;
    __u32 ip_total_length = iph->tot_len;

    ip_hlen = iph->ihl << 2;

    if (ip_hlen < sizeof(*iph)) {
      return ;
    }

    struct tcphdr *tcph = data + nh_off + sizeof(*iph);

    if (tcph + 1 > data_end) {
      return ;
    }

    tcp_hlen = tcph->doff << 2;

  if(port == bpf_htonl(tcph->dest) >> 16 || port == bpf_htonl(tcph->source) >> 16) {
    poffset = ETH_HLEN + ip_hlen + tcp_hlen;
    unsigned int len = skb->len - poffset;
    bpf_printk("dport: %d, sport: %d, add socket len: %d\n", bpf_htonl(tcph->dest) >> 16, bpf_htonl(tcph->source) >> 16, len);

    // 填充 map 的 key, 用作后续查找使用. 
    extract_key4_from_ops(iph, tcph, &key);
    __u32* value = bpf_map_lookup_elem(&send_bytes, &key);
    if (value != NULL) {
      *value = *value + len;
      bpf_printk("Value read from the map: %d\n" , *value);
    } else {
      long result = bpf_map_update_elem(&send_bytes, &key, &len, BPF_ANY);
      if (result != 0) {
        bpf_printk("bpf_map_update_elem failed = %d\n",result);
      }
    }
  }
}

SEC("tc")
int classification(struct __sk_buff *skb) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;

  __u16 h_proto;
  __u64 nh_off = 0;
  nh_off = sizeof(*eth);

  if (data + nh_off > data_end) {
    return TC_ACT_OK;
  }

  h_proto = eth->h_proto;

  add_socket_len(skb, nh_off);

  if (h_proto == bpf_htons(ETH_P_IP)) {
    // if (is_hello(skb, nh_off) == 1) {
    //   bpf_printk("Yes! It is Hello World!\n");
    // }
  }

  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
