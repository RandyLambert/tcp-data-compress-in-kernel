#ifndef _TC_H
#define _TC_H

struct sock_key {
  __u32 saddr;
  __u32 daddr;
  __u8  family;
  __u8  pad1; // this padding required for 64bit alignment
  __u16 pad2; // else ebpf kernel verifier rejects loading of the program
  __u16 sport;
  __u16 dport;
};

struct http_payload {
  int method;
};

#endif