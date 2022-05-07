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

typedef struct __MEM {
//	unsigned char name[20];
	float total;
	float free;
}MEM; 

typedef struct PACKED {       //定义一个cpu occupy的结构体 
	char name[20];      //定义一个char类型的数组名name有20个元素
	unsigned int user; //定义一个无符号的int类型的user
	unsigned int nice; //定义一个无符号的int类型的nice
	unsigned int system;//定义一个无符号的int类型的system
	unsigned int idle; //定义一个无符号的int类型的idle
	unsigned int lowait;
	unsigned int irq;
	unsigned int softirq;
} CPU_OCCUPY;

#endif