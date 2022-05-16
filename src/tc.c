// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "tc.skel.h"
#include "tc.h"
#include "bpf_common.h"

/*
详细信息请参照 note.md
不压缩传输速率: T1 = D/N
压缩后传输速率: T2 = D/N*(R+N/Vc+N/vd)
如果R + N/Vc + N/Vd < 1,则压缩后传输要更快，否则压缩后传输反而更慢。
ZSTD 1.3.4 压缩1/2.877 + N/470 + N/1380 = 0.35 + N*0.00285
得出结论: 对于ZSTD 1.3.4 在传输速率 小于 228 MBps 时, 应该使用压缩算法
*/
#define ZSTD_SPEED 228

struct bpf_progs_desc bpf_prog = {
	"classification",
	BPF_PROG_TYPE_SCHED_CLS,
	NULL
};
char saddr_buf[16];
char daddr_buf[16];
char* num_to_ip(unsigned int num, char *ip_buf)
{
	unsigned char* p = (unsigned char *)&num;
	sprintf(ip_buf, "%d.%d.%d.%d", p[3]&0xff,p[2]&0xff,p[1]&0xff,p[0]&0xff);
	return ip_buf;
}

int get_meminfo() 
{
	MEM meminfo;
	memset(&meminfo,0x00,sizeof(MEM));
	FILE* fp = fopen("/proc/meminfo","r");
 
	if(fp == NULL)
	{
		printf("Can not open file\r\n");
		return 0;
	}
	
	char buf[64];
	char name[32];
	memset(buf,0x00,sizeof(buf));
	fgets(buf,sizeof(buf),fp);
	sscanf(buf,"%s %f %s",name,&meminfo.total,name);
	memset(buf,0x00,sizeof(buf));
	fgets(buf,sizeof(buf),fp);
	sscanf(buf,"%s %f %s",name,&meminfo.free,name);
	printf("buf is %s  name is %s %f\r\n",buf,name,meminfo.free);
	float temp;
 
	sscanf(buf,"%s			%f %s",name,&temp,name);
	printf("temp is %f \r\n",temp);
	double rate = (meminfo.total - meminfo.free)/meminfo.total;
	printf("%f  %f	rate is %f\r\n",meminfo.total,meminfo.free,rate);
	fclose(fp);
	return 1;
}

int cal_cpuoccupy(CPU_OCCUPY *o, CPU_OCCUPY *n) 
{   
	unsigned long od, nd;
	double cpu_use = 0;   
 
	od = (unsigned long) (o->user + o->nice + o->system +o->idle + o->lowait + o->irq + o->softirq);//第一次(用户+优先级+系统+空闲)的时间再赋给od
	nd = (unsigned long) (n->user + n->nice + n->system +n->idle + n->lowait + n->irq + n->softirq);//第二次(用户+优先级+系统+空闲)的时间再赋给od
 
	double sum = nd - od;
	double idle = n->idle - o->idle;
	cpu_use = idle/sum;
 
 
	printf("%f\r\n",cpu_use);
 
	idle = n->user + n->system + n->nice -o->user - o->system- o->nice;
	cpu_use = idle/sum;
 
	printf("%f\r\n",cpu_use);
	return 0;
}
 
void get_cpuoccupy(CPU_OCCUPY *cpu_occupy) //对无类型get函数含有一个形参结构体类弄的指针O
{   
	FILE *fd;                  
	char buff[256]; 
 
	fd = fopen ("/proc/stat", "r"); 
	fgets (buff, sizeof(buff), fd);
	sscanf (buff, "%s %u %u %u %u %u %u %u", cpu_occupy->name, &cpu_occupy->user, &cpu_occupy->nice,&cpu_occupy->system, &cpu_occupy->idle,&cpu_occupy->lowait,&cpu_occupy->irq,&cpu_occupy->softirq);
	printf("%s %u %u %u %u %u %u %u\r\n", cpu_occupy->name,cpu_occupy->user, cpu_occupy->nice,cpu_occupy->system, cpu_occupy->idle,cpu_occupy->lowait,cpu_occupy->irq,cpu_occupy->softirq);
	printf("%s %u\r\n", cpu_occupy->name,cpu_occupy->user);
	fclose(fd);     
}

int main(int argc, char **argv)
{
	struct tc_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();
	skel = tc_bpf__open();

	/* ensure BPF program only handles write() syscalls from our process */
	skel->bss->port = 1234;

	/* Load & verify BPF programs */
	err = tc_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	// set prog type
	bpf_prog.prog = bpf_object__find_program_by_name(skel->obj, bpf_prog.name);
	if (!bpf_prog.prog) {
		fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
		goto cleanup;
	}
	bpf_program__set_type(bpf_prog.prog, bpf_prog.type);

	// get prog_fd
	int prog_fd = bpf_program__fd(bpf_prog.prog);
	printf("prog_fd = %d\n", prog_fd);
	if (prog_fd < 0) {
		fprintf(stderr, "Error: Couldn't get file descriptor for program %s\n", bpf_prog.name);
		goto cleanup;
	}

	// TC相关,bpf_tc_attach的例子太少了,现在也没时间看libbpf的代码,所以pin下,命令行手动挂载
	char pathname[PATH_MAX];
	construct_mount_path(pathname, bpf_prog.name);
	printf("main prog[%s] mount path : %s\n", bpf_prog.name, pathname);
	retry:
	if (bpf_program__pin(bpf_prog.prog, pathname)) {
		fprintf(stderr, "Error: Failed to pin program '%s' to path %s\n", bpf_prog.name, pathname);
		if (errno == EEXIST) {
			fprintf(stdout, "BPF program '%s' already pinned, unpinning it to reload it\n", bpf_prog.name);
			if (bpf_program__unpin(bpf_prog.prog, pathname)) {
				fprintf(stderr, "Error: Fail to unpin program '%s' at %s\n", bpf_prog.name, pathname);
				goto cleanup;
			}
			printf("Retry mount TC bpf to %s\n", pathname);
			goto retry;
		}
		return -1;
	}

	int map_send_bytes_fd = bpf_object__find_map_fd_by_name(skel->obj, "send_bytes");
	if (map_send_bytes_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		return 1;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	struct sock_key lookup_key, next_key;
	unsigned int tx_byte = 0;
	for (;;) {
		CPU_OCCUPY cpu_stat1;
		CPU_OCCUPY cpu_stat2;
		int cpu;
		//获取 cpu 使用情况
		cpu_stat2 = cpu_stat1;
		get_cpuoccupy(&cpu_stat1);
	
		//计算cpu使用率
		cpu = cal_cpuoccupy((CPU_OCCUPY *)&cpu_stat1, (CPU_OCCUPY *)&cpu_stat2);
		printf("cpu: %d\n",cpu);
		//获取内存
		get_meminfo();
		
		/* trigger our BPF program */
		// 首次查找, key 设置为不存在, 从头开始遍历
		lookup_key.family = 3;
		printf("%-6s %-16s %-6s %-16s %-6s %8s\n","FAMILY", "SADDR", "SPORT", "DADDR", "DPORT", "TX_BYTE");
		while(bpf_map_get_next_key(map_send_bytes_fd, &lookup_key, &next_key) == 0) {
			bpf_map_lookup_elem(map_send_bytes_fd, &next_key, &tx_byte);
			printf("%-6d %-16s %-6d %-16s %-6d %8d\n", next_key.family, num_to_ip(next_key.saddr, saddr_buf), next_key.sport, num_to_ip(next_key.daddr, daddr_buf), next_key.dport, tx_byte);
			if(lookup_key.family != 3) {
				int result = bpf_map_delete_elem(map_send_bytes_fd, &lookup_key);
				if (result != 0) {
					printf("Failed to delete element from the map: %d (%s)\n", result, strerror(errno));
				}
			}
			lookup_key = next_key;
			if(tx_byte/1024 > ZSTD_SPEED) {
				// setsockopt();
			}
		}
		if(lookup_key.family != 3) {
			int result = bpf_map_delete_elem(map_send_bytes_fd, &lookup_key);
			if (result != 0){
				printf("Failed to delete element from the map: %d (%s)\n", result, strerror(errno));
			}
		}

		sleep(6);
	}

cleanup:
	tc_bpf__destroy(skel);
	return -err;
}

