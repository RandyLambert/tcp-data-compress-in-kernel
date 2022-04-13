// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>

#include "tc.skel.h"
#include "tc.h"

#define BPF_SYSFS_ROOT "/sys/fs/bpf"
#define PATH_MAX 512

struct bpf_progs_desc {
	char name[256];
	enum bpf_prog_type type;
	struct bpf_program *prog;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

void construct_mount_path(char* pathame, char* prog_name) {
	int len = snprintf(pathame, PATH_MAX, "%s/%s", BPF_SYSFS_ROOT, prog_name);
	printf("mount path : %s\n", pathame);
	if (len < 0) {
		fprintf(stderr, "Error: Program name '%s' is invalid\n", prog_name);
		exit(1);
	} else if (len >= PATH_MAX) {
		fprintf(stderr, "Error: Path name '%s' is too long\n", prog_name);
		exit(1);
	}
	return;
}

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
		}
		if(lookup_key.family != 3) {
			int result = bpf_map_delete_elem(map_send_bytes_fd, &lookup_key);
			if (result != 0){
				printf("Failed to delete element from the map: %d (%s)\n", result, strerror(errno));
			}
		}
		sleep(3);
	}

cleanup:
	tc_bpf__destroy(skel);
	return -err;
}

