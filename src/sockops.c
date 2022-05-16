#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "sockops.skel.h"
#include "bpf_common.h"

struct bpf_progs_desc bpf_prog = {
	"bpf_tcpoptionstoa",
	BPF_CGROUP_SOCK_OPS,
	NULL
};

int main(int argc, char **argv)
{
	struct sockops_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Open BPF application */
	skel = sockops_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	
	skel->bss->port = 1234;

	// /* ensure BPF program only handles write() syscalls from our process */
	// skel->bss->my_pid = getpid();

	/* Load & verify BPF programs */
	err = sockops_bpf__load(skel);
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

	// int map_send_bytes_fd = bpf_object__find_map_fd_by_name(skel->obj, "send_bytes");
	// if (map_send_bytes_fd < 0) {
	// 	fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
	// 	return 1;
	// }

	/* Attach tracepoint handler */
	// err = sockops_bpf__attach(skel);
	// if (err) {
	// 	fprintf(stderr, "Failed to attach BPF skeleton\n");
	// 	goto cleanup;
	// }

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	sockops_bpf__destroy(skel);
	return -err;
}