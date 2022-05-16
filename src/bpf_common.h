#ifndef _BPF_COMMON_H
#define _BPF_COMMON_H
#include <string.h>
#include <stdio.h>
#include <unistd.h>

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

void construct_mount_path(char* pathame, char* prog_name) 
{
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

#endif