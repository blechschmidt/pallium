#ifndef NOLIBC
#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sched.h>
#include <fcntl.h>
#else

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER		0x10000000	/* New user namespace */
#endif
int sys_unshare(int flags)
{
        return my_syscall1(__NR_unshare, flags);
}

static __attribute__((unused))
int unshare(int flags)
{
        ssize_t ret = sys_unshare(flags);

        if (ret < 0) {
                SET_ERRNO(-ret);
                ret = -1;
        }
        return ret;
}
#endif

void write_string(char *path, char *data) {
	int f = open(path, O_WRONLY);
	if (f == -1) {
		perror("error opening file");
		exit(1);
	}

	if (write(f, data, strlen(data)) == -1) {
		perror("error writing file");
		exit(1);
	}

	if (close(f) == -1) {
		perror("error closing file");
		exit(1);
	}
}

int main(int argc, char **argv) {
	char *uid_map = NULL;
	char *gid_map = NULL;
	char **cmd = NULL;
	char *mount_root = NULL;
	char *exec_file = NULL;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0 && i < argc - 1) {
			cmd = &argv[i + 1];
			break;
		}
		if (strcmp(argv[i], "--mount-root") == 0 && i < argc - 1) {
			mount_root = argv[i + 1];
		}
		if (strcmp(argv[i], "--uid-map") == 0 && i < argc - 1) {
			uid_map = argv[i + 1];
		}
		if (strcmp(argv[i], "--gid-map") == 0 && i < argc - 1) {
			gid_map = argv[i + 1];
		}
		if (strcmp(argv[i], "--exec-file") == 0 && i < argc - 1) {
			exec_file = argv[i + 1];
		}
		if (strcmp(argv[i], "--rm") == 0 && i < argc - 1) {
			unlink(argv[i + 1]);
		}
		if (strcmp(argv[i], "--controlling-terminal")) {
			int pgrp;
			pgrp = getpgrp();
			ioctl(0, TIOCSPGRP, &pgrp);
		}
	}

	if (mount_root != NULL) {
		if (mount(mount_root, "/", "none", MS_BIND | MS_REC, 0) != 0) {
			perror("mounting root");
			exit(1);
		}
	}

	if (uid_map != NULL || gid_map != NULL) {
		if (unshare(CLONE_NEWUSER) != 0) {
			perror("unshare failed");
			exit(1);
		}
	}

	if (uid_map != NULL) {
		write_string("/proc/self/uid_map", uid_map);
	}

	if (gid_map != NULL) {
		// write_string("/proc/self/setgroups", "deny"); // gVisor does not support that yet.
		write_string("/proc/self/gid_map", gid_map);
	}

	if (cmd != NULL) {
		if (exec_file == NULL) {
			exec_file = cmd[0];
		}
		if (execve(exec_file, cmd, environ) == -1) {
			perror("exec failed");
			return 1;
		}
	}

	return 0;
}
