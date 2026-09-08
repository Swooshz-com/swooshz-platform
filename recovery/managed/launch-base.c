#define _GNU_SOURCE
#include "platform.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int __attribute__((unused)) allowed_component(const char *path)
{
	static const char *const paths[] = {
		"/usr/local/libexec/swz-supervisor", "/usr/local/libexec/swz-custodian",
		"/usr/local/libexec/swz-dispatcher", "/usr/local/libexec/swz-bootstrap",
		"/usr/local/libexec/swz-broker", "/usr/local/libexec/swz-agent",
	};
	struct stat info;
	if (path == NULL || lstat(path, &info) != 0 || !S_ISREG(info.st_mode) ||
		(info.st_mode & 0022) != 0 || (info.st_mode & S_IXUSR) == 0)
		return 0;
	for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); index++)
		if (strcmp(path, paths[index]) == 0)
			return 1;
	return 0;
}

int main(int argc, char **argv)
{
	static const char supervisor[] = "/usr/local/libexec/swz-supervisor";
	static const int inherited_seed_fd = 4;
	char seed_fd_text[16];
	uint8_t generation[32] = { 0 };
	int seed_fd = -1;
	struct stat info;
	if (argc != 6 || strcmp(argv[1], "--inetd") != 0 || strcmp(argv[2], "--generation-raw32") != 0 ||
		swz_hex_decode(argv[3], generation, sizeof(generation)) != 0 || strcmp(argv[4], "--seed-fd") != 0 ||
		swz_parse_fd(argv[5], &seed_fd) != 0 || lstat(supervisor, &info) != 0 ||
		!S_ISREG(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0022) != 0 || (info.st_mode & S_IXUSR) == 0 ||
		swz_validate_seed_fd(seed_fd, geteuid(), getegid()) != 0 || dup2(seed_fd, inherited_seed_fd) < 0 ||
		fcntl(inherited_seed_fd, F_SETFD, fcntl(inherited_seed_fd, F_GETFD) & ~FD_CLOEXEC) < 0 ||
		snprintf(seed_fd_text, sizeof(seed_fd_text), "%d", inherited_seed_fd) <= 0)
	{
		if (seed_fd >= 0)
			close(seed_fd);
		swz_zeroize(generation, sizeof(generation));
		return 64;
	}
	if (seed_fd != inherited_seed_fd)
		close(seed_fd);
	if (clearenv() != 0 || swz_confine_process() != 0)
	{
		swz_zeroize(generation, sizeof(generation));
		return 70;
	}
	execl(supervisor, supervisor, "--inetd", "--generation-raw32", argv[3], "--seed-fd", seed_fd_text, (char *)NULL);
	swz_zeroize(generation, sizeof(generation));
	return errno == ENOENT ? 127 : 126;
}
