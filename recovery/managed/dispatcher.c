#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int valid_executable(const char *path)
{
	struct stat info;
	size_t length = path == NULL ? 0 : strlen(path);
	return path != NULL && path[0] == '/' && length > 1 && length < 4096 &&
		strstr(path, "//") == NULL && strstr(path, "/../") == NULL &&
		lstat(path, &info) == 0 && S_ISREG(info.st_mode) &&
		(info.st_mode & 0022) == 0 && (info.st_mode & S_IXUSR) != 0;
}

static int strict_protocol_command(void)
{
	const char *command = getenv("SSH_ORIGINAL_COMMAND");
	return command != NULL && strcmp(command, "swz-recovery-v1") == 0;
}

int main(int argc, char **argv)
{
	static const char bootstrap[] = SWZ_BOOTSTRAP_PATH;
	(void)argv;
	if (argc != 1 || !strict_protocol_command() || !valid_executable(bootstrap))
		return 64;
	if (clearenv() != 0 || swz_confine_process() != 0)
		return 70;
	execl(bootstrap, bootstrap, (char *)NULL);
	return errno == ENOENT ? 127 : 126;
}
