#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int authorized_environment(void)
{
	const char *accepted = getenv("SWZ_ACCEPTED");
	const char *authorized = getenv("SWZ_LAUNCH_AUTHORIZED");
	const char *lifecycle = getenv("SWZ_LIFECYCLE");
	return accepted != NULL && strcmp(accepted, "1") == 0 &&
	    authorized != NULL && strcmp(authorized, "1") == 0 &&
	    lifecycle != NULL && strcmp(lifecycle, "ACTIVE") == 0;
}

static int allowed_component(const char *path)
{
	static const char *const components[] = {
		"/usr/local/libexec/swz-supervisor",
		"/usr/local/libexec/swz-custodian",
		"/usr/local/libexec/swz-dispatcher",
		"/usr/local/libexec/swz-bootstrap",
		"/usr/local/libexec/swz-broker",
		"/usr/local/libexec/swz-agent",
	};
	struct stat info;
	if (path == NULL || !authorized_environment() ||
		lstat(path, &info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != 0 ||
		(info.st_mode & 022) != 0 || (info.st_mode & S_IXUSR) == 0)
		return 0;
	for (size_t index = 0; index < sizeof(components) / sizeof(components[0]); index++) {
		if (strcmp(path, components[index]) == 0)
			return 1;
	}
	return 0;
}

static int save_binding_environment(char values[][128], unsigned char present[], size_t count)
{
	static const char *const names[] = {
		"SWZ_ACCEPTED", "SWZ_LAUNCH_AUTHORIZED", "SWZ_PROCEED_AUTHORIZED",
		"SWZ_SESSION", "SWZ_GENERATION", "SWZ_CONNECTION_COOKIE",
		"SWZ_LIFECYCLE", "SWZ_BOOTSTRAP",
	};
	if (count != sizeof(names) / sizeof(names[0]))
		return -1;
	for (size_t index = 0; index < count; index++) {
		const char *value = getenv(names[index]);
		if (value == NULL)
			continue;
		size_t length = strlen(value);
		if (length == 0 || length >= 128)
			return -1;
		memcpy(values[index], value, length + 1);
		present[index] = 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2 || !allowed_component(argv[1]))
		return 64;
	if (setuid(0) != 0 || setgid(0) != 0)
		return 77;
	char values[8][128] = {{ 0 }};
	unsigned char present[8] = { 0 };
	if (save_binding_environment(values, present, 8) != 0)
		return 79;
	if (clearenv() != 0)
		return 78;
	setenv("PATH", "/usr/local/libexec:/opt/swz/openssh/bin:/usr/bin:/bin", 1);
	setenv("SWZ_LAUNCH_BASE", "authenticated", 1);
	static const char *const names[] = {
		"SWZ_ACCEPTED", "SWZ_LAUNCH_AUTHORIZED", "SWZ_PROCEED_AUTHORIZED",
		"SWZ_SESSION", "SWZ_GENERATION", "SWZ_CONNECTION_COOKIE",
		"SWZ_LIFECYCLE", "SWZ_BOOTSTRAP",
	};
	for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
		if (present[index] && setenv(names[index], values[index], 1) != 0)
			return 79;
	}
	execv(argv[1], &argv[1]);
	return errno == ENOENT ? 127 : 126;
}
