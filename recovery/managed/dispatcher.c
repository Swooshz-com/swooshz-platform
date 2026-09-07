#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int valid_hex(const char *text)
{
	uint8_t decoded[32];
	return text != NULL && swz_hex_decode(text, decoded, sizeof(decoded)) == 0;
}

static int valid_path(const char *path)
{
	size_t length = path == NULL ? 0 : strlen(path);
	if (path == NULL || path[0] != '/' || length < 2 || length >= 4096)
		return -1;
	if (strstr(path, "//") != NULL || strstr(path, "/../") != NULL ||
	    (length >= 3 && strcmp(path + length - 3, "/..") == 0))
		return -1;
	return 0;
}

static int read_frame_fd(int fd, uint8_t *buffer, size_t capacity, size_t *length)
{
	size_t used = 0;
	while (used < SWZ_FRAME_HEADER_BYTES) {
		ssize_t count = read(fd, buffer + used, SWZ_FRAME_HEADER_BYTES - used);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		used += (size_t)count;
	}
	uint32_t payload_length = ((uint32_t)buffer[52] << 24) |
	    ((uint32_t)buffer[53] << 16) | ((uint32_t)buffer[54] << 8) | buffer[55];
	if (payload_length > SWZ_MAX_CONTROL_PAYLOAD ||
	    SWZ_FRAME_HEADER_BYTES + payload_length > capacity)
		return -1;
	while (used < SWZ_FRAME_HEADER_BYTES + payload_length) {
		ssize_t count = read(fd, buffer + used, SWZ_FRAME_HEADER_BYTES + payload_length - used);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		used += (size_t)count;
	}
	*length = used;
	return 0;
}

static int parse_pid(const char *text, pid_t *result)
{
	char *end = NULL;
	errno = 0;
	long value = text == NULL ? 0 : strtol(text, &end, 10);
	if (errno != 0 || end == text || end == NULL || *end != '\0' || value <= 0)
		return -1;
	*result = (pid_t)value;
	return 0;
}

static int run_bootstrap(
	const char *bootstrap_path,
	const char *session,
	const char *generation,
	const char *cookie,
	pid_t owner_pid,
	const uint8_t *input,
	size_t input_length,
	uint8_t *output,
	size_t output_capacity,
	size_t *output_length)
{
	int input_pipe[2] = { -1, -1 };
	int output_pipe[2] = { -1, -1 };
	if (pipe(input_pipe) != 0 || pipe(output_pipe) != 0) {
		if (input_pipe[0] >= 0)
			close(input_pipe[0]);
		if (input_pipe[1] >= 0)
			close(input_pipe[1]);
		return -1;
	}
	pid_t child = fork();
	if (child < 0) {
		close(input_pipe[0]);
		close(input_pipe[1]);
		close(output_pipe[0]);
		close(output_pipe[1]);
		return -1;
	}
	if (child == 0) {
		close(input_pipe[1]);
		close(output_pipe[0]);
		if (dup2(input_pipe[0], STDIN_FILENO) < 0 || dup2(output_pipe[1], STDOUT_FILENO) < 0)
			_exit(126);
		close(input_pipe[0]);
		close(output_pipe[1]);
		if (setenv("SWZ_BOOTSTRAP", "1", 1) != 0)
			_exit(126);
		char owner_text[32];
		int owner_length = snprintf(owner_text, sizeof(owner_text), "%ld", (long)owner_pid);
		if (owner_length <= 0 || (size_t)owner_length >= sizeof(owner_text))
			_exit(126);
		execl(
		    bootstrap_path, bootstrap_path,
		    "--session", session, "--generation", generation, "--cookie", cookie,
		    "--owner-pid", owner_text, (char *)NULL);
		_exit(127);
	}
	close(input_pipe[0]);
	close(output_pipe[1]);
	int result = swz_write_full(input_pipe[1], input, input_length);
	close(input_pipe[1]);
	if (result == 0)
		result = read_frame_fd(output_pipe[0], output, output_capacity, output_length);
	close(output_pipe[0]);
	int status = 0;
	if (waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		result = -1;
	return result;
}

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s --bootstrap PATH --session HEX64 --generation HEX64 --cookie HEX64 --owner-pid PID\n", program);
}

int main(int argc, char **argv)
{
	const char *bootstrap_path = NULL;
	const char *session = NULL;
	const char *generation = NULL;
	const char *cookie = NULL;
	const char *owner_pid_text = NULL;
	int option;
	static const struct option options[] = {
		{ "bootstrap", required_argument, NULL, 'b' },
		{ "session", required_argument, NULL, 'n' },
		{ "generation", required_argument, NULL, 'g' },
		{ "cookie", required_argument, NULL, 'c' },
		{ "owner-pid", required_argument, NULL, 'o' },
		{ NULL, 0, NULL, 0 },
	};
	while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
		if (option == 'b')
			bootstrap_path = optarg;
		else if (option == 'n')
			session = optarg;
		else if (option == 'g')
			generation = optarg;
		else if (option == 'c')
			cookie = optarg;
		else if (option == 'o')
			owner_pid_text = optarg;
		else {
			usage(argv[0]);
			return 64;
		}
	}
	pid_t owner_pid = 0;
	const char *lifecycle = getenv("SWZ_LIFECYCLE");
	if (valid_path(bootstrap_path) != 0 || !valid_hex(session) ||
	    !valid_hex(generation) || !valid_hex(cookie) ||
	    parse_pid(owner_pid_text, &owner_pid) != 0 ||
	    !swz_is_descendant(getpid(), owner_pid) ||
	    getenv("SWZ_ACCEPTED") == NULL || strcmp(getenv("SWZ_ACCEPTED"), "1") != 0 ||
	    lifecycle == NULL || strcmp(lifecycle, "ACTIVE") != 0 ||
	    swz_proc_env_equals(getpid(), "SWZ_SESSION", session) != 0 ||
	    swz_proc_env_equals(getpid(), "SWZ_GENERATION", generation) != 0 ||
	    swz_proc_env_equals(getpid(), "SWZ_CONNECTION_COOKIE", cookie) != 0)
		return 64;
	uint8_t input[SWZ_MAX_FRAME];
	size_t input_length = 0;
	struct swz_frame input_frame;
	if (read_frame_fd(STDIN_FILENO, input, sizeof(input), &input_length) != 0 ||
	    swz_frame_decode(input, input_length, &input_frame) != 0 ||
	    input_frame.direction != SWZ_LOCAL_TO_REMOTE ||
	    input_frame.message != SWZ_ACCEPTED || input_frame.sequence != 5 ||
	    swz_frame_is_canonical_json(input_frame.payload, input_frame.payload_length) != 0)
		return 65;
	uint8_t output[SWZ_MAX_FRAME];
	size_t output_length = 0;
	if (run_bootstrap(
		bootstrap_path, session, generation, cookie, owner_pid,
		input, input_length, output, sizeof(output), &output_length) != 0)
		return 70;
	struct swz_frame output_frame;
	if (swz_frame_decode(output, output_length, &output_frame) != 0 ||
	    output_frame.direction != SWZ_REMOTE_TO_LOCAL ||
	    output_frame.message != SWZ_CHALLENGE)
		return 71;
	return swz_write_full(STDOUT_FILENO, output, output_length) == 0 ? 0 : 72;
}
