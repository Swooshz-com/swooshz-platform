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
#include <unistd.h>

static int valid_hex(const char *text)
{
	uint8_t decoded[32];
	return text != NULL && swz_hex_decode(text, decoded, sizeof(decoded)) == 0;
}

static int read_frame(uint8_t *buffer, size_t capacity, size_t *length)
{
	size_t used = 0;
	while (used < SWZ_FRAME_HEADER_BYTES) {
		ssize_t count = read(STDIN_FILENO, buffer + used, SWZ_FRAME_HEADER_BYTES - used);
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
		ssize_t count = read(STDIN_FILENO, buffer + used, SWZ_FRAME_HEADER_BYTES + payload_length - used);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		used += (size_t)count;
	}
	*length = used;
	return 0;
}

static int expected_environment(const char *session, const char *generation, const char *cookie, pid_t owner_pid)
{
	const char *accepted = getenv("SWZ_ACCEPTED");
	const char *bootstrap = getenv("SWZ_BOOTSTRAP");
	const char *lifecycle = getenv("SWZ_LIFECYCLE");
	return owner_pid > 0 && swz_is_descendant(getpid(), owner_pid) &&
	    accepted != NULL && strcmp(accepted, "1") == 0 &&
	    bootstrap != NULL && strcmp(bootstrap, "1") == 0 &&
	    lifecycle != NULL && strcmp(lifecycle, "ACTIVE") == 0 &&
	    swz_proc_env_equals(getpid(), "SWZ_SESSION", session) == 0 &&
	    swz_proc_env_equals(getpid(), "SWZ_GENERATION", generation) == 0 &&
	    swz_proc_env_equals(getpid(), "SWZ_CONNECTION_COOKIE", cookie) == 0;
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

static int emit_challenge(const char *session)
{
	char payload[256];
	int length = snprintf(payload, sizeof(payload), "[\"CHALLENGE\",2,\"swz-managed.v1\",\"%s\"]", session);
	if (length <= 0 || (size_t)length >= sizeof(payload))
		return -1;
	uint8_t nonce[32];
	if (swz_random_bytes(nonce, sizeof(nonce)) != 0)
		return -1;
	struct swz_frame frame = {
		.direction = SWZ_REMOTE_TO_LOCAL,
		.message = SWZ_CHALLENGE,
		.sequence = 2,
		.payload_length = (uint32_t)length,
		.payload = (const uint8_t *)payload,
	};
	memcpy(frame.nonce, nonce, sizeof(nonce));
	uint8_t encoded[SWZ_MAX_FRAME];
	size_t encoded_length = 0;
	if (swz_frame_encode(&frame, encoded, sizeof(encoded), &encoded_length) != 0)
		return -1;
	return swz_write_full(STDOUT_FILENO, encoded, encoded_length);
}

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s --session HEX64 --generation HEX64 --cookie HEX64 --owner-pid PID\n", program);
}

int main(int argc, char **argv)
{
	const char *session = NULL;
	const char *generation = NULL;
	const char *cookie = NULL;
	const char *owner_pid_text = NULL;
	int option;
	static const struct option options[] = {
		{ "session", required_argument, NULL, 'n' },
		{ "generation", required_argument, NULL, 'g' },
		{ "cookie", required_argument, NULL, 'c' },
		{ "owner-pid", required_argument, NULL, 'o' },
		{ NULL, 0, NULL, 0 },
	};
	while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
		if (option == 'n')
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
	if (!valid_hex(session) || !valid_hex(generation) || !valid_hex(cookie) ||
	    parse_pid(owner_pid_text, &owner_pid) != 0 ||
	    !expected_environment(session, generation, cookie, owner_pid))
		return 64;
	uint8_t input[SWZ_MAX_FRAME];
	size_t input_length = 0;
	struct swz_frame frame;
	if (read_frame(input, sizeof(input), &input_length) != 0 ||
	    swz_frame_decode(input, input_length, &frame) != 0 ||
	    frame.direction != SWZ_LOCAL_TO_REMOTE || frame.message != SWZ_ACCEPTED ||
	    frame.sequence != 5 ||
	    swz_frame_is_canonical_json(frame.payload, frame.payload_length) != 0)
		return 65;
	return emit_challenge(session) == 0 ? 0 : 70;
}
