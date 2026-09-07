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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int valid_hex(const char *text, size_t octets)
{
	uint8_t decoded[32];
	return octets <= sizeof(decoded) && text != NULL &&
	    swz_hex_decode(text, decoded, octets) == 0;
}

static int valid_store_digest(const char *text)
{
	uint8_t decoded[32];
	return text != NULL && strncmp(text, "sha256:v1:", 10) == 0 &&
	    swz_hex_decode(text + 10, decoded, sizeof(decoded)) == 0;
}

static int hex_value(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	return -1;
}

static int decode_payload_hex(const char *text, uint8_t **payload, size_t *length)
{
	if (text == NULL || payload == NULL || length == NULL)
		return -1;
	size_t encoded_length = strlen(text);
	if (encoded_length == 0 || encoded_length > SWZ_MAX_CONTROL_PAYLOAD * 2 ||
	    encoded_length % 2 != 0)
		return -1;
	size_t decoded_length = encoded_length / 2;
	uint8_t *decoded = malloc(decoded_length);
	if (decoded == NULL)
		return -1;
	for (size_t index = 0; index < decoded_length; index++) {
		int high = hex_value(text[index * 2]);
		int low = hex_value(text[index * 2 + 1]);
		if (high < 0 || low < 0) {
			free(decoded);
			return -1;
		}
		decoded[index] = (uint8_t)((high << 4) | low);
	}
	*payload = decoded;
	*length = decoded_length;
	return 0;
}

static int valid_transition(const char *transition)
{
	if (transition == NULL || strlen(transition) != 59 ||
	    strncmp(transition, "restore-v2-", 11) != 0)
		return 0;
	for (size_t index = 11; index < 59; index++) {
		char value = transition[index];
		if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')))
			return 0;
	}
	return 1;
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

static int read_until_eof(uint8_t *buffer, size_t capacity, size_t *length)
{
	size_t used = 0;
	for (;;) {
		ssize_t count = read(STDIN_FILENO, buffer + used, capacity - used);
		if (count == 0) {
			*length = used;
			return 0;
		}
		if (count < 0 && errno == EINTR)
			continue;
		if (count < 0 || (size_t)count > capacity - used)
			return -1;
		used += (size_t)count;
		if (used == capacity) {
			uint8_t probe;
			ssize_t extra = read(STDIN_FILENO, &probe, 1);
			if (extra == 0) {
				*length = used;
				return 0;
			}
			return -1;
		}
	}
}

static int read_file_contents(const char *source, uint8_t **contents, size_t *length)
{
	if (contents == NULL || length == NULL)
		return -1;
	int fd = open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	struct stat info;
	if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
	    info.st_size < 0 || info.st_size > 16 * 1024 * 1024) {
		close(fd);
		return -1;
	}
	size_t capacity = (size_t)info.st_size;
	uint8_t *buffer = capacity == 0 ? NULL : malloc(capacity);
	if (capacity != 0 && buffer == NULL) {
		close(fd);
		return -1;
	}
	size_t used = 0;
	while (used < capacity) {
		ssize_t count = read(fd, buffer + used, capacity - used);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0) {
			free(buffer);
			close(fd);
			return -1;
		}
		used += (size_t)count;
	}
	struct stat final_stat;
	int result = fstat(fd, &final_stat) == 0 && S_ISREG(final_stat.st_mode) &&
	    final_stat.st_size == info.st_size && used == capacity;
	close(fd);
	if (!result) {
		free(buffer);
		return -1;
	}
	*contents = buffer;
	*length = used;
	return 0;
}

static int copy_artifact(const char *target, const uint8_t *contents, size_t length)
{
	if (length != 0 && contents == NULL)
		return -1;
	const char *target_name = strrchr(target, '/');
	if (target_name == NULL || *++target_name == '\0' || strchr(target_name, '/') != NULL)
		return -1;
	char parent_path[4096];
	size_t parent_length = (size_t)(target_name - target - 1);
	if (parent_length == 0) {
		parent_path[0] = '/';
		parent_path[1] = '\0';
	} else if (parent_length >= sizeof(parent_path)) {
		return -1;
	} else {
		memcpy(parent_path, target, parent_length);
		parent_path[parent_length] = '\0';
	}
	int parent_fd = open(parent_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (parent_fd < 0)
		return -1;
	struct stat target_stat;
	if (fstatat(parent_fd, target_name, &target_stat, AT_SYMLINK_NOFOLLOW) == 0 &&
	    S_ISLNK(target_stat.st_mode)) {
		close(parent_fd);
		return -1;
	}
	char temporary_name[96];
	int name_length = snprintf(temporary_name, sizeof(temporary_name), ".swz-restore-%ld", (long)getpid());
	if (name_length <= 0 || (size_t)name_length >= sizeof(temporary_name)) {
		close(parent_fd);
		return -1;
	}
	int output_fd = openat(parent_fd, temporary_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (output_fd < 0) {
		close(parent_fd);
		return -1;
	}
	int result = -1;
	uint8_t buffer[65536];
	size_t offset = 0;
	while (offset < length) {
		size_t chunk = length - offset > sizeof(buffer) ? sizeof(buffer) : length - offset;
		memcpy(buffer, contents + offset, chunk);
		uint8_t *cursor = buffer;
		size_t left = chunk;
		while (left > 0) {
			ssize_t written = write(output_fd, cursor, left);
			if (written < 0 && errno == EINTR)
				continue;
			if (written <= 0)
				goto cleanup;
			cursor += written;
			left -= (size_t)written;
		}
		offset += chunk;
	}
	if (fsync(output_fd) != 0)
		goto cleanup;
	if (close(output_fd) != 0) {
		output_fd = -1;
		goto cleanup;
	}
	output_fd = -1;
	if (renameat(parent_fd, temporary_name, parent_fd, target_name) != 0 ||
	    fsync(parent_fd) != 0)
		goto cleanup;
	result = 0;
cleanup:
	if (output_fd >= 0)
		close(output_fd);
	if (result != 0)
		(void)unlinkat(parent_fd, temporary_name, 0);
	close(parent_fd);
	return result;
}

static int expected_environment(const char *session, const char *generation, const char *cookie, pid_t owner_pid)
{
	const char *accepted = getenv("SWZ_ACCEPTED");
	const char *authorized = getenv("SWZ_PROCEED_AUTHORIZED");
	const char *environment_session = getenv("SWZ_SESSION");
	const char *environment_generation = getenv("SWZ_GENERATION");
	const char *environment_cookie = getenv("SWZ_CONNECTION_COOKIE");
	const char *lifecycle = getenv("SWZ_LIFECYCLE");
	return owner_pid > 0 && swz_is_descendant(getpid(), owner_pid) &&
	    accepted != NULL && strcmp(accepted, "1") == 0 &&
	    authorized != NULL && strcmp(authorized, "1") == 0 &&
	    environment_session != NULL && strcmp(environment_session, session) == 0 &&
	    environment_generation != NULL && strcmp(environment_generation, generation) == 0 &&
	    environment_cookie != NULL && strcmp(environment_cookie, cookie) == 0 &&
	    lifecycle != NULL && strcmp(lifecycle, "ACTIVE") == 0;
}

static int parse_owner_pid(const char *text, pid_t *pid)
{
	char *end = NULL;
	errno = 0;
	long value = text == NULL ? 0 : strtol(text, &end, 10);
	if (errno != 0 || end == text || end == NULL || *end != '\0' || value <= 0)
		return -1;
	*pid = (pid_t)value;
	return 0;
}

static int validate_proceed(
	const uint8_t *payload,
	size_t payload_length,
	const char *session,
	const char *transition,
	const char *transition_data,
	const char *restore_begin_frame,
	char pc_hex[65])
{
	uint8_t session_raw[32];
	uint8_t transition_data_raw[32];
	uint8_t restore_begin_raw[32];
	if (swz_hex_decode(session, session_raw, sizeof(session_raw)) != 0 ||
	    swz_hex_decode(transition_data + 10, transition_data_raw, sizeof(transition_data_raw)) != 0 ||
	    swz_hex_decode(restore_begin_frame, restore_begin_raw, sizeof(restore_begin_raw)) != 0)
		return -1;
	const uint8_t *parts[] = {
		session_raw, (const uint8_t *)transition, transition_data_raw, restore_begin_raw,
	};
	const size_t lengths[] = {
		sizeof(session_raw), strlen(transition), sizeof(transition_data_raw), sizeof(restore_begin_raw),
	};
	uint8_t pc_raw[32];
	if (swz_managed_hash("proceed.v1", parts, lengths, 4, pc_raw) != 0)
		return -1;
	static const char hex[] = "0123456789abcdef";
	for (size_t index = 0; index < sizeof(pc_raw); index++) {
		pc_hex[index * 2] = hex[pc_raw[index] >> 4];
		pc_hex[index * 2 + 1] = hex[pc_raw[index] & 0x0f];
	}
	pc_hex[64] = '\0';
	char expected[1024];
	int expected_length = snprintf(
	    expected, sizeof(expected),
	    "[\"PROCEED\",2,\"swz-managed.v1\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]",
	    restore_begin_frame, session, transition, transition_data, restore_begin_frame, pc_hex);
	if (expected_length <= 0 || (size_t)expected_length != payload_length)
		return -1;
	return memcmp(expected, payload, payload_length) == 0 ? 0 : -1;
}

static int emit_result(const uint8_t *payload, size_t payload_length)
{
	if (payload == NULL || payload_length == 0 ||
	    payload_length > SWZ_MAX_CONTROL_PAYLOAD ||
	    swz_frame_is_canonical_json(payload, payload_length) != 0)
		return -1;
	uint8_t nonce[32];
	if (swz_random_bytes(nonce, sizeof(nonce)) != 0)
		return -1;
	struct swz_frame frame = {
		.direction = SWZ_REMOTE_TO_LOCAL,
		.message = SWZ_RESULT,
		.sequence = 9,
		.payload_length = (uint32_t)payload_length,
		.payload = (const uint8_t *)payload,
	};
	memcpy(frame.nonce, nonce, sizeof(nonce));
	uint8_t encoded[SWZ_MAX_FRAME];
	size_t written = 0;
	if (swz_frame_encode(&frame, encoded, sizeof(encoded), &written) != 0)
		return -1;
	return swz_write_full(STDOUT_FILENO, encoded, written);
}

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s --source ABSOLUTE_PATH --target ABSOLUTE_PATH --session HEX64 --generation HEX64 --cookie HEX64 --owner-pid PID --transition restore-v2-HEX48 --transition-data sha256:v1:HEX64 --artifact-stream sha256:v1:HEX64 --restore-begin-frame HEX64 --result-payload HEX\n", program);
}

int main(int argc, char **argv)
{
	const char *source = NULL;
	const char *target = NULL;
	const char *session = NULL;
	const char *generation = NULL;
	const char *cookie = NULL;
	const char *transition = NULL;
	const char *transition_data = NULL;
	const char *artifact_stream = NULL;
	const char *restore_begin_frame = NULL;
	const char *result_payload_hex = NULL;
	const char *owner_pid_text = NULL;
	int option;
	static const struct option options[] = {
		{ "source", required_argument, NULL, 's' },
		{ "target", required_argument, NULL, 't' },
		{ "session", required_argument, NULL, 'n' },
		{ "generation", required_argument, NULL, 'g' },
		{ "cookie", required_argument, NULL, 'c' },
		{ "owner-pid", required_argument, NULL, 'o' },
		{ "transition", required_argument, NULL, 'r' },
		{ "transition-data", required_argument, NULL, 'd' },
		{ "artifact-stream", required_argument, NULL, 'a' },
		{ "restore-begin-frame", required_argument, NULL, 'b' },
		{ "result-payload", required_argument, NULL, 'p' },
		{ NULL, 0, NULL, 0 },
	};
	while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
		if (option == 's')
			source = optarg;
		else if (option == 't')
			target = optarg;
		else if (option == 'n')
			session = optarg;
		else if (option == 'g')
			generation = optarg;
		else if (option == 'c')
			cookie = optarg;
		else if (option == 'o')
			owner_pid_text = optarg;
		else if (option == 'r')
			transition = optarg;
		else if (option == 'd')
			transition_data = optarg;
		else if (option == 'a')
			artifact_stream = optarg;
		else if (option == 'b')
			restore_begin_frame = optarg;
		else if (option == 'p')
			result_payload_hex = optarg;
		else {
			usage(argv[0]);
			return 64;
		}
	}
	pid_t owner_pid = 0;
	if (valid_path(source) != 0 || valid_path(target) != 0 ||
	    !valid_hex(session, 32) || !valid_hex(generation, 32) ||
	    !valid_hex(cookie, 32) || parse_owner_pid(owner_pid_text, &owner_pid) != 0 ||
		!valid_transition(transition) || !valid_store_digest(transition_data) ||
		!valid_store_digest(artifact_stream) ||
		!valid_hex(restore_begin_frame, 32) ||
		result_payload_hex == NULL ||
		!expected_environment(session, generation, cookie, owner_pid))
		return 64;
	uint8_t input[SWZ_MAX_FRAME];
	size_t input_length = 0;
	if (read_until_eof(input, sizeof(input), &input_length) != 0)
		return 65;
	struct swz_frame frame;
	if (swz_frame_decode(input, input_length, &frame) != 0 ||
	    frame.direction != SWZ_LOCAL_TO_REMOTE || frame.message != SWZ_PROCEED ||
	    frame.sequence != 8 ||
	    swz_frame_is_canonical_json(frame.payload, frame.payload_length) != 0)
		return 66;
	char proceed_hex[65];
	if (validate_proceed(
		frame.payload, frame.payload_length, session, transition, transition_data,
		restore_begin_frame, proceed_hex) != 0)
		return 67;
	uint8_t *result_payload = NULL;
	size_t result_payload_length = 0;
	if (decode_payload_hex(result_payload_hex, &result_payload, &result_payload_length) != 0 ||
		swz_frame_is_canonical_json(result_payload, result_payload_length) != 0) {
		free(result_payload);
		return 68;
	}
	uint8_t *contents = NULL;
	size_t contents_length = 0;
	if (read_file_contents(source, &contents, &contents_length) != 0) {
		free(result_payload);
		return 69;
	}
	char source_commitment[75];
	if (swz_store_commitment("artifact-stream", contents, contents_length, source_commitment) != 0) {
		free(contents);
		free(result_payload);
		return 69;
	}
	if (strcmp(source_commitment, artifact_stream) != 0)
	{
		free(contents);
		free(result_payload);
		return 70;
	}
	if (copy_artifact(target, contents, contents_length) != 0) {
		free(contents);
		free(result_payload);
		return 71;
	}
	free(contents);
	int result = emit_result(result_payload, result_payload_length);
	free(result_payload);
	return result == 0 ? 0 : 72;
}
