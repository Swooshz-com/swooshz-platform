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

#define SWZ_ARTIFACT_MAX (16U * 1024U * 1024U)
#define SWZ_PATH_MAX 4096U

static int valid_hex(const char *text, size_t octets)
{
	uint8_t value[32];
	return text != NULL && octets <= sizeof(value) && swz_hex_decode(text, value, octets) == 0;
}

static int valid_store_digest(const char *text)
{
	uint8_t value[32];
	return text != NULL && strlen(text) == 74 && strncmp(text, "sha256:v1:", 10) == 0 &&
		swz_hex_decode(text + 10, value, sizeof(value)) == 0;
}

static int valid_transition(const char *text)
{
	if (text == NULL || strlen(text) != 59 || strncmp(text, "restore-v2-", 11) != 0)
		return 0;
	for (size_t index = 11; index < 59; index++) {
		char value = text[index];
		if (!((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')))
			return 0;
	}
	return 1;
}

static int valid_path(const char *path)
{
	size_t length = path == NULL ? 0 : strlen(path);
	if (path == NULL || path[0] != '/' || length < 2 || length >= SWZ_PATH_MAX)
		return -1;
	if (strstr(path, "//") != NULL || strstr(path, "/../") != NULL ||
		(length >= 3 && strcmp(path + length - 3, "/..") == 0))
		return -1;
	return 0;
}

static int read_bounded_file(const char *path, uint8_t **contents, size_t *length)
{
	if (contents == NULL || length == NULL || valid_path(path) != 0)
		return -1;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	struct stat before;
	if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size < 0 ||
		(uintmax_t)before.st_size > SWZ_ARTIFACT_MAX) {
		close(fd);
		return -1;
	}
	size_t capacity = (size_t)before.st_size;
	uint8_t *value = capacity == 0 ? NULL : malloc(capacity);
	if (capacity != 0 && value == NULL) {
		close(fd);
		return -1;
	}
	size_t used = 0;
	while (used < capacity) {
		ssize_t received = read(fd, value + used, capacity - used);
		if (received < 0 && errno == EINTR)
			continue;
		if (received <= 0) {
			free(value);
			close(fd);
			return -1;
		}
		used += (size_t)received;
	}
	struct stat after;
	int stable = fstat(fd, &after) == 0 && after.st_dev == before.st_dev &&
		after.st_ino == before.st_ino && after.st_size == before.st_size;
	close(fd);
	if (!stable) {
		free(value);
		return -1;
	}
	*contents = value;
	*length = used;
	return 0;
}

static int decode_hex(const char *text, uint8_t **value, size_t *length)
{
	if (text == NULL || value == NULL || length == NULL)
		return -1;
	size_t encoded_length = strlen(text);
	if (encoded_length == 0 || encoded_length > SWZ_MAX_CONTROL_PAYLOAD * 2 || (encoded_length & 1U) != 0)
		return -1;
	size_t decoded_length = encoded_length / 2;
	uint8_t *decoded = malloc(decoded_length);
	if (decoded == NULL)
		return -1;
	if (swz_hex_decode(text, decoded, decoded_length) != 0) {
		free(decoded);
		return -1;
	}
	*value = decoded;
	*length = decoded_length;
	return 0;
}

static int copy_artifact(const char *target, const uint8_t *contents, size_t length)
{
	if (valid_path(target) != 0 || (length != 0 && contents == NULL))
		return -1;
	const char *name = strrchr(target, '/');
	if (name == NULL || name[1] == '\0' || strchr(name + 1, '/') != NULL ||
		strcmp(name + 1, ".") == 0 || strcmp(name + 1, "..") == 0)
		return -1;
	size_t parent_length = (size_t)(name - target);
	char parent_path[SWZ_PATH_MAX];
	if (parent_length == 0) {
		memcpy(parent_path, "/", 2);
	} else if (parent_length >= sizeof(parent_path)) {
		return -1;
	} else {
		memcpy(parent_path, target, parent_length);
		parent_path[parent_length] = '\0';
	}
	int parent_fd = open(parent_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (parent_fd < 0)
		return -1;
	struct stat existing;
	if (fstatat(parent_fd, name + 1, &existing, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(existing.st_mode)) {
		close(parent_fd);
		return -1;
	}
	char temporary[96];
	int temporary_length = snprintf(temporary, sizeof(temporary), ".swz-restore-%ld", (long)getpid());
	if (temporary_length <= 0 || (size_t)temporary_length >= sizeof(temporary)) {
		close(parent_fd);
		return -1;
	}
	int output_fd = openat(parent_fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (output_fd < 0) {
		close(parent_fd);
		return -1;
	}
	int result = -1;
	size_t offset = 0;
	while (offset < length) {
		ssize_t written = write(output_fd, contents + offset, length - offset);
		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0)
			goto cleanup;
		offset += (size_t)written;
	}
	if (fsync(output_fd) != 0 || close(output_fd) != 0) {
		output_fd = -1;
		goto cleanup;
	}
	output_fd = -1;
	if (renameat(parent_fd, temporary, parent_fd, name + 1) != 0 || fsync(parent_fd) != 0)
		goto cleanup;
	result = 0;
cleanup:
	if (output_fd >= 0)
		close(output_fd);
	if (result != 0)
		(void)unlinkat(parent_fd, temporary, 0);
	close(parent_fd);
	return result;
}

static int make_hex(const uint8_t *value, size_t length, char *output, size_t output_size)
{
	static const char hex[] = "0123456789abcdef";
	if (value == NULL || output == NULL || output_size < length * 2 + 1)
		return -1;
	for (size_t index = 0; index < length; index++) {
		output[index * 2] = hex[value[index] >> 4];
		output[index * 2 + 1] = hex[value[index] & 0x0fU];
	}
	output[length * 2] = '\0';
	return 0;
}

static int validate_proceed(const uint8_t *payload, size_t payload_length, const char *session,
	const char *transition, const char *transition_data, const char *restore_begin_frame)
{
	uint8_t session_raw[32];
	uint8_t transition_data_raw[32];
	uint8_t restore_begin_raw[32];
	if (swz_hex_decode(session, session_raw, sizeof(session_raw)) != 0 ||
		swz_hex_decode(transition_data + 10, transition_data_raw, sizeof(transition_data_raw)) != 0 ||
		swz_hex_decode(restore_begin_frame, restore_begin_raw, sizeof(restore_begin_raw)) != 0)
		return -1;
	const uint8_t *parts[] = { session_raw, (const uint8_t *)transition, transition_data_raw, restore_begin_raw };
	const size_t lengths[] = { sizeof(session_raw), strlen(transition), sizeof(transition_data_raw), sizeof(restore_begin_raw) };
	uint8_t proceed_raw[32];
	char proceed_hex[65];
	if (swz_managed_hash("proceed.v1", parts, lengths, 4, proceed_raw) != 0 ||
		make_hex(proceed_raw, sizeof(proceed_raw), proceed_hex, sizeof(proceed_hex)) != 0)
		return -1;
	char expected[1024];
	int expected_length = snprintf(expected, sizeof(expected),
		"[\"PROCEED\",2,\"swz-managed.v1\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]",
		restore_begin_frame, session, transition, transition_data, restore_begin_frame, proceed_hex);
	return expected_length > 0 && (size_t)expected_length == payload_length &&
		memcmp(expected, payload, payload_length) == 0 ? 0 : -1;
}

static int load_result_payload(const char *payload_path, const char *payload_hex, uint8_t **payload, size_t *length)
{
	if ((payload_path == NULL) == (payload_hex == NULL))
		return -1;
	if (payload_path != NULL && read_bounded_file(payload_path, payload, length) != 0)
		return -1;
	if (payload_hex != NULL && decode_hex(payload_hex, payload, length) != 0)
		return -1;
	return *length > 0 && *length <= SWZ_MAX_CONTROL_PAYLOAD &&
		swz_frame_is_canonical_json(*payload, *length) == 0 ? 0 : -1;
}

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s --source ABSOLUTE_PATH --target ABSOLUTE_PATH --transition restore-v2-HEX48 --transition-data sha256:v1:HEX64 --artifact-stream sha256:v1:HEX64 --restore-begin-frame HEX64 (--result-payload-file ABSOLUTE_PATH | --result-payload HEX)\n", program);
}

int main(int argc, char **argv)
{
	const char *source = NULL;
	const char *target = NULL;
	const char *transition = NULL;
	const char *transition_data = NULL;
	const char *artifact_stream = NULL;
	const char *restore_begin_frame = NULL;
	const char *result_payload_path = NULL;
	const char *result_payload_hex = NULL;
	static const struct option options[] = {
		{ "source", required_argument, NULL, 's' }, { "target", required_argument, NULL, 't' },
		{ "transition", required_argument, NULL, 'r' }, { "transition-data", required_argument, NULL, 'd' },
		{ "artifact-stream", required_argument, NULL, 'a' }, { "restore-begin-frame", required_argument, NULL, 'b' },
		{ "result-payload-file", required_argument, NULL, 'f' }, { "result-payload", required_argument, NULL, 'p' },
		{ NULL, 0, NULL, 0 },
	};
	int option;
	while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
		switch (option) {
		case 's': source = optarg; break;
		case 't': target = optarg; break;
		case 'r': transition = optarg; break;
		case 'd': transition_data = optarg; break;
		case 'a': artifact_stream = optarg; break;
		case 'b': restore_begin_frame = optarg; break;
		case 'f': result_payload_path = optarg; break;
		case 'p': result_payload_hex = optarg; break;
		default: usage(argv[0]); return 64;
		}
	}
	uint8_t context_session[32] = { 0 };
	uint8_t context_generation[32] = { 0 };
	uint8_t context_connection[32] = { 0 };
	uint8_t context_cookie[32] = { 0 };
	char session[65];
	if (valid_path(source) != 0 || valid_path(target) != 0 ||
		!valid_transition(transition) || !valid_store_digest(transition_data) ||
		!valid_store_digest(artifact_stream) || !valid_hex(restore_begin_frame, 32) ||
		swz_read_context_record(SWZ_CONTEXT_FD, context_session, context_generation, context_connection, context_cookie) != 0 ||
		make_hex(context_session, sizeof(context_session), session, sizeof(session)) != 0 ||
		clearenv() != 0 ||
		(result_payload_path != NULL && valid_path(result_payload_path) != 0))
		return 64;
	uint8_t input[SWZ_MAX_FRAME];
	size_t input_length = 0;
	struct swz_frame frame;
	if (swz_frame_read_fd(STDIN_FILENO, input, sizeof(input), &input_length, 10000) != 0 ||
		swz_frame_decode(input, input_length, &frame) != 0 ||
		frame.direction != SWZ_LOCAL_TO_REMOTE || frame.message != SWZ_PROCEED || frame.sequence != 8 ||
		swz_frame_is_canonical_json(frame.payload, frame.payload_length) != 0 ||
		validate_proceed(frame.payload, frame.payload_length, session, transition, transition_data, restore_begin_frame) != 0)
		return 65;
	uint8_t trailing;
	ssize_t trailing_count;
	do {
		trailing_count = read(STDIN_FILENO, &trailing, 1);
	} while (trailing_count < 0 && errno == EINTR);
	if (trailing_count != 0)
		return 66;
	uint8_t *contents = NULL;
	size_t contents_length = 0;
	if (read_bounded_file(source, &contents, &contents_length) != 0)
		return 67;
	char source_commitment[75];
	if (swz_store_commitment("artifact-stream", contents, contents_length, source_commitment) != 0 ||
		strcmp(source_commitment, artifact_stream) != 0 || copy_artifact(target, contents, contents_length) != 0) {
		free(contents);
		return 68;
	}
	free(contents);
	uint8_t *result_payload = NULL;
	size_t result_payload_length = 0;
	if (load_result_payload(result_payload_path, result_payload_hex, &result_payload, &result_payload_length) != 0) {
		free(result_payload);
		return 69;
	}
	if (swz_confine_process() != 0) {
		free(result_payload);
		return 70;
	}
	uint8_t nonce[32];
	if (swz_random_bytes(nonce, sizeof(nonce)) != 0) {
		free(result_payload);
		return 71;
	}
	struct swz_frame result = {
		.direction = SWZ_REMOTE_TO_LOCAL,
		.message = SWZ_RESULT,
		.sequence = 9,
		.nonce = { 0 },
		.payload_length = (uint32_t)result_payload_length,
		.payload = result_payload,
	};
	memcpy(result.nonce, nonce, sizeof(nonce));
	int write_result = swz_frame_write_fd(STDOUT_FILENO, &result);
	free(result_payload);
	return write_result == 0 ? 0 : 72;
}
