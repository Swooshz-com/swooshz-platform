#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int valid_binding(const char *text)
{
	uint8_t value[32];
	return text != NULL && swz_hex_decode(text, value, sizeof(value)) == 0;
}

static int read_frame(uint8_t *buffer, size_t capacity, size_t *length)
{
	size_t used = 0;
	while (used < SWZ_FRAME_HEADER_BYTES) {
		ssize_t count = read(STDIN_FILENO, buffer + used, SWZ_FRAME_HEADER_BYTES - used);
		if (count < 0 && errno == EINTR)
			continue;
		if (count == 0)
			return used == 0 ? 1 : -1;
		if (count < 0)
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

int main(void)
{
	const char *accepted = getenv("SWZ_ACCEPTED");
	const char *session = getenv("SWZ_SESSION");
	const char *generation = getenv("SWZ_GENERATION");
	const char *cookie = getenv("SWZ_CONNECTION_COOKIE");
	const char *lifecycle = getenv("SWZ_LIFECYCLE");
	if (accepted == NULL || strcmp(accepted, "1") != 0 ||
	    session == NULL || generation == NULL || cookie == NULL ||
	    lifecycle == NULL || strcmp(lifecycle, "ACTIVE") != 0 ||
	    !valid_binding(session) || !valid_binding(generation) || !valid_binding(cookie))
		return 64;
	static const enum swz_message expected[] = {
		SWZ_ACCEPTED, SWZ_DISCOVERY, SWZ_RESTORE_BEGIN, SWZ_PROCEED, SWZ_RESULT,
	};
	static const uint8_t directions[] = {
		SWZ_REMOTE_TO_LOCAL, SWZ_LOCAL_TO_REMOTE, SWZ_REMOTE_TO_LOCAL,
		SWZ_LOCAL_TO_REMOTE, SWZ_REMOTE_TO_LOCAL,
	};
	static const uint64_t sequences[] = { 5, 6, 7, 8, 9 };
	uint8_t buffer[SWZ_MAX_FRAME];
	for (size_t index = 0; index < sizeof(expected) / sizeof(expected[0]); index++) {
		size_t length = 0;
		struct swz_frame frame;
		if (read_frame(buffer, sizeof(buffer), &length) != 0 ||
		    swz_frame_decode(buffer, length, &frame) != 0 ||
		    frame.message != expected[index] ||
		    frame.direction != directions[index] ||
		    frame.sequence != sequences[index] ||
		    swz_frame_is_canonical_json(frame.payload, frame.payload_length) != 0)
			return 65;
	}
	uint8_t trailing;
	ssize_t count;
	do {
		count = read(STDIN_FILENO, &trailing, 1);
	} while (count < 0 && errno == EINTR);
	if (count != 0)
		return 66;
	static const char finality[] = "BROKER_FINAL\n";
	return swz_write_full(STDOUT_FILENO, finality, sizeof(finality) - 1) == 0 ? 0 : 70;
}
