#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_expected(uint8_t message, uint8_t direction, uint64_t sequence, uint8_t *buffer, size_t *length)
{
	struct swz_frame frame;
	if (swz_frame_read_fd(STDIN_FILENO, buffer, SWZ_MAX_FRAME, length, 10000) != 0 ||
		swz_frame_decode(buffer, *length, &frame) != 0 || frame.message != message ||
		frame.direction != direction || frame.sequence != sequence ||
		swz_frame_is_canonical_json(frame.payload, frame.payload_length) != 0)
		return -1;
	return 0;
}

int main(int argc, char **argv)
{
	(void)argv;
	uint8_t context_session[32] = { 0 };
	uint8_t context_generation[32] = { 0 };
	uint8_t context_connection[32] = { 0 };
	uint8_t context_cookie[32] = { 0 };
	if (argc != 1 || swz_read_context_record(SWZ_CONTEXT_FD, context_session, context_generation, context_connection, context_cookie) != 0 ||
		clearenv() != 0 || swz_confine_process() != 0)
		return 64;
	uint8_t buffer[SWZ_MAX_FRAME];
	size_t length = 0;
	static const uint8_t messages[] = { SWZ_ACCEPTED, SWZ_DISCOVERY, SWZ_RESTORE_BEGIN, SWZ_PROCEED, SWZ_RESULT };
	static const uint8_t directions[] = { SWZ_REMOTE_TO_LOCAL, SWZ_LOCAL_TO_REMOTE, SWZ_REMOTE_TO_LOCAL, SWZ_LOCAL_TO_REMOTE, SWZ_REMOTE_TO_LOCAL };
	static const uint64_t sequences[] = { 5, 6, 7, 8, 9 };
	for (size_t index = 0; index < sizeof(messages); index++)
		if (read_expected(messages[index], directions[index], sequences[index], buffer, &length) != 0)
			return 65;
	uint8_t trailing;
	ssize_t count;
	do {
		count = read(STDIN_FILENO, &trailing, 1);
	} while (count < 0 && errno == EINTR);
	if (count != 0)
		return 66;
	static const char finality[] = "BROKER_FINAL\n";
	int result = swz_write_full(STDOUT_FILENO, finality, sizeof(finality) - 1) == 0 ? 0 : 70;
	swz_zeroize(context_session, sizeof(context_session));
	swz_zeroize(context_generation, sizeof(context_generation));
	swz_zeroize(context_connection, sizeof(context_connection));
	swz_zeroize(context_cookie, sizeof(context_cookie));
	return result;
}
