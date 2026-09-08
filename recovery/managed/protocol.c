#define _POSIX_C_SOURCE 200809L
#include "protocol.h"
#include "platform.h"

#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

static uint32_t read_u32(const uint8_t *value)
{
	return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
	    ((uint32_t)value[2] << 8) | value[3];
}

static uint64_t read_u64(const uint8_t *value)
{
	uint64_t result = 0;
	for (size_t index = 0; index < 8; index++)
		result = (result << 8) | value[index];
	return result;
}

static void write_u32(uint8_t *value, uint32_t input)
{
	value[0] = (uint8_t)(input >> 24);
	value[1] = (uint8_t)(input >> 16);
	value[2] = (uint8_t)(input >> 8);
	value[3] = (uint8_t)input;
}

static void write_u64(uint8_t *value, uint64_t input)
{
	for (size_t index = 0; index < 8; index++) {
		value[7 - index] = (uint8_t)input;
		input >>= 8;
	}
}

static int valid_message(uint8_t message)
{
	return message >= SWZ_BOOT && message <= SWZ_ABORT;
}

const char *swz_message_name(uint8_t message)
{
	static const char *const names[] = {
		"", "BOOT", "CHALLENGE", "EVIDENCE", "ACCEPT", "ACCEPTED",
		"DISCOVERY", "RESTORE_BEGIN", "PROCEED", "RESULT", "ABORT",
	};
	return valid_message(message) ? names[message] : NULL;
}

int swz_frame_validate(const struct swz_frame *frame)
{
	if (frame == NULL || frame->direction < SWZ_LOCAL_TO_REMOTE ||
	    frame->direction > SWZ_REMOTE_TO_LOCAL || !valid_message(frame->message) ||
	    frame->sequence == 0 || frame->sequence > SWZ_MAX_SESSION_FRAMES ||
	    frame->payload == NULL || frame->payload_length == 0 ||
	    frame->payload_length > SWZ_MAX_CONTROL_PAYLOAD ||
	    SWZ_FRAME_HEADER_BYTES + frame->payload_length > SWZ_MAX_FRAME)
		return -1;
	return 0;
}

int swz_frame_encode(const struct swz_frame *frame, uint8_t *out, size_t out_size, size_t *written)
{
	if (swz_frame_validate(frame) != 0 || out == NULL ||
	    out_size < SWZ_FRAME_HEADER_BYTES + frame->payload_length)
		return -1;
	memcpy(out, SWZ_MAGIC, SWZ_MAGIC_BYTES);
	out[8] = SWZ_VERSION;
	out[9] = frame->direction;
	out[10] = frame->message;
	out[11] = 0;
	write_u64(out + 12, frame->sequence);
	memcpy(out + 20, frame->nonce, sizeof(frame->nonce));
	write_u32(out + 52, frame->payload_length);
	memcpy(out + SWZ_FRAME_HEADER_BYTES, frame->payload, frame->payload_length);
	if (written != NULL)
		*written = SWZ_FRAME_HEADER_BYTES + frame->payload_length;
	return 0;
}

int swz_frame_decode(const uint8_t *input, size_t input_size, struct swz_frame *frame)
{
	if (input == NULL || frame == NULL || input_size < SWZ_FRAME_HEADER_BYTES ||
	    input_size > SWZ_MAX_FRAME || memcmp(input, SWZ_MAGIC, SWZ_MAGIC_BYTES) != 0 ||
	    input[8] != SWZ_VERSION || input[11] != 0)
		return -1;
	frame->direction = input[9];
	frame->message = input[10];
	frame->sequence = read_u64(input + 12);
	memcpy(frame->nonce, input + 20, sizeof(frame->nonce));
	frame->payload_length = read_u32(input + 52);
	frame->payload = input + SWZ_FRAME_HEADER_BYTES;
	if (SWZ_FRAME_HEADER_BYTES + frame->payload_length != input_size ||
	    swz_frame_validate(frame) != 0)
		return -1;
	return 0;
}

int swz_frame_read_fd(int fd, uint8_t *buffer, size_t capacity, size_t *length, int timeout_ms)
{
	if (fd < 0 || buffer == NULL || length == NULL || capacity < SWZ_FRAME_HEADER_BYTES)
		return -1;
	struct swz_frame header;
	uint8_t header_bytes[SWZ_FRAME_HEADER_BYTES];
	ssize_t first;
	for (;;) {
		first = read(fd, header_bytes, sizeof(header_bytes));
		if (first < 0 && errno == EINTR)
			continue;
		break;
	}
	if (first == 0)
		return 1;
	if (first < 0)
		return -1;
	if ((size_t)first < sizeof(header_bytes) &&
		swz_read_full(fd, header_bytes + first, sizeof(header_bytes) - (size_t)first, timeout_ms) != 0)
		return -1;
	uint32_t payload_length = read_u32(header_bytes + 52);
	if (payload_length == 0 || payload_length > SWZ_MAX_CONTROL_PAYLOAD ||
		SWZ_FRAME_HEADER_BYTES + payload_length > capacity)
		return -1;
	memcpy(buffer, header_bytes, sizeof(header_bytes));
	if (swz_read_full(fd, buffer + SWZ_FRAME_HEADER_BYTES, payload_length, timeout_ms) != 0)
		return -1;
	*length = SWZ_FRAME_HEADER_BYTES + payload_length;
	if (swz_frame_decode(buffer, *length, &header) != 0)
		return -1;
	return 0;
}

int swz_frame_write_fd(int fd, const struct swz_frame *frame)
{
	uint8_t encoded[SWZ_MAX_FRAME];
	size_t written = 0;
	if (swz_frame_encode(frame, encoded, sizeof(encoded), &written) != 0)
		return -1;
	return swz_write_full(fd, encoded, written);
}

static int json_string(const uint8_t *payload, size_t length, size_t *cursor)
{
	if (*cursor >= length || payload[*cursor] != '"')
		return -1;
	(*cursor)++;
	while (*cursor < length) {
		uint8_t value = payload[*cursor];
		if (value == '"') {
			(*cursor)++;
			return 0;
		}
		if (value < 0x20U)
			return -1;
		if (value == '\\') {
			(*cursor)++;
			if (*cursor >= length)
				return -1;
			if (strchr("\\\"/bfnrt", (int)payload[*cursor]) != NULL) {
				(*cursor)++;
			} else if (payload[*cursor] == 'u' && *cursor + 4 < length) {
				for (size_t digit = 1; digit <= 4; digit++)
					if (!isxdigit((int)payload[*cursor + digit]))
						return -1;
				(*cursor) += 5;
			} else {
				return -1;
			}
			continue;
		}
		(*cursor)++;
	}
	return -1;
}

/* C verifies JSON lexical safety and forbidden transport whitespace. Python
 * performs the full J(value) canonicality and typed record validation. */
int swz_frame_is_canonical_json(const uint8_t *payload, size_t length)
{
	if (payload == NULL || length == 0 || length > SWZ_MAX_CONTROL_PAYLOAD)
		return -1;
	int in_string = 0;
	int escaped = 0;
	for (size_t index = 0; index < length; index++) {
		uint8_t value = payload[index];
		if (in_string) {
			if (escaped) {
				escaped = 0;
				continue;
			}
			if (value == '\\') {
				escaped = 1;
				continue;
			}
			if (value == '"')
				in_string = 0;
			if (value < 0x20U)
				return -1;
			continue;
		}
		if (value == '"') {
			in_string = 1;
			continue;
		}
		if (value == ' ' || value == '\t' || value == '\r' || value == '\n' || value < 0x20U)
			return -1;
	}
	if (in_string || escaped)
		return -1;
	if (payload[0] == '"') {
		size_t cursor = 0;
		if (json_string(payload, length, &cursor) != 0 || cursor != length)
			return -1;
	}
	return 0;
}
