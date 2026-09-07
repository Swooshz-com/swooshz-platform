#define _POSIX_C_SOURCE 200809L
#include "protocol.h"

#include <ctype.h>
#include <string.h>

static uint16_t read_u16(const uint8_t *p)
{
	return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_u32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	    ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t read_u64(const uint8_t *p)
{
	uint64_t value = 0;
	for (size_t i = 0; i < 8; i++)
		value = (value << 8) | p[i];
	return value;
}

static void write_u32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)(value >> 24);
	p[1] = (uint8_t)(value >> 16);
	p[2] = (uint8_t)(value >> 8);
	p[3] = (uint8_t)value;
}

static void write_u64(uint8_t *p, uint64_t value)
{
	for (size_t i = 0; i < 8; i++) {
		p[7 - i] = (uint8_t)value;
		value >>= 8;
	}
}

static int valid_message(uint8_t message)
{
	return message >= SWZ_BOOT && message <= SWZ_ABORT;
}

int swz_frame_validate(const struct swz_frame *frame)
{
	if (frame == NULL || frame->direction < SWZ_LOCAL_TO_REMOTE ||
	    frame->direction > SWZ_REMOTE_TO_LOCAL || !valid_message(frame->message) ||
	    frame->sequence == 0 || frame->sequence > SWZ_MAX_SESSION_FRAMES ||
	    frame->payload_length > SWZ_MAX_CONTROL_PAYLOAD || frame->payload == NULL ||
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
	memcpy(out + 20, frame->nonce, 32);
	write_u32(out + 52, frame->payload_length);
	memcpy(out + SWZ_FRAME_HEADER_BYTES, frame->payload, frame->payload_length);
	if (written != NULL)
		*written = SWZ_FRAME_HEADER_BYTES + frame->payload_length;
	return 0;
}

int swz_frame_decode(const uint8_t *input, size_t input_size, struct swz_frame *frame)
{
	if (input == NULL || frame == NULL || input_size < SWZ_FRAME_HEADER_BYTES ||
	    memcmp(input, SWZ_MAGIC, SWZ_MAGIC_BYTES) != 0 || input[8] != SWZ_VERSION ||
	    input[11] != 0)
		return -1;
	frame->direction = input[9];
	frame->message = input[10];
	frame->sequence = read_u64(input + 12);
	memcpy(frame->nonce, input + 20, 32);
	frame->payload_length = read_u32(input + 52);
	frame->payload = input + SWZ_FRAME_HEADER_BYTES;
	if (SWZ_FRAME_HEADER_BYTES + frame->payload_length != input_size ||
	    frame->payload_length > SWZ_MAX_CONTROL_PAYLOAD ||
	    swz_frame_validate(frame) != 0)
		return -1;
	return 0;
}

/* This is intentionally a structural check. Full J(value) equality belongs
 * to the independent Python parser; C must still reject empty/control input
 * before it enters the native state machine. */
int swz_frame_is_canonical_json(const uint8_t *payload, size_t length)
{
	if (payload == NULL || length == 0 || length > SWZ_MAX_CONTROL_PAYLOAD)
		return -1;
	for (size_t i = 0; i < length; i++) {
		if (payload[i] == ' ' || payload[i] == '\t' || payload[i] == '\r' ||
		    payload[i] == '\n')
			return -1;
		if (payload[i] < 0x20 && payload[i] != '\t')
			return -1;
	}
	return 0;
}
