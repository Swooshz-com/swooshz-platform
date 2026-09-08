#define _GNU_SOURCE

#include "protocol.h"
#include "platform.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static void put32(unsigned char *out, uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static void put64(unsigned char *out, uint64_t value)
{
    size_t i;
    for (i = 0U; i < 8U; ++i) {
        out[7U - i] = (unsigned char)(value >> (i * 8U));
    }
}

static uint32_t get32(const unsigned char *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | in[3];
}

static uint64_t get64(const unsigned char *in)
{
    uint64_t value = 0U;
    size_t i;
    for (i = 0U; i < 8U; ++i) {
        value = (value << 8) | in[i];
    }
    return value;
}

int swz_frame_type_is_valid(uint16_t type)
{
    return (type >= SWZ_BOOT && type <= SWZ_BROKER_FINAL) ||
           type == SWZ_ERROR;
}

int swz_frame_encode(const struct swz_frame *frame, unsigned char *out,
                     size_t capacity, size_t *written)
{
    size_t total;

    if (frame == NULL || out == NULL || written == NULL ||
        frame->direction < 1U || frame->direction > 2U || frame->flags != 0U ||
        !swz_frame_type_is_valid(frame->type) ||
        frame->payload_length > SWZ_MAX_CONTROL_PAYLOAD_BYTES) {
        return -1;
    }
    total = SWZ_FRAME_HEADER_BYTES + (size_t)frame->payload_length;
    if (total > capacity || total > SWZ_MAX_FRAME_BYTES) {
        return -1;
    }
    memcpy(out, SWZ_FRAME_MAGIC, 8U);
    out[8U] = (unsigned char)SWZ_PROTOCOL_VERSION;
    out[9U] = (unsigned char)frame->direction;
    out[10U] = (unsigned char)frame->type;
    out[11U] = frame->flags;
    put64(out + 12U, frame->sequence);
    memcpy(out + 20U, frame->previous_hash, 32U);
    put32(out + 52U, frame->payload_length);
    if (frame->payload_length != 0U && frame->payload == NULL) {
        return -1;
    }
    if (frame->payload_length != 0U) {
        memcpy(out + SWZ_FRAME_HEADER_BYTES, frame->payload,
               frame->payload_length);
    }
    *written = total;
    return 0;
}

int swz_frame_decode(const unsigned char *bytes, size_t length,
                     struct swz_frame *frame, unsigned char *payload,
                     size_t payload_capacity)
{
    uint32_t payload_length;

    if (bytes == NULL || frame == NULL || length < SWZ_FRAME_HEADER_BYTES ||
        memcmp(bytes, SWZ_FRAME_MAGIC, 8U) != 0 ||
        bytes[8U] != SWZ_PROTOCOL_VERSION || bytes[11U] != 0U ||
        bytes[9U] < 1U || bytes[9U] > 2U) {
        return -1;
    }
    payload_length = get32(bytes + 52U);
    if (payload_length > SWZ_MAX_CONTROL_PAYLOAD_BYTES ||
        payload_length > SWZ_MAX_FRAME_BYTES - SWZ_FRAME_HEADER_BYTES ||
        length != SWZ_FRAME_HEADER_BYTES + (size_t)payload_length ||
        payload_length > payload_capacity ||
        (payload_length != 0U && payload == NULL) ||
        !swz_frame_type_is_valid(bytes[10U])) {
        return -1;
    }
    frame->direction = bytes[9U];
    frame->type = bytes[10U];
    frame->flags = bytes[11U];
    frame->sequence = get64(bytes + 12U);
    frame->payload_length = payload_length;
    memcpy(frame->previous_hash, bytes + 20U, 32U);
    frame->payload = payload;
    if (payload_length != 0U) {
        memcpy(payload, bytes + SWZ_FRAME_HEADER_BYTES, payload_length);
    }
    return 0;
}

int swz_frame_hash(const unsigned char *bytes, size_t length,
                   unsigned char out[32])
{
    return swz_sha256(bytes, length, out);
}

int swz_frame_write(int fd, const struct swz_frame *frame)
{
    unsigned char *wire;
    size_t written;
    int result;

    if (frame == NULL || frame->payload_length > SWZ_MAX_CONTROL_PAYLOAD_BYTES) {
        return -1;
    }
    wire = calloc(1U, SWZ_FRAME_HEADER_BYTES + frame->payload_length);
    if (wire == NULL) {
        return -1;
    }
    result = swz_frame_encode(frame, wire,
                              SWZ_FRAME_HEADER_BYTES + frame->payload_length,
                              &written);
    if (result == 0) {
        result = swz_write_full(fd, wire, written);
    }
    free(wire);
    return result;
}

int swz_frame_read(int fd, struct swz_frame *frame, unsigned char *payload,
                   size_t payload_capacity)
{
    unsigned char header[SWZ_FRAME_HEADER_BYTES];
    unsigned char *wire;
    uint32_t payload_length;
    int result;

    if (frame == NULL || payload == NULL ||
        payload_capacity < SWZ_MAX_CONTROL_PAYLOAD_BYTES ||
        swz_read_full(fd, header, sizeof(header)) != 0) {
        return -1;
    }
    payload_length = get32(header + 52U);
    if (payload_length > SWZ_MAX_CONTROL_PAYLOAD_BYTES) {
        return -1;
    }
    wire = calloc(1U, SWZ_FRAME_HEADER_BYTES + payload_length);
    if (wire == NULL) {
        return -1;
    }
    memcpy(wire, header, sizeof(header));
    if (payload_length != 0U &&
        swz_read_full(fd, wire + SWZ_FRAME_HEADER_BYTES, payload_length) != 0) {
        free(wire);
        return -1;
    }
    result = swz_frame_decode(wire, SWZ_FRAME_HEADER_BYTES + payload_length,
                              frame, payload, payload_capacity);
    free(wire);
    return result;
}

