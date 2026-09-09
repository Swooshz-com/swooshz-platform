#define _GNU_SOURCE

#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/random.h>
#include <unistd.h>

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

#define SWZ_RESOLVE_NO_XDEV 0x01ULL
#define SWZ_RESOLVE_NO_MAGICLINKS 0x02ULL
#define SWZ_RESOLVE_NO_SYMLINKS 0x04ULL
#define SWZ_RESOLVE_BENEATH 0x08ULL
#define SWZ_TRANSITION_ID_BYTES 59U
#define SWZ_STORE_DOCUMENT_MAX_BYTES SWZ_MAX_CONTROL_PAYLOAD_BYTES
#define SWZ_BIND_COMMITMENTS 17U

struct swz_open_how_local {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

struct json_span {
    const unsigned char *start;
    const unsigned char *end;
};

struct object_cursor {
    const unsigned char *cursor;
    const unsigned char *end;
    int started;
    int finished;
};

struct transition_material {
    char epoch_ref[129];
    char authority_ref[129];
    char barrier_utc[28];
    unsigned char commitments[9][32];
    unsigned char transition_commitment[32];
    char transition_commitment_tag[80];
    char transition_id[SWZ_TRANSITION_ID_BYTES + 1U];
};

struct evidence_material {
    char transition_id[SWZ_TRANSITION_ID_BYTES + 1U];
    unsigned char transition_data_commitment[32];
    unsigned char artifact_commitment[32];
    unsigned char artifact_stream_commitment[32];
};

struct restore_material {
    unsigned char session[32];
    unsigned char generation[32];
    unsigned char connection[32];
    unsigned char n_local[32];
    unsigned char accepted_frame_hash[32];
    unsigned char accepted_session[32];
    unsigned char activation[32];
    unsigned char restore_begin_frame_hash[32];
    unsigned char consumed_record[32];
    unsigned char restore_begin_commitment[32];
    struct transition_material transition;
    struct evidence_material evidence;
};

struct bind_material {
    uint64_t context_generation;
    unsigned char generation[32];
    unsigned char connection[32];
    unsigned char session[32];
    unsigned char n_local[32];
    unsigned char restore_begin_frame_hash[32];
    char transition_id[SWZ_TRANSITION_ID_BYTES + 1U];
    char epoch_ref[129];
    char authority_ref[129];
    char barrier_utc[28];
    unsigned char commitments[SWZ_BIND_COMMITMENTS][32];
    struct stat source_stat;
    unsigned char source_content_sha256[32];
    unsigned char source_artifact_stream_digest[32];
    struct stat target_pipe_stat;
    uint32_t worker_registration_serial;
    unsigned char target_digest[32];
    unsigned char target_isolation_digest[32];
};

static int parse_hex_tag_text(const char *tag, unsigned char output[32]);

static void put_u16(unsigned char output[2], uint16_t value)
{
    output[0] = (unsigned char)(value >> 8);
    output[1] = (unsigned char)value;
}

static void put_u32(unsigned char output[4], uint32_t value)
{
    output[0] = (unsigned char)(value >> 24);
    output[1] = (unsigned char)(value >> 16);
    output[2] = (unsigned char)(value >> 8);
    output[3] = (unsigned char)value;
}

static void put_u64(unsigned char output[8], uint64_t value)
{
    size_t index;

    for (index = 0U; index < 8U; ++index) {
        output[7U - index] = (unsigned char)(value >> (index * 8U));
    }
}

static uint64_t get_u64(const unsigned char input[8])
{
    uint64_t value = 0U;
    size_t index;

    for (index = 0U; index < 8U; ++index) {
        value = (value << 8) | input[index];
    }
    return value;
}

static int random_u64(uint64_t *output)
{
    unsigned char bytes[sizeof(uint64_t)];
    size_t offset = 0U;
    ssize_t received;
    uint64_t value;

    if (output == NULL) {
        return -1;
    }
    while (offset < sizeof(bytes)) {
        do {
            received = getrandom(bytes + offset, sizeof(bytes) - offset, 0U);
        } while (received < 0 && errno == EINTR);
        if (received <= 0) {
            explicit_bzero(bytes, sizeof(bytes));
            return -1;
        }
        offset += (size_t)received;
    }
    value = get_u64(bytes);
    explicit_bzero(bytes, sizeof(bytes));
    if (value == 0U) {
        return -1;
    }
    *output = value;
    return 0;
}

static int appendf(char *output, size_t capacity, size_t *offset,
                   const char *format, ...)
{
    va_list arguments;
    int written;

    if (output == NULL || offset == NULL || format == NULL || *offset >= capacity) {
        return -1;
    }
    va_start(arguments, format);
    written = vsnprintf(output + *offset, capacity - *offset, format, arguments);
    va_end(arguments);
    if (written < 0 || (size_t)written >= capacity - *offset) {
        return -1;
    }
    *offset += (size_t)written;
    return 0;
}

static int append_bytes(unsigned char *output, size_t capacity, size_t *offset,
                        const void *value, size_t length)
{
    if (output == NULL || offset == NULL || value == NULL ||
        *offset > capacity || length > capacity - *offset) {
        return -1;
    }
    memcpy(output + *offset, value, length);
    *offset += length;
    return 0;
}

static int append_u16(unsigned char *output, size_t capacity, size_t *offset,
                      uint16_t value)
{
    unsigned char encoded[2];

    put_u16(encoded, value);
    return append_bytes(output, capacity, offset, encoded, sizeof(encoded));
}

static int append_u32(unsigned char *output, size_t capacity, size_t *offset,
                      uint32_t value)
{
    unsigned char encoded[4];

    put_u32(encoded, value);
    return append_bytes(output, capacity, offset, encoded, sizeof(encoded));
}

static int append_u64(unsigned char *output, size_t capacity, size_t *offset,
                      uint64_t value)
{
    unsigned char encoded[8];

    put_u64(encoded, value);
    return append_bytes(output, capacity, offset, encoded, sizeof(encoded));
}

static int read_eof(int fd)
{
    unsigned char byte;
    ssize_t received;

    do {
        received = read(fd, &byte, sizeof(byte));
    } while (received < 0 && errno == EINTR);
    return received == 0 ? 0 : -1;
}

static int read_frame_exact(struct swz_frame *frame,
                            unsigned char payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES],
                            unsigned char raw[SWZ_FRAME_HEADER_BYTES + SWZ_MAX_CONTROL_PAYLOAD_BYTES],
                            unsigned char frame_hash[32], uint16_t type,
                            uint8_t direction, uint64_t sequence,
                            const unsigned char n_local[32],
                            const unsigned char previous_hash[32])
{
    unsigned char actual_previous[32];
    size_t written;

    memset(frame, 0, sizeof(*frame));
    if (swz_frame_read(STDIN_FILENO, frame, payload,
                       SWZ_MAX_CONTROL_PAYLOAD_BYTES) != 0 ||
        frame->type != type || frame->direction != direction ||
        frame->sequence != sequence || memcmp(frame->n_local, n_local, 32U) != 0 ||
        swz_managed_payload_predecessor(frame->payload, frame->payload_length,
                                        actual_previous) != 0 ||
        memcmp(actual_previous, previous_hash, 32U) != 0 ||
        swz_frame_encode(frame, raw,
                         SWZ_FRAME_HEADER_BYTES + SWZ_MAX_CONTROL_PAYLOAD_BYTES,
                         &written) != 0 || swz_frame_hash(raw, written, frame_hash) != 0) {
        return -1;
    }
    return 0;
}

static int write_discovery(const unsigned char session[32],
                           const unsigned char previous_hash[32],
                           const unsigned char n_local[32],
                           unsigned char discovery_hash[32])
{
    static const char filename[] = "qualified-artifact";
    static const char encoded_filename[] = "cXVhbGlmaWVkLWFydGlmYWN0";
    static const char *const domains[] = {
        "qualified-image", "qualified-target", "qualified-isolation",
        "qualified-artifact", "qualified-artifact-stream"
    };
    static const char *const values[] = {
        "swz-managed-qualified-image-v1", "swz-managed-qualified-target-v1",
        "swz-managed-qualified-isolation-v1", "swz-managed-qualified-artifact-v1",
        "swz-managed-qualified-artifact-stream-v1"
    };
    char previous[65];
    char session_hex[65];
    char tags[5][80];
    unsigned char tag_raw[5][32];
    unsigned char row_id[8];
    const unsigned char *parts[8];
    size_t lengths[8];
    char payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    char discovery_hex[65];
    size_t offset = 0U;
    size_t index;
    struct swz_frame frame;

    if (session == NULL || previous_hash == NULL || n_local == NULL ||
        discovery_hash == NULL || swz_hex(previous_hash, 32U, previous,
                                          sizeof(previous)) != 0 ||
        swz_hex(session, 32U, session_hex, sizeof(session_hex)) != 0) {
        return -1;
    }
    for (index = 0U; index < 5U; ++index) {
        if (swz_store_commitment(domains[index],
                                 (const unsigned char *)values[index],
                                 strlen(values[index]), tags[index]) != 0 ||
            parse_hex_tag_text(tags[index], tag_raw[index]) != 0) {
            return -1;
        }
    }
    put_u64(row_id, 23U);
    parts[0] = session;
    parts[1] = row_id;
    parts[2] = (const unsigned char *)filename;
    lengths[0] = 32U;
    lengths[1] = sizeof(row_id);
    lengths[2] = sizeof(filename) - 1U;
    for (index = 0U; index < 5U; ++index) {
        parts[3U + index] = tag_raw[index];
        lengths[3U + index] = sizeof(tag_raw[index]);
    }
    if (swz_managed_hash("discovery.v1", parts, lengths, 8U,
                         discovery_hash) != 0 ||
        swz_hex(discovery_hash, 32U, discovery_hex, sizeof(discovery_hex)) != 0 ||
        appendf(payload, sizeof(payload), &offset,
                "[\"DISCOVERY\",2,\"swz-managed.v1\",\"%s\",\"%s\",\"23\",\"%s\"",
                previous, session_hex, encoded_filename) != 0) {
        return -1;
    }
    for (index = 0U; index < 5U; ++index) {
        if (appendf(payload, sizeof(payload), &offset, ",\"%s\"", tags[index]) != 0) {
            return -1;
        }
    }
    if (appendf(payload, sizeof(payload), &offset, ",\"%s\"]", discovery_hex) != 0) {
        return -1;
    }
    memset(&frame, 0, sizeof(frame));
    frame.direction = 2U;
    frame.type = SWZ_DISCOVERY;
    frame.sequence = 5U;
    memcpy(frame.n_local, n_local, 32U);
    frame.payload = (unsigned char *)payload;
    frame.payload_length = (uint32_t)offset;
    return swz_frame_write(STDOUT_FILENO, &frame);
}

static int json_string_span(const unsigned char **cursor,
                            const unsigned char *end,
                            struct json_span *span)
{
    const unsigned char *start;

    if (cursor == NULL || *cursor == NULL || end == NULL || *cursor >= end ||
        **cursor != '"') {
        return -1;
    }
    ++*cursor;
    start = *cursor;
    while (*cursor < end) {
        unsigned char value = **cursor;

        if (value == '"') {
            if (span != NULL) {
                span->start = start;
                span->end = *cursor;
            }
            ++*cursor;
            return 0;
        }
        if (value < 0x20U || value == 0x7fU) {
            return -1;
        }
        if (value == '\\') {
            ++*cursor;
            if (*cursor >= end || strchr("\"\\/bfnrt", (int)**cursor) == NULL) {
                return -1;
            }
        }
        ++*cursor;
    }
    return -1;
}

static int json_value_span(const unsigned char **cursor,
                           const unsigned char *end,
                           struct json_span *span);

static int json_array_span(const unsigned char **cursor,
                           const unsigned char *end,
                           struct json_span *span)
{
    const unsigned char *start;

    if (cursor == NULL || *cursor == NULL || end == NULL || *cursor >= end ||
        **cursor != '[') {
        return -1;
    }
    start = *cursor;
    ++*cursor;
    if (*cursor < end && **cursor == ']') {
        ++*cursor;
        if (span != NULL) {
            span->start = start;
            span->end = *cursor;
        }
        return 0;
    }
    for (;;) {
        if (json_value_span(cursor, end, NULL) != 0 || *cursor >= end) {
            return -1;
        }
        if (**cursor == ']') {
            ++*cursor;
            if (span != NULL) {
                span->start = start;
                span->end = *cursor;
            }
            return 0;
        }
        if (**cursor != ',') {
            return -1;
        }
        ++*cursor;
    }
}

static int json_object_span(const unsigned char **cursor,
                            const unsigned char *end,
                            struct json_span *span)
{
    const unsigned char *start;

    if (cursor == NULL || *cursor == NULL || end == NULL || *cursor >= end ||
        **cursor != '{') {
        return -1;
    }
    start = *cursor;
    ++*cursor;
    if (*cursor < end && **cursor == '}') {
        ++*cursor;
        if (span != NULL) {
            span->start = start;
            span->end = *cursor;
        }
        return 0;
    }
    for (;;) {
        if (json_string_span(cursor, end, NULL) != 0 || *cursor >= end ||
            **cursor != ':') {
            return -1;
        }
        ++*cursor;
        if (json_value_span(cursor, end, NULL) != 0 || *cursor >= end) {
            return -1;
        }
        if (**cursor == '}') {
            ++*cursor;
            if (span != NULL) {
                span->start = start;
                span->end = *cursor;
            }
            return 0;
        }
        if (**cursor != ',') {
            return -1;
        }
        ++*cursor;
    }
}

static int json_number_span(const unsigned char **cursor,
                            const unsigned char *end,
                            struct json_span *span)
{
    const unsigned char *start;

    if (cursor == NULL || *cursor == NULL || end == NULL || *cursor >= end ||
        **cursor < '0' || **cursor > '9') {
        return -1;
    }
    start = *cursor;
    if (**cursor == '0') {
        ++*cursor;
        if (*cursor < end && **cursor >= '0' && **cursor <= '9') {
            return -1;
        }
    } else {
        while (*cursor < end && **cursor >= '0' && **cursor <= '9') {
            ++*cursor;
        }
    }
    if (*cursor < end && (**cursor == '.' || **cursor == 'e' || **cursor == 'E')) {
        return -1;
    }
    if (span != NULL) {
        span->start = start;
        span->end = *cursor;
    }
    return 0;
}

static int json_value_span(const unsigned char **cursor,
                           const unsigned char *end,
                           struct json_span *span)
{
    const unsigned char *start;

    if (cursor == NULL || *cursor == NULL || end == NULL || *cursor >= end) {
        return -1;
    }
    if (**cursor == '"') {
        return json_string_span(cursor, end, span);
    }
    start = *cursor;
    if (**cursor == '[') {
        if (json_array_span(cursor, end, NULL) != 0) {
            return -1;
        }
    } else if (**cursor == '{') {
        if (json_object_span(cursor, end, NULL) != 0) {
            return -1;
        }
    } else if (**cursor == 't') {
        if ((size_t)(end - *cursor) < 4U || memcmp(*cursor, "true", 4U) != 0) {
            return -1;
        }
        *cursor += 4U;
    } else if (**cursor == 'f') {
        if ((size_t)(end - *cursor) < 5U || memcmp(*cursor, "false", 5U) != 0) {
            return -1;
        }
        *cursor += 5U;
    } else if (json_number_span(cursor, end, NULL) != 0) {
        return -1;
    }
    if (span != NULL) {
        span->start = start;
        span->end = *cursor;
    }
    return 0;
}

static int json_array_field(const unsigned char *payload, size_t length,
                            size_t wanted, struct json_span *field)
{
    const unsigned char *cursor = payload;
    const unsigned char *end = payload == NULL ? NULL : payload + length;
    size_t index;
    struct json_span value;

    if (payload == NULL || field == NULL || length == 0U || cursor >= end ||
        *cursor++ != '[') {
        return -1;
    }
    for (index = 0U;; ++index) {
        if (index != 0U) {
            if (cursor >= end || *cursor++ != ',') {
                return -1;
            }
        }
        if (cursor >= end || *cursor == ']') {
            return -1;
        }
        if (json_value_span(&cursor, end, &value) != 0) {
            return -1;
        }
        if (index == wanted) {
            *field = value;
            return 0;
        }
        if (cursor < end && *cursor == ']') {
            return -1;
        }
    }
}

static int decode_json_string(struct json_span value, char *output,
                              size_t capacity, size_t *length)
{
    const unsigned char *cursor = value.start;
    size_t offset = 0U;

    if (output == NULL || capacity == 0U || value.start == NULL ||
        value.end == NULL || value.start > value.end) {
        return -1;
    }
    while (cursor < value.end) {
        unsigned char byte = *cursor++;

        if (byte == '\\') {
            if (cursor >= value.end) {
                return -1;
            }
            switch (*cursor++) {
            case '"': byte = '"'; break;
            case '\\': byte = '\\'; break;
            case '/': byte = '/'; break;
            case 'b': byte = '\b'; break;
            case 'f': byte = '\f'; break;
            case 'n': byte = '\n'; break;
            case 'r': byte = '\r'; break;
            case 't': byte = '\t'; break;
            default: return -1;
            }
        }
        if (offset + 1U >= capacity) {
            return -1;
        }
        output[offset++] = (char)byte;
    }
    output[offset] = '\0';
    if (length != NULL) {
        *length = offset;
    }
    return 0;
}

static int span_string_equals(struct json_span value, const char *expected)
{
    char decoded[256];
    size_t length;

    return expected != NULL && decode_json_string(value, decoded, sizeof(decoded),
                                                   &length) == 0 &&
                   length == strlen(expected) && memcmp(decoded, expected, length) == 0
               ? 0
               : -1;
}

static int span_u64(struct json_span value, uint64_t *output)
{
    const unsigned char *cursor = value.start;
    uint64_t parsed = 0U;

    if (output == NULL || cursor == NULL || value.end == NULL || cursor >= value.end) {
        return -1;
    }
    while (cursor < value.end) {
        unsigned int digit;

        if (*cursor < '0' || *cursor > '9') {
            return -1;
        }
        digit = (unsigned int)(*cursor++ - '0');
        if (parsed > (UINT64_MAX - digit) / 10U) {
            return -1;
        }
        parsed = parsed * 10U + digit;
    }
    *output = parsed;
    return 0;
}

static int span_true(struct json_span value)
{
    return value.start != NULL && value.end != NULL &&
                   (size_t)(value.end - value.start) == 4U &&
                   memcmp(value.start, "true", 4U) == 0
               ? 0
               : -1;
}

static int store_tag_from_span(struct json_span value, unsigned char output[32])
{
    char decoded[80];
    size_t length;

    if (output == NULL || decode_json_string(value, decoded, sizeof(decoded), &length) != 0 ||
        length != 74U || memcmp(decoded, "sha256:v1:", 10U) != 0) {
        return -1;
    }
    return parse_hex_tag_text(decoded, output);
}

static int ref_from_span(struct json_span value, char *output, size_t capacity)
{
    size_t length;
    size_t index;

    if (decode_json_string(value, output, capacity, &length) != 0 || length == 0U ||
        length > 128U || !((output[0] >= 'A' && output[0] <= 'Z') ||
                           (output[0] >= 'a' && output[0] <= 'z') ||
                           (output[0] >= '0' && output[0] <= '9'))) {
        return -1;
    }
    for (index = 1U; index < length; ++index) {
        if (!((output[index] >= 'A' && output[index] <= 'Z') ||
              (output[index] >= 'a' && output[index] <= 'z') ||
              (output[index] >= '0' && output[index] <= '9') ||
              output[index] == '.' || output[index] == '_' || output[index] == '-')) {
            return -1;
        }
    }
    return 0;
}

static int utc6_from_span(struct json_span value, char output[28])
{
    static const size_t separators[] = { 4U, 7U, 10U, 13U, 16U, 19U, 26U };
    static const unsigned char separator_values[] = { '-', '-', 'T', ':', ':', '.', 'Z' };
    size_t length;
    size_t index;

    if (decode_json_string(value, output, 28U, &length) != 0 || length != 27U) {
        return -1;
    }
    for (index = 0U; index < sizeof(separators) / sizeof(separators[0]); ++index) {
        if ((unsigned char)output[separators[index]] != separator_values[index]) {
            return -1;
        }
    }
    for (index = 0U; index < length; ++index) {
        if (index == 4U || index == 7U || index == 10U || index == 13U ||
            index == 16U || index == 19U || index == 26U) {
            continue;
        }
        if (output[index] < '0' || output[index] > '9') {
            return -1;
        }
    }
    return 0;
}

static int transition_id_from_bytes(const unsigned char *bytes, size_t length,
                                    char output[SWZ_TRANSITION_ID_BYTES + 1U])
{
    static const unsigned char label[] = "restore-transition-id.v2";
    unsigned char preimage[4U + sizeof(label) - 1U + 4U + SWZ_STORE_DOCUMENT_MAX_BYTES];
    unsigned char digest[32];
    unsigned char encoded_length[4];
    size_t offset = 0U;
    char hex[65];

    if (bytes == NULL || output == NULL || length == 0U ||
        length > SWZ_STORE_DOCUMENT_MAX_BYTES ||
        append_u32(preimage, sizeof(preimage), &offset,
                   (uint32_t)(sizeof(label) - 1U)) != 0 ||
        append_bytes(preimage, sizeof(preimage), &offset, label,
                     sizeof(label) - 1U) != 0) {
        return -1;
    }
    put_u32(encoded_length, (uint32_t)length);
    if (append_bytes(preimage, sizeof(preimage), &offset, encoded_length,
                     sizeof(encoded_length)) != 0 ||
        append_bytes(preimage, sizeof(preimage), &offset, bytes, length) != 0 ||
        swz_sha256(preimage, offset, digest) != 0 ||
        swz_hex(digest, sizeof(digest), hex, sizeof(hex)) != 0) {
        return -1;
    }
    memcpy(output, "restore-v2-", 11U);
    memcpy(output + 11U, hex, 48U);
    output[SWZ_TRANSITION_ID_BYTES] = '\0';
    return 0;
}

static int object_start(struct object_cursor *cursor, const unsigned char *data,
                        size_t length)
{
    if (cursor == NULL || data == NULL || length == 0U) {
        return -1;
    }
    cursor->cursor = data;
    cursor->end = data + length;
    cursor->started = 0;
    cursor->finished = 0;
    return 0;
}

static int object_next(struct object_cursor *cursor, const char *expected_key,
                       struct json_span *value)
{
    struct json_span key;

    if (cursor == NULL || expected_key == NULL || value == NULL ||
        cursor->cursor == NULL || cursor->finished) {
        return -1;
    }
    if (cursor->started == 0) {
        if (cursor->cursor >= cursor->end || *cursor->cursor++ != '{') {
            return -1;
        }
        cursor->started = 1;
    } else if (cursor->cursor >= cursor->end || *cursor->cursor++ != ',') {
        return -1;
    }
    if (json_string_span(&cursor->cursor, cursor->end, &key) != 0 ||
        (size_t)(key.end - key.start) != strlen(expected_key) ||
        memcmp(key.start, expected_key, strlen(expected_key)) != 0 ||
        cursor->cursor >= cursor->end || *cursor->cursor++ != ':' ||
        json_value_span(&cursor->cursor, cursor->end, value) != 0) {
        return -1;
    }
    return 0;
}

static int object_finish(struct object_cursor *cursor)
{
    if (cursor == NULL || cursor->cursor == NULL || cursor->finished ||
        cursor->cursor >= cursor->end || *cursor->cursor++ != '}' ||
        cursor->cursor != cursor->end) {
        return -1;
    }
    cursor->finished = 1;
    return 0;
}

static int validate_durability(struct json_span value)
{
    static const char *const fields[] = {
        "file_flush_verified", "readback_verified",
        "atomic_authority_transition", "directory_flush_verified"
    };
    struct object_cursor cursor;
    struct json_span child;
    size_t index;

    if (value.start == NULL || value.end == NULL || value.start > value.end ||
        object_start(&cursor, value.start, (size_t)(value.end - value.start)) != 0) {
        return -1;
    }
    for (index = 0U; index < sizeof(fields) / sizeof(fields[0]); ++index) {
        if (object_next(&cursor, fields[index], &child) != 0 || span_true(child) != 0) {
            return -1;
        }
    }
    return object_finish(&cursor);
}

static int validate_transition_store(const unsigned char *bytes, size_t length,
                                     struct transition_material *output)
{
    static const char *const fields[] = {
        "schema", "version", "epoch_ref", "authority_ref", "barrier_utc",
        "barrier_commitment", "runner_commitment", "bundle_commitment",
        "image_commitment", "target_commitment", "isolation_commitment",
        "artifact_commitment", "artifact_stream_commitment",
        "pre_cas_ledger_digest"
    };
    struct object_cursor cursor;
    struct json_span value;
    uint64_t version;
    size_t index;

    if (bytes == NULL || output == NULL || length == 0U ||
        object_start(&cursor, bytes, length) != 0 ||
        object_next(&cursor, fields[0], &value) != 0 ||
        span_string_equals(value, "restore-ledger-transition-data.v2") != 0 ||
        object_next(&cursor, fields[1], &value) != 0 || span_u64(value, &version) != 0 ||
        version != 2U || object_next(&cursor, fields[2], &value) != 0 ||
        ref_from_span(value, output->epoch_ref, sizeof(output->epoch_ref)) != 0 ||
        object_next(&cursor, fields[3], &value) != 0 ||
        ref_from_span(value, output->authority_ref, sizeof(output->authority_ref)) != 0 ||
        object_next(&cursor, fields[4], &value) != 0 ||
        utc6_from_span(value, output->barrier_utc) != 0) {
        return -1;
    }
    for (index = 0U; index < 9U; ++index) {
        if (object_next(&cursor, fields[5U + index], &value) != 0 ||
            store_tag_from_span(value, output->commitments[index]) != 0) {
            return -1;
        }
    }
    if (object_finish(&cursor) != 0 ||
        swz_store_commitment("restore-ledger-transition", bytes, length,
                             output->transition_commitment_tag) != 0 ||
        parse_hex_tag_text(output->transition_commitment_tag,
                           output->transition_commitment) != 0 ||
        transition_id_from_bytes(bytes, length, output->transition_id) != 0) {
        return -1;
    }
    return 0;
}

static int validate_evidence_store(const unsigned char *bytes, size_t length,
                                   const struct transition_material *transition,
                                   struct evidence_material *output)
{
    static const char *const fields[] = {
        "schema", "epoch_ref", "transition_id", "transition_data_commitment",
        "artifact_commitment", "artifact_stream_commitment", "ledger_state",
        "record_state", "spool_previous_stage", "frame_sequence",
        "previous_frame_hash", "frame_hash", "spool_commitment",
        "ledger_after_digest", "durability"
    };
    struct object_cursor cursor;
    struct json_span value;
    unsigned char ignored[32];
    uint64_t frame_sequence;
    char epoch[129];
    char transition_id[SWZ_TRANSITION_ID_BYTES + 1U];
    size_t index;

    if (bytes == NULL || transition == NULL || output == NULL ||
        object_start(&cursor, bytes, length) != 0 ||
        object_next(&cursor, fields[0], &value) != 0 ||
        span_string_equals(value, "restore-begin-evidence.v2") != 0 ||
        object_next(&cursor, fields[1], &value) != 0 ||
        ref_from_span(value, epoch, sizeof(epoch)) != 0 ||
        strcmp(epoch, transition->epoch_ref) != 0 ||
        object_next(&cursor, fields[2], &value) != 0 ||
        decode_json_string(value, transition_id, sizeof(transition_id), NULL) != 0 ||
        strlen(transition_id) != SWZ_TRANSITION_ID_BYTES ||
        strcmp(transition_id, transition->transition_id) != 0 ||
        object_next(&cursor, fields[3], &value) != 0 ||
        store_tag_from_span(value, output->transition_data_commitment) != 0 ||
        memcmp(output->transition_data_commitment, transition->transition_commitment, 32U) != 0 ||
        object_next(&cursor, fields[4], &value) != 0 ||
        store_tag_from_span(value, output->artifact_commitment) != 0 ||
        memcmp(output->artifact_commitment, transition->commitments[6], 32U) != 0 ||
        object_next(&cursor, fields[5], &value) != 0 ||
        store_tag_from_span(value, output->artifact_stream_commitment) != 0 ||
        memcmp(output->artifact_stream_commitment, transition->commitments[7], 32U) != 0 ||
        object_next(&cursor, fields[6], &value) != 0 || span_string_equals(value, "CONSUMED") != 0 ||
        object_next(&cursor, fields[7], &value) != 0 || span_string_equals(value, "CONSUMED") != 0 ||
        object_next(&cursor, fields[8], &value) != 0 || span_string_equals(value, "RESTORE_BEGIN") != 0 ||
        object_next(&cursor, fields[9], &value) != 0 || span_u64(value, &frame_sequence) != 0 ||
        frame_sequence != 1U) {
        return -1;
    }
    for (index = 10U; index < 14U; ++index) {
        if (object_next(&cursor, fields[index], &value) != 0 ||
            store_tag_from_span(value, ignored) != 0) {
            return -1;
        }
    }
    if (object_next(&cursor, fields[14], &value) != 0 ||
        validate_durability(value) != 0 || object_finish(&cursor) != 0) {
        return -1;
    }
    memcpy(output->transition_id, transition_id, sizeof(output->transition_id));
    return 0;
}

static int copy_store_wire(const unsigned char *payload, size_t length, size_t index,
                           const char *expected_schema,
                           unsigned char output[SWZ_STORE_DOCUMENT_MAX_BYTES],
                           size_t *output_length)
{
    struct json_span wire;
    const unsigned char *cursor;
    const unsigned char *end;
    struct json_span item;
    char marker[32];
    char schema[128];
    size_t marker_length;
    size_t schema_length;
    size_t item_index;
    size_t decoded_length = 0U;

    if (payload == NULL || expected_schema == NULL || output == NULL ||
        output_length == NULL || json_array_field(payload, length, index, &wire) != 0 ||
        wire.start >= wire.end || *wire.start++ != '[') {
        return -1;
    }
    cursor = wire.start;
    end = wire.end;
    for (item_index = 0U; item_index < 3U; ++item_index) {
        if (item_index != 0U && (cursor >= end || *cursor++ != ',')) {
            return -1;
        }
        if (json_value_span(&cursor, end, &item) != 0) {
            return -1;
        }
        if (item_index == 0U &&
            (decode_json_string(item, marker, sizeof(marker), &marker_length) != 0 ||
             marker_length != strlen(SWZ_STORE_WIRE_MARKER) ||
             memcmp(marker, SWZ_STORE_WIRE_MARKER, marker_length) != 0)) {
            return -1;
        }
        if (item_index == 1U &&
            (decode_json_string(item, schema, sizeof(schema), &schema_length) != 0 ||
             schema_length != strlen(expected_schema) ||
             memcmp(schema, expected_schema, schema_length) != 0)) {
            return -1;
        }
        if (item_index == 2U &&
            (decode_json_string(item, (char *)output,
                                SWZ_STORE_DOCUMENT_MAX_BYTES,
                                &decoded_length) != 0 || decoded_length == 0U)) {
            return -1;
        }
    }
    *output_length = decoded_length;
    return cursor < end && *cursor == ']' && ++cursor == end &&
                   decoded_length >= 2U && output[decoded_length - 1U] == '\n' &&
                   output[decoded_length - 2U] != '\n'
               ? 0
               : -1;
}

static int parse_hex_tag_text(const char *tag, unsigned char output[32])
{
    size_t index;

    if (tag == NULL || output == NULL || strlen(tag) != 74U ||
        memcmp(tag, "sha256:v1:", 10U) != 0) {
        return -1;
    }
    for (index = 0U; index < 32U; ++index) {
        int high;
        int low;
        unsigned char high_char = (unsigned char)tag[10U + index * 2U];
        unsigned char low_char = (unsigned char)tag[11U + index * 2U];

        high = high_char >= '0' && high_char <= '9' ? high_char - '0' :
               high_char >= 'a' && high_char <= 'f' ? high_char - 'a' + 10 : -1;
        low = low_char >= '0' && low_char <= '9' ? low_char - '0' :
              low_char >= 'a' && low_char <= 'f' ? low_char - 'a' + 10 : -1;
        if (high < 0 || low < 0) {
            return -1;
        }
        output[index] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static int copy_field_exact(const unsigned char *payload, size_t length, size_t index,
                            char *output, size_t capacity, size_t expected_length)
{
    return output != NULL &&
                   swz_managed_payload_string_field(payload, length, index,
                                                    output, capacity) == 0 &&
                   strlen(output) == expected_length
               ? 0
               : -1;
}

static int read_restore_begin(const unsigned char n_local[32],
                              const unsigned char discovery_hash[32],
                              const unsigned char accepted_session[32],
                              struct restore_material *output)
{
    unsigned char payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char raw[SWZ_FRAME_HEADER_BYTES + SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char restore_hash[32];
    unsigned char transition_bytes[SWZ_STORE_DOCUMENT_MAX_BYTES];
    unsigned char evidence_bytes[SWZ_STORE_DOCUMENT_MAX_BYTES];
    char field[129];
    char expected[65];
    size_t transition_length;
    size_t evidence_length;
    struct swz_frame frame;

    if (n_local == NULL || discovery_hash == NULL || accepted_session == NULL ||
        output == NULL || read_frame_exact(&frame, payload, raw, restore_hash,
                                           SWZ_RESTORE_BEGIN, 1U, 6U, n_local,
                                           discovery_hash) != 0 ||
        copy_field_exact(payload, frame.payload_length, 4U, field, sizeof(field),
                         64U) != 0 || swz_hex(discovery_hash, 32U, expected,
                                               sizeof(expected)) != 0 ||
        strcmp(field, expected) != 0 ||
        copy_field_exact(payload, frame.payload_length, 5U, field, sizeof(field),
                         64U) != 0 || swz_hex(accepted_session, 32U, expected,
                                               sizeof(expected)) != 0 ||
        strcmp(field, expected) != 0 ||
        copy_store_wire(payload, frame.payload_length, 6U,
                        "restore-ledger-transition-data.v2", transition_bytes,
                        &transition_length) != 0 ||
        copy_store_wire(payload, frame.payload_length, 7U,
                        "restore-begin-evidence.v2", evidence_bytes,
                        &evidence_length) != 0 ||
        copy_field_exact(payload, frame.payload_length, 8U, field, sizeof(field),
                         74U) != 0 || parse_hex_tag_text(field, output->consumed_record) != 0 ||
        validate_transition_store(transition_bytes, transition_length,
                                  &output->transition) != 0 ||
        validate_evidence_store(evidence_bytes, evidence_length, &output->transition,
                                &output->evidence) != 0 ||
        strcmp(output->evidence.transition_id, output->transition.transition_id) != 0 ||
        swz_store_commitment("restore-begin-evidence", evidence_bytes, evidence_length,
                             field) != 0 || parse_hex_tag_text(field,
                                                               output->restore_begin_commitment) != 0) {
        return -1;
    }
    memcpy(output->session, accepted_session, 32U);
    memcpy(output->restore_begin_frame_hash, restore_hash, 32U);
    return 0;
}

static int digest_update_lp(EVP_MD_CTX *context, const unsigned char *value,
                            size_t length)
{
    unsigned char prefix[4];

    if (context == NULL || value == NULL || length > UINT32_MAX) {
        return -1;
    }
    put_u32(prefix, (uint32_t)length);
    return EVP_DigestUpdate(context, prefix, sizeof(prefix)) == 1 &&
                   EVP_DigestUpdate(context, value, length) == 1
               ? 0
               : -1;
}

static int hash_source_artifact(int fd, unsigned char content_digest[32],
                                unsigned char stream_digest[32], uint64_t *total)
{
    EVP_MD_CTX *content = NULL;
    EVP_MD_CTX *stream = NULL;
    unsigned char buffer[65536];
    unsigned int content_length = 0U;
    unsigned int stream_length = 0U;
    uint64_t count = 0U;
    int result = -1;

    if (fd < 0 || content_digest == NULL || stream_digest == NULL || total == NULL ||
        lseek(fd, 0, SEEK_SET) != 0 || (content = EVP_MD_CTX_new()) == NULL ||
        (stream = EVP_MD_CTX_new()) == NULL ||
        EVP_DigestInit_ex(content, EVP_sha256(), NULL) != 1 ||
        EVP_DigestInit_ex(stream, EVP_sha256(), NULL) != 1 ||
        digest_update_lp(stream, (const unsigned char *)"recovery-commitment.v1",
                         sizeof("recovery-commitment.v1") - 1U) != 0 ||
        digest_update_lp(stream, (const unsigned char *)"artifact-stream",
                         sizeof("artifact-stream") - 1U) != 0) {
        goto done;
    }
    for (;;) {
        ssize_t received = read(fd, buffer, sizeof(buffer));

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0 || UINT64_MAX - count < (uint64_t)received) {
            goto done;
        }
        if (received == 0) {
            break;
        }
        if (EVP_DigestUpdate(content, buffer, (size_t)received) != 1 ||
            digest_update_lp(stream, buffer, (size_t)received) != 0) {
            goto done;
        }
        count += (uint64_t)received;
    }
    if (EVP_DigestFinal_ex(content, content_digest, &content_length) != 1 ||
        EVP_DigestFinal_ex(stream, stream_digest, &stream_length) != 1 ||
        content_length != 32U || stream_length != 32U ||
        lseek(fd, 0, SEEK_SET) != 0) {
        goto done;
    }
    *total = count;
    result = 0;
done:
    explicit_bzero(buffer, sizeof(buffer));
    EVP_MD_CTX_free(content);
    EVP_MD_CTX_free(stream);
    return result;
}

static int open_qualified_source(void)
{
    struct swz_open_how_local how;
    int root_fd;
    int source_fd;

    memset(&how, 0, sizeof(how));
    how.flags = (uint64_t)(O_RDONLY | O_CLOEXEC);
    how.resolve = SWZ_RESOLVE_BENEATH | SWZ_RESOLVE_NO_SYMLINKS |
                  SWZ_RESOLVE_NO_MAGICLINKS | SWZ_RESOLVE_NO_XDEV;
    root_fd = open(SWZ_QUALIFIED_ARTIFACT_ROOT,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) {
        return -1;
    }
    source_fd = (int)syscall(SYS_openat2, root_fd, "qualified-artifact",
                             &how, sizeof(how));
    close(root_fd);
    return source_fd;
}

static int validate_source_fd(int fd, struct stat *info)
{
    int flags;

    if (fd < 0 || info == NULL || fstat(fd, info) != 0 || !S_ISREG(info->st_mode) ||
        (info->st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0 || info->st_nlink != 1 ||
        info->st_size < 0 || (uint64_t)info->st_size > (uint64_t)64U * 1024U * 1024U * 1024U ||
        lseek(fd, 0, SEEK_CUR) != 0 || (flags = fcntl(fd, F_GETFL)) < 0 ||
        (flags & O_ACCMODE) != O_RDONLY) {
        return -1;
    }
    return 0;
}

static int context_envelope(const char magic[8], uint16_t kind,
                            const unsigned char *payload, size_t payload_length,
                            size_t maximum, unsigned char *output,
                            size_t capacity, size_t *output_length)
{
    unsigned char header[16];
    unsigned char digest[32];
    size_t offset = 0U;

    if (magic == NULL || payload == NULL || output == NULL || output_length == NULL ||
        payload_length > maximum || payload_length > UINT32_MAX ||
        capacity < sizeof(header) + payload_length + sizeof(digest)) {
        return -1;
    }
    memcpy(header, magic, 8U);
    put_u16(header + 8U, SWZ_RESULT_CONTEXT_VERSION);
    put_u16(header + 10U, kind);
    put_u32(header + 12U, (uint32_t)payload_length);
    if (append_bytes(output, capacity, &offset, header, sizeof(header)) != 0 ||
        append_bytes(output, capacity, &offset, payload, payload_length) != 0 ||
        swz_sha256(output, offset, digest) != 0 ||
        append_bytes(output, capacity, &offset, digest, sizeof(digest)) != 0) {
        return -1;
    }
    *output_length = offset;
    return 0;
}

static int build_bind(const struct restore_material *restore, int source_fd,
                      int restore_write_fd, uint32_t worker_serial,
                      uint64_t context_generation,
                      struct bind_material *output,
                      unsigned char envelope[16U + SWZ_RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES + 32U],
                      size_t *envelope_length)
{
    unsigned char payload[SWZ_RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES];
    size_t payload_length = 0U;
    uint64_t source_total;
    size_t index;
    char tag[80];

    if (restore == NULL || output == NULL || envelope == NULL || envelope_length == NULL ||
        source_fd < 0 || restore_write_fd < 0 || worker_serial == 0U ||
        context_generation == 0U ||
        fstat(source_fd, &output->source_stat) != 0 ||
        fstat(restore_write_fd, &output->target_pipe_stat) != 0 ||
        restore->transition_id[0] == '\0') {
        return -1;
    }
    if (swz_store_commitment("ssh-endpoint",
                             (const unsigned char *)"10.0.2.15:22222",
                             sizeof("10.0.2.15:22222") - 1U, tag) != 0 ||
        parse_hex_tag_text(tag, output->commitments[0]) != 0 ||
        swz_store_commitment("epoch",
                             (const unsigned char *)restore->transition.epoch_ref,
                             strlen(restore->transition.epoch_ref), tag) != 0 ||
        parse_hex_tag_text(tag, output->commitments[1]) != 0 ||
        swz_store_commitment("authority",
                             (const unsigned char *)restore->transition.authority_ref,
                             strlen(restore->transition.authority_ref), tag) != 0 ||
        parse_hex_tag_text(tag, output->commitments[2]) != 0 ||
        swz_store_commitment("launcher",
                             (const unsigned char *)"swz-launch-base",
                             sizeof("swz-launch-base") - 1U, tag) != 0 ||
        parse_hex_tag_text(tag, output->commitments[6]) != 0 ||
        swz_store_commitment("agent", (const unsigned char *)"swz-agent",
                             sizeof("swz-agent") - 1U, tag) != 0 ||
        parse_hex_tag_text(tag, output->commitments[7]) != 0) {
        return -1;
    }
    memcpy(output->commitments[3], restore->transition.commitments[0], 32U);
    memcpy(output->commitments[4], restore->transition.commitments[1], 32U);
    memcpy(output->commitments[5], restore->transition.commitments[2], 32U);
    memcpy(output->commitments[8], restore->transition.commitments[3], 32U);
    memcpy(output->commitments[9], restore->transition.commitments[4], 32U);
    memcpy(output->commitments[10], restore->transition.commitments[5], 32U);
    memcpy(output->commitments[11], restore->transition.commitments[6], 32U);
    memcpy(output->commitments[12], restore->transition.commitments[7], 32U);
    memcpy(output->commitments[13], restore->transition.commitments[8], 32U);
    memcpy(output->commitments[14], restore->transition.transition_commitment, 32U);
    memcpy(output->commitments[15], restore->consumed_record, 32U);
    memcpy(output->commitments[16], restore->restore_begin_commitment, 32U);
    output->context_generation = context_generation;
    memcpy(output->generation, restore->generation, 32U);
    memcpy(output->connection, restore->connection, 32U);
    memcpy(output->session, restore->session, 32U);
    memcpy(output->n_local, restore->n_local, 32U);
    memcpy(output->restore_begin_frame_hash, restore->restore_begin_frame_hash, 32U);
    memcpy(output->target_digest, output->commitments[9], 32U);
    memcpy(output->target_isolation_digest, output->commitments[10], 32U);
    output->worker_registration_serial = worker_serial;
    memcpy(output->transition_id, restore->transition.transition_id,
           sizeof(output->transition_id));
    memcpy(output->epoch_ref, restore->transition.epoch_ref, sizeof(output->epoch_ref));
    memcpy(output->authority_ref, restore->transition.authority_ref,
           sizeof(output->authority_ref));
    memcpy(output->barrier_utc, restore->transition.barrier_utc,
           sizeof(output->barrier_utc));
    if (hash_source_artifact(source_fd, output->source_content_sha256,
                             output->source_artifact_stream_digest,
                             &source_total) != 0 ||
        source_total != (uint64_t)output->source_stat.st_size ||
        append_u64(payload, sizeof(payload), &payload_length, output->context_generation) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length, output->generation, 32U) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length, output->connection, 32U) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length, output->session, 32U) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length, output->n_local, 32U) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length,
                     output->restore_begin_frame_hash, 32U) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length, output->transition_id,
                     SWZ_TRANSITION_ID_BYTES) != 0 ||
        append_u16(payload, sizeof(payload), &payload_length,
                   (uint16_t)strlen(output->epoch_ref)) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length, output->epoch_ref,
                     strlen(output->epoch_ref)) != 0 ||
        append_u16(payload, sizeof(payload), &payload_length,
                   (uint16_t)strlen(output->authority_ref)) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length, output->authority_ref,
                     strlen(output->authority_ref)) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length, output->barrier_utc, 27U) != 0) {
        return -1;
    }
    for (index = 0U; index < SWZ_BIND_COMMITMENTS; ++index) {
        if (append_bytes(payload, sizeof(payload), &payload_length,
                         output->commitments[index], 32U) != 0) {
            return -1;
        }
    }
    if (append_u64(payload, sizeof(payload), &payload_length,
                   (uint64_t)output->source_stat.st_dev) != 0 ||
        append_u64(payload, sizeof(payload), &payload_length,
                   (uint64_t)output->source_stat.st_ino) != 0 ||
        append_u64(payload, sizeof(payload), &payload_length,
                   (uint64_t)output->source_stat.st_size) != 0 ||
        append_u32(payload, sizeof(payload), &payload_length,
                   (uint32_t)output->source_stat.st_mode) != 0 ||
        append_u32(payload, sizeof(payload), &payload_length,
                   (uint32_t)output->source_stat.st_uid) != 0 ||
        append_u32(payload, sizeof(payload), &payload_length,
                   (uint32_t)output->source_stat.st_gid) != 0 ||
        append_u64(payload, sizeof(payload), &payload_length,
                   (uint64_t)output->source_stat.st_nlink) != 0 ||
        append_u64(payload, sizeof(payload), &payload_length, 0U) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length,
                     output->source_content_sha256, 32U) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length,
                     output->source_artifact_stream_digest, 32U) != 0 ||
        append_u64(payload, sizeof(payload), &payload_length,
                   (uint64_t)output->target_pipe_stat.st_dev) != 0 ||
        append_u64(payload, sizeof(payload), &payload_length,
                   (uint64_t)output->target_pipe_stat.st_ino) != 0 ||
        append_u32(payload, sizeof(payload), &payload_length,
                   (uint32_t)output->target_pipe_stat.st_mode) != 0 ||
        append_u32(payload, sizeof(payload), &payload_length, worker_serial) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length,
                     output->target_digest, 32U) != 0 ||
        append_bytes(payload, sizeof(payload), &payload_length,
                     output->target_isolation_digest, 32U) != 0 ||
        context_envelope(SWZ_RESULT_CONTEXT_BIND_MAGIC,
                         SWZ_RESULT_CONTEXT_BIND_KIND, payload, payload_length,
                         SWZ_RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES, envelope,
                         16U + SWZ_RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES + 32U,
                         envelope_length) != 0) {
        return -1;
    }
    return 0;
}

static int restore_worker_loop(int read_fd)
{
    int target_fd = -1;
    unsigned char buffer[65536];
    int result = -1;

    if (read_fd < 0 || swz_confine_component("restore-worker") != 0) {
        close(read_fd);
        return -1;
    }
    for (;;) {
        ssize_t received = read(read_fd, buffer, sizeof(buffer));

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0) {
            goto done;
        }
        if (target_fd < 0 &&
            (target_fd = open(SWZ_RESTORE_TARGET_PATH,
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                              0600)) < 0) {
            goto done;
        }
        if (received != 0 && swz_write_full(target_fd, buffer,
                                             (size_t)received) != 0) {
            goto done;
        }
        if (received == 0) {
            break;
        }
    }
    if (fsync(target_fd) != 0) {
        goto done;
    }
    result = 0;
done:
    explicit_bzero(buffer, sizeof(buffer));
    close(target_fd);
    close(read_fd);
    return result;
}

static int read_capture_eof(int fd, unsigned char *output, size_t capacity,
                            size_t *length)
{
    unsigned char extra;

    if (fd < 0 || output == NULL || length == NULL) {
        return -1;
    }
    *length = 0U;
    while (*length < capacity) {
        ssize_t received = read(fd, output + *length, capacity - *length);

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0) {
            return -1;
        }
        if (received == 0) {
            return 0;
        }
        *length += (size_t)received;
    }
    do {
        ssize_t received = read(fd, &extra, sizeof(extra));

        if (received < 0 && errno == EINTR) {
            continue;
        }
        return received == 0 ? 0 : -1;
    } while (1);
}

static int observe_pidfd_exit(int pidfd)
{
    struct pollfd descriptor;
    int result;

    if (pidfd < 0) {
        return -1;
    }
    descriptor.fd = pidfd;
    descriptor.events = POLLIN | POLLHUP | POLLERR;
    descriptor.revents = 0;
    do {
        result = poll(&descriptor, 1U, 0);
    } while (result < 0 && errno == EINTR);
    return result > 0 &&
                   (descriptor.revents & (POLLIN | POLLHUP | POLLERR)) != 0
               ? 0
               : -1;
}

static int spawn_worker(int read_fd, int stdout_write_fd, int stderr_write_fd,
                        pid_t *worker_pid, int *worker_pidfd)
{
    pid_t child;

    if (read_fd < 0 || stdout_write_fd < 0 || stderr_write_fd < 0 ||
        read_fd == stdout_write_fd || read_fd == stderr_write_fd ||
        stdout_write_fd == stderr_write_fd || worker_pid == NULL || worker_pidfd == NULL ||
        (child = fork()) < 0) {
        return -1;
    }
    if (child == 0) {
        int fd;

        if (dup2(stdout_write_fd, STDOUT_FILENO) < 0 ||
            dup2(stderr_write_fd, STDERR_FILENO) < 0) {
            _exit(126);
        }
        for (fd = 3; fd < 64; ++fd) {
            if (fd != read_fd) {
                (void)close(fd);
            }
        }
        _exit(restore_worker_loop(read_fd) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    *worker_pidfd = swz_pidfd_open(child);
    if (*worker_pidfd < 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        return -1;
    }
    *worker_pid = child;
    return 0;
}

static int spawn_agent(const int descriptors[3], pid_t *agent_pid)
{
    int channels[2] = { -1, -1 };
    pid_t child;
    int status;

    if (descriptors == NULL || agent_pid == NULL ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channels) != 0 ||
        (child = fork()) < 0) {
        close(channels[0]);
        close(channels[1]);
        return -1;
    }
    if (child == 0) {
        int fd;
        int flags;

        close(channels[0]);
        if (channels[1] == SWZ_AGENT_BUNDLE_FD) {
            flags = fcntl(channels[1], F_GETFD);
            if (flags < 0 || fcntl(channels[1], F_SETFD, flags & ~FD_CLOEXEC) < 0) {
                _exit(126);
            }
        } else if (dup3(channels[1], SWZ_AGENT_BUNDLE_FD, 0) < 0) {
            _exit(126);
        }
        if (channels[1] != SWZ_AGENT_BUNDLE_FD) {
            close(channels[1]);
        }
        for (fd = 3; fd < 64; ++fd) {
            if (fd != SWZ_AGENT_BUNDLE_FD) {
                (void)close(fd);
            }
        }
        execl(SWZ_BOOTSTRAP_PATH, SWZ_BOOTSTRAP_PATH, (char *)NULL);
        _exit(errno == ENOENT ? 127 : 126);
    }
    close(channels[1]);
    if (swz_send_agent_descriptor_bundle(channels[0], descriptors) != 0 ||
        close(channels[0]) != 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, &status, 0);
        return -1;
    }
    *agent_pid = child;
    return 0;
}

static int hash_fd_content(int fd, unsigned char digest[32], uint64_t *total)
{
    EVP_MD_CTX *context = NULL;
    unsigned char buffer[65536];
    unsigned int digest_length = 0U;
    uint64_t count = 0U;
    int result = -1;

    if (fd < 0 || digest == NULL || total == NULL || lseek(fd, 0, SEEK_SET) != 0 ||
        (context = EVP_MD_CTX_new()) == NULL ||
        EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        goto done;
    }
    for (;;) {
        ssize_t received = read(fd, buffer, sizeof(buffer));

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0 || UINT64_MAX - count < (uint64_t)received) {
            goto done;
        }
        if (received == 0) {
            break;
        }
        if (EVP_DigestUpdate(context, buffer, (size_t)received) != 1) {
            goto done;
        }
        count += (uint64_t)received;
    }
    if (EVP_DigestFinal_ex(context, digest, &digest_length) != 1 ||
        digest_length != 32U || lseek(fd, 0, SEEK_SET) != 0) {
        goto done;
    }
    *total = count;
    result = 0;
done:
    explicit_bzero(buffer, sizeof(buffer));
    EVP_MD_CTX_free(context);
    return result;
}

static int run_restore_sequence(void)
{
    unsigned char transcript[SWZ_TRANSCRIPT_BYTES];
    unsigned char discovery_hash[32];
    unsigned char bind_envelope[16U + SWZ_RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES + 32U];
    unsigned char final_envelope[16U + SWZ_RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES + 32U];
    unsigned char final_payload[SWZ_RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES];
    unsigned char bind_digest[32];
    unsigned char source_digest[32];
    unsigned char source_stream_digest[32];
    unsigned char target_digest[32];
    unsigned char ack_digest[32];
    unsigned char cleanup_digest[32];
    unsigned char worker_stdout_capture[SWZ_RESULT_CONTEXT_CAPTURE_MAX_BYTES];
    unsigned char worker_stderr_capture[SWZ_RESULT_CONTEXT_CAPTURE_MAX_BYTES];
    static const unsigned char cleanup_marker[] = "fixed-restore-target-retired";
    struct restore_material restore;
    struct bind_material bind;
    struct stat source_stat;
    int source_fd = -1;
    int target_fd = -1;
    int restore_pipe[2] = { -1, -1 };
    int context_pipe[2] = { -1, -1 };
    int worker_stdout_pipe[2] = { -1, -1 };
    int worker_stderr_pipe[2] = { -1, -1 };
    int descriptors[3] = { -1, -1, -1 };
    pid_t worker_pid = -1;
    pid_t agent_pid = -1;
    int worker_pidfd = -1;
    int worker_status = -1;
    int agent_status = -1;
    int worker_pidfd_exited = 0;
    uint64_t source_bytes;
    uint64_t target_bytes;
    size_t bind_length;
    size_t final_length;
    size_t final_payload_length = 0U;
    size_t worker_stdout_length = 0U;
    size_t worker_stderr_length = 0U;
    size_t index;
    uint64_t context_generation;
    char cleanup_tag[80];
    int result = -1;

    memset(&restore, 0, sizeof(restore));
    memset(&bind, 0, sizeof(bind));
    if (swz_read_full(SWZ_TRANSCRIPT_FD, transcript, sizeof(transcript)) != 0 ||
        read_eof(SWZ_TRANSCRIPT_FD) != 0 ||
        memcmp(transcript, SWZ_CONTEXT_MAGIC, sizeof(SWZ_CONTEXT_MAGIC) - 1U) != 0 ||
        memcmp(transcript + 8U, (const unsigned char[32]){ 0 }, 32U) == 0 ||
        memcmp(transcript + 40U, (const unsigned char[32]){ 0 }, 32U) == 0 ||
        memcmp(transcript + 72U, (const unsigned char[32]){ 0 }, 32U) == 0 ||
        memcmp(transcript + 104U, (const unsigned char[32]){ 0 }, 32U) == 0) {
        goto done;
    }
    memcpy(restore.session, transcript + 8U, 32U);
    memcpy(restore.generation, transcript + 40U, 32U);
    memcpy(restore.connection, transcript + 72U, 32U);
    memcpy(restore.n_local, transcript + 136U, 32U);
    memcpy(restore.accepted_frame_hash, transcript + 168U, 32U);
    memcpy(restore.accepted_session, transcript + 200U, 32U);
    memcpy(restore.activation, transcript + 232U, 32U);
    if (memcmp(restore.session, restore.accepted_session, 32U) != 0 ||
        write_discovery(restore.accepted_session, restore.accepted_frame_hash,
                        restore.n_local, discovery_hash) != 0 ||
        read_restore_begin(restore.n_local, discovery_hash, restore.accepted_session,
                           &restore) != 0) {
        goto done;
    }
    source_fd = open_qualified_source();
    if (validate_source_fd(source_fd, &source_stat) != 0 ||
        hash_source_artifact(source_fd, source_digest, source_stream_digest,
                             &source_bytes) != 0 || source_bytes != (uint64_t)source_stat.st_size ||
        pipe2(restore_pipe, O_CLOEXEC) != 0 || pipe2(context_pipe, O_CLOEXEC) != 0 ||
        pipe2(worker_stdout_pipe, O_CLOEXEC) != 0 ||
        pipe2(worker_stderr_pipe, O_CLOEXEC) != 0) {
        goto done;
    }
    if (random_u64(&context_generation) != 0 ||
        spawn_worker(restore_pipe[0], worker_stdout_pipe[1], worker_stderr_pipe[1],
                     &worker_pid, &worker_pidfd) != 0) {
        goto done;
    }
    close(restore_pipe[0]);
    restore_pipe[0] = -1;
    close(worker_stdout_pipe[1]);
    worker_stdout_pipe[1] = -1;
    close(worker_stderr_pipe[1]);
    worker_stderr_pipe[1] = -1;
    if (worker_pid <= 0 || (uint64_t)worker_pid > UINT32_MAX ||
        build_bind(&restore, source_fd, restore_pipe[1], (uint32_t)worker_pid,
                   context_generation, &bind, bind_envelope, &bind_length) != 0 ||
        memcmp(source_digest, bind.source_content_sha256, 32U) != 0 ||
        memcmp(source_stream_digest, bind.source_artifact_stream_digest, 32U) != 0 ||
        swz_sha256(bind_envelope, bind_length, bind_digest) != 0) {
        goto done;
    }
    descriptors[0] = source_fd;
    descriptors[1] = restore_pipe[1];
    descriptors[2] = context_pipe[0];
    if (spawn_agent(descriptors, &agent_pid) != 0) {
        goto done;
    }
    for (index = 0U; index < 3U; ++index) {
        if (close(descriptors[index]) != 0) {
            goto done;
        }
        descriptors[index] = -1;
    }
    source_fd = -1;
    restore_pipe[1] = -1;
    context_pipe[0] = -1;
    if (swz_write_full(context_pipe[1], bind_envelope, bind_length) != 0) {
        goto done;
    }
    if (waitpid(worker_pid, &worker_status, 0) != worker_pid ||
        !WIFEXITED(worker_status) || WEXITSTATUS(worker_status) != EXIT_SUCCESS ||
        observe_pidfd_exit(worker_pidfd) != 0 ||
        read_capture_eof(worker_stdout_pipe[0], worker_stdout_capture,
                         sizeof(worker_stdout_capture), &worker_stdout_length) != 0 ||
        read_capture_eof(worker_stderr_pipe[0], worker_stderr_capture,
                         sizeof(worker_stderr_capture), &worker_stderr_length) != 0 ||
        (target_fd = open(SWZ_RESTORE_TARGET_PATH,
                          O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0 ||
        hash_fd_content(target_fd, target_digest, &target_bytes) != 0 ||
        target_bytes != source_bytes || memcmp(target_digest, source_digest, 32U) != 0 ||
        swz_sha256(target_digest, sizeof(target_digest), ack_digest) != 0 ||
        swz_store_commitment("cleanup", cleanup_marker, sizeof(cleanup_marker) - 1U,
                             cleanup_tag) != 0 || parse_hex_tag_text(cleanup_tag, cleanup_digest) != 0 ||
        unlink(SWZ_RESTORE_TARGET_PATH) != 0) {
        goto done;
    }
    worker_pidfd_exited = 1;
    close(worker_stdout_pipe[0]);
    worker_stdout_pipe[0] = -1;
    close(worker_stderr_pipe[0]);
    worker_stderr_pipe[0] = -1;
    close(target_fd);
    target_fd = -1;
    if (append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     bind_digest, 32U) != 0 ||
        append_u64(final_payload, sizeof(final_payload), &final_payload_length,
                   bind.context_generation) != 0 ||
        append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     bind.generation, 32U) != 0 ||
        append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     bind.connection, 32U) != 0 ||
        append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     bind.session, 32U) != 0 ||
        append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     bind.transition_id, SWZ_TRANSITION_ID_BYTES) != 0 ||
        append_u64(final_payload, sizeof(final_payload), &final_payload_length,
                   (uint64_t)worker_pid) != 0 ||
        append_u64(final_payload, sizeof(final_payload), &final_payload_length,
                   source_bytes) != 0 ||
        append_u64(final_payload, sizeof(final_payload), &final_payload_length,
                   target_bytes) != 0 ||
        append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     source_digest, 32U) != 0 ||
        append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     ack_digest, 32U) != 0 ||
        append_u32(final_payload, sizeof(final_payload), &final_payload_length, 1U) != 0 ||
        append_u32(final_payload, sizeof(final_payload), &final_payload_length, 0U) != 0 ||
        append_u32(final_payload, sizeof(final_payload), &final_payload_length, 0U) != 0 ||
        append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     (const unsigned char[]){ 1U, 1U, 1U, 1U,
                                               (unsigned char)worker_pidfd_exited,
                                               (unsigned char)worker_pidfd_exited,
                                               1U, 1U, 1U }, 9U) != 0 ||
        append_u32(final_payload, sizeof(final_payload), &final_payload_length,
                   (uint32_t)worker_stdout_length) != 0 ||
        append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     worker_stdout_capture, worker_stdout_length) != 0 ||
        append_u32(final_payload, sizeof(final_payload), &final_payload_length,
                   (uint32_t)worker_stderr_length) != 0 ||
        append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     worker_stderr_capture, worker_stderr_length) != 0 ||
        append_bytes(final_payload, sizeof(final_payload), &final_payload_length,
                     cleanup_digest, 32U) != 0 ||
        context_envelope(SWZ_RESULT_CONTEXT_FINAL_MAGIC,
                         SWZ_RESULT_CONTEXT_FINAL_KIND, final_payload,
                         final_payload_length, SWZ_RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES,
                         final_envelope, sizeof(final_envelope), &final_length) != 0 ||
        swz_write_full(context_pipe[1], final_envelope, final_length) != 0) {
        goto done;
    }
    close(context_pipe[1]);
    context_pipe[1] = -1;
    if (waitpid(agent_pid, &agent_status, 0) != agent_pid || !WIFEXITED(agent_status) ||
        WEXITSTATUS(agent_status) != EXIT_SUCCESS) {
        goto done;
    }
    result = 0;
done:
    if (target_fd >= 0) {
        close(target_fd);
    }
    if (source_fd >= 0) {
        close(source_fd);
    }
    for (index = 0U; index < 2U; ++index) {
        if (restore_pipe[index] >= 0) {
            close(restore_pipe[index]);
        }
        if (context_pipe[index] >= 0) {
            close(context_pipe[index]);
        }
        if (worker_stdout_pipe[index] >= 0) {
            close(worker_stdout_pipe[index]);
        }
        if (worker_stderr_pipe[index] >= 0) {
            close(worker_stderr_pipe[index]);
        }
    }
    for (index = 0U; index < 3U; ++index) {
        if (descriptors[index] >= 0) {
            close(descriptors[index]);
        }
    }
    if (worker_pid > 0 && worker_status == -1) {
        (void)kill(worker_pid, SIGKILL);
        (void)waitpid(worker_pid, NULL, 0);
    }
    if (agent_pid > 0 && agent_status == -1) {
        (void)kill(agent_pid, SIGKILL);
        (void)waitpid(agent_pid, NULL, 0);
    }
    if (worker_pidfd >= 0) {
        close(worker_pidfd);
    }
    explicit_bzero(transcript, sizeof(transcript));
    explicit_bzero(&restore, sizeof(restore));
    explicit_bzero(&bind, sizeof(bind));
    explicit_bzero(final_payload, sizeof(final_payload));
    explicit_bzero(worker_stdout_capture, sizeof(worker_stdout_capture));
    explicit_bzero(worker_stderr_capture, sizeof(worker_stderr_capture));
    return result;
}

int main(void)
{
    if (swz_confine_component("broker") != 0) {
        return 126;
    }
    return run_restore_sequence() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
