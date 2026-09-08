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

struct json_cursor {
    const unsigned char *current;
    const unsigned char *end;
};

static int hex_lower(const unsigned char *bytes, size_t length)
{
    size_t index;

    for (index = 0U; index < length; ++index) {
        if (!((bytes[index] >= '0' && bytes[index] <= '9') ||
              (bytes[index] >= 'a' && bytes[index] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int json_string(struct json_cursor *cursor, const unsigned char **start,
                       size_t *length)
{
    const unsigned char *content;

    if (cursor->current >= cursor->end || *cursor->current != '"') {
        return -1;
    }
    ++cursor->current;
    content = cursor->current;
    while (cursor->current < cursor->end) {
        unsigned char value = *cursor->current;

        if (value == '"') {
            if (start != NULL) {
                *start = content;
            }
            if (length != NULL) {
                *length = (size_t)(cursor->current - content);
            }
            ++cursor->current;
            return 0;
        }
        if (value < 0x20U || value >= 0x80U) {
            return -1;
        }
        if (value == '\\') {
            ++cursor->current;
            if (cursor->current >= cursor->end ||
                strchr("\"\\/bfnrt", (int)*cursor->current) == NULL) {
                return -1;
            }
        }
        ++cursor->current;
    }
    return -1;
}

static int json_integer(struct json_cursor *cursor, uint64_t *value)
{
    uint64_t result = 0U;
    size_t digits = 0U;

    if (cursor->current >= cursor->end || *cursor->current < '0' ||
        *cursor->current > '9') {
        return -1;
    }
    if (*cursor->current == '0') {
        ++cursor->current;
        digits = 1U;
        if (cursor->current < cursor->end && *cursor->current >= '0' &&
            *cursor->current <= '9') {
            return -1;
        }
    } else {
        while (cursor->current < cursor->end && *cursor->current >= '0' &&
               *cursor->current <= '9') {
            unsigned int digit = (unsigned int)(*cursor->current - '0');

            if (result > (UINT64_MAX - digit) / 10U) {
                return -1;
            }
            result = result * 10U + digit;
            ++cursor->current;
            ++digits;
        }
    }
    if (cursor->current < cursor->end &&
        (*cursor->current == '.' || *cursor->current == 'e' ||
         *cursor->current == 'E')) {
        return -1;
    }
    if (value != NULL) {
        *value = result;
    }
    return digits == 0U ? -1 : 0;
}

static int json_value(struct json_cursor *cursor);

static int json_array(struct json_cursor *cursor, size_t *count)
{
    size_t items = 0U;

    if (cursor->current >= cursor->end || *cursor->current != '[') {
        return -1;
    }
    ++cursor->current;
    if (cursor->current < cursor->end && *cursor->current == ']') {
        ++cursor->current;
        if (count != NULL) {
            *count = 0U;
        }
        return 0;
    }
    for (;;) {
        if (json_value(cursor) != 0) {
            return -1;
        }
        ++items;
        if (cursor->current >= cursor->end) {
            return -1;
        }
        if (*cursor->current == ']') {
            ++cursor->current;
            if (count != NULL) {
                *count = items;
            }
            return 0;
        }
        if (*cursor->current != ',') {
            return -1;
        }
        ++cursor->current;
    }
}

static int json_value(struct json_cursor *cursor)
{
    if (cursor->current >= cursor->end) {
        return -1;
    }
    if (*cursor->current == '"') {
        return json_string(cursor, NULL, NULL);
    }
    if (*cursor->current == '[') {
        return json_array(cursor, NULL);
    }
    if (*cursor->current == 't') {
        if ((size_t)(cursor->end - cursor->current) < 4U ||
            memcmp(cursor->current, "true", 4U) != 0) {
            return -1;
        }
        cursor->current += 4U;
        return 0;
    }
    if (*cursor->current == 'f') {
        if ((size_t)(cursor->end - cursor->current) < 5U ||
            memcmp(cursor->current, "false", 5U) != 0) {
            return -1;
        }
        cursor->current += 5U;
        return 0;
    }
    if (*cursor->current >= '0' && *cursor->current <= '9') {
        return json_integer(cursor, NULL);
    }
    return -1;
}

static int json_comma(struct json_cursor *cursor)
{
    if (cursor->current >= cursor->end || *cursor->current != ',') {
        return -1;
    }
    ++cursor->current;
    return 0;
}

static int json_exact_integer(struct json_cursor *cursor, uint64_t expected)
{
    uint64_t value;

    return json_integer(cursor, &value) == 0 && value == expected ? 0 : -1;
}

static size_t expected_fields(uint16_t type)
{
    switch (type) {
    case SWZ_BOOT: return 9U;
    case SWZ_CHALLENGE: return 5U;
    case SWZ_EVIDENCE: return 24U;
    case SWZ_ACCEPT: return 6U;
    case SWZ_ACCEPTED: return 5U;
    case SWZ_DISCOVERY: return 9U;
    case SWZ_RESTORE_BEGIN: return 5U;
    case SWZ_PROCEED: return 5U;
    case SWZ_RESULT: return 5U;
    case SWZ_ABORT: return 4U;
    default: return 0U;
    }
}

static int predecessor_is_zero(const unsigned char *payload, size_t length)
{
    size_t string_index = 0U;
    size_t start = 0U;
    size_t index;
    int in_string = 0;

    for (index = 0U; index < length; ++index) {
        if (!in_string && payload[index] == '"') {
            in_string = 1;
            start = index + 1U;
        } else if (in_string && payload[index] == '"' &&
                   (index == 0U || payload[index - 1U] != '\\')) {
            if (string_index == 2U) {
                size_t offset;

                if (index - start != 64U) {
                    return -1;
                }
                for (offset = start; offset < index; ++offset) {
                    if (payload[offset] != '0') {
                        return 0;
                    }
                }
                return 1;
            }
            ++string_index;
            in_string = 0;
        }
    }
    return -1;
}

static int json_plain_string(struct json_cursor *cursor,
                             const unsigned char **start, size_t *length)
{
    const unsigned char *value;
    size_t value_length;

    if (json_string(cursor, &value, &value_length) != 0 ||
        memchr(value, '\\', value_length) != NULL) {
        return -1;
    }
    if (start != NULL) {
        *start = value;
    }
    if (length != NULL) {
        *length = value_length;
    }
    return 0;
}

static int json_plain_string_exact(struct json_cursor *cursor, const char *expected)
{
    const unsigned char *value;
    size_t value_length;

    return expected != NULL && json_plain_string(cursor, &value, &value_length) == 0 &&
           value_length == strlen(expected) &&
           memcmp(value, expected, value_length) == 0 ? 0 : -1;
}

static int json_managed32(struct json_cursor *cursor)
{
    const unsigned char *value;
    size_t length;

    return json_plain_string(cursor, &value, &length) == 0 && length == 64U &&
           hex_lower(value, length) ? 0 : -1;
}

static int json_plain_sha256(struct json_cursor *cursor)
{
    const unsigned char *value;
    size_t length;

    if (json_plain_string(cursor, &value, &length) != 0 || length != 74U ||
        memcmp(value, "sha256:v1:", 10U) != 0 ||
        !hex_lower(value + 10U, 64U)) {
        return -1;
    }
    return 0;
}

static int json_ref(struct json_cursor *cursor)
{
    const unsigned char *value;
    size_t length;
    size_t index;

    if (json_plain_string(cursor, &value, &length) != 0 || length == 0U ||
        length > 128U || !((value[0] >= 'A' && value[0] <= 'Z') ||
                           (value[0] >= 'a' && value[0] <= 'z') ||
                           (value[0] >= '0' && value[0] <= '9'))) {
        return -1;
    }
    for (index = 1U; index < length; ++index) {
        if (!((value[index] >= 'A' && value[index] <= 'Z') ||
              (value[index] >= 'a' && value[index] <= 'z') ||
              (value[index] >= '0' && value[index] <= '9') ||
              value[index] == '.' || value[index] == '_' || value[index] == '-')) {
            return -1;
        }
    }
    return 0;
}

static int json_utc6(struct json_cursor *cursor)
{
    const unsigned char *value;
    size_t length;
    size_t index;
    static const size_t separators[] = { 4U, 7U, 10U, 13U, 16U, 19U, 26U };
    static const unsigned char separator_values[] = { '-', '-', 'T', ':', ':', '.', 'Z' };

    if (json_plain_string(cursor, &value, &length) != 0 || length != 27U) {
        return -1;
    }
    for (index = 0U; index < sizeof(separators) / sizeof(separators[0]); ++index) {
        if (value[separators[index]] != separator_values[index]) {
            return -1;
        }
    }
    for (index = 0U; index < length; ++index) {
        if (index == 4U || index == 7U || index == 10U || index == 13U ||
            index == 16U || index == 19U || index == 26U) {
            continue;
        }
        if (value[index] < '0' || value[index] > '9') {
            return -1;
        }
    }
    return 0;
}

static int json_u64_text(struct json_cursor *cursor)
{
    const unsigned char *value;
    size_t length;
    size_t index;
    uint64_t result = 0U;

    if (json_plain_string(cursor, &value, &length) != 0 || length == 0U ||
        length > 20U || (length > 1U && value[0] == '0')) {
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        unsigned int digit;

        if (value[index] < '0' || value[index] > '9') {
            return -1;
        }
        digit = (unsigned int)(value[index] - '0');
        if (result > (UINT64_MAX - digit) / 10U) {
            return -1;
        }
        result = result * 10U + digit;
    }
    return 0;
}

static int json_u32_number(struct json_cursor *cursor)
{
    uint64_t value;

    return json_integer(cursor, &value) == 0 && value <= UINT32_MAX ? 0 : -1;
}

static int json_bool_true(struct json_cursor *cursor)
{
    if ((size_t)(cursor->end - cursor->current) >= 4U &&
        memcmp(cursor->current, "true", 4U) == 0) {
        cursor->current += 4U;
        return 0;
    }
    return -1;
}

static int json_uuid(struct json_cursor *cursor)
{
    const unsigned char *value;
    size_t length;
    size_t index;

    if (json_plain_string(cursor, &value, &length) != 0 || length != 36U ||
        value[8U] != '-' || value[13U] != '-' || value[18U] != '-' ||
        value[23U] != '-' || value[14U] != '4' ||
        (value[19U] != '8' && value[19U] != '9' && value[19U] != 'a' &&
         value[19U] != 'b')) {
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        if (index == 8U || index == 13U || index == 18U || index == 23U) {
            continue;
        }
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) {
            return -1;
        }
    }
    return 0;
}

static int json_transition_id(struct json_cursor *cursor)
{
    const unsigned char *value;
    size_t length;
    size_t index;

    if (json_plain_string(cursor, &value, &length) != 0 || length != 59U ||
        memcmp(value, "restore-v2-", 11U) != 0) {
        return -1;
    }
    for (index = 11U; index < length; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) {
            return -1;
        }
    }
    return 0;
}

static int json_store_wire(struct json_cursor *cursor)
{
    const unsigned char *schema;
    const unsigned char *document;
    size_t schema_length;
    size_t document_length;

    if (cursor->current >= cursor->end || *cursor->current++ != '[' ||
        json_plain_string_exact(cursor, "store-json.v1") != 0 ||
        json_comma(cursor) != 0 ||
        json_plain_string(cursor, &schema, &schema_length) != 0 ||
        !((schema_length == strlen("restore-ledger-transition-data.v2") &&
           memcmp(schema, "restore-ledger-transition-data.v2", schema_length) == 0) ||
          (schema_length == strlen("restore-begin-evidence.v2") &&
           memcmp(schema, "restore-begin-evidence.v2", schema_length) == 0) ||
          (schema_length == strlen("swz-recovery-result.v2") &&
           memcmp(schema, "swz-recovery-result.v2", schema_length) == 0)) ||
        json_comma(cursor) != 0 || json_string(cursor, &document, &document_length) != 0 ||
        document_length < 2U || cursor->current >= cursor->end ||
        *cursor->current++ != ']') {
        return -1;
    }
    return 0;
}

static int json_runtime_record(struct json_cursor *cursor)
{
    size_t index;

    if (cursor->current >= cursor->end || *cursor->current++ != '[' ||
        json_uuid(cursor) != 0) {
        return -1;
    }
    for (index = 1U; index < 15U; ++index) {
        if (json_comma(cursor) != 0 || json_u64_text(cursor) != 0) {
            return -1;
        }
    }
    if (json_comma(cursor) != 0 || json_bool_true(cursor) != 0 ||
        json_comma(cursor) != 0 || json_bool_true(cursor) != 0 ||
        json_comma(cursor) != 0 || json_exact_integer(cursor, 0U) != 0 ||
        json_comma(cursor) != 0 || json_u64_text(cursor) != 0 ||
        json_comma(cursor) != 0 || json_bool_true(cursor) != 0) {
        return -1;
    }
    for (index = 20U; index < 23U; ++index) {
        if (json_comma(cursor) != 0 || json_managed32(cursor) != 0) {
            return -1;
        }
    }
    if (cursor->current >= cursor->end || *cursor->current++ != ']') {
        return -1;
    }
    return 0;
}

static int json_message_field(struct json_cursor *cursor, uint16_t type,
                              size_t index)
{
    if (type == SWZ_BOOT) {
        if (index < 2U) {
            return json_ref(cursor);
        }
        if (index == 2U) {
            return json_utc6(cursor);
        }
        return json_managed32(cursor);
    }
    if (type == SWZ_CHALLENGE) {
        return index == 4U ? json_u64_text(cursor) : json_managed32(cursor);
    }
    if (type == SWZ_EVIDENCE) {
        return index == 22U ? json_runtime_record(cursor) : json_managed32(cursor);
    }
    if (type == SWZ_ACCEPT) {
        return index == 4U ? json_managed32(cursor) : json_managed32(cursor);
    }
    if (type == SWZ_ACCEPTED) {
        return json_managed32(cursor);
    }
    if (type == SWZ_DISCOVERY) {
        if (index == 0U || index == 8U) {
            return json_managed32(cursor);
        }
        if (index == 1U) {
            return json_u64_text(cursor);
        }
        return json_plain_string(cursor, NULL, NULL);
    }
    if (type == SWZ_RESTORE_BEGIN) {
        if (index == 0U) {
            return json_managed32(cursor);
        }
        if (index == 1U) {
            return json_managed32(cursor);
        }
        if (index == 2U || index == 3U) {
            return json_store_wire(cursor);
        }
        return json_plain_sha256(cursor);
    }
    if (type == SWZ_PROCEED) {
        if (index == 1U) {
            return json_transition_id(cursor);
        }
        if (index == 2U) {
            return json_plain_sha256(cursor);
        }
        return json_managed32(cursor);
    }
    if (type == SWZ_RESULT) {
        if (index == 1U) {
            return json_transition_id(cursor);
        }
        if (index == 3U) {
            return json_store_wire(cursor);
        }
        return json_managed32(cursor);
    }
    if (type == SWZ_ABORT) {
        return index < 2U ? json_ref(cursor) : json_managed32(cursor);
    }
    return -1;
}

const char *swz_message_name(uint16_t type)
{
    switch (type) {
    case SWZ_BOOT: return "BOOT";
    case SWZ_CHALLENGE: return "CHALLENGE";
    case SWZ_EVIDENCE: return "EVIDENCE";
    case SWZ_ACCEPT: return "ACCEPT";
    case SWZ_ACCEPTED: return "ACCEPTED";
    case SWZ_DISCOVERY: return "DISCOVERY";
    case SWZ_RESTORE_BEGIN: return "RESTORE_BEGIN";
    case SWZ_PROCEED: return "PROCEED";
    case SWZ_RESULT: return "RESULT";
    case SWZ_ABORT: return "ABORT";
    default: return NULL;
    }
}

int swz_frame_type_is_valid(uint16_t type)
{
    return swz_message_name(type) != NULL;
}

static int direction_valid(uint16_t type, uint8_t direction)
{
    if (type == SWZ_ABORT) {
        return direction == 1U || direction == 2U;
    }
    if (type == SWZ_BOOT || type == SWZ_ACCEPT ||
        type == SWZ_RESTORE_BEGIN || type == SWZ_PROCEED) {
        return direction == 1U;
    }
    return direction == 2U;
}

int swz_managed_payload_validate(const unsigned char *payload, size_t length,
                                 uint16_t type)
{
    struct json_cursor cursor;
    const unsigned char *message;
    const unsigned char *predecessor;
    size_t message_length;
    size_t predecessor_length;
    size_t fields;
    size_t index;
    const char *expected_name = swz_message_name(type);

    if (payload == NULL || expected_name == NULL || length == 0U ||
        length > SWZ_MAX_CONTROL_PAYLOAD_BYTES || payload[length - 1U] == '\n' ||
        (length >= 3U && payload[0] == 0xefU && payload[1] == 0xbbU &&
         payload[2] == 0xbfU)) {
        return -1;
    }
    cursor.current = payload;
    cursor.end = payload + length;
    if (json_array(&cursor, NULL) != 0 || cursor.current != cursor.end) {
        return -1;
    }
    cursor.current = payload;
    if (*cursor.current++ != '[' ||
        json_plain_string(&cursor, &message, &message_length) != 0 ||
        message_length != strlen(expected_name) ||
        memcmp(message, expected_name, message_length) != 0 ||
        json_comma(&cursor) != 0 || json_exact_integer(&cursor, 2U) != 0 ||
        json_comma(&cursor) != 0 ||
        json_plain_string_exact(&cursor, "swz-managed.v1") != 0 ||
        json_comma(&cursor) != 0 ||
        json_plain_string(&cursor, &predecessor, &predecessor_length) != 0 ||
        predecessor_length != 64U || !hex_lower(predecessor, predecessor_length) ||
        cursor.current >= cursor.end) {
        return -1;
    }
    fields = expected_fields(type);
    if (fields == 0U || *cursor.current != ',') {
        return -1;
    }
    ++cursor.current;
    for (index = 0U; index < fields; ++index) {
        if (json_message_field(&cursor, type, index) != 0) {
            return -1;
        }
        if (index + 1U == fields) {
            if (cursor.current >= cursor.end || *cursor.current++ != ']') {
                return -1;
            }
        } else if (json_comma(&cursor) != 0) {
            return -1;
        }
    }
    return cursor.current == cursor.end ? 0 : -1;
}

int swz_managed_payload_string_field(const unsigned char *payload, size_t length,
                                     size_t index, char *out, size_t capacity)
{
    struct json_cursor cursor;
    size_t current_index = 0U;
    const unsigned char *start;
    size_t field_length;

    if (payload == NULL || out == NULL || capacity == 0U || length == 0U) {
        return -1;
    }
    cursor.current = payload;
    cursor.end = payload + length;
    if (cursor.current >= cursor.end || *cursor.current++ != '[') {
        return -1;
    }
    if (cursor.current >= cursor.end || *cursor.current == ']') {
        return -1;
    }
    for (;;) {
        if (current_index == index) {
            if (json_string(&cursor, &start, &field_length) != 0 ||
                field_length + 1U > capacity ||
                memchr(start, '\\', field_length) != NULL) {
                return -1;
            }
            memcpy(out, start, field_length);
            out[field_length] = '\0';
            return 0;
        }
        if (json_value(&cursor) != 0 || cursor.current >= cursor.end ||
            *cursor.current != ',') {
            return -1;
        }
        ++cursor.current;
        ++current_index;
    }
}

int swz_managed_payload_predecessor(const unsigned char *payload, size_t length,
                                    unsigned char out[32])
{
    char encoded[65];
    size_t index;

    if (out == NULL || swz_managed_payload_string_field(payload, length, 3U,
                                                         encoded,
                                                         sizeof(encoded)) != 0 ||
        strlen(encoded) != 64U || !hex_lower((const unsigned char *)encoded, 64U)) {
        return -1;
    }
    for (index = 0U; index < 32U; ++index) {
        unsigned char high = encoded[index * 2U];
        unsigned char low = encoded[index * 2U + 1U];

        high = (unsigned char)(high <= '9' ? high - '0' : high - 'a' + 10U);
        low = (unsigned char)(low <= '9' ? low - '0' : low - 'a' + 10U);
        out[index] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

int swz_frame_encode(const struct swz_frame *frame, unsigned char *out,
                     size_t capacity, size_t *written)
{
    size_t total;

    if (frame == NULL || out == NULL || written == NULL ||
        frame->direction < 1U || frame->direction > 2U || frame->flags != 0U ||
        !swz_frame_type_is_valid(frame->type) ||
        !direction_valid(frame->type, frame->direction) ||
        frame->sequence >= SWZ_MAX_SESSION_FRAMES ||
        frame->payload_length == 0U ||
        frame->payload_length > SWZ_MAX_CONTROL_PAYLOAD_BYTES ||
        (frame->payload == NULL && frame->payload_length != 0U) ||
        swz_managed_payload_validate(frame->payload, frame->payload_length,
                                     frame->type) != 0 ||
        (frame->sequence == 0U && predecessor_is_zero(frame->payload,
                                                        frame->payload_length) != 1) ||
        (frame->sequence != 0U && predecessor_is_zero(frame->payload,
                                                         frame->payload_length) == 1)) {
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
    memcpy(out + 20U, frame->n_local, 32U);
    put32(out + 52U, frame->payload_length);
    memcpy(out + SWZ_FRAME_HEADER_BYTES, frame->payload, frame->payload_length);
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
        bytes[9U] < 1U || bytes[9U] > 2U ||
        !swz_frame_type_is_valid(bytes[10U]) ||
        !direction_valid(bytes[10U], bytes[9U])) {
        return -1;
    }
    payload_length = get32(bytes + 52U);
    if (payload_length == 0U || payload_length > SWZ_MAX_CONTROL_PAYLOAD_BYTES ||
        payload_length > SWZ_MAX_FRAME_BYTES - SWZ_FRAME_HEADER_BYTES ||
        length != SWZ_FRAME_HEADER_BYTES + (size_t)payload_length ||
        payload_length > payload_capacity ||
        payload == NULL || get64(bytes + 12U) >= SWZ_MAX_SESSION_FRAMES ||
        swz_managed_payload_validate(bytes + SWZ_FRAME_HEADER_BYTES,
                                     payload_length, bytes[10U]) != 0 ||
        (get64(bytes + 12U) == 0U && predecessor_is_zero(
             bytes + SWZ_FRAME_HEADER_BYTES, payload_length) != 1) ||
        (get64(bytes + 12U) != 0U && predecessor_is_zero(
             bytes + SWZ_FRAME_HEADER_BYTES, payload_length) == 1)) {
        return -1;
    }
    frame->direction = bytes[9U];
    frame->type = bytes[10U];
    frame->flags = bytes[11U];
    frame->sequence = get64(bytes + 12U);
    frame->payload_length = payload_length;
    memcpy(frame->n_local, bytes + 20U, 32U);
    frame->payload = payload;
    memcpy(payload, bytes + SWZ_FRAME_HEADER_BYTES, payload_length);
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
    if (payload_length == 0U || payload_length > SWZ_MAX_CONTROL_PAYLOAD_BYTES) {
        return -1;
    }
    wire = calloc(1U, SWZ_FRAME_HEADER_BYTES + payload_length);
    if (wire == NULL) {
        return -1;
    }
    memcpy(wire, header, sizeof(header));
    if (swz_read_full(fd, wire + SWZ_FRAME_HEADER_BYTES, payload_length) != 0) {
        free(wire);
        return -1;
    }
    result = swz_frame_decode(wire, SWZ_FRAME_HEADER_BYTES + payload_length,
                              frame, payload, payload_capacity);
    free(wire);
    return result;
}
