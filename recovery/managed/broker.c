#define _GNU_SOURCE

#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int appendf(char *output, size_t capacity, size_t *offset,
                   const char *format, ...)
{
    va_list arguments;
    int written;

    if (output == NULL || offset == NULL || *offset >= capacity) {
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

static int append_json_string(char *output, size_t capacity, size_t *offset,
                              const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;

    if (output == NULL || offset == NULL || value == NULL || *offset >= capacity) {
        return -1;
    }
    output[(*offset)++] = '"';
    while (*cursor != '\0') {
        unsigned char byte = *cursor++;

        if (byte == '"' || byte == '\\') {
            if (*offset + 2U >= capacity) {
                return -1;
            }
            output[(*offset)++] = '\\';
            output[(*offset)++] = (char)byte;
        } else if (byte == '\n') {
            if (*offset + 2U >= capacity) {
                return -1;
            }
            output[(*offset)++] = '\\';
            output[(*offset)++] = 'n';
        } else if (byte == '\r') {
            if (*offset + 2U >= capacity) {
                return -1;
            }
            output[(*offset)++] = '\\';
            output[(*offset)++] = 'r';
        } else if (byte < 0x20U || byte >= 0x80U) {
            return -1;
        } else {
            if (*offset + 1U >= capacity) {
                return -1;
            }
            output[(*offset)++] = (char)byte;
        }
    }
    if (*offset + 1U >= capacity) {
        return -1;
    }
    output[(*offset)++] = '"';
    output[*offset] = '\0';
    return 0;
}

static void put_u64(unsigned char output[8], uint64_t value)
{
    size_t index;

    for (index = 0U; index < 8U; ++index) {
        output[7U - index] = (unsigned char)(value >> (index * 8U));
    }
}

static int hex_value(unsigned char value)
{
    if (value >= '0' && value <= '9') {
        return (int)(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return (int)(value - 'a' + 10U);
    }
    return -1;
}

static int parse_hex32(const char *text, unsigned char output[32])
{
    size_t index;

    if (text == NULL || output == NULL || strlen(text) != 64U) {
        return -1;
    }
    for (index = 0U; index < 32U; ++index) {
        int high = hex_value((unsigned char)text[index * 2U]);
        int low = hex_value((unsigned char)text[index * 2U + 1U]);

        if (high < 0 || low < 0) {
            return -1;
        }
        output[index] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static int copy_field(const unsigned char *payload, size_t length, size_t index,
                      char output[65])
{
    return swz_managed_payload_string_field(payload, length, index, output, 65U) == 0 &&
           strlen(output) == 64U ? 0 : -1;
}

static int make_store_tag(const char *domain, const char *value, char output[80],
                          unsigned char raw[32])
{
    char tagged[80];

    if (domain == NULL || value == NULL || output == NULL || raw == NULL ||
        swz_store_commitment(domain, (const unsigned char *)value, strlen(value),
                             tagged) != 0 || strlen(tagged) != 74U ||
        memcmp(tagged, "sha256:v1:", 10U) != 0 ||
        parse_hex32(tagged + 10U, raw) != 0) {
        return -1;
    }
    memcpy(output, tagged, strlen(tagged) + 1U);
    return 0;
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
        frame->sequence != sequence ||
        memcmp(frame->n_local, n_local, 32U) != 0 ||
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

static int write_frame(uint8_t direction, uint16_t type, uint64_t sequence,
                       const unsigned char n_local[32],
                       const unsigned char previous_hash[32],
                       const char *payload, unsigned char frame_hash[32])
{
    struct swz_frame frame;
    unsigned char raw[SWZ_FRAME_HEADER_BYTES + SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char actual_previous[32];
    size_t written;

    memset(&frame, 0, sizeof(frame));
    frame.direction = direction;
    frame.type = type;
    frame.sequence = sequence;
    memcpy(frame.n_local, n_local, 32U);
    frame.payload = (unsigned char *)payload;
    frame.payload_length = (uint32_t)strlen(payload);
    if (swz_frame_encode(&frame, raw, sizeof(raw), &written) != 0 ||
        swz_managed_payload_predecessor(frame.payload, frame.payload_length,
                                        actual_previous) != 0 ||
        memcmp(actual_previous, previous_hash, 32U) != 0 ||
        swz_write_full(STDOUT_FILENO, raw, written) != 0 ||
        swz_frame_hash(raw, written, frame_hash) != 0) {
        return -1;
    }
    return 0;
}

static int copy_store_field(const unsigned char *payload, size_t length,
                            size_t index, char output[80],
                            unsigned char raw[32])
{
    return swz_managed_payload_string_field(payload, length, index, output, 80U) == 0 &&
           strlen(output) == 74U && memcmp(output, "sha256:v1:", 10U) == 0 &&
           parse_hex32(output + 10U, raw) == 0 ? 0 : -1;
}

static int extract_transition_id(const unsigned char *payload, size_t length,
                                 char output[60])
{
    static const char prefix[] = "\\\"transition_id\\\":\\\"restore-v2-";
    size_t prefix_length = sizeof(prefix) - 1U;
    size_t index;
    int found = 0;

    if (payload == NULL || output == NULL || length < prefix_length + 50U) {
        return -1;
    }
    for (index = 0U; index + prefix_length + 50U <= length; ++index) {
        size_t digit;

        if (memcmp(payload + index, prefix, prefix_length) != 0) {
            continue;
        }
        if (found != 0 || index + prefix_length + 50U > length) {
            return -1;
        }
        memcpy(output, "restore-v2-", 11U);
        for (digit = 0U; digit < 48U; ++digit) {
            if (hex_value(payload[index + prefix_length + digit]) < 0) {
                return -1;
            }
            output[11U + digit] = (char)payload[index + prefix_length + digit];
        }
        if (payload[index + prefix_length + 48U] != '\\' ||
            payload[index + prefix_length + 49U] != '"') {
            return -1;
        }
        output[59U] = '\0';
        found = 1;
    }
    return found != 0 ? 0 : -1;
}

static int make_discovery(const unsigned char session[32],
                          const unsigned char previous_hash[32],
                          char output[4096], unsigned char discovery_hash[32])
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
    size_t index;
    size_t offset = 0U;

    if (session == NULL || previous_hash == NULL || output == NULL ||
        discovery_hash == NULL || swz_hex(previous_hash, 32U, previous,
                                          sizeof(previous)) != 0 ||
        swz_hex(session, 32U, session_hex, sizeof(session_hex)) != 0) {
        return -1;
    }
    for (index = 0U; index < 5U; ++index) {
        if (make_store_tag(domains[index], values[index], tags[index],
                           tag_raw[index]) != 0) {
            return -1;
        }
    }
    put_u64(row_id, 23U);
    parts[0] = session;
    parts[1] = row_id;
    parts[2] = (const unsigned char *)filename;
    lengths[0] = 32U;
    lengths[1] = sizeof(row_id);
    lengths[2] = strlen(filename);
    for (index = 0U; index < 5U; ++index) {
        parts[3U + index] = tag_raw[index];
        lengths[3U + index] = sizeof(tag_raw[index]);
    }
    if (swz_managed_hash("discovery.v1", parts, lengths, 8U,
                         discovery_hash) != 0 ||
        appendf(output, 4096U, &offset,
                "[\"DISCOVERY\",2,\"swz-managed.v1\",\"%s\",\"%s\",\"23\",\"%s\"",
                previous, session_hex, encoded_filename) != 0) {
        return -1;
    }
    for (index = 0U; index < 5U; ++index) {
        if (appendf(output, 4096U, &offset, ",\"%s\"", tags[index]) != 0) {
            return -1;
        }
    }
    {
        char discovery_hex[65];

        if (swz_hex(discovery_hash, 32U, discovery_hex,
                    sizeof(discovery_hex)) != 0 ||
            appendf(output, 4096U, &offset, ",\"%s\"]", discovery_hex) != 0) {
            return -1;
        }
    }
    return 0;
}

static int valid_transition_id(const char *value)
{
    size_t index;

    if (value == NULL || strlen(value) != 59U ||
        memcmp(value, "restore-v2-", 11U) != 0) {
        return -1;
    }
    for (index = 11U; index < 59U; ++index) {
        if (hex_value((unsigned char)value[index]) < 0) {
            return -1;
        }
    }
    return 0;
}

static int valid_store_tag(const char *value, unsigned char raw[32])
{
    return value != NULL && strlen(value) == 74U &&
           memcmp(value, "sha256:v1:", 10U) == 0 &&
           parse_hex32(value + 10U, raw) == 0 ? 0 : -1;
}

static int make_result_store(const char *transition_id,
                             const char *transition_commitment,
                             const char *consumed_commitment,
                             char output[4096], size_t *output_length)
{
    static const char *const domains[] = {
        "ssh-endpoint", "epoch", "authority", "barrier", "runner",
        "bundle", "launcher", "agent", "image", "target", "isolation",
        "artifact", "artifact-stream", "pre-cas-ledger", "restore-begin",
        "process", "restore", "cleanup", "stdout-capture", "stderr-capture"
    };
    static const char *const values[] = {
        "10.0.2.15:22222", "epoch-qualified-001", "authority-qualified-001",
        "2026-09-07T00:00:00.000000Z", "qualified-runner", "qualified-bundle",
        "swz-launch-base", "swz-agent", "swz-managed-qualified-image-v1",
        "swz-managed-qualified-target-v1", "swz-managed-qualified-isolation-v1",
        "swz-managed-qualified-artifact-v1",
        "swz-managed-qualified-artifact-stream-v1", "qualified-pre-cas-ledger",
        "qualified-restore-begin", "swz-agent:exit=0",
        "qualified-restored-artifact", "socket-closed;generation-retired", "",
        ""
    };
    char tags[20][80];
    unsigned char ignored_raw[32];
    size_t index;
    size_t offset = 0U;

    if (valid_transition_id(transition_id) != 0 ||
        valid_store_tag(transition_commitment, ignored_raw) != 0 ||
        valid_store_tag(consumed_commitment, ignored_raw) != 0 ||
        output == NULL || output_length == NULL) {
        return -1;
    }
    for (index = 0U; index < 20U; ++index) {
        if (make_store_tag(domains[index], values[index], tags[index],
                           ignored_raw) != 0) {
            return -1;
        }
    }
    if (appendf(output, 4096U, &offset,
                "{\"schema\":\"swz-recovery-result.v2\",\"classification\":\"SUCCESS\",\"stage\":\"RESTORE\",\"epoch_ref\":\"epoch-qualified-001\",\"authority_ref\":\"authority-qualified-001\",\"barrier_utc\":\"2026-09-07T00:00:00.000000Z\",\"ssh_endpoint_commitment\":\"%s\",\"epoch_commitment\":\"%s\",\"authority_commitment\":\"%s\",\"barrier_commitment\":\"%s\",\"runner_commitment\":\"%s\",\"bundle_commitment\":\"%s\",\"launcher_commitment\":\"%s\",\"agent_commitment\":\"%s\",\"image_commitment\":\"%s\",\"target_commitment\":\"%s\",\"isolation_commitment\":\"%s\",\"artifact_commitment\":\"%s\",\"artifact_stream_commitment\":\"%s\",\"transition_id\":\"%s\",\"pre_cas_ledger_digest\":\"%s\",\"transition_data_commitment\":\"%s\",\"consumed_record_commitment\":\"%s\",\"restore_begin_commitment\":\"%s\",\"process_commitment\":\"%s\",\"restore_commitment\":\"%s\",\"cleanup_commitment\":\"%s\",\"stdout_capture_commitment\":\"%s\",\"stderr_capture_commitment\":\"%s\",\"result_code\":0,\"restore_count\":1,\"exit_status\":0,\"stdin_eof\":true,\"stdout_eof\":true,\"stderr_eof\":true,\"trailing_unframed_bytes\":false,\"terminal_input_eof\":true,\"terminal_input_trailing_bytes\":false,\"cleanup_state\":\"CLEAN\"}\n",
                tags[0], tags[1], tags[2], tags[3], tags[4], tags[5], tags[6],
                tags[7], tags[8], tags[9], tags[10], tags[11], tags[12],
                transition_id, tags[13], transition_commitment,
                consumed_commitment, tags[14], tags[15], tags[16], tags[17],
                tags[18], tags[19]) != 0) {
        return -1;
    }
    *output_length = offset;
    return 0;
}

static int make_result(const unsigned char session[32],
                       const unsigned char previous_hash[32],
                       const unsigned char proceed_commitment[32],
                       const char *transition_id,
                       const char *transition_commitment,
                       const char *consumed_commitment, char output[4096])
{
    char document[4096];
    char previous[65];
    char session_hex[65];
    char proceed_hex[65];
    char result_hex[65];
    unsigned char result_commitment[32];
    const unsigned char *parts[4];
    size_t lengths[4];
    size_t document_length;
    size_t offset = 0U;

    if (session == NULL || previous_hash == NULL || proceed_commitment == NULL ||
        output == NULL || make_result_store(transition_id, transition_commitment,
                                             consumed_commitment, document,
                                             &document_length) != 0 ||
        swz_hex(previous_hash, 32U, previous, sizeof(previous)) != 0 ||
        swz_hex(session, 32U, session_hex, sizeof(session_hex)) != 0 ||
        swz_hex(proceed_commitment, 32U, proceed_hex, sizeof(proceed_hex)) != 0) {
        return -1;
    }
    parts[0] = session;
    parts[1] = (const unsigned char *)transition_id;
    parts[2] = proceed_commitment;
    parts[3] = (const unsigned char *)document;
    lengths[0] = 32U;
    lengths[1] = strlen(transition_id);
    lengths[2] = 32U;
    lengths[3] = document_length;
    if (swz_managed_hash("result.v1", parts, lengths, 4U,
                         result_commitment) != 0 ||
        swz_hex(result_commitment, 32U, result_hex, sizeof(result_hex)) != 0 ||
        appendf(output, 4096U, &offset,
                "[\"RESULT\",2,\"swz-managed.v1\",\"%s\",\"%s\",\"%s\",\"%s\",[\"store-json.v1\",\"swz-recovery-result.v2\",",
                previous, session_hex, transition_id, proceed_hex) != 0 ||
        append_json_string(output, 4096U, &offset, document) != 0 ||
        appendf(output, 4096U, &offset, "],\"%s\"]", result_hex) != 0) {
        return -1;
    }
    return 0;
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

static int run_restore_sequence(void)
{
    unsigned char transcript[SWZ_TRANSCRIPT_BYTES];
    unsigned char raw[SWZ_FRAME_HEADER_BYTES + SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char session[32];
    unsigned char generation[32];
    unsigned char connection[32];
    unsigned char cookie[32];
    unsigned char n_local[32];
    unsigned char accepted_frame_hash[32];
    unsigned char accepted_session[32];
    unsigned char activation[32];
    unsigned char payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char discovery_hash[32];
    unsigned char restore_hash[32];
    unsigned char proceed_hash[32];
    unsigned char proceed_commitment[32];
    unsigned char repeat_hash[32];
    struct swz_frame incoming;
    char field[80];
    char expected[80];
    char transition_id[60];
    char transition_commitment[80];
    char consumed_commitment[80];
    char discovery[4096];
    char result[4096];

    if (swz_read_full(SWZ_TRANSCRIPT_FD, transcript, sizeof(transcript)) != 0 ||
        read_eof(SWZ_TRANSCRIPT_FD) != 0 ||
        memcmp(transcript, SWZ_CONTEXT_MAGIC, sizeof(SWZ_CONTEXT_MAGIC) - 1U) != 0) {
        return -1;
    }
    memcpy(session, transcript + 8U, sizeof(session));
    memcpy(generation, transcript + 40U, sizeof(generation));
    memcpy(connection, transcript + 72U, sizeof(connection));
    memcpy(cookie, transcript + 104U, sizeof(cookie));
    memcpy(n_local, transcript + SWZ_CONTEXT_BYTES, sizeof(n_local));
    memcpy(accepted_frame_hash, transcript + SWZ_CONTEXT_BYTES + 32U,
           sizeof(accepted_frame_hash));
    memcpy(accepted_session, transcript + SWZ_CONTEXT_BYTES + 64U,
           sizeof(accepted_session));
    memcpy(activation, transcript + SWZ_CONTEXT_BYTES + 96U, sizeof(activation));
    if (memcmp(session, (const unsigned char[32]){ 0 }, sizeof(session)) == 0 ||
        memcmp(accepted_session, (const unsigned char[32]){ 0 }, sizeof(accepted_session)) == 0 ||
        memcmp(connection, (const unsigned char[32]){ 0 }, sizeof(connection)) == 0 ||
        memcmp(generation, (const unsigned char[32]){ 0 }, sizeof(generation)) == 0 ||
        memcmp(cookie, (const unsigned char[32]){ 0 }, sizeof(cookie)) == 0 ||
        memcmp(activation, (const unsigned char[32]){ 0 }, sizeof(activation)) == 0 ||
        make_discovery(accepted_session, accepted_frame_hash, discovery, discovery_hash) != 0 ||
        write_frame(2U, SWZ_DISCOVERY, 5U, n_local, accepted_frame_hash,
                    discovery, discovery_hash) != 0) {
        return -1;
    }
    if (read_frame_exact(&incoming, payload, raw, restore_hash,
                         SWZ_RESTORE_BEGIN, 1U, 6U, n_local, discovery_hash) != 0 ||
        copy_field(incoming.payload, incoming.payload_length, 4U, field) != 0 ||
        swz_hex(discovery_hash, 32U, expected, sizeof(expected)) != 0 ||
        strcmp(field, expected) != 0 ||
        copy_field(incoming.payload, incoming.payload_length, 5U, field) != 0 ||
        swz_hex(accepted_session, 32U, expected, sizeof(expected)) != 0 ||
        strcmp(field, expected) != 0 ||
        extract_transition_id(incoming.payload, incoming.payload_length,
                              transition_id) != 0 ||
        copy_store_field(incoming.payload, incoming.payload_length, 8U,
                         consumed_commitment, repeat_hash) != 0) {
        return -1;
    }
    if (read_frame_exact(&incoming, payload, raw, proceed_hash,
                         SWZ_PROCEED, 1U, 7U, n_local, restore_hash) != 0 ||
        copy_field(incoming.payload, incoming.payload_length, 4U, field) != 0 ||
        swz_hex(accepted_session, 32U, expected, sizeof(expected)) != 0 ||
        strcmp(field, expected) != 0 ||
        copy_field(incoming.payload, incoming.payload_length, 5U, field) != 0 ||
        strcmp(field, transition_id) != 0 ||
        copy_store_field(incoming.payload, incoming.payload_length, 6U,
                         transition_commitment, repeat_hash) != 0 ||
        copy_field(incoming.payload, incoming.payload_length, 7U, field) != 0 ||
        swz_hex(restore_hash, 32U, expected, sizeof(expected)) != 0 ||
        strcmp(field, expected) != 0 ||
        copy_field(incoming.payload, incoming.payload_length, 8U, field) != 0 ||
        parse_hex32(field, proceed_commitment) != 0 ||
        read_eof(STDIN_FILENO) != 0 ||
        make_result(accepted_session, proceed_hash, proceed_commitment, transition_id,
                    transition_commitment, consumed_commitment, result) != 0 ||
        write_frame(2U, SWZ_RESULT, 8U, n_local, proceed_hash, result,
                    repeat_hash) != 0) {
        return -1;
    }
    return 0;
}

int main(void)
{
    if (swz_confine_component("broker") != 0) {
        return 126;
    }
    return run_restore_sequence() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
