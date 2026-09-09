#define _GNU_SOURCE

#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SWZ_BIND_COMMITMENTS 17U
#define SWZ_TRANSITION_ID_BYTES 59U
#define SWZ_MAX_RESULT_DOCUMENT_BYTES 8192U
#define SWZ_MAX_RESULT_PAYLOAD_BYTES 16384U

struct bind_record {
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
    uint64_t source_dev;
    uint64_t source_ino;
    uint64_t source_size;
    uint32_t source_mode;
    uint32_t source_uid;
    uint32_t source_gid;
    uint64_t source_nlink;
    uint64_t source_offset;
    unsigned char source_content_sha256[32];
    unsigned char source_artifact_stream_digest[32];
    uint64_t target_pipe_dev;
    uint64_t target_pipe_ino;
    uint32_t target_mode;
    uint32_t worker_registration_serial;
    unsigned char target_digest[32];
    unsigned char target_isolation_digest[32];
};

struct final_record {
    unsigned char bind_envelope_sha256[32];
    uint64_t context_generation;
    unsigned char generation[32];
    unsigned char connection[32];
    unsigned char session[32];
    char transition_id[SWZ_TRANSITION_ID_BYTES + 1U];
    uint64_t finality_serial;
    uint64_t source_bytes_read;
    uint64_t sink_bytes_accepted;
    unsigned char source_sha256[32];
    unsigned char sink_ack_digest[32];
    uint32_t restore_count;
    uint32_t exit_status;
    uint32_t result_code;
    unsigned char source_eof;
    unsigned char restore_stdin_eof;
    unsigned char worker_stdout_eof;
    unsigned char worker_stderr_eof;
    unsigned char worker_pidfd_exited;
    unsigned char worker_cgroup_empty;
    unsigned char target_readback_verified;
    unsigned char owned_cleanup_complete;
    unsigned char cleanup_state;
    unsigned char stdout_capture[SWZ_RESULT_CONTEXT_CAPTURE_MAX_BYTES];
    size_t stdout_length;
    unsigned char stderr_capture[SWZ_RESULT_CONTEXT_CAPTURE_MAX_BYTES];
    size_t stderr_length;
    unsigned char cleanup_inventory_digest[32];
};

static uint16_t get_u16(const unsigned char *value)
{
    return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static uint32_t get_u32(const unsigned char *value)
{
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | value[3];
}

static uint64_t get_u64(const unsigned char *value)
{
    uint64_t result = 0U;
    size_t index;

    for (index = 0U; index < 8U; ++index) {
        result = (result << 8) | value[index];
    }
    return result;
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

static int nonzero_raw32(const unsigned char value[32])
{
    size_t index;

    for (index = 0U; index < 32U; ++index) {
        if (value[index] != 0U) {
            return 1;
        }
    }
    return 0;
}

static int take_bytes(const unsigned char **cursor, const unsigned char *end,
                      void *out, size_t length)
{
    if (cursor == NULL || *cursor == NULL || end == NULL ||
        out == NULL || *cursor > end || length > (size_t)(end - *cursor)) {
        return -1;
    }
    memcpy(out, *cursor, length);
    *cursor += length;
    return 0;
}

static int valid_ref_bytes(const unsigned char *value, size_t length)
{
    size_t index;

    if (value == NULL || length == 0U || length > 128U ||
        !((value[0] >= 'A' && value[0] <= 'Z') ||
          (value[0] >= 'a' && value[0] <= 'z') ||
          (value[0] >= '0' && value[0] <= '9'))) {
        return -1;
    }
    for (index = 1U; index < length; ++index) {
        if (!((value[index] >= 'A' && value[index] <= 'Z') ||
              (value[index] >= 'a' && value[index] <= 'z') ||
              (value[index] >= '0' && value[index] <= '9') ||
              value[index] == '.' || value[index] == '_' ||
              value[index] == '-')) {
            return -1;
        }
    }
    return 0;
}

static int valid_utc6(const unsigned char *value)
{
    static const size_t separators[] = { 4U, 7U, 10U, 13U, 16U, 19U, 26U };
    static const unsigned char separator_values[] = { '-', '-', 'T', ':', ':', '.', 'Z' };
    size_t index;

    if (value == NULL) {
        return -1;
    }
    for (index = 0U; index < 27U; ++index) {
        size_t separator_index;
        int is_separator = 0;

        for (separator_index = 0U;
             separator_index < sizeof(separators) / sizeof(separators[0]);
             ++separator_index) {
            if (index == separators[separator_index]) {
                is_separator = 1;
                if (value[index] != separator_values[separator_index]) {
                    return -1;
                }
            }
        }
        if (!is_separator && (value[index] < '0' || value[index] > '9')) {
            return -1;
        }
    }
    return 0;
}

static int valid_transition_id(const char *value)
{
    size_t index;

    if (value == NULL || strlen(value) != SWZ_TRANSITION_ID_BYTES ||
        memcmp(value, "restore-v2-", 11U) != 0) {
        return -1;
    }
    for (index = 11U; index < SWZ_TRANSITION_ID_BYTES; ++index) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
              (value[index] >= 'a' && value[index] <= 'f'))) {
            return -1;
        }
    }
    return 0;
}

static int parse_bind(const unsigned char *payload, size_t length,
                      struct bind_record *bind)
{
    const unsigned char *cursor = payload;
    const unsigned char *end;
    unsigned char raw_length[2];
    unsigned char raw8[8];
    unsigned char transition[SWZ_TRANSITION_ID_BYTES];
    unsigned char source_record[116];
    unsigned char target_record[88];
    size_t index;
    size_t ref_length;

    if (payload == NULL || bind == NULL ||
        length > SWZ_RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES) {
        return -1;
    }
    end = payload + length;
    if (take_bytes(&cursor, end, raw8, sizeof(raw8)) != 0) {
        return -1;
    }
    bind->context_generation = get_u64(raw8);
    if (bind->context_generation == 0U ||
        take_bytes(&cursor, end, bind->generation, sizeof(bind->generation)) != 0 ||
        take_bytes(&cursor, end, bind->connection, sizeof(bind->connection)) != 0 ||
        take_bytes(&cursor, end, bind->session, sizeof(bind->session)) != 0 ||
        take_bytes(&cursor, end, bind->n_local, sizeof(bind->n_local)) != 0 ||
        take_bytes(&cursor, end, bind->restore_begin_frame_hash,
                   sizeof(bind->restore_begin_frame_hash)) != 0 ||
        !nonzero_raw32(bind->generation) || !nonzero_raw32(bind->connection) ||
        !nonzero_raw32(bind->session) || !nonzero_raw32(bind->n_local) ||
        !nonzero_raw32(bind->restore_begin_frame_hash) ||
        take_bytes(&cursor, end, transition, sizeof(transition)) != 0) {
        return -1;
    }
    memcpy(bind->transition_id, transition, sizeof(transition));
    bind->transition_id[sizeof(transition)] = '\0';
    if (valid_transition_id(bind->transition_id) != 0) {
        return -1;
    }
    for (index = 0U; index < 2U; ++index) {
        if (take_bytes(&cursor, end, raw_length, sizeof(raw_length)) != 0) {
            return -1;
        }
        ref_length = (size_t)get_u16(raw_length);
        if (ref_length >= 129U) {
            return -1;
        }
        if (index == 0U) {
            if (take_bytes(&cursor, end, bind->epoch_ref, ref_length) != 0 ||
                valid_ref_bytes((const unsigned char *)bind->epoch_ref,
                                ref_length) != 0) {
                return -1;
            }
            bind->epoch_ref[ref_length] = '\0';
        } else {
            if (take_bytes(&cursor, end, bind->authority_ref, ref_length) != 0 ||
                valid_ref_bytes((const unsigned char *)bind->authority_ref,
                                ref_length) != 0) {
                return -1;
            }
            bind->authority_ref[ref_length] = '\0';
        }
    }
    if (take_bytes(&cursor, end, bind->barrier_utc, 27U) != 0 ||
        valid_utc6((const unsigned char *)bind->barrier_utc) != 0) {
        return -1;
    }
    bind->barrier_utc[27U] = '\0';
    for (index = 0U; index < SWZ_BIND_COMMITMENTS; ++index) {
        if (take_bytes(&cursor, end, bind->commitments[index], 32U) != 0 ||
            !nonzero_raw32(bind->commitments[index])) {
            return -1;
        }
    }
    if (take_bytes(&cursor, end, source_record, sizeof(source_record)) != 0 ||
        take_bytes(&cursor, end, target_record, sizeof(target_record)) != 0 ||
        cursor != end) {
        return -1;
    }
    bind->source_dev = get_u64(source_record);
    bind->source_ino = get_u64(source_record + 8U);
    bind->source_size = get_u64(source_record + 16U);
    bind->source_mode = get_u32(source_record + 24U);
    bind->source_uid = get_u32(source_record + 28U);
    bind->source_gid = get_u32(source_record + 32U);
    bind->source_nlink = get_u64(source_record + 36U);
    bind->source_offset = get_u64(source_record + 44U);
    memcpy(bind->source_content_sha256, source_record + 52U, 32U);
    memcpy(bind->source_artifact_stream_digest, source_record + 84U, 32U);
    bind->target_pipe_dev = get_u64(target_record);
    bind->target_pipe_ino = get_u64(target_record + 8U);
    bind->target_mode = get_u32(target_record + 16U);
    bind->worker_registration_serial = get_u32(target_record + 20U);
    memcpy(bind->target_digest, target_record + 24U, 32U);
    memcpy(bind->target_isolation_digest, target_record + 56U, 32U);
    return bind->source_nlink == 1U && bind->source_offset == 0U &&
                   bind->source_size <= (uint64_t)64U * 1024U * 1024U * 1024U &&
                   bind->worker_registration_serial != 0U &&
                   nonzero_raw32(bind->source_content_sha256) &&
                   nonzero_raw32(bind->source_artifact_stream_digest) &&
                   nonzero_raw32(bind->target_digest) &&
                   nonzero_raw32(bind->target_isolation_digest)
               ? 0
               : -1;
}

static int read_context_envelope(int fd, const char magic[8], uint16_t kind,
                                 size_t maximum, unsigned char *payload,
                                 size_t *payload_length,
                                 unsigned char envelope_hash[32])
{
    unsigned char header[16];
    unsigned char digest[32];
    unsigned char expected[32];
    unsigned char wire[SWZ_RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES + 48U];
    uint32_t length;
    EVP_MD_CTX *hash = NULL;
    unsigned int output_length = 0U;

    if (fd < 0 || magic == NULL || payload == NULL || payload_length == NULL ||
        envelope_hash == NULL || swz_read_full(fd, header, sizeof(header)) != 0 ||
        memcmp(header, magic, 8U) != 0 ||
        get_u16(header + 8U) != (uint16_t)SWZ_RESULT_CONTEXT_VERSION ||
        get_u16(header + 10U) != kind) {
        return -1;
    }
    length = get_u32(header + 12U);
    if (length > maximum ||
        swz_read_full(fd, payload, (size_t)length) != 0 ||
        swz_read_full(fd, digest, sizeof(digest)) != 0 ||
        (hash = EVP_MD_CTX_new()) == NULL ||
        EVP_DigestInit_ex(hash, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(hash, header, sizeof(header)) != 1 ||
        (length != 0U && EVP_DigestUpdate(hash, payload, length) != 1) ||
        EVP_DigestFinal_ex(hash, expected, &output_length) != 1 ||
        output_length != 32U || memcmp(expected, digest, 32U) != 0) {
        EVP_MD_CTX_free(hash);
        return -1;
    }
    EVP_MD_CTX_free(hash);
    memcpy(wire, header, sizeof(header));
    memcpy(wire + sizeof(header), payload, length);
    memcpy(wire + sizeof(header) + length, digest, sizeof(digest));
    if (swz_sha256(wire, sizeof(header) + (size_t)length + sizeof(digest),
                   envelope_hash) != 0) {
        return -1;
    }
    *payload_length = (size_t)length;
    return 0;
}

static int read_context_eof(void)
{
    unsigned char value;
    ssize_t received;

    do {
        received = read(SWZ_AGENT_RESULT_CONTEXT_FD, &value, sizeof(value));
    } while (received < 0 && errno == EINTR);
    return received == 0 ? 0 : -1;
}

static int descriptor_closed(int fd)
{
    errno = 0;
    if (fcntl(fd, F_GETFD) >= 0) {
        return -1;
    }
    return errno == EBADF ? 0 : -1;
}

static int validate_agent_descriptors(const struct bind_record *bind)
{
    struct stat source;
    struct stat target;
    struct stat context;
    int source_flags;
    int target_flags;
    int context_flags;
    int fd;

    if (bind == NULL || fstat(SWZ_AGENT_SOURCE_FD, &source) != 0 ||
        fstat(SWZ_AGENT_RESTORE_FD, &target) != 0 ||
        fstat(SWZ_AGENT_RESULT_CONTEXT_FD, &context) != 0 ||
        !S_ISREG(source.st_mode) || !S_ISFIFO(target.st_mode) ||
        !S_ISFIFO(context.st_mode) ||
        (uint64_t)source.st_dev != bind->source_dev ||
        (uint64_t)source.st_ino != bind->source_ino ||
        (uint64_t)source.st_size != bind->source_size ||
        (uint32_t)source.st_mode != bind->source_mode ||
        (uint32_t)source.st_uid != bind->source_uid ||
        (uint32_t)source.st_gid != bind->source_gid ||
        (uint64_t)source.st_nlink != bind->source_nlink ||
        (uint64_t)target.st_dev != bind->target_pipe_dev ||
        (uint64_t)target.st_ino != bind->target_pipe_ino ||
        (uint32_t)target.st_mode != bind->target_mode ||
        (target.st_mode & 0777U) != 0600U ||
        (source.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) != 0 ||
        lseek(SWZ_AGENT_SOURCE_FD, 0, SEEK_CUR) != 0 ||
        lseek(SWZ_AGENT_RESTORE_FD, 0, SEEK_CUR) >= 0 ||
        errno != ESPIPE ||
        lseek(SWZ_AGENT_RESULT_CONTEXT_FD, 0, SEEK_CUR) >= 0 ||
        errno != ESPIPE || (context.st_mode & 0777U) != 0600U ||
        descriptor_closed(3) != 0) {
        return -1;
    }
    source_flags = fcntl(SWZ_AGENT_SOURCE_FD, F_GETFL);
    target_flags = fcntl(SWZ_AGENT_RESTORE_FD, F_GETFL);
    context_flags = fcntl(SWZ_AGENT_RESULT_CONTEXT_FD, F_GETFL);
    if (source_flags < 0 || target_flags < 0 || context_flags < 0 ||
        (source_flags & O_ACCMODE) != O_RDONLY ||
        (target_flags & O_ACCMODE) != O_WRONLY ||
        (context_flags & O_ACCMODE) != O_RDONLY) {
        return -1;
    }
    for (fd = 7; fd < 64; ++fd) {
        if (descriptor_closed(fd) != 0) {
            return -1;
        }
    }
    return swz_set_cloexec(SWZ_AGENT_SOURCE_FD) == 0 &&
                   swz_set_cloexec(SWZ_AGENT_RESTORE_FD) == 0 &&
                   swz_set_cloexec(SWZ_AGENT_RESULT_CONTEXT_FD) == 0
               ? 0
               : -1;
}

static int digest_update_lp(EVP_MD_CTX *context, const unsigned char *value,
                            size_t length)
{
    unsigned char prefix[4];

    if (length > UINT32_MAX) {
        return -1;
    }
    prefix[0] = (unsigned char)(length >> 24);
    prefix[1] = (unsigned char)(length >> 16);
    prefix[2] = (unsigned char)(length >> 8);
    prefix[3] = (unsigned char)length;
    return EVP_DigestUpdate(context, prefix, sizeof(prefix)) == 1 &&
                   (length == 0U || EVP_DigestUpdate(context, value, length) == 1)
               ? 0
               : -1;
}

static int hash_source_once(const struct bind_record *bind,
                            unsigned char content_digest[32],
                            unsigned char stream_digest[32])
{
    EVP_MD_CTX *content = NULL;
    EVP_MD_CTX *stream = NULL;
    unsigned char buffer[65536];
    unsigned int content_length = 0U;
    unsigned int stream_length = 0U;
    uint64_t total = 0U;
    int result = -1;

    if (bind == NULL || content_digest == NULL || stream_digest == NULL ||
        lseek(SWZ_AGENT_SOURCE_FD, 0, SEEK_SET) != 0 ||
        (content = EVP_MD_CTX_new()) == NULL ||
        (stream = EVP_MD_CTX_new()) == NULL ||
        EVP_DigestInit_ex(content, EVP_sha256(), NULL) != 1 ||
        EVP_DigestInit_ex(stream, EVP_sha256(), NULL) != 1 ||
        digest_update_lp(stream,
                         (const unsigned char *)"recovery-commitment.v1",
                         sizeof("recovery-commitment.v1") - 1U) != 0 ||
        digest_update_lp(stream, (const unsigned char *)"artifact-stream",
                         sizeof("artifact-stream") - 1U) != 0) {
        goto done;
    }
    for (;;) {
        ssize_t received = read(SWZ_AGENT_SOURCE_FD, buffer, sizeof(buffer));

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0) {
            goto done;
        }
        if (received == 0) {
            break;
        }
        if (UINT64_MAX - total < (uint64_t)received ||
            EVP_DigestUpdate(content, buffer, (size_t)received) != 1 ||
            digest_update_lp(stream, buffer, (size_t)received) != 0) {
            goto done;
        }
        total += (uint64_t)received;
    }
    if (total != bind->source_size ||
        EVP_DigestFinal_ex(content, content_digest, &content_length) != 1 ||
        content_length != 32U ||
        EVP_DigestFinal_ex(stream, stream_digest, &stream_length) != 1 ||
        stream_length != 32U || lseek(SWZ_AGENT_SOURCE_FD, 0, SEEK_SET) != 0 ||
        memcmp(content_digest, bind->source_content_sha256, 32U) != 0 ||
        memcmp(stream_digest, bind->source_artifact_stream_digest, 32U) != 0) {
        goto done;
    }
    result = 0;
done:
    explicit_bzero(buffer, sizeof(buffer));
    EVP_MD_CTX_free(content);
    EVP_MD_CTX_free(stream);
    return result;
}

static int copy_source_after_barrier(const struct bind_record *bind,
                                     const unsigned char expected_content[32])
{
    EVP_MD_CTX *content = NULL;
    unsigned char buffer[65536];
    unsigned char actual[32];
    unsigned int actual_length = 0U;
    uint64_t total = 0U;
    int result = -1;

    if (bind == NULL || expected_content == NULL ||
        (content = EVP_MD_CTX_new()) == NULL ||
        EVP_DigestInit_ex(content, EVP_sha256(), NULL) != 1 ||
        lseek(SWZ_AGENT_SOURCE_FD, 0, SEEK_SET) != 0) {
        goto done;
    }
    for (;;) {
        ssize_t received = read(SWZ_AGENT_SOURCE_FD, buffer, sizeof(buffer));

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0) {
            goto done;
        }
        if (received == 0) {
            break;
        }
        if (UINT64_MAX - total < (uint64_t)received ||
            swz_write_full(SWZ_AGENT_RESTORE_FD, buffer, (size_t)received) != 0 ||
            EVP_DigestUpdate(content, buffer, (size_t)received) != 1) {
            goto done;
        }
        total += (uint64_t)received;
    }
    if (total != bind->source_size ||
        EVP_DigestFinal_ex(content, actual, &actual_length) != 1 ||
        actual_length != 32U || memcmp(actual, expected_content, 32U) != 0) {
        goto done;
    }
    result = 0;
done:
    explicit_bzero(buffer, sizeof(buffer));
    explicit_bzero(actual, sizeof(actual));
    EVP_MD_CTX_free(content);
    return result;
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

static int append_json_string(char *output, size_t capacity, size_t *offset,
                              const unsigned char *value, size_t length)
{
    size_t index;

    if (output == NULL || offset == NULL || value == NULL || *offset >= capacity ||
        *offset + 1U >= capacity) {
        return -1;
    }
    output[(*offset)++] = '"';
    for (index = 0U; index < length; ++index) {
        unsigned char byte = value[index];

        if (byte == '"' || byte == '\\') {
            if (*offset + 2U >= capacity) {
                return -1;
            }
            output[(*offset)++] = '\\';
            output[(*offset)++] = (char)byte;
        } else if (byte == '\n' || byte == '\r') {
            if (*offset + 2U >= capacity) {
                return -1;
            }
            output[(*offset)++] = '\\';
            output[(*offset)++] = byte == '\n' ? 'n' : 'r';
        } else if (byte < 0x20U || byte >= 0x80U ||
                   *offset + 1U >= capacity) {
            return -1;
        } else {
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

static int store_tag(const unsigned char raw[32], char output[80])
{
    char hex[65];

    return raw != NULL && output != NULL &&
                   swz_hex(raw, 32U, hex, sizeof(hex)) == 0 &&
                   snprintf(output, 80U, "sha256:v1:%s", hex) > 0
               ? 0
               : -1;
}

static int observation_commitments(const struct final_record *final,
                                   char process[80], char restore[80],
                                   char cleanup[80], char stdout_capture[80],
                                   char stderr_capture[80])
{
    char process_json[256];
    char restore_json[512];
    char cleanup_json[256];
    char sink_ack[65];
    char source_sha[65];
    char cleanup_inventory[65];
    size_t process_length = 0U;
    size_t restore_length = 0U;
    size_t cleanup_length = 0U;

    if (final == NULL || swz_hex(final->sink_ack_digest, 32U, sink_ack,
                                 sizeof(sink_ack)) != 0 ||
        swz_hex(final->source_sha256, 32U, source_sha, sizeof(source_sha)) != 0 ||
        swz_hex(final->cleanup_inventory_digest, 32U, cleanup_inventory,
                sizeof(cleanup_inventory)) != 0 ||
        appendf(process_json, sizeof(process_json), &process_length,
                "{\"exit_status\":%u,\"worker_cgroup_empty\":%s,\"worker_pidfd_exited\":%s}",
                (unsigned int)final->exit_status,
                final->worker_cgroup_empty != 0U ? "true" : "false",
                final->worker_pidfd_exited != 0U ? "true" : "false") != 0 ||
        appendf(restore_json, sizeof(restore_json), &restore_length,
                "{\"restore_count\":%u,\"sink_ack_digest\":\"%s\",\"sink_bytes_accepted\":%llu,\"source_bytes_read\":%llu,\"source_eof\":%s,\"source_sha256\":\"%s\",\"target_readback_verified\":%s}",
                (unsigned int)final->restore_count, sink_ack,
                (unsigned long long)final->sink_bytes_accepted,
                (unsigned long long)final->source_bytes_read,
                final->source_eof != 0U ? "true" : "false", source_sha,
                final->target_readback_verified != 0U ? "true" : "false") != 0 ||
        appendf(cleanup_json, sizeof(cleanup_json), &cleanup_length,
                "{\"cleanup_inventory_digest\":\"%s\",\"cleanup_state\":%u,\"finality_serial\":%llu,\"owned_cleanup_complete\":%s}",
                cleanup_inventory, (unsigned int)final->cleanup_state,
                (unsigned long long)final->finality_serial,
                final->owned_cleanup_complete != 0U ? "true" : "false") != 0 ||
        swz_store_commitment("process-evidence",
                            (const unsigned char *)process_json, process_length,
                            process) != 0 ||
        swz_store_commitment("restore-evidence",
                            (const unsigned char *)restore_json, restore_length,
                            restore) != 0 ||
        swz_store_commitment("cleanup-evidence",
                            (const unsigned char *)cleanup_json, cleanup_length,
                            cleanup) != 0 ||
        swz_store_commitment("stdout-capture", final->stdout_capture,
                             final->stdout_length, stdout_capture) != 0 ||
        swz_store_commitment("stderr-capture", final->stderr_capture,
                             final->stderr_length, stderr_capture) != 0) {
        return -1;
    }
    explicit_bzero(process_json, sizeof(process_json));
    explicit_bzero(restore_json, sizeof(restore_json));
    explicit_bzero(cleanup_json, sizeof(cleanup_json));
    return 0;
}

static int make_result_document(const struct bind_record *bind,
                                const struct final_record *final,
                                char output[SWZ_MAX_RESULT_DOCUMENT_BYTES],
                                size_t *output_length)
{
    char tags[SWZ_BIND_COMMITMENTS][80];
    char process[80];
    char restore[80];
    char cleanup[80];
    char stdout_capture[80];
    char stderr_capture[80];
    size_t offset = 0U;
    size_t index;
    int success;

    if (bind == NULL || final == NULL || output == NULL || output_length == NULL ||
        final->context_generation != bind->context_generation ||
        memcmp(final->generation, bind->generation, 32U) != 0 ||
        memcmp(final->connection, bind->connection, 32U) != 0 ||
        memcmp(final->session, bind->session, 32U) != 0 ||
        strcmp(final->transition_id, bind->transition_id) != 0 ||
        observation_commitments(final, process, restore, cleanup, stdout_capture,
                                stderr_capture) != 0) {
        return -1;
    }
    for (index = 0U; index < SWZ_BIND_COMMITMENTS; ++index) {
        if (store_tag(bind->commitments[index], tags[index]) != 0) {
            return -1;
        }
    }
    success = final->source_eof != 0U && final->restore_stdin_eof != 0U &&
              final->worker_stdout_eof != 0U && final->worker_stderr_eof != 0U &&
              final->worker_pidfd_exited != 0U &&
              final->worker_cgroup_empty != 0U &&
              final->target_readback_verified != 0U &&
              final->owned_cleanup_complete != 0U && final->cleanup_state == 1U &&
              final->restore_count == 1U && final->exit_status == 0U &&
              final->result_code == 0U &&
              final->source_bytes_read == final->sink_bytes_accepted;
    if (appendf(output, SWZ_MAX_RESULT_DOCUMENT_BYTES, &offset,
                "{\"schema\":\"swz-recovery-result.v2\",\"classification\":\"%s\",\"stage\":\"RESTORE\",\"epoch_ref\":\"%s\",\"authority_ref\":\"%s\",\"barrier_utc\":\"%s\",\"ssh_endpoint_commitment\":\"%s\",\"epoch_commitment\":\"%s\",\"authority_commitment\":\"%s\",\"barrier_commitment\":\"%s\",\"runner_commitment\":\"%s\",\"bundle_commitment\":\"%s\",\"launcher_commitment\":\"%s\",\"agent_commitment\":\"%s\",\"image_commitment\":\"%s\",\"target_commitment\":\"%s\",\"isolation_commitment\":\"%s\",\"artifact_commitment\":\"%s\",\"artifact_stream_commitment\":\"%s\",\"transition_id\":\"%s\",\"pre_cas_ledger_digest\":\"%s\",\"transition_data_commitment\":\"%s\",\"consumed_record_commitment\":\"%s\",\"restore_begin_commitment\":\"%s\",\"process_commitment\":\"%s\",\"restore_commitment\":\"%s\",\"cleanup_commitment\":\"%s\",\"stdout_capture_commitment\":\"%s\",\"stderr_capture_commitment\":\"%s\",\"result_code\":%u,\"restore_count\":%u,\"exit_status\":%u,\"stdin_eof\":%s,\"stdout_eof\":%s,\"stderr_eof\":%s,\"trailing_unframed_bytes\":false,\"terminal_input_eof\":true,\"terminal_input_trailing_bytes\":false,\"cleanup_state\":\"%s\"}\n",
                success != 0 ? "SUCCESS" : "FAILURE", bind->epoch_ref,
                bind->authority_ref, bind->barrier_utc, tags[0], tags[1],
                tags[2], tags[3], tags[4], tags[5], tags[6], tags[7], tags[8],
                tags[9], tags[10], tags[11], tags[12], bind->transition_id,
                tags[13], tags[14], tags[15], tags[16], process, restore, cleanup,
                stdout_capture, stderr_capture, (unsigned int)final->result_code,
                (unsigned int)final->restore_count, (unsigned int)final->exit_status,
                final->restore_stdin_eof != 0U ? "true" : "false",
                final->worker_stdout_eof != 0U ? "true" : "false",
                final->worker_stderr_eof != 0U ? "true" : "false",
                final->cleanup_state == 1U ? "CLEAN" : "DIRTY") != 0) {
        return -1;
    }
    *output_length = offset;
    return 0;
}

static int copy_field(const unsigned char *payload, size_t length, size_t index,
                      char *output, size_t capacity, size_t expected_length)
{
    return output != NULL &&
                   swz_managed_payload_string_field(payload, length, index,
                                                    output, capacity) == 0 &&
                   strlen(output) == expected_length
               ? 0
               : -1;
}

static int copy_store_field(const unsigned char *payload, size_t length,
                            size_t index, char output[80])
{
    return copy_field(payload, length, index, output, 80U, 74U) == 0 &&
                   memcmp(output, "sha256:v1:", 10U) == 0 &&
                   parse_hex32(output + 10U, (unsigned char[32]){ 0 }) == 0
               ? 0
               : -1;
}

static int read_terminal_input_eof(void)
{
    unsigned char value;
    ssize_t received;

    do {
        received = read(STDIN_FILENO, &value, sizeof(value));
    } while (received < 0 && errno == EINTR);
    return received == 0 ? 0 : -1;
}

static int read_proceed_and_terminal_eof(const struct bind_record *bind,
                                         unsigned char proceed_hash[32],
                                         unsigned char proceed_commitment[32])
{
    unsigned char payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char raw[SWZ_FRAME_HEADER_BYTES + SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char actual_previous[32];
    unsigned char expected_pc[32];
    unsigned char transition_digest[32];
    char session_hex[80];
    char transition[80];
    char transition_commitment[80];
    char restore_hash[80];
    char pc_hex[80];
    char expected_hex[80];
    char expected_transition_commitment[80];
    size_t written;
    const unsigned char *parts[4];
    size_t lengths[4] = { 32U, SWZ_TRANSITION_ID_BYTES, 32U, 32U };
    struct swz_frame frame;

    memset(&frame, 0, sizeof(frame));
    if (swz_frame_read(STDIN_FILENO, &frame, payload, sizeof(payload)) != 0 ||
        frame.type != SWZ_PROCEED || frame.direction != 1U ||
        frame.sequence != 7U || memcmp(frame.n_local, bind->n_local, 32U) != 0 ||
        swz_managed_payload_predecessor(frame.payload, frame.payload_length,
                                        actual_previous) != 0 ||
        memcmp(actual_previous, bind->restore_begin_frame_hash, 32U) != 0 ||
        swz_frame_encode(&frame, raw, sizeof(raw), &written) != 0 ||
        swz_frame_hash(raw, written, proceed_hash) != 0 ||
        copy_field(payload, frame.payload_length, 4U, session_hex,
                   sizeof(session_hex), 64U) != 0 ||
        copy_field(payload, frame.payload_length, 5U, transition,
                   sizeof(transition), SWZ_TRANSITION_ID_BYTES) != 0 ||
        copy_store_field(payload, frame.payload_length, 6U,
                         transition_commitment) != 0 ||
        copy_field(payload, frame.payload_length, 7U, restore_hash,
                   sizeof(restore_hash), 64U) != 0 ||
        copy_field(payload, frame.payload_length, 8U, pc_hex,
                   sizeof(pc_hex), 64U) != 0 ||
        swz_hex(bind->session, 32U, expected_hex, sizeof(expected_hex)) != 0 ||
        swz_hex(bind->restore_begin_frame_hash, 32U,
                expected_transition_commitment,
                sizeof(expected_transition_commitment)) != 0 ||
        store_tag(bind->commitments[14], transition_commitment) != 0 ||
        parse_hex32(transition_commitment + 10U, transition_digest) != 0 ||
        parse_hex32(pc_hex, proceed_commitment) != 0) {
        return -1;
    }
    if (strcmp(session_hex, expected_hex) != 0 ||
        strcmp(transition, bind->transition_id) != 0 ||
        strcmp(restore_hash, expected_transition_commitment) != 0 ||
        swz_hex(bind->commitments[14], 32U, expected_hex,
                sizeof(expected_hex)) != 0) {
        return -1;
    }
    {
        char expected_store[80];

        if (store_tag(bind->commitments[14], expected_store) != 0 ||
            strcmp(transition_commitment, expected_store) != 0) {
            return -1;
        }
    }
    parts[0] = bind->session;
    parts[1] = (const unsigned char *)bind->transition_id;
    parts[2] = transition_digest;
    parts[3] = bind->restore_begin_frame_hash;
    if (swz_managed_hash("proceed.v1", parts, lengths, 4U, expected_pc) != 0 ||
        memcmp(expected_pc, proceed_commitment, 32U) != 0 ||
        read_terminal_input_eof() != 0) {
        return -1;
    }
    return 0;
}

static int parse_final(const unsigned char *payload, size_t length,
                       struct final_record *final)
{
    const unsigned char *cursor = payload;
    const unsigned char *end;
    unsigned char raw8[8];
    unsigned char raw4[4];
    unsigned char transition[SWZ_TRANSITION_ID_BYTES];
    unsigned char flags[8];
    size_t capture_length;
    size_t index;

    if (payload == NULL || final == NULL ||
        length > SWZ_RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES) {
        return -1;
    }
    end = payload + length;
    if (take_bytes(&cursor, end, final->bind_envelope_sha256, 32U) != 0 ||
        take_bytes(&cursor, end, raw8, sizeof(raw8)) != 0) {
        return -1;
    }
    final->context_generation = get_u64(raw8);
    if (final->context_generation == 0U ||
        take_bytes(&cursor, end, final->generation, 32U) != 0 ||
        take_bytes(&cursor, end, final->connection, 32U) != 0 ||
        take_bytes(&cursor, end, final->session, 32U) != 0 ||
        take_bytes(&cursor, end, transition, sizeof(transition)) != 0) {
        return -1;
    }
    memcpy(final->transition_id, transition, sizeof(transition));
    final->transition_id[sizeof(transition)] = '\0';
    if (valid_transition_id(final->transition_id) != 0 ||
        take_bytes(&cursor, end, raw8, sizeof(raw8)) != 0) {
        return -1;
    }
    final->finality_serial = get_u64(raw8);
    if (take_bytes(&cursor, end, raw8, sizeof(raw8)) != 0) {
        return -1;
    }
    final->source_bytes_read = get_u64(raw8);
    if (take_bytes(&cursor, end, raw8, sizeof(raw8)) != 0) {
        return -1;
    }
    final->sink_bytes_accepted = get_u64(raw8);
    if (take_bytes(&cursor, end, final->source_sha256, 32U) != 0 ||
        take_bytes(&cursor, end, final->sink_ack_digest, 32U) != 0 ||
        take_bytes(&cursor, end, raw4, sizeof(raw4)) != 0) {
        return -1;
    }
    final->restore_count = get_u32(raw4);
    if (take_bytes(&cursor, end, raw4, sizeof(raw4)) != 0) {
        return -1;
    }
    final->exit_status = get_u32(raw4);
    if (take_bytes(&cursor, end, raw4, sizeof(raw4)) != 0) {
        return -1;
    }
    final->result_code = get_u32(raw4);
    if (take_bytes(&cursor, end, flags, sizeof(flags)) != 0 ||
        take_bytes(&cursor, end, &final->cleanup_state, 1U) != 0) {
        return -1;
    }
    for (index = 0U; index < sizeof(flags); ++index) {
        if (flags[index] > 1U) {
            return -1;
        }
    }
    final->source_eof = flags[0];
    final->restore_stdin_eof = flags[1];
    final->worker_stdout_eof = flags[2];
    final->worker_stderr_eof = flags[3];
    final->worker_pidfd_exited = flags[4];
    final->worker_cgroup_empty = flags[5];
    final->target_readback_verified = flags[6];
    final->owned_cleanup_complete = flags[7];
    if (take_bytes(&cursor, end, raw4, sizeof(raw4)) != 0) {
        return -1;
    }
    capture_length = (size_t)get_u32(raw4);
    if (capture_length > sizeof(final->stdout_capture) ||
        take_bytes(&cursor, end, final->stdout_capture, capture_length) != 0 ||
        take_bytes(&cursor, end, raw4, sizeof(raw4)) != 0) {
        return -1;
    }
    final->stdout_length = capture_length;
    capture_length = (size_t)get_u32(raw4);
    if (capture_length > sizeof(final->stderr_capture) ||
        take_bytes(&cursor, end, final->stderr_capture, capture_length) != 0 ||
        take_bytes(&cursor, end, final->cleanup_inventory_digest, 32U) != 0 ||
        cursor != end) {
        return -1;
    }
    final->stderr_length = capture_length;
    return final->finality_serial != 0U && nonzero_raw32(final->source_sha256) &&
                   nonzero_raw32(final->sink_ack_digest) &&
                   nonzero_raw32(final->cleanup_inventory_digest)
               ? 0
               : -1;
}

static int write_native_result(const struct bind_record *bind,
                               const struct final_record *final,
                               const unsigned char proceed_frame_hash[32],
                               const unsigned char proceed_commitment[32])
{
    char document[SWZ_MAX_RESULT_DOCUMENT_BYTES];
    char previous_hex[65];
    char session_hex[65];
    char proceed_hex[65];
    char result_hex[65];
    char payload[SWZ_MAX_RESULT_PAYLOAD_BYTES];
    unsigned char result_commitment[32];
    const unsigned char *parts[4];
    size_t lengths[4];
    size_t document_length;
    size_t offset = 0U;
    struct swz_frame frame;

    if (make_result_document(bind, final, document, &document_length) != 0 ||
        swz_hex(proceed_frame_hash, 32U, previous_hex, sizeof(previous_hex)) != 0 ||
        swz_hex(bind->session, 32U, session_hex, sizeof(session_hex)) != 0 ||
        swz_hex(proceed_commitment, 32U, proceed_hex, sizeof(proceed_hex)) != 0) {
        return -1;
    }
    parts[0] = bind->session;
    parts[1] = (const unsigned char *)bind->transition_id;
    parts[2] = proceed_commitment;
    parts[3] = (const unsigned char *)document;
    lengths[0] = 32U;
    lengths[1] = strlen(bind->transition_id);
    lengths[2] = 32U;
    lengths[3] = document_length;
    if (swz_managed_hash("result.v1", parts, lengths, 4U,
                         result_commitment) != 0 ||
        swz_hex(result_commitment, 32U, result_hex, sizeof(result_hex)) != 0 ||
        appendf(payload, sizeof(payload), &offset,
                "[\"RESULT\",2,\"swz-managed.v1\",\"%s\",\"%s\",\"%s\",\"%s\",[\"store-json.v1\",\"swz-recovery-result.v2\",",
                previous_hex, session_hex, bind->transition_id, proceed_hex) != 0 ||
        append_json_string(payload, sizeof(payload), &offset,
                           (const unsigned char *)document, document_length) != 0 ||
        appendf(payload, sizeof(payload), &offset, "],\"%s\"]", result_hex) != 0) {
        return -1;
    }
    memset(&frame, 0, sizeof(frame));
    frame.direction = 2U;
    frame.type = SWZ_RESULT;
    frame.sequence = 8U;
    memcpy(frame.n_local, bind->n_local, sizeof(frame.n_local));
    frame.payload = (unsigned char *)payload;
    frame.payload_length = (uint32_t)offset;
    return swz_frame_write(STDOUT_FILENO, &frame);
}

int main(void)
{
    unsigned char bind_payload[SWZ_RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES];
    unsigned char bind_envelope_hash[32];
    unsigned char final_payload[SWZ_RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES];
    unsigned char final_envelope_hash[32];
    unsigned char expected_content[32];
    unsigned char expected_stream[32];
    unsigned char proceed_hash[32];
    unsigned char proceed_commitment[32];
    struct bind_record bind;
    struct final_record final;
    size_t bind_length;
    size_t final_length;
    size_t bind_payload_plus_final;
    int success;

    if (swz_confine_component("agent") != 0 ||
        read_context_envelope(SWZ_AGENT_RESULT_CONTEXT_FD,
                              SWZ_RESULT_CONTEXT_BIND_MAGIC,
                              SWZ_RESULT_CONTEXT_BIND_KIND,
                              SWZ_RESULT_CONTEXT_BIND_PAYLOAD_MAX_BYTES,
                              bind_payload, &bind_length, bind_envelope_hash) != 0 ||
        parse_bind(bind_payload, bind_length, &bind) != 0 ||
        validate_agent_descriptors(&bind) != 0 ||
        hash_source_once(&bind, expected_content, expected_stream) != 0 ||
        read_proceed_and_terminal_eof(&bind, proceed_hash,
                                      proceed_commitment) != 0 ||
        copy_source_after_barrier(&bind, expected_content) != 0) {
        return 126;
    }
    close(SWZ_AGENT_RESTORE_FD);
    if (read_context_envelope(SWZ_AGENT_RESULT_CONTEXT_FD,
                              SWZ_RESULT_CONTEXT_FINAL_MAGIC,
                              SWZ_RESULT_CONTEXT_FINAL_KIND,
                              SWZ_RESULT_CONTEXT_FINAL_PAYLOAD_MAX_BYTES,
                              final_payload, &final_length, final_envelope_hash) != 0 ||
        parse_final(final_payload, final_length, &final) != 0 ||
        memcmp(final.bind_envelope_sha256, bind_envelope_hash, 32U) != 0 ||
        final.context_generation != bind.context_generation ||
        memcmp(final.generation, bind.generation, 32U) != 0 ||
        memcmp(final.connection, bind.connection, 32U) != 0 ||
        memcmp(final.session, bind.session, 32U) != 0 ||
        strcmp(final.transition_id, bind.transition_id) != 0 ||
        read_context_eof() != 0 ||
        write_native_result(&bind, &final, proceed_hash,
                            proceed_commitment) != 0) {
        return 126;
    }
    bind_payload_plus_final = bind_length + final_length;
    if (bind_payload_plus_final > SWZ_RESULT_CONTEXT_COMBINED_PAYLOAD_MAX_BYTES) {
        return 126;
    }
    success = final.source_eof != 0U && final.restore_stdin_eof != 0U &&
              final.worker_stdout_eof != 0U && final.worker_stderr_eof != 0U &&
              final.worker_pidfd_exited != 0U &&
              final.worker_cgroup_empty != 0U &&
              final.target_readback_verified != 0U &&
              final.owned_cleanup_complete != 0U && final.cleanup_state == 1U &&
              final.restore_count == 1U && final.exit_status == 0U &&
              final.result_code == 0U &&
              final.source_bytes_read == final.sink_bytes_accepted;
    explicit_bzero(&bind, sizeof(bind));
    explicit_bzero(&final, sizeof(final));
    explicit_bzero(expected_content, sizeof(expected_content));
    explicit_bzero(expected_stream, sizeof(expected_stream));
    explicit_bzero(proceed_commitment, sizeof(proceed_commitment));
    explicit_bzero(final_envelope_hash, sizeof(final_envelope_hash));
    return success != 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
