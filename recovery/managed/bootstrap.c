#define _GNU_SOURCE

#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int random_raw32(unsigned char value[32])
{
    size_t offset = 0U;

    while (offset < 32U) {
        ssize_t received = getrandom(value + offset, 32U - offset, 0U);

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        offset += (size_t)received;
    }
    return 0;
}

static int receive_context(unsigned char context[SWZ_CONTEXT_BYTES])
{
    struct sockaddr_un address;
    struct msghdr message;
    struct iovec vector;
    int fd;
    ssize_t received;

    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, SWZ_SESSION_CONTROL_SOCKET_PATH,
           strlen(SWZ_SESSION_CONTROL_SOCKET_PATH) + 1U);
    if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    memset(&message, 0, sizeof(message));
    vector.iov_base = context;
    vector.iov_len = SWZ_CONTEXT_BYTES;
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    received = recvmsg(fd, &message, MSG_CMSG_CLOEXEC | MSG_TRUNC);
    close(fd);
    return received == (ssize_t)SWZ_CONTEXT_BYTES &&
           (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0 &&
           memcmp(context, SWZ_CONTEXT_MAGIC, 8U) == 0 &&
           memcmp(context + 8U, (const unsigned char[32]){ 0 }, 32U) != 0 &&
           memcmp(context + 40U, (const unsigned char[32]){ 0 }, 32U) != 0 &&
           memcmp(context + 72U, (const unsigned char[32]){ 0 }, 32U) != 0 &&
            memcmp(context + 104U, (const unsigned char[32]){ 0 }, 32U) != 0 ? 0 : -1;
}

static int descriptor_is_open(int fd)
{
    int result;

    errno = 0;
    result = fcntl(fd, F_GETFD);
    if (result >= 0) {
        return 1;
    }
    return errno == EBADF ? 0 : -1;
}

static int close_agent_unexpected(int fd)
{
    if (fd < 0 || fd == STDIN_FILENO || fd == STDOUT_FILENO ||
        fd == STDERR_FILENO || fd == SWZ_AGENT_SOURCE_FD ||
        fd == SWZ_AGENT_RESTORE_FD || fd == SWZ_AGENT_RESULT_CONTEXT_FD) {
        return 0;
    }
    return close(fd);
}

static int bootstrap_agent_descriptor_bundle(void)
{
    int received[3] = { -1, -1, -1 };
    int temporary[3] = { -1, -1, -1 };
    size_t index;
    int result = -1;

    if (swz_recv_agent_descriptor_bundle(SWZ_AGENT_BUNDLE_FD, received) != 0) {
        return -1;
    }
    for (index = 0U; index < 3U; ++index) {
        temporary[index] = fcntl(received[index], F_DUPFD_CLOEXEC, 16);
        if (temporary[index] < 0) {
            goto done;
        }
    }
    for (index = 0U; index < 3U; ++index) {
        close(received[index]);
        received[index] = -1;
    }
    for (index = 0U; index < 3U; ++index) {
        if (dup3(temporary[index], (int)(SWZ_AGENT_SOURCE_FD + index), 0) < 0) {
            goto done;
        }
    }
    for (index = 0U; index < 3U; ++index) {
        close(temporary[index]);
        temporary[index] = -1;
    }
    if (close(SWZ_AGENT_BUNDLE_FD) != 0 ||
        (close(3) != 0 && errno != EBADF)) {
        goto done;
    }
    for (index = 7U; index < 64U; ++index) {
        if (close_agent_unexpected((int)index) != 0 && errno != EBADF) {
            goto done;
        }
    }
    if (clearenv() != 0) {
        goto done;
    }
    execl(SWZ_AGENT_PATH, SWZ_AGENT_PATH, (char *)NULL);
    result = errno == ENOENT ? 127 : 126;
done:
    for (index = 0U; index < 3U; ++index) {
        if (received[index] >= 0) {
            close(received[index]);
        }
        if (temporary[index] >= 0) {
            close(temporary[index]);
        }
    }
    return result;
}

static int write_frame(uint8_t direction, uint16_t type, uint64_t sequence,
                       const unsigned char n_local[32],
                       const unsigned char previous_hash[32],
                       const char *payload, unsigned char hash[32])
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
        memcmp(actual_previous, previous_hash, sizeof(actual_previous)) != 0 ||
        swz_write_full(STDOUT_FILENO, raw, written) != 0 ||
        swz_frame_hash(raw, written, hash) != 0) {
        return -1;
    }
    return 0;
}

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

static int append_string(char *output, size_t capacity, size_t *offset,
                         const char *value)
{
    return appendf(output, capacity, offset, ",\"%s\"", value);
}

struct admission_material {
    char installation[65];
    char endpoint_template[65];
    char generation[65];
    char launch_base[65];
    char authority_context[65];
    char request_context[65];
    char actual_endpoint[65];
    char activation[65];
    char policy[65];
    char verity[65];
    char openssh[65];
    char host_public_key[65];
    char auth_account_config[65];
    char supervisor[65];
    char dispatcher[65];
    char bootstrap[65];
    char custodian[65];
    char broker[65];
    char agent[65];
    char build_qualification[65];
    char accepted_connection[65];
    char n_local_commitment[65];
    char challenge_commitment[65];
    char evidence_commitment[65];
    char runtime_record[1024];
};

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

static int parse_hex(const char *text, unsigned char *out, size_t length)
{
    size_t index;

    if (text == NULL || out == NULL || strlen(text) != length * 2U) {
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        int high = hex_value((unsigned char)text[index * 2U]);
        int low = hex_value((unsigned char)text[index * 2U + 1U]);

        if (high < 0 || low < 0) {
            return -1;
        }
        out[index] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static int copy_hex_field(const unsigned char *payload, size_t length,
                          size_t index, char out[65])
{
    return swz_managed_payload_string_field(payload, length, index, out, 65U) == 0 &&
           strlen(out) == 64U && parse_hex(out, (unsigned char[32]){ 0 }, 32U) == 0 ?
           0 : -1;
}

static void put_u64(unsigned char out[8], uint64_t value)
{
    size_t index;

    for (index = 0U; index < 8U; ++index) {
        out[7U - index] = (unsigned char)(value >> (index * 8U));
    }
}

static int managed_digest_hex(const char *domain, const unsigned char *const *parts,
                              const size_t *lengths, size_t count, char out[65])
{
    unsigned char digest[32];

    return swz_managed_hash(domain, parts, lengths, count, digest) == 0 &&
           swz_hex(digest, sizeof(digest), out, 65U) == 0 ? 0 : -1;
}

static int managed_file_hex(const char *domain, const char *path, char out[65])
{
    unsigned char digest[32];
    const unsigned char *parts[] = { digest };
    const size_t lengths[] = { sizeof(digest) };

    return swz_file_sha256(path, digest) == 0 &&
           managed_digest_hex(domain, parts, lengths, 1U, out) == 0 ? 0 : -1;
}

static int read_line(const char *path, char *out, size_t capacity)
{
    FILE *stream = NULL;
    size_t length;

    if (path == NULL || out == NULL || capacity < 2U ||
        (stream = fopen(path, "r")) == NULL || fgets(out, (int)capacity, stream) == NULL) {
        if (stream != NULL) {
            fclose(stream);
        }
        return -1;
    }
    fclose(stream);
    length = strlen(out);
    while (length != 0U && (out[length - 1U] == '\n' || out[length - 1U] == '\r')) {
        out[--length] = '\0';
    }
    return length == 0U ? -1 : 0;
}

static int read_boot_uuid(unsigned char raw[16], char text[37])
{
    if (read_line("/proc/sys/kernel/random/boot_id", text, 37U) != 0 ||
        strlen(text) != 36U || text[8] != '-' || text[13] != '-' ||
        text[18] != '-' || text[23] != '-' || text[36] != '\0') {
        return -1;
    }
    {
        char compact[33];
        size_t source;
        size_t target = 0U;

        for (source = 0U; source < 36U; ++source) {
            if (text[source] != '-') {
                compact[target++] = text[source];
            }
        }
        compact[target] = '\0';
        return parse_hex(compact, raw, 16U);
    }
}

static int stat_pair(const char *path, uint64_t *device, uint64_t *inode)
{
    struct stat info;

    if (path == NULL || device == NULL || inode == NULL || stat(path, &info) != 0) {
        return -1;
    }
    *device = (uint64_t)info.st_dev;
    *inode = (uint64_t)info.st_ino;
    return 0;
}

static int read_start_time(uint64_t *value)
{
    char line[4096];
    char *rest;
    char *save = NULL;
    char *token;
    unsigned int field = 3U;
    char *end;
    unsigned long long parsed;
    FILE *stream = fopen("/proc/self/stat", "r");

    if (value == NULL || stream == NULL || fgets(line, sizeof(line), stream) == NULL) {
        if (stream != NULL) {
            fclose(stream);
        }
        return -1;
    }
    fclose(stream);
    rest = strrchr(line, ')');
    if (rest == NULL || rest[1] != ' ') {
        return -1;
    }
    rest += 2;
    token = strtok_r(rest, " \t\n", &save);
    while (token != NULL && field <= 22U) {
        if (field == 22U) {
            errno = 0;
            parsed = strtoull(token, &end, 10);
            if (errno != 0 || end == token || *end != '\0') {
                return -1;
            }
            *value = (uint64_t)parsed;
            return 0;
        }
        ++field;
        token = strtok_r(NULL, " \t\n", &save);
    }
    return -1;
}

static int read_capability_mask(char out[32])
{
    char line[128];
    char *value;
    char *end;
    unsigned long long mask;
    FILE *stream = fopen("/proc/self/status", "r");

    if (stream == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        if (strncmp(line, "CapEff:", 7U) == 0) {
            value = line + 7U;
            while (*value == ' ' || *value == '\t') {
                ++value;
            }
            errno = 0;
            mask = strtoull(value, &end, 16);
            if (errno == 0 && end != value && (*end == '\n' || *end == '\0') &&
                snprintf(out, 32U, "%llu", mask) > 0) {
                fclose(stream);
                return 0;
            }
            break;
        }
    }
    fclose(stream);
    return -1;
}

static int read_selinux_enforcing(void)
{
    char value[2];
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t received;

    if (fd < 0) {
        return -1;
    }
    received = read(fd, value, sizeof(value));
    close(fd);
    return received == 1 && value[0] == '1' ? 0 : -1;
}

static int read_socket_cookie(uint64_t *value)
{
#ifdef SO_COOKIE
    socklen_t length = sizeof(*value);

    return value != NULL && getsockopt(STDIN_FILENO, SOL_SOCKET, SO_COOKIE,
                                       value, &length) == 0 &&
           length == sizeof(*value) ? 0 : -1;
#else
    (void)value;
    return -1;
#endif
}

static int make_fd_inventory(char out[256])
{
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    size_t offset = 0U;

    if (directory == NULL) {
        return -1;
    }
    while ((entry = readdir(directory)) != NULL) {
        char *end;
        unsigned long value;

        if (entry->d_name[0] == '.' ||
            (value = strtoul(entry->d_name, &end, 10), *end != '\0')) {
            continue;
        }
        if (appendf(out, 256U, &offset, "%s%lu", offset == 0U ? "" : ",",
                    value) != 0) {
            closedir(directory);
            return -1;
        }
    }
    closedir(directory);
    return offset == 0U ? -1 : 0;
}

static int find_compiled_policy(char out[PATH_MAX])
{
    const char directory_path[] = "/etc/selinux/targeted/policy";
    DIR *directory = opendir(directory_path);
    struct dirent *entry;
    unsigned long best = 0U;
    int found = 0;

    if (directory == NULL) {
        return -1;
    }
    while ((entry = readdir(directory)) != NULL) {
        char *end;
        unsigned long value;

        if (strncmp(entry->d_name, "policy.", 7U) != 0) {
            continue;
        }
        errno = 0;
        value = strtoul(entry->d_name + 7U, &end, 10);
        if (errno == 0 && end != entry->d_name + 7U && *end == '\0' &&
            (!found || value > best)) {
            best = value;
            found = 1;
        }
    }
    closedir(directory);
    if (!found || snprintf(out, PATH_MAX, "%s/policy.%lu", directory_path, best) < 0) {
        return -1;
    }
    return 0;
}

static int decimal_u64(uint64_t value, char out[32])
{
    int written = snprintf(out, 32U, "%" PRIu64, value);

    return written > 0 && (size_t)written < 32U ? 0 : -1;
}

static int make_runtime_record(char out[1024])
{
    char boot_id[37];
    char fd_inventory[256];
    char fd_commitment[65];
    char argv_commitment[65];
    char limits_commitment[65];
    char capability[32];
    char values[14][32];
    const unsigned char *parts[2];
    size_t lengths[2];
    struct statvfs root_info;
    struct rlimit limits;
    uint64_t device;
    uint64_t inode;
    uint64_t socket_cookie;
    uint64_t start_time;
    size_t index;
    size_t offset = 0U;

    if (read_boot_uuid((unsigned char[16]){ 0 }, boot_id) != 0 ||
        stat_pair("/run/swz/recovery-network.sock", &device, &inode) != 0 ||
        decimal_u64(device, values[0]) != 0 || decimal_u64(inode, values[1]) != 0 ||
        read_socket_cookie(&socket_cookie) != 0 ||
        decimal_u64(socket_cookie, values[2]) != 0) {
        return -1;
    }
    index = 3U;
    for (; index < 11U; ++index) {
        static const char *const names[] = { "user", "mnt", "pid", "net" };
        char path[PATH_MAX];
        size_t namespace_index = (index - 3U) / 2U;

        if (snprintf(path, sizeof(path), "/proc/self/ns/%s",
                     names[namespace_index]) < 0 ||
            stat_pair(path, &device, &inode) != 0 ||
            decimal_u64((index % 2U) == 1U ? inode : device, values[index]) != 0) {
            return -1;
        }
    }
    if (stat_pair("/sys/fs/cgroup", &device, &inode) != 0 ||
        decimal_u64(inode, values[11]) != 0 || read_start_time(&start_time) != 0 ||
        decimal_u64(start_time, values[12]) != 0 ||
        decimal_u64(start_time, values[13]) != 0 ||
        read_selinux_enforcing() != 0 || statvfs("/", &root_info) != 0 ||
        (root_info.f_flag & ST_RDONLY) == 0U ||
        read_capability_mask(capability) != 0 || make_fd_inventory(fd_inventory) != 0 ||
        getrlimit(RLIMIT_NOFILE, &limits) != 0) {
        return -1;
    }
    parts[0] = (const unsigned char *)fd_inventory;
    lengths[0] = strlen(fd_inventory);
    if (managed_digest_hex("fd-inventory.v1", parts, lengths, 1U, fd_commitment) != 0) {
        return -1;
    }
    parts[0] = (const unsigned char *)"swz-bootstrap";
    lengths[0] = strlen((const char *)parts[0]);
    if (managed_digest_hex("runtime-argv.v1", parts, lengths, 1U, argv_commitment) != 0) {
        return -1;
    }
    {
        unsigned char limit_bytes[16];

        put_u64(limit_bytes, (uint64_t)limits.rlim_cur);
        put_u64(limit_bytes + 8U, (uint64_t)limits.rlim_max);
        parts[0] = limit_bytes;
        lengths[0] = sizeof(limit_bytes);
        if (managed_digest_hex("runtime-limits.v1", parts, lengths, 1U,
                               limits_commitment) != 0) {
            return -1;
        }
    }
    if (appendf(out, 1024U, &offset, "[\"%s\"", boot_id) != 0) {
        return -1;
    }
    for (index = 0U; index < 14U; ++index) {
        if (append_string(out, 1024U, &offset, values[index]) != 0) {
            return -1;
        }
    }
    if (appendf(out, 1024U, &offset,
                ",true,true,0,\"%s\",true,\"%s\",\"%s\",\"%s\"]",
                capability, fd_commitment, argv_commitment, limits_commitment) != 0) {
        return -1;
    }
    return 0;
}

static int make_challenge(const char *activation, const char *connection,
                          const unsigned char n_remote[32],
                          const unsigned char boot_hash[32],
                          const char *accepted_boottime_ns, char output[4096])
{
    char remote[65];
    char boot[65];
    size_t offset = 0U;

    if (activation == NULL || connection == NULL || n_remote == NULL ||
        accepted_boottime_ns == NULL ||
        swz_hex(boot_hash, 32U, boot, sizeof(boot)) != 0 ||
        swz_hex(n_remote, 32U, remote, sizeof(remote)) != 0 ||
        strlen(activation) != 64U || strlen(connection) != 64U ||
        strlen(accepted_boottime_ns) == 0U ||
        appendf(output, 4096U, &offset,
                "[\"CHALLENGE\",2,\"swz-managed.v1\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]",
                boot, activation, connection, remote, boot,
                accepted_boottime_ns) != 0) {
        return -1;
    }
    return 0;
}

static int make_evidence(struct admission_material *material,
                         const unsigned char n_local[32],
                         const unsigned char challenge_hash[32],
                         char output[4096])
{
    const char *fields[] = {
        material->installation, material->endpoint_template,
        material->actual_endpoint, material->activation, material->generation,
        material->launch_base, material->policy, material->verity,
        material->openssh, material->host_public_key,
        material->auth_account_config, material->dispatcher, material->bootstrap,
        material->custodian, material->broker, material->agent,
        material->build_qualification, material->accepted_connection,
        material->n_local_commitment, material->authority_context,
        material->request_context, material->challenge_commitment,
    };
    char body[4096];
    char previous[65];
    unsigned char evidence_digest[32];
    const unsigned char *parts[3];
    size_t lengths[3];
    size_t body_offset = 0U;
    size_t output_offset = 0U;
    size_t index;

    if (swz_hex(challenge_hash, 32U, previous, sizeof(previous)) != 0 ||
        appendf(body, sizeof(body), &body_offset, "[\"%s\"", fields[0]) != 0) {
        return -1;
    }
    for (index = 1U; index < sizeof(fields) / sizeof(fields[0]); ++index) {
        if (append_string(body, sizeof(body), &body_offset, fields[index]) != 0) {
            return -1;
        }
    }
    if (appendf(body, sizeof(body), &body_offset, ",%s]", material->runtime_record) != 0) {
        return -1;
    }
    parts[0] = n_local;
    parts[1] = challenge_hash;
    parts[2] = (const unsigned char *)body;
    lengths[0] = 32U;
    lengths[1] = 32U;
    lengths[2] = body_offset;
    if (swz_managed_hash("evidence.v1", parts, lengths, 3U, evidence_digest) != 0 ||
        swz_hex(evidence_digest, sizeof(evidence_digest),
                material->evidence_commitment, 65U) != 0 ||
        appendf(output, 4096U, &output_offset,
                "[\"EVIDENCE\",2,\"swz-managed.v1\",\"%s\"", previous) != 0) {
        return -1;
    }
    for (index = 0U; index < sizeof(fields) / sizeof(fields[0]); ++index) {
        if (append_string(output, 4096U, &output_offset, fields[index]) != 0) {
            return -1;
        }
    }
    return appendf(output, 4096U, &output_offset, ",%s,\"%s\"]",
                   material->runtime_record, material->evidence_commitment);
}

static int prepare_material(const unsigned char context[SWZ_CONTEXT_BYTES],
                            const unsigned char n_local[32],
                            const unsigned char *boot_payload,
                            size_t boot_length,
                            struct admission_material *material)
{
    unsigned char installation[32];
    unsigned char endpoint_template[32];
    unsigned char generation[32];
    unsigned char actual_endpoint[32];
    unsigned char boot_uuid[16];
    unsigned char activation_random[32];
    unsigned char device_bytes[8];
    unsigned char inode_bytes[8];
    unsigned char source_digest[32];
    unsigned char compiled_digest[32];
    unsigned char labels_digest[32];
    unsigned char enforcing = 1U;
    unsigned char auth_digest[4][32];
    unsigned char serial_bytes[8];
    const unsigned char *parts[6];
    size_t lengths[6];
    char boot_id[37];
    char policy_path[PATH_MAX];
    uint64_t device;
    uint64_t inode;

    if (context == NULL || n_local == NULL || boot_payload == NULL ||
        material == NULL || copy_hex_field(boot_payload, boot_length, 7U,
                                           material->installation) != 0 ||
        copy_hex_field(boot_payload, boot_length, 8U,
                       material->endpoint_template) != 0 ||
        copy_hex_field(boot_payload, boot_length, 9U, material->generation) != 0 ||
        copy_hex_field(boot_payload, boot_length, 10U,
                       material->launch_base) != 0 ||
        copy_hex_field(boot_payload, boot_length, 11U,
                       material->authority_context) != 0 ||
        copy_hex_field(boot_payload, boot_length, 12U,
                       material->request_context) != 0 ||
        swz_hex(context + 72U, 32U, material->accepted_connection,
                sizeof(material->accepted_connection)) != 0 ||
        parse_hex(material->installation, installation, sizeof(installation)) != 0 ||
        parse_hex(material->endpoint_template, endpoint_template,
                  sizeof(endpoint_template)) != 0 ||
        parse_hex(material->generation, generation, sizeof(generation)) != 0 ||
        read_boot_uuid(boot_uuid, boot_id) != 0 ||
        stat_pair("/run/swz/recovery-network.sock", &device, &inode) != 0 ||
        swz_file_sha256("/etc/selinux/swz/swz-managed.cil", source_digest) != 0 ||
        find_compiled_policy(policy_path) != 0 ||
        swz_file_sha256(policy_path, compiled_digest) != 0 ||
        swz_file_sha256("/etc/selinux/swz/file_contexts", labels_digest) != 0 ||
        read_selinux_enforcing() != 0) {
        return -1;
    }
    put_u64(device_bytes, device);
    put_u64(inode_bytes, inode);
    parts[0] = endpoint_template;
    parts[1] = boot_uuid;
    parts[2] = device_bytes;
    parts[3] = inode_bytes;
    lengths[0] = sizeof(endpoint_template);
    lengths[1] = sizeof(boot_uuid);
    lengths[2] = sizeof(device_bytes);
    lengths[3] = sizeof(inode_bytes);
    if (managed_digest_hex("endpoint-actual.v1", parts, lengths, 4U,
                           material->actual_endpoint) != 0 ||
        parse_hex(material->actual_endpoint, actual_endpoint,
                  sizeof(actual_endpoint)) != 0 ||
        random_raw32(activation_random) != 0) {
        return -1;
    }
    parts[0] = installation;
    parts[1] = generation;
    parts[2] = actual_endpoint;
    parts[3] = boot_uuid;
    put_u64(serial_bytes, 1U);
    parts[4] = serial_bytes;
    parts[5] = activation_random;
    lengths[4] = sizeof(serial_bytes);
    lengths[5] = sizeof(activation_random);
    if (managed_digest_hex("activation.v1", parts, lengths, 6U,
                           material->activation) != 0 ||
        managed_digest_hex("policy.v1",
                           (const unsigned char *const[]){ source_digest,
                                                            compiled_digest,
                                                            labels_digest,
                                                            &enforcing },
                           (const size_t[]){ sizeof(source_digest),
                                             sizeof(compiled_digest),
                                             sizeof(labels_digest),
                                             sizeof(enforcing) },
                           4U, material->policy) != 0 ||
        managed_file_hex("verity.v1", "/proc/self/mountinfo",
                         material->verity) != 0 ||
        managed_file_hex("openssh-closure.v1", "/opt/swz/openssh/sbin/sshd",
                         material->openssh) != 0 ||
        managed_file_hex("host-public-key.v1",
                         "/etc/ssh/recovery_host_ed25519_key.pub",
                         material->host_public_key) != 0 ||
        managed_file_hex("component-supervisor.v1",
                         "/usr/local/libexec/swz-supervisor",
                         material->supervisor) != 0 ||
        managed_file_hex("component-dispatcher.v1",
                         "/usr/local/libexec/swz-dispatcher",
                         material->dispatcher) != 0 ||
        managed_file_hex("component-bootstrap.v1",
                         "/usr/local/libexec/swz-bootstrap",
                         material->bootstrap) != 0 ||
        managed_file_hex("component-custodian.v1",
                         "/usr/local/libexec/swz-custodian",
                         material->custodian) != 0 ||
        managed_file_hex("component-broker.v1", "/usr/local/libexec/swz-broker",
                         material->broker) != 0 ||
        managed_file_hex("component-agent.v1", "/usr/local/libexec/swz-agent",
                         material->agent) != 0 ||
        managed_file_hex("build-qualification.v1",
                         "/etc/ssh/recovery_sshd_config",
                         material->build_qualification) != 0 ||
        swz_file_sha256("/etc/passwd", auth_digest[0]) != 0 ||
        swz_file_sha256("/etc/group", auth_digest[1]) != 0 ||
        swz_file_sha256("/etc/ssh/recovery_authorized_keys", auth_digest[2]) != 0 ||
        swz_file_sha256(SWZ_SSHD_CONFIG_PATH, auth_digest[3]) != 0) {
        return -1;
    }
    parts[0] = auth_digest[0];
    parts[1] = auth_digest[1];
    parts[2] = auth_digest[2];
    parts[3] = auth_digest[3];
    lengths[0] = sizeof(auth_digest[0]);
    lengths[1] = sizeof(auth_digest[1]);
    lengths[2] = sizeof(auth_digest[2]);
    lengths[3] = sizeof(auth_digest[3]);
    if (managed_digest_hex("n-local.v1", (const unsigned char *const[]){ n_local },
                           (const size_t[]){ 32U }, 1U,
                           material->n_local_commitment) != 0 ||
        managed_digest_hex("auth-account-config.v1", parts, lengths, 4U,
                           material->auth_account_config) != 0 ||
        make_runtime_record(material->runtime_record) != 0) {
        return -1;
    }
    return 0;
}

static int read_expected_frame(struct swz_frame *frame,
                               unsigned char payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES],
                               unsigned char raw[SWZ_FRAME_HEADER_BYTES + SWZ_MAX_CONTROL_PAYLOAD_BYTES],
                               unsigned char frame_hash[32],
                               uint16_t type, uint8_t direction, uint64_t sequence,
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
        (n_local != NULL && memcmp(frame->n_local, n_local, 32U) != 0) ||
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

static int make_accepted(const struct admission_material *material,
                         const unsigned char n_local[32],
                         const unsigned char accept_frame_hash[32],
                         const unsigned char accept_commitment[32],
                         char output[4096],
                         unsigned char accepted_session[32],
                         unsigned char receipt_commitment[32])
{
    unsigned char parts[9][32];
    const unsigned char *hash_parts[9];
    size_t lengths[9];
    const unsigned char *receipt_parts[4];
    size_t receipt_lengths[4] = { 32U, 32U, 32U, 32U };
    char connection_hex[65];
    char activation_hex[65];
    char accept_hex[65];
    char session_hex[65];
    char receipt_hex[65];
    size_t offset = 0U;
    size_t index;

    if (material == NULL || n_local == NULL ||
        accept_frame_hash == NULL || accept_commitment == NULL ||
        output == NULL || accepted_session == NULL || receipt_commitment == NULL ||
        parse_hex(material->installation, parts[0], sizeof(parts[0])) != 0 ||
        parse_hex(material->actual_endpoint, parts[1], sizeof(parts[1])) != 0 ||
        parse_hex(material->activation, parts[2], sizeof(parts[2])) != 0 ||
        parse_hex(material->generation, parts[3], sizeof(parts[3])) != 0 ||
        parse_hex(material->accepted_connection, parts[4], sizeof(parts[4])) != 0 ||
        parse_hex(material->authority_context, parts[6], sizeof(parts[6])) != 0 ||
        parse_hex(material->evidence_commitment, parts[7], sizeof(parts[7])) != 0) {
        return -1;
    }
    memcpy(parts[5], n_local, sizeof(parts[5]));
    memcpy(parts[8], accept_commitment, sizeof(parts[8]));
    for (index = 0U; index < 9U; ++index) {
        hash_parts[index] = parts[index];
        lengths[index] = sizeof(parts[index]);
    }
    if (swz_managed_hash("accepted-session.v1", hash_parts, lengths, 9U,
                         accepted_session) != 0) {
        return -1;
    }
    receipt_parts[0] = accepted_session;
    receipt_parts[1] = accept_frame_hash;
    receipt_parts[2] = parts[4];
    receipt_parts[3] = parts[2];
    if (swz_managed_hash("accepted-receipt.v1", receipt_parts, receipt_lengths,
                         4U, receipt_commitment) != 0 ||
        swz_hex(parts[4], sizeof(parts[4]), connection_hex,
                sizeof(connection_hex)) != 0 ||
        swz_hex(parts[2], sizeof(parts[2]), activation_hex,
                sizeof(activation_hex)) != 0 ||
        swz_hex(accept_commitment, 32U, accept_hex, sizeof(accept_hex)) != 0 ||
        swz_hex(accepted_session, 32U, session_hex, sizeof(session_hex)) != 0 ||
        swz_hex(receipt_commitment, 32U, receipt_hex, sizeof(receipt_hex)) != 0 ||
        appendf(output, 4096U, &offset,
                "[\"ACCEPTED\",2,\"swz-managed.v1\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]",
                connection_hex, activation_hex, accept_hex, session_hex,
                receipt_hex) != 0) {
        return -1;
    }
    return 0;
}

static int exchange_admission(const unsigned char context[SWZ_CONTEXT_BYTES])
{
    unsigned char payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char raw[SWZ_FRAME_HEADER_BYTES + SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char n_remote[32];
    unsigned char n_local[32];
    unsigned char boot_hash[32];
    unsigned char challenge_hash[32];
    unsigned char evidence_hash[32];
    unsigned char accept_frame_hash[32];
    unsigned char accepted_frame_hash[32];
    unsigned char accepted_session[32];
    unsigned char receipt_commitment[32];
    unsigned char challenge_commitment[32];
    unsigned char accept_commitment[32];
    unsigned char connection[32];
    unsigned char activation[32];
    const unsigned char *parts[5];
    size_t lengths[5] = { 32U, 32U, 32U, 32U, 32U };
    struct swz_frame incoming;
    struct admission_material material;
    char challenge[4096];
    char evidence[4096];
    char accepted[4096];
    char boot_time[32];
    char field[65];
    char evidence_hash_hex[65];
    char accept_text[65];
    char accept_body[512];
    size_t accept_body_length;
    struct timespec time_value;

    if (read_expected_frame(&incoming, payload, raw, boot_hash, SWZ_BOOT, 1U,
                            0U, NULL,
                            (const unsigned char[32]){ 0 }) != 0) {
        return -1;
    }
    memcpy(n_local, incoming.n_local, sizeof(n_local));
    if (prepare_material(context, n_local, incoming.payload,
                         incoming.payload_length, &material) != 0 ||
        random_raw32(n_remote) != 0 || clock_gettime(CLOCK_BOOTTIME, &time_value) != 0 ||
        time_value.tv_sec < 0 ||
        (uint64_t)time_value.tv_sec > (UINT64_MAX - (uint64_t)time_value.tv_nsec) / 1000000000U ||
        decimal_u64((uint64_t)time_value.tv_sec * 1000000000U +
                    (uint64_t)time_value.tv_nsec, boot_time) != 0 ||
        parse_hex(material.accepted_connection, connection, sizeof(connection)) != 0 ||
        parse_hex(material.activation, activation, sizeof(activation)) != 0) {
        return -1;
    }
    parts[0] = boot_hash;
    parts[1] = connection;
    parts[2] = activation;
    parts[3] = n_local;
    parts[4] = n_remote;
    if (swz_managed_hash("challenge.v1", parts, lengths, 5U,
                         challenge_commitment) != 0 ||
        swz_hex(challenge_commitment, sizeof(challenge_commitment),
                material.challenge_commitment,
                sizeof(material.challenge_commitment)) != 0 ||
        make_challenge(material.activation, material.accepted_connection, n_remote,
                       boot_hash, boot_time, challenge) != 0 ||
        write_frame(2U, SWZ_CHALLENGE, 1U, n_local, boot_hash, challenge,
                    challenge_hash) != 0 ||
        make_evidence(&material, n_local, challenge_hash, evidence) != 0 ||
        write_frame(2U, SWZ_EVIDENCE, 2U, n_local, challenge_hash, evidence,
                    evidence_hash) != 0 ||
        read_expected_frame(&incoming, payload, raw, accept_frame_hash, SWZ_ACCEPT,
                            1U, 3U, n_local, evidence_hash) != 0 ||
        swz_managed_payload_string_field(incoming.payload, incoming.payload_length,
                                         4U, field, sizeof(field)) != 0 ||
        strcmp(field, material.accepted_connection) != 0 ||
        swz_managed_payload_string_field(incoming.payload, incoming.payload_length,
                                         5U, field, sizeof(field)) != 0 ||
        strcmp(field, material.generation) != 0 ||
        swz_managed_payload_string_field(incoming.payload, incoming.payload_length,
                                         6U, field, sizeof(field)) != 0 ||
        strcmp(field, material.authority_context) != 0 ||
        swz_managed_payload_string_field(incoming.payload, incoming.payload_length,
                                         7U, field, sizeof(field)) != 0 ||
        strcmp(field, material.evidence_commitment) != 0 ||
        swz_managed_payload_string_field(incoming.payload, incoming.payload_length,
                                         8U, field, sizeof(field)) != 0 ||
        swz_hex(evidence_hash, sizeof(evidence_hash), evidence_hash_hex,
                sizeof(evidence_hash_hex)) != 0 ||
        strcmp(field, evidence_hash_hex) != 0) {
        return -1;
    }
    if (swz_managed_payload_string_field(incoming.payload, incoming.payload_length,
                                         9U, accept_text, sizeof(accept_text)) != 0 ||
        strlen(accept_text) != 64U || parse_hex(accept_text, accept_commitment,
                                                 sizeof(accept_commitment)) != 0) {
        return -1;
    }
    accept_body_length = 0U;
    if (appendf(accept_body, sizeof(accept_body), &accept_body_length,
                "[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]",
                material.accepted_connection, material.generation,
                material.authority_context, material.evidence_commitment,
                evidence_hash_hex) != 0) {
        return -1;
    }
    parts[0] = n_local;
    parts[1] = (const unsigned char *)accept_body;
    if (swz_managed_hash("accept.v1",
                         (const unsigned char *const[]){ parts[0], parts[1] },
                         (const size_t[]){ 32U, accept_body_length }, 2U,
                         accept_commitment) != 0 ||
        swz_hex(accept_commitment, sizeof(accept_commitment), field,
                sizeof(field)) != 0 || strcmp(field, accept_text) != 0 ||
        make_accepted(&material, n_local, accept_frame_hash,
                      accept_commitment, accepted, accepted_session,
                      receipt_commitment) != 0 ||
        strlen(accepted) > SWZ_MAX_CONTROL_PAYLOAD_BYTES ||
        write_frame(2U, SWZ_ACCEPTED, 4U, n_local, accept_frame_hash, accepted,
                    accepted_frame_hash) != 0 ||
        swz_write_full(SWZ_TRANSCRIPT_FD, context, SWZ_CONTEXT_BYTES) != 0 ||
        swz_write_full(SWZ_TRANSCRIPT_FD, n_local, sizeof(n_local)) != 0 ||
        swz_write_full(SWZ_TRANSCRIPT_FD, accepted_frame_hash,
                       sizeof(accepted_frame_hash)) != 0 ||
        swz_write_full(SWZ_TRANSCRIPT_FD, accepted_session,
                       sizeof(accepted_session)) != 0 ||
        swz_write_full(SWZ_TRANSCRIPT_FD, activation, sizeof(activation)) != 0 ||
        lseek(SWZ_TRANSCRIPT_FD, 0, SEEK_SET) < 0) {
        return -1;
    }
    return 0;
}

int main(void)
{
    unsigned char context[SWZ_CONTEXT_BYTES];
    int bundle_open;

    if (swz_confine_component("bootstrap") != 0) {
        return 126;
    }
    bundle_open = descriptor_is_open(SWZ_AGENT_BUNDLE_FD);
    if (bundle_open < 0) {
        return 126;
    }
    if (bundle_open != 0) {
        return bootstrap_agent_descriptor_bundle();
    }
    if (receive_context(context) != 0 || exchange_admission(context) != 0) {
        return 126;
    }
    execl(SWZ_BROKER_PATH, SWZ_BROKER_PATH, (char *)NULL);
    return errno == ENOENT ? 127 : 126;
}
