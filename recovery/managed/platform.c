#define _GNU_SOURCE

#include "platform.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static int digest_update_lp(EVP_MD_CTX *ctx, const unsigned char *bytes,
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
    if (EVP_DigestUpdate(ctx, prefix, sizeof(prefix)) != 1) {
        return -1;
    }
    if (length != 0U && EVP_DigestUpdate(ctx, bytes, length) != 1) {
        return -1;
    }
    return 0;
}

int swz_write_full(int fd, const void *buf, size_t len)
{
    const unsigned char *cursor = buf;
    size_t remaining = len;

    while (remaining != 0U) {
        ssize_t written = write(fd, cursor, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        cursor += (size_t)written;
        remaining -= (size_t)written;
    }
    return 0;
}

int swz_read_full(int fd, void *buf, size_t len)
{
    unsigned char *cursor = buf;
    size_t remaining = len;

    while (remaining != 0U) {
        ssize_t received = read(fd, cursor, remaining);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return -1;
        }
        cursor += (size_t)received;
        remaining -= (size_t)received;
    }
    return 0;
}

int swz_read_bounded(int fd, void *buf, size_t capacity, size_t *length)
{
    ssize_t received;

    if (buf == NULL || length == NULL || capacity == 0U) {
        return -1;
    }
    do {
        received = read(fd, buf, capacity);
    } while (received < 0 && errno == EINTR);
    if (received < 0) {
        return -1;
    }
    *length = (size_t)received;
    return 0;
}

int swz_sha256(const void *data, size_t len, unsigned char out[32])
{
    EVP_MD_CTX *ctx;
    unsigned int output_length = 0U;
    int result;

    if (data == NULL || out == NULL) {
        return -1;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    result = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, data, len) == 1 &&
             EVP_DigestFinal_ex(ctx, out, &output_length) == 1 &&
             output_length == 32U ? 0 : -1;
    EVP_MD_CTX_free(ctx);
    return result;
}

int swz_file_sha256(const char *path, unsigned char out[32])
{
    EVP_MD_CTX *ctx = NULL;
    unsigned char buffer[65536];
    unsigned int output_length = 0U;
    int fd = -1;
    int result = -1;

    if (path == NULL || out == NULL || (fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0) {
        return -1;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        goto done;
    }
    for (;;) {
        ssize_t received = read(fd, buffer, sizeof(buffer));

        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received < 0 || (received != 0 &&
                             EVP_DigestUpdate(ctx, buffer, (size_t)received) != 1)) {
            goto done;
        }
        if (received == 0) {
            break;
        }
    }
    if (EVP_DigestFinal_ex(ctx, out, &output_length) == 1 && output_length == 32U) {
        result = 0;
    }
done:
    explicit_bzero(buffer, sizeof(buffer));
    EVP_MD_CTX_free(ctx);
    close(fd);
    return result;
}

int swz_managed_hash(const char *domain, const unsigned char *const *parts,
                     const size_t *lengths, size_t count,
                     unsigned char out[32])
{
    static const unsigned char prefix[] = "swz-managed.v1";
    EVP_MD_CTX *ctx;
    unsigned int output_length = 0U;
    size_t index;
    int result = -1;

    if (domain == NULL || parts == NULL || lengths == NULL || out == NULL) {
        return -1;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        digest_update_lp(ctx, prefix, sizeof(prefix) - 1U) != 0 ||
        digest_update_lp(ctx, (const unsigned char *)domain, strlen(domain)) != 0) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    for (index = 0U; index < count; ++index) {
        if (parts[index] == NULL && lengths[index] != 0U) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        if (digest_update_lp(ctx, parts[index], lengths[index]) != 0) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
    }
    if (EVP_DigestFinal_ex(ctx, out, &output_length) == 1 &&
        output_length == 32U) {
        result = 0;
    }
    EVP_MD_CTX_free(ctx);
    return result;
}

int swz_hex(const unsigned char *bytes, size_t length, char *out,
            size_t capacity)
{
    static const char digits[] = "0123456789abcdef";
    size_t index;

    if (bytes == NULL || out == NULL || capacity < (length * 2U) + 1U) {
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        out[index * 2U] = digits[bytes[index] >> 4];
        out[index * 2U + 1U] = digits[bytes[index] & 0x0fU];
    }
    out[length * 2U] = '\0';
    return 0;
}

int swz_store_commitment(const char *domain, const unsigned char *bytes,
                         size_t length, char out[80])
{
    static const unsigned char prefix[] = "recovery-commitment.v1";
    EVP_MD_CTX *ctx;
    unsigned char digest[32];
    char hex[65];
    unsigned int digest_length = 0U;

    if (domain == NULL || bytes == NULL || out == NULL) {
        return -1;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        digest_update_lp(ctx, prefix, sizeof(prefix) - 1U) != 0 ||
        digest_update_lp(ctx, (const unsigned char *)domain, strlen(domain)) != 0 ||
        digest_update_lp(ctx, bytes, length) != 0 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
        digest_length != 32U || swz_hex(digest, sizeof(digest), hex, sizeof(hex)) != 0) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);
    if (snprintf(out, 80U, "sha256:v1:%s", hex) < 0) {
        return -1;
    }
    return 0;
}

int swz_parse_ipv4(const char *text, unsigned char out[4])
{
    struct in_addr address;

    if (text == NULL || out == NULL || inet_pton(AF_INET, text, &address) != 1) {
        return -1;
    }
    memcpy(out, &address, 4U);
    return 0;
}

int swz_validate_seed_fd(int fd)
{
    struct stat info;

    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size != (off_t)SWZ_MAX_SEED_BYTES || info.st_uid != 0U ||
        (info.st_mode & 0777U) != 0400U) {
        return -1;
    }
    return 0;
}

int swz_read_seed_exact(int fd, unsigned char seed[SWZ_MAX_SEED_BYTES])
{
    unsigned char extra;

    if (seed == NULL || swz_validate_seed_fd(fd) != 0 ||
        lseek(fd, 0, SEEK_SET) < 0 || swz_read_full(fd, seed, SWZ_MAX_SEED_BYTES) != 0) {
        if (seed != NULL) {
            explicit_bzero(seed, SWZ_MAX_SEED_BYTES);
        }
        return -1;
    }
    if (read(fd, &extra, sizeof(extra)) != 0) {
        explicit_bzero(seed, SWZ_MAX_SEED_BYTES);
        return -1;
    }
    return 0;
}

int swz_disable_dump_core(void)
{
    struct rlimit limits;

    limits.rlim_cur = 0U;
    limits.rlim_max = 0U;
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 ||
        setrlimit(RLIMIT_CORE, &limits) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }
    return 0;
}

int swz_set_cloexec(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        return -1;
    }
    return 0;
}

int swz_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    return 0;
}

int swz_make_unix_listener(const char *path, int type, mode_t mode)
{
    struct sockaddr_un address;
    struct stat existing;
    int fd;

    if (path == NULL || strlen(path) >= sizeof(address.sun_path)) {
        return -1;
    }
    if (lstat(path, &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode) || unlink(path) != 0) {
            return -1;
        }
    } else if (errno != ENOENT) {
        return -1;
    }
    fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
    if (fd < 0 || swz_set_cloexec(fd) != 0) {
        close(fd);
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(path, mode) != 0 || listen(fd, 16) != 0) {
        close(fd);
        (void)swz_remove_unix_socket(path);
        return -1;
    }
    return fd;
}

int swz_remove_unix_socket(const char *path)
{
    struct stat info;

    if (path == NULL || lstat(path, &info) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISSOCK(info.st_mode)) {
        return -1;
    }
    return unlink(path);
}

int swz_peer_uidgid(int fd, uid_t *uid, gid_t *gid)
{
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    if (uid == NULL || gid == NULL ||
        getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials)) {
        return -1;
    }
    *uid = credentials.uid;
    *gid = credentials.gid;
    return 0;
}

int swz_peer_pid(int fd, pid_t *pid)
{
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    if (pid == NULL || getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials,
                                  &length) != 0 || length != sizeof(credentials) ||
        credentials.pid <= 0) {
        return -1;
    }
    *pid = credentials.pid;
    return 0;
}

int swz_peer_domain_is(int fd, const char *expected_domain)
{
#ifdef SO_PEERSEC
    char domain[128];
    socklen_t length = sizeof(domain);
    const char *type_start;
    const char *type_end;
    size_t expected_length;

    if (expected_domain == NULL ||
        getsockopt(fd, SOL_SOCKET, SO_PEERSEC, domain, &length) != 0 ||
        length == 0U || length > sizeof(domain)) {
        return -1;
    }
    if (domain[length - 1U] == '\0') {
        --length;
    }
    if (length == 0U || length >= sizeof(domain)) {
        return -1;
    }
    domain[length] = '\0';
    expected_length = strlen(expected_domain);
    type_start = domain;
    type_end = domain + length;
    {
        const char *separator = strchr(type_start, ':');

        if (separator != NULL) {
            separator = strchr(separator + 1, ':');
            if (separator == NULL || separator + 1 >= type_end) {
                return -1;
            }
            type_start = separator + 1;
            type_end = strchr(type_start, ':');
            if (type_end == NULL) {
                type_end = domain + length;
            }
        }
    }
    return expected_length == (size_t)(type_end - type_start) &&
           memcmp(type_start, expected_domain, expected_length) == 0 ? 0 : -1;
#else
    (void)fd;
    (void)expected_domain;
    return -1;
#endif
}

int swz_same_socket_peer(int fd, pid_t expected_pid)
{
    struct ucred credentials;
    socklen_t length = sizeof(credentials);

    return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0 &&
           credentials.pid == expected_pid;
}

int swz_process_is_descendant(pid_t pid, pid_t ancestor)
{
    char path[64];
    char line[512];
    char *closing_parenthesis;
    FILE *stream;
    long parent;

    if (pid <= 0 || ancestor <= 0) {
        return 0;
    }
    while (pid > 1) {
        if (pid == ancestor) {
            return 1;
        }
        if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) < 0) {
            return 0;
        }
        stream = fopen(path, "r");
        if (stream == NULL || fgets(line, sizeof(line), stream) == NULL) {
            if (stream != NULL) {
                fclose(stream);
            }
            return 0;
        }
        fclose(stream);
        closing_parenthesis = strrchr(line, ')');
        if (closing_parenthesis == NULL ||
            sscanf(closing_parenthesis + 2, "%*c %ld", &parent) != 1 ||
            parent <= 0 || parent == pid) {
            return 0;
        }
        pid = (pid_t)parent;
    }
    return 0;
}

static int namespace_link_matches(pid_t first, pid_t second, const char *name)
{
    char first_path[96];
    char second_path[96];
    char first_link[128];
    char second_link[128];
    ssize_t first_length;
    ssize_t second_length;

    if (name == NULL ||
        snprintf(first_path, sizeof(first_path), "/proc/%ld/ns/%s",
                 (long)first, name) < 0 ||
        snprintf(second_path, sizeof(second_path), "/proc/%ld/ns/%s",
                 (long)second, name) < 0) {
        return 0;
    }
    first_length = readlink(first_path, first_link, sizeof(first_link) - 1U);
    second_length = readlink(second_path, second_link, sizeof(second_link) - 1U);
    if (first_length <= 0 || second_length <= 0 ||
        first_length >= (ssize_t)sizeof(first_link) ||
        second_length >= (ssize_t)sizeof(second_link)) {
        return 0;
    }
    first_link[first_length] = '\0';
    second_link[second_length] = '\0';
    return first_length == second_length &&
           memcmp(first_link, second_link, (size_t)first_length) == 0;
}

int swz_process_namespaces_match(pid_t first, pid_t second)
{
    static const char *const namespaces[] = { "user", "mnt", "pid", "net" };
    size_t index;

    if (first <= 0 || second <= 0) {
        return 0;
    }
    for (index = 0U; index < sizeof(namespaces) / sizeof(namespaces[0]); ++index) {
        if (!namespace_link_matches(first, second, namespaces[index])) {
            return 0;
        }
    }
    return 1;
}

int swz_pidfd_open(pid_t pid)
{
#ifdef SYS_pidfd_open
    return (int)syscall(SYS_pidfd_open, pid, 0U);
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

int swz_pidfd_alive(int pidfd)
{
    struct pollfd descriptor;
    int result;

    descriptor.fd = pidfd;
    descriptor.events = POLLIN | POLLHUP | POLLERR;
    descriptor.revents = 0;
    result = poll(&descriptor, 1U, 0);
    if (result < 0 && errno == EINTR) {
        return 1;
    }
    return result == 0 || (result > 0 &&
                           (descriptor.revents & (POLLIN | POLLHUP | POLLERR)) == 0);
}

int swz_pidfd_get_pid(int pidfd, pid_t *pid)
{
    char path[64];
    char line[128];
    FILE *stream;
    long value;

    if (pid == NULL || pidfd < 0 ||
        snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd) < 0) {
        return -1;
    }
    stream = fopen(path, "r");
    if (stream == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        if (sscanf(line, "Pid: %ld", &value) == 1 && value > 0 &&
            value <= (long)INT32_MAX) {
            fclose(stream);
            *pid = (pid_t)value;
            return 0;
        }
    }
    fclose(stream);
    return -1;
}

int swz_send_record_fd(int socket_fd, const void *record, size_t length, int fd)
{
    struct msghdr message;
    struct iovec vector;
    union {
        struct cmsghdr header;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    struct cmsghdr *header;

    if (record == NULL || length == 0U || fd < 0) {
        return -1;
    }
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    vector.iov_base = (void *)record;
    vector.iov_len = length;
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    header = CMSG_FIRSTHDR(&message);
    if (header == NULL) {
        return -1;
    }
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    return sendmsg(socket_fd, &message, MSG_NOSIGNAL) == (ssize_t)length ? 0 : -1;
}

int swz_recv_record_fd(int socket_fd, void *record, size_t length, int *fd)
{
    struct msghdr message;
    struct iovec vector;
    union {
        struct cmsghdr header;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    struct cmsghdr *header;
    int received_fd = -1;
    size_t rights_count = 0U;

    if (record == NULL || length == 0U || fd == NULL) {
        return -1;
    }
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    vector.iov_base = record;
    vector.iov_len = length;
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    if (recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC) != (ssize_t)length ||
        (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
        return -1;
    }
    for (header = CMSG_FIRSTHDR(&message); header != NULL;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len != CMSG_LEN(sizeof(int))) {
            close(received_fd);
            return -1;
        }
        ++rights_count;
        memcpy(&received_fd, CMSG_DATA(header), sizeof(received_fd));
    }
    if (rights_count != 1U || received_fd < 0) {
        close(received_fd);
        return -1;
    }
    *fd = received_fd;
    return 0;
}

int swz_send_fd(int socket_fd, int fd)
{
    const unsigned char marker = 0U;

    return swz_send_record_fd(socket_fd, &marker, sizeof(marker), fd);
}

int swz_recv_fd(int socket_fd)
{
    unsigned char marker;
    int fd = -1;

    return swz_recv_record_fd(socket_fd, &marker, sizeof(marker), &fd) == 0 ? fd : -1;
}

int swz_confine_component(const char *component)
{
    struct rlimit limits;

    if (component == NULL || component[0] == '\0' ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }
    limits.rlim_cur = 64U;
    limits.rlim_max = 64U;
    if (setrlimit(RLIMIT_NOFILE, &limits) != 0) {
        return -1;
    }
    return 0;
}

int swz_write_record(int fd, const void *record, size_t length)
{
    return record == NULL || length == 0U ? -1 : swz_write_full(fd, record, length);
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

int swz_registration_record(unsigned char out[SWZ_REGISTRATION_BYTES],
                            const unsigned char generation[32],
                            const unsigned char connection[32],
                            const unsigned char cookie[32])
{
    if (out == NULL || generation == NULL || connection == NULL || cookie == NULL ||
        !nonzero_raw32(generation) || !nonzero_raw32(connection) ||
        !nonzero_raw32(cookie)) {
        return -1;
    }
    memcpy(out, SWZ_REGISTRATION_MAGIC, 8U);
    memcpy(out + 8U, generation, 32U);
    memcpy(out + 40U, connection, 32U);
    memcpy(out + 72U, cookie, 32U);
    return 0;
}

int swz_context_record(unsigned char out[SWZ_CONTEXT_BYTES],
                       const unsigned char session[32],
                       const unsigned char generation[32],
                       const unsigned char connection[32],
                       const unsigned char cookie[32])
{
    if (out == NULL || session == NULL || generation == NULL ||
        connection == NULL || cookie == NULL || !nonzero_raw32(session) ||
        !nonzero_raw32(generation) || !nonzero_raw32(connection) ||
        !nonzero_raw32(cookie)) {
        return -1;
    }
    memcpy(out, SWZ_CONTEXT_MAGIC, 8U);
    memcpy(out + 8U, session, 32U);
    memcpy(out + 40U, generation, 32U);
    memcpy(out + 72U, connection, 32U);
    memcpy(out + 104U, cookie, 32U);
    return 0;
}
