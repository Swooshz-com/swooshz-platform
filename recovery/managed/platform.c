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
    unsigned char seed[SWZ_MAX_SEED_BYTES];
    off_t original;

    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size != (off_t)SWZ_MAX_SEED_BYTES) {
        return -1;
    }
    original = lseek(fd, 0, SEEK_CUR);
    if (original < 0 || lseek(fd, 0, SEEK_SET) < 0) {
        return -1;
    }
    if (swz_read_full(fd, seed, sizeof(seed)) != 0) {
        explicit_bzero(seed, sizeof(seed));
        (void)lseek(fd, original, SEEK_SET);
        return -1;
    }
    explicit_bzero(seed, sizeof(seed));
    return lseek(fd, original, SEEK_SET) < 0 ? -1 : 0;
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
    int fd;

    if (path == NULL || strlen(path) >= sizeof(address.sun_path)) {
        return -1;
    }
    fd = socket(AF_UNIX, type, 0);
    if (fd < 0 || swz_set_cloexec(fd) != 0) {
        close(fd);
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    (void)unlink(path);
    if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(path, mode) != 0 || listen(fd, 16) != 0) {
        close(fd);
        (void)unlink(path);
        return -1;
    }
    return fd;
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
        if (sscanf(line, "%*d %*[^)] ) %*c %ld", &parent) != 1 ||
            parent <= 0 || parent == pid) {
            return 0;
        }
        pid = (pid_t)parent;
    }
    return 0;
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

int swz_send_fd(int socket_fd, int fd)
{
    struct msghdr message;
    struct iovec vector;
    unsigned char byte = 0U;
    union {
        struct cmsghdr header;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    struct cmsghdr *header;

    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    vector.iov_base = &byte;
    vector.iov_len = sizeof(byte);
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    return sendmsg(socket_fd, &message, MSG_NOSIGNAL) == (ssize_t)sizeof(byte) ? 0 : -1;
}

int swz_recv_fd(int socket_fd)
{
    struct msghdr message;
    struct iovec vector;
    unsigned char byte;
    union {
        struct cmsghdr header;
        unsigned char bytes[CMSG_SPACE(sizeof(int))];
    } control;
    struct cmsghdr *header;
    int fd = -1;

    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    vector.iov_base = &byte;
    vector.iov_len = sizeof(byte);
    message.msg_iov = &vector;
    message.msg_iovlen = 1U;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    if (recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(byte) ||
        (message.msg_flags & MSG_CTRUNC) != 0) {
        return -1;
    }
    header = CMSG_FIRSTHDR(&message);
    if (header == NULL || header->cmsg_level != SOL_SOCKET ||
        header->cmsg_type != SCM_RIGHTS || header->cmsg_len != CMSG_LEN(sizeof(int))) {
        return -1;
    }
    memcpy(&fd, CMSG_DATA(header), sizeof(fd));
    return fd;
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

static void put_token(unsigned char *out, uint32_t value)
{
    memset(out, 0, 32U);
    out[28] = (unsigned char)(value >> 24);
    out[29] = (unsigned char)(value >> 16);
    out[30] = (unsigned char)(value >> 8);
    out[31] = (unsigned char)value;
}

int swz_registration_record(unsigned char out[SWZ_REGISTRATION_BYTES],
                            uint32_t generation, uint32_t connection,
                            uint32_t cookie, pid_t pid, int pidfd)
{
    if (out == NULL || pid <= 0 || pidfd < 0) {
        return -1;
    }
    memcpy(out, SWZ_REGISTRATION_MAGIC, 8U);
    put_token(out + 8U, generation);
    put_token(out + 40U, connection);
    put_token(out + 72U, cookie);
    return 0;
}

int swz_context_record(unsigned char out[SWZ_CONTEXT_BYTES], uint32_t session,
                       uint32_t generation, uint32_t connection,
                       uint32_t cookie)
{
    if (out == NULL) {
        return -1;
    }
    memcpy(out, SWZ_CONTEXT_MAGIC, 8U);
    put_token(out + 8U, session);
    put_token(out + 40U, generation);
    put_token(out + 72U, connection);
    put_token(out + 104U, cookie);
    return 0;
}
