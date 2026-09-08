#define _GNU_SOURCE

#include "platform.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SWZ_AGENT_REQUEST 11U
#define SWZ_AGENT_REQUEST_SIGN 13U
#define SWZ_AGENT_RESPONSE_IDENTITIES 12U
#define SWZ_AGENT_RESPONSE 14U
#define SWZ_AGENT_MAX_REQUEST 4096U

static uint32_t read_u32(const unsigned char *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static void write_u32(unsigned char *bytes, uint32_t value)
{
    bytes[0] = (unsigned char)(value >> 24);
    bytes[1] = (unsigned char)(value >> 16);
    bytes[2] = (unsigned char)(value >> 8);
    bytes[3] = (unsigned char)value;
}

static int read_public_pin(const unsigned char expected[32])
{
    char algorithm[32];
    char encoded[128];
    unsigned char blob[96];
    unsigned char decoded[64];
    FILE *stream;
    int decoded_length;
    size_t encoded_length;

    stream = fopen(SWZ_HOST_PUBLIC_KEY_PATH, "r");
    if (stream == NULL || fscanf(stream, "%31s %127s", algorithm, encoded) != 2) {
        if (stream != NULL) {
            fclose(stream);
        }
        return -1;
    }
    fclose(stream);
    if (strcmp(algorithm, "ssh-ed25519") != 0) {
        return -1;
    }
    encoded_length = strlen(encoded);
    if (encoded_length > 88U) {
        return -1;
    }
    decoded_length = EVP_DecodeBlock(decoded, (const unsigned char *)encoded,
                                     (int)encoded_length);
    if (decoded_length < 4 + 11 + 4 + 32 ||
        memcmp(decoded, "\0\0\0\013ssh-ed25519\0\0\0\040", 19U) != 0 ||
        memcmp(decoded + 19U, expected, 32U) != 0) {
        explicit_bzero(blob, sizeof(blob));
        explicit_bzero(decoded, sizeof(decoded));
        return -1;
    }
    memcpy(blob, decoded, (size_t)decoded_length);
    explicit_bzero(blob, sizeof(blob));
    explicit_bzero(decoded, sizeof(decoded));
    return 0;
}

static int send_rejection(int fd)
{
    static const unsigned char rejection[] = { 5U, 0U, 0U, 0U, 0U };
    return swz_write_full(fd, rejection, sizeof(rejection));
}

static int write_lifecycle_marker(int fd, int retiring)
{
    static const unsigned char disable_magic[] = "SWZDIS01";
    static const unsigned char retire_magic[] = "SWZRET01";

    return swz_write_full(fd, retiring ? retire_magic : disable_magic, 8U);
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

static int acknowledge_registration(int fd, unsigned char registration[SWZ_REGISTRATION_BYTES],
                                    pid_t *registered_pid, int *retained_pidfd)
{
    int pidfd = -1;
    pid_t pid;

    if (registration == NULL || registered_pid == NULL || retained_pidfd == NULL ||
        swz_recv_record_fd(fd, registration, SWZ_REGISTRATION_BYTES, &pidfd) != 0 ||
        memcmp(registration, "SWZREG01", 8U) != 0 ||
        !nonzero_raw32(registration + 8U) ||
        !nonzero_raw32(registration + 40U) ||
        !nonzero_raw32(registration + 72U) ||
        !swz_pidfd_alive(pidfd) || swz_pidfd_get_pid(pidfd, &pid) != 0 ||
        pid <= 0) {
        close(pidfd);
        return -1;
    }
    *registered_pid = pid;
    *retained_pidfd = pidfd;
    return swz_write_full(fd, "SWZRGOK1", 8U);
}

static int send_identities(int client_fd, const unsigned char public_key[32])
{
    unsigned char response[4U + 1U + 4U + 4U + 51U + 4U +
                           sizeof("swz-recovery") - 1U];
    size_t offset = 4U;
    static const unsigned char comment[] = "swz-recovery";

    write_u32(response, 1U + 4U + 4U + 51U + 4U + (uint32_t)sizeof(comment) - 1U);
    response[offset++] = SWZ_AGENT_RESPONSE_IDENTITIES;
    write_u32(response + offset, 1U);
    offset += 4U;
    write_u32(response + offset, 51U);
    offset += 4U;
    write_u32(response + offset, 11U);
    memcpy(response + offset + 4U, "ssh-ed25519", 11U);
    write_u32(response + offset + 15U, 32U);
    memcpy(response + offset + 19U, public_key, 32U);
    offset += 51U;
    write_u32(response + offset, (uint32_t)sizeof(comment) - 1U);
    offset += 4U;
    memcpy(response + offset, comment, sizeof(comment) - 1U);
    return swz_write_full(client_fd, response,
                          offset + sizeof(comment) - 1U);
}

static int serve_agent(int client_fd, EVP_PKEY *key, const unsigned char public_key[32],
                       pid_t registered_pid, int retained_pidfd,
                       const unsigned char registration[SWZ_REGISTRATION_BYTES],
                       int signing_enabled)
{
    unsigned char length_bytes[4];
    unsigned char request[SWZ_AGENT_MAX_REQUEST];
    unsigned char signature[64];
    unsigned char response[4U + 1U + 4U + 11U + 64U];
    unsigned char key_blob[51];
    uint32_t request_length;
    uint32_t key_length;
    uint32_t data_length;
    uint32_t flags;
    size_t offset;
    size_t signature_length = sizeof(signature);
    EVP_MD_CTX *context = NULL;
    static const unsigned char algorithm[] = "ssh-ed25519";
    uid_t uid;
    gid_t gid;
    pid_t peer_pid;

    if (swz_peer_uidgid(client_fd, &uid, &gid) != 0 ||
        uid != 0U || gid == (gid_t)-1 ||
        swz_peer_pid(client_fd, &peer_pid) != 0 ||
        !swz_process_is_descendant(peer_pid, registered_pid) ||
        !swz_process_namespaces_match(peer_pid, registered_pid) ||
        swz_peer_domain_is(client_fd, SWZ_EXPECTED_SSHD_DOMAIN) != 0 ||
        registration == NULL || memcmp(registration, "SWZREG01", 8U) != 0 ||
        signing_enabled == 0 || !swz_pidfd_alive(retained_pidfd)) {
        return -1;
    }
    if (swz_read_full(client_fd, length_bytes, sizeof(length_bytes)) != 0) {
        return -1;
    }
    request_length = read_u32(length_bytes);
    if (request_length == 0U || request_length > SWZ_AGENT_MAX_REQUEST ||
        swz_read_full(client_fd, request, request_length) != 0) {
        return -1;
    }
    if (request[0] == SWZ_AGENT_REQUEST) {
        if (request_length != 1U) {
            return send_rejection(client_fd);
        }
        return send_identities(client_fd, public_key);
    }
    if (request[0] != SWZ_AGENT_REQUEST_SIGN || request_length < 13U) {
        return send_rejection(client_fd);
    }
    key_length = read_u32(request + 1U);
    if (key_length != sizeof(key_blob) || 5U + key_length + 4U > request_length) {
        return send_rejection(client_fd);
    }
    memcpy(key_blob, request + 5U, sizeof(key_blob));
    data_length = read_u32(request + 5U + key_length);
    offset = 9U + key_length;
    if (data_length == 0U || data_length > SWZ_AGENT_MAX_REQUEST ||
        offset + data_length + 4U != request_length) {
        return send_rejection(client_fd);
    }
    flags = read_u32(request + offset + data_length);
    context = EVP_MD_CTX_new();
    if (flags != 0U || memcmp(key_blob, "\0\0\0\013ssh-ed25519\0\0\0\040", 19U) != 0 ||
        memcmp(key_blob + 19U, public_key, 32U) != 0 || context == NULL ||
        EVP_DigestSignInit(context, NULL, NULL, NULL, key) != 1 ||
        EVP_DigestSign(context, signature, &signature_length, request + offset,
                       data_length) != 1 || signature_length != sizeof(signature)) {
        EVP_MD_CTX_free(context);
        return send_rejection(client_fd);
    }
    EVP_MD_CTX_free(context);
    write_u32(response, 1U + 4U + (uint32_t)sizeof(algorithm) - 1U + 64U);
    response[4] = SWZ_AGENT_RESPONSE;
    write_u32(response + 5U, (uint32_t)sizeof(algorithm) - 1U + 64U);
    memcpy(response + 9U, algorithm, sizeof(algorithm) - 1U);
    memcpy(response + 9U + sizeof(algorithm) - 1U, signature, sizeof(signature));
    return swz_write_full(client_fd, response,
                          9U + sizeof(algorithm) - 1U + sizeof(signature));
}

static int run_custodian(void)
{
    unsigned char seed[SWZ_MAX_SEED_BYTES];
    unsigned char public_key[32];
    EVP_PKEY *key = NULL;
    int seed_fd = SWZ_SEED_FD;
    int control_fd = SWZ_CUSTODIAN_CONTROL_FD;
    int listener_fd = SWZ_AGENT_LISTENER_FD;
    int retained_pidfd = -1;
    pid_t registered_pid = -1;
    int client_fd = -1;
    int result = -1;
    int signing_enabled = 0;
    unsigned char registration[SWZ_REGISTRATION_BYTES];
    size_t public_length = sizeof(public_key);

    if (swz_disable_dump_core() != 0 || swz_validate_seed_fd(seed_fd) != 0 ||
        swz_read_seed_exact(seed_fd, seed) != 0 || close(seed_fd) != 0) {
        explicit_bzero(seed, sizeof(seed));
        return -1;
    }
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed));
    explicit_bzero(seed, sizeof(seed));
    if (key == NULL || EVP_PKEY_get_raw_public_key(key, public_key, &public_length) != 1 ||
        public_length != sizeof(public_key) || read_public_pin(public_key) != 0 ||
        swz_confine_component("custodian") != 0 ||
        swz_write_full(control_fd, SWZ_READY_MAGIC, SWZ_READY_BYTES) != 0 ||
        acknowledge_registration(control_fd, registration, &registered_pid,
                                 &retained_pidfd) != 0) {
        EVP_PKEY_free(key);
        close(retained_pidfd);
        return -1;
    }
    signing_enabled = 1;
    result = 0;
    while (swz_pidfd_alive(retained_pidfd)) {
        struct pollfd descriptors[2];
        int polled;

        descriptors[0].fd = listener_fd;
        descriptors[0].events = POLLIN;
        descriptors[0].revents = 0;
        descriptors[1].fd = control_fd;
        descriptors[1].events = POLLIN | POLLHUP | POLLERR;
        descriptors[1].revents = 0;
        polled = poll(descriptors, 2U, 100);
        if (polled < 0 && errno == EINTR) {
            continue;
        }
        if (polled < 0 || (descriptors[1].revents & (POLLHUP | POLLERR)) != 0) {
            break;
        }
        if ((descriptors[1].revents & POLLIN) != 0) {
            unsigned char command[8];
            ssize_t received = recv(control_fd, command, sizeof(command),
                                    MSG_DONTWAIT | MSG_CMSG_CLOEXEC);

            if (received != (ssize_t)sizeof(command) ||
                (memcmp(command, SWZ_DISABLE_MAGIC, sizeof(command)) != 0 &&
                 memcmp(command, SWZ_RETIRE_MAGIC, sizeof(command)) != 0)) {
                break;
            }
            signing_enabled = 0;
            close(listener_fd);
            listener_fd = -1;
            if (memcmp(command, SWZ_RETIRE_MAGIC, sizeof(command)) == 0) {
                break;
            }
        }
        if (listener_fd >= 0 && (descriptors[0].revents & POLLIN) != 0) {
            client_fd = accept4(listener_fd, NULL, NULL, SOCK_CLOEXEC);
            if (client_fd < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            result = serve_agent(client_fd, key, public_key, registered_pid,
                                 retained_pidfd, registration, signing_enabled);
            close(client_fd);
            client_fd = -1;
            if (result != 0) {
                continue;
            }
        }
    }
    signing_enabled = 0;
    if (listener_fd >= 0) {
        close(listener_fd);
    }
    (void)write_lifecycle_marker(control_fd, 0);
    (void)write_lifecycle_marker(control_fd, 1);
    close(retained_pidfd);
    EVP_PKEY_free(key);
    explicit_bzero(public_key, sizeof(public_key));
    return result;
}

int main(void)
{
    return run_custodian() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
