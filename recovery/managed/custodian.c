#define _GNU_SOURCE

#include "platform.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SWZ_AGENT_REQUEST 11U
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

static int sign_message(int seed_fd, const unsigned char *message,
                        size_t message_length, unsigned char signature[64])
{
    unsigned char seed[SWZ_MAX_SEED_BYTES];
    EVP_PKEY *key;
    EVP_MD_CTX *context;
    size_t signature_length = 64U;
    int result = -1;

    if (message == NULL || message_length == 0U ||
        lseek(seed_fd, 0, SEEK_SET) < 0 ||
        swz_read_full(seed_fd, seed, sizeof(seed)) != 0) {
        return -1;
    }
    key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed,
                                       sizeof(seed));
    context = EVP_MD_CTX_new();
    if (key != NULL && context != NULL && EVP_DigestSignInit(context, NULL,
                                                               NULL, NULL, key) == 1 &&
        EVP_DigestSign(context, signature, &signature_length, message,
                       message_length) == 1 && signature_length == 64U) {
        result = 0;
    }
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return result;
}

static int send_rejection(int fd)
{
    static const unsigned char rejection[] = { 5U, 0U, 0U, 0U, 0U };
    return swz_write_full(fd, rejection, sizeof(rejection));
}

static int write_lifecycle_marker(int fd, int retiring)
{
    return swz_write_full(fd, retiring ? "SWZRET01" : "SWZDIS01", 8U);
}

static int acknowledge_registration(int fd)
{
    unsigned char record[SWZ_REGISTRATION_BYTES];
    unsigned char magic[8];
    int pidfd = -1;

    if (swz_read_full(fd, record, sizeof(record)) != 0 ||
        memcmp(record, "SWZREG01", sizeof(magic)) != 0 ||
        (pidfd = swz_recv_fd(fd)) < 0 || !swz_pidfd_alive(pidfd)) {
        close(pidfd);
        return -1;
    }
    close(pidfd);
    return swz_write_full(fd, "SWZRGOK1", 8U);
}

static int serve_agent(int client_fd, int seed_fd)
{
    unsigned char length_bytes[4];
    unsigned char request[SWZ_AGENT_MAX_REQUEST];
    unsigned char reply[4U + 1U + 4U + 12U + 64U];
    uint32_t request_length;
    size_t request_size;
    unsigned char signature[64];
    static const unsigned char algorithm[] = "ssh-ed25519";

    if (swz_read_full(client_fd, length_bytes, sizeof(length_bytes)) != 0) {
        return -1;
    }
    request_length = read_u32(length_bytes);
    if (request_length > SWZ_AGENT_MAX_REQUEST || request_length < 9U ||
        swz_read_full(client_fd, request, request_length) != 0) {
        return -1;
    }
    request_size = request_length;
    if (request[0] != SWZ_AGENT_REQUEST ||
        request_size < 1U + 4U ||
        read_u32(request + 1U) > request_size - 5U ||
        sign_message(seed_fd, request + 5U + read_u32(request + 1U),
                     request_size - 5U - read_u32(request + 1U), signature) != 0) {
        return send_rejection(client_fd);
    }
    write_u32(reply, 1U + 4U + (uint32_t)sizeof(algorithm) - 1U + 64U + 4U);
    reply[4] = SWZ_AGENT_RESPONSE;
    write_u32(reply + 5U, (uint32_t)sizeof(algorithm) - 1U + 64U);
    memcpy(reply + 9U, algorithm, sizeof(algorithm) - 1U);
    memcpy(reply + 9U + sizeof(algorithm) - 1U, signature, sizeof(signature));
    return swz_write_full(client_fd, reply,
                          9U + sizeof(algorithm) - 1U + sizeof(signature));
}

static int run_custodian(void)
{
    int seed_fd;
    int listener_fd = 3;
    int client_fd;

    if (fcntl(4, F_GETFD) >= 0 &&
        (acknowledge_registration(4) != 0 || write_lifecycle_marker(4, 0) != 0)) {
        return -1;
    }
    seed_fd = open(SWZ_PRODUCTION_SEED_PATH, O_RDONLY | O_CLOEXEC);
    if (seed_fd < 0 || swz_validate_seed_fd(seed_fd) != 0 ||
        swz_confine_component("custodian") != 0) {
        close(seed_fd);
        return -1;
    }
    client_fd = accept4(listener_fd, NULL, NULL, SOCK_CLOEXEC);
    if (client_fd < 0) {
        close(seed_fd);
        return -1;
    }
    (void)serve_agent(client_fd, seed_fd);
    close(client_fd);
    close(seed_fd);
    return 0;
}

int main(void)
{
    return run_custodian() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
