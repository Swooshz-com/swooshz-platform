#ifndef SWZ_MANAGED_PLATFORM_H
#define SWZ_MANAGED_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int swz_read_full(int fd, void *buffer, size_t length, int timeout_ms);
int swz_write_full(int fd, const void *buffer, size_t length);
int swz_close_on_exec(int fd);
int swz_set_nonblocking(int fd);
int swz_random_bytes(uint8_t *out, size_t length);
int swz_sha256(const uint8_t *data, size_t length, uint8_t digest[32]);
int swz_sha256_hex(const uint8_t *data, size_t length, char out[65]);
int swz_managed_hash(const char *domain, const uint8_t *const parts[], const size_t lengths[], size_t count, uint8_t digest[32]);
int swz_store_commitment(const char *domain, const uint8_t *data, size_t length, char out[75]);
int swz_hex_decode(const char *text, uint8_t *out, size_t out_length);
int swz_proc_env_equals(pid_t pid, const char *name, const char *expected);
int swz_is_descendant(pid_t pid, pid_t ancestor);
int swz_pidfd_open(pid_t pid);
int swz_pidfd_send_signal(int pidfd, int signal_number);
int swz_secure_socket_path(const char *path, uid_t owner);
int swz_literal_ipv4(const char *text, uint8_t out[4]);

#endif
