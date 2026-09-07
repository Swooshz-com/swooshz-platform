#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

int swz_read_full(int fd, void *buffer, size_t length, int timeout_ms)
{
	uint8_t *cursor = buffer;
	size_t total = 0;
	while (total < length) {
		struct pollfd pollfd = { .fd = fd, .events = POLLIN };
		int ready = poll(&pollfd, 1, timeout_ms);
		if (ready <= 0 || (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
			return -1;
		ssize_t got = read(fd, cursor + total, length - total);
		if (got <= 0)
			return -1;
		total += (size_t)got;
	}
	return 0;
}

int swz_write_full(int fd, const void *buffer, size_t length)
{
	const uint8_t *cursor = buffer;
	size_t total = 0;
	while (total < length) {
		ssize_t written = write(fd, cursor + total, length - total);
		if (written <= 0)
			return -1;
		total += (size_t)written;
	}
	return 0;
}

int swz_close_on_exec(int fd)
{
	int flags = fcntl(fd, F_GETFD);
	return flags < 0 ? -1 : fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

int swz_set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int swz_random_bytes(uint8_t *out, size_t length)
{
	if (out == NULL || length == 0)
		return -1;
	size_t total = 0;
	while (total < length) {
		ssize_t got = getrandom(out + total, length - total, 0);
		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0)
			return -1;
		total += (size_t)got;
	}
	return 0;
}

int swz_sha256(const uint8_t *data, size_t length, uint8_t digest[32])
{
	EVP_MD_CTX *context = NULL;
	unsigned int digest_length = 0;
	int result = -1;
	if (data == NULL || digest == NULL || (context = EVP_MD_CTX_new()) == NULL)
		return -1;
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(context, data, length) == 1 &&
	    EVP_DigestFinal_ex(context, digest, &digest_length) == 1 && digest_length == 32)
		result = 0;
	EVP_MD_CTX_free(context);
	return result;
}

int swz_sha256_hex(const uint8_t *data, size_t length, char out[65])
{
	static const char hex[] = "0123456789abcdef";
	uint8_t digest[32];
	if (out == NULL || swz_sha256(data, length, digest) != 0)
		return -1;
	for (size_t i = 0; i < sizeof(digest); i++) {
		out[i * 2] = hex[digest[i] >> 4];
		out[i * 2 + 1] = hex[digest[i] & 0x0f];
	}
	out[64] = '\0';
	return 0;
}

static int digest_update_lp(EVP_MD_CTX *context, const uint8_t *data, size_t length)
{
	uint8_t prefix[4];
	if (context == NULL || (length != 0 && data == NULL) || length > UINT32_MAX)
		return -1;
	prefix[0] = (uint8_t)(length >> 24);
	prefix[1] = (uint8_t)(length >> 16);
	prefix[2] = (uint8_t)(length >> 8);
	prefix[3] = (uint8_t)length;
	if (EVP_DigestUpdate(context, prefix, sizeof(prefix)) != 1)
		return -1;
	return length == 0 || EVP_DigestUpdate(context, data, length) == 1 ? 0 : -1;
}

static int digest_update_ascii_lp(EVP_MD_CTX *context, const char *value)
{
	if (value == NULL)
		return -1;
	for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; cursor++) {
		if (*cursor > 0x7f)
			return -1;
	}
	return digest_update_lp(context, (const uint8_t *)value, strlen(value));
}

int swz_managed_hash(const char *domain, const uint8_t *const parts[], const size_t lengths[], size_t count, uint8_t digest[32])
{
	EVP_MD_CTX *context;
	unsigned int digest_length = 0;
	int result = -1;
	if (domain == NULL || (count != 0 && (parts == NULL || lengths == NULL)) || digest == NULL ||
	    (context = EVP_MD_CTX_new()) == NULL)
		return -1;
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
	    digest_update_ascii_lp(context, "swz-managed.v1") == 0 &&
	    digest_update_ascii_lp(context, domain) == 0) {
		result = 0;
		for (size_t index = 0; index < count; index++) {
			if (digest_update_lp(context, parts[index], lengths[index]) != 0) {
				result = -1;
				break;
			}
		}
		if (result == 0 &&
		    (EVP_DigestFinal_ex(context, digest, &digest_length) != 1 || digest_length != 32))
			result = -1;
	}
	EVP_MD_CTX_free(context);
	return result;
}

int swz_store_commitment(const char *domain, const uint8_t *data, size_t length, char out[75])
{
	EVP_MD_CTX *context;
	uint8_t digest[32];
	unsigned int digest_length = 0;
	static const char hex[] = "0123456789abcdef";
	if (domain == NULL || (length != 0 && data == NULL) || out == NULL ||
	    (context = EVP_MD_CTX_new()) == NULL)
		return -1;
	int result = -1;
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
	    digest_update_ascii_lp(context, "recovery-commitment.v1") == 0 &&
	    digest_update_ascii_lp(context, domain) == 0 &&
	    digest_update_lp(context, data, length) == 0 &&
	    EVP_DigestFinal_ex(context, digest, &digest_length) == 1 && digest_length == 32) {
		memcpy(out, "sha256:v1:", 10);
		for (size_t index = 0; index < sizeof(digest); index++) {
			out[10 + index * 2] = hex[digest[index] >> 4];
			out[10 + index * 2 + 1] = hex[digest[index] & 0x0f];
		}
		out[74] = '\0';
		result = 0;
	}
	EVP_MD_CTX_free(context);
	return result;
}

static int hex_digit(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	return -1;
}

int swz_hex_decode(const char *text, uint8_t *out, size_t out_length)
{
	if (text == NULL || out == NULL || strlen(text) != out_length * 2)
		return -1;
	for (size_t i = 0; i < out_length; i++) {
		int high = hex_digit(text[i * 2]);
		int low = hex_digit(text[i * 2 + 1]);
		if (high < 0 || low < 0)
			return -1;
		out[i] = (uint8_t)((high << 4) | low);
	}
	return 0;
}

static int read_parent_pid(pid_t pid, pid_t *parent)
{
	char path[64];
	char line[512];
	FILE *file;
	long parent_value;
	snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	file = fopen(path, "r");
	if (file == NULL || fgets(line, sizeof(line), file) == NULL) {
		if (file != NULL)
			fclose(file);
		return -1;
	}
	fclose(file);
	char *close_paren = strrchr(line, ')');
	if (close_paren == NULL)
		return -1;
	if (sscanf(close_paren + 2, "%*c %ld", &parent_value) != 1 ||
	    parent_value <= 0)
		return -1;
	*parent = (pid_t)parent_value;
	return 0;
}

int swz_is_descendant(pid_t pid, pid_t ancestor)
{
	if (pid <= 0 || ancestor <= 0)
		return 0;
	for (unsigned int depth = 0; depth < 64 && pid > 1; depth++) {
		if (pid == ancestor)
			return 1;
		pid_t parent = 0;
		if (read_parent_pid(pid, &parent) != 0 || parent == pid)
			return 0;
		pid = parent;
	}
	return pid == ancestor;
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

int swz_pidfd_send_signal(int pidfd, int signal_number)
{
#ifdef SYS_pidfd_send_signal
	return (int)syscall(SYS_pidfd_send_signal, pidfd, signal_number, NULL, 0U);
#else
	(void)pidfd;
	(void)signal_number;
	errno = ENOSYS;
	return -1;
#endif
}

int swz_secure_socket_path(const char *path, uid_t owner)
{
	struct stat info;
	if (path == NULL || lstat(path, &info) != 0 || !S_ISSOCK(info.st_mode) ||
	    info.st_uid != owner || (info.st_mode & 0077) != 0)
		return -1;
	return 0;
}

int swz_literal_ipv4(const char *text, uint8_t out[4])
{
	struct in_addr address;
	if (text == NULL || out == NULL || inet_pton(AF_INET, text, &address) != 1 ||
	    strcmp(text, inet_ntoa(address)) != 0 || address.s_addr == htonl(INADDR_ANY))
		return -1;
	memcpy(out, &address, sizeof(address));
	return 0;
}

int swz_proc_env_equals(pid_t pid, const char *name, const char *expected)
{
	char path[64];
	char buffer[4096];
	int fd;
	ssize_t length;
	if (pid <= 0 || name == NULL || expected == NULL)
		return -1;
	snprintf(path, sizeof(path), "/proc/%ld/environ", (long)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	length = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (length <= 0)
		return -1;
	buffer[length] = '\0';
	size_t name_length = strlen(name);
	for (ssize_t index = 0; index < length;) {
		char *entry = buffer + index;
		size_t entry_length = strlen(entry);
		if (entry_length > name_length + 1 && strncmp(entry, name, name_length) == 0 && entry[name_length] == '=')
			return strcmp(entry + name_length + 1, expected) == 0 ? 0 : -1;
		index += (ssize_t)entry_length + 1;
	}
	return -1;
}
