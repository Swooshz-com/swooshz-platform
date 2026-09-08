#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L
#include "platform.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

static int64_t monotonic_milliseconds(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return -1;
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int wait_ready(int fd, short events, int timeout_ms)
{
	struct pollfd descriptor = { .fd = fd, .events = events };
	int64_t deadline = timeout_ms < 0 ? -1 : monotonic_milliseconds() + timeout_ms;
	if (fd < 0 || (timeout_ms >= 0 && deadline < 0))
		return -1;
	for (;;) {
		int wait_ms = -1;
		if (deadline >= 0) {
			int64_t remaining = deadline - monotonic_milliseconds();
			if (remaining < 0)
				return -1;
			wait_ms = remaining > INT_MAX ? INT_MAX : (int)remaining;
		}
		int result = poll(&descriptor, 1, wait_ms);
		if (result < 0 && errno == EINTR)
			continue;
		return result > 0 && (descriptor.revents & (events | POLLHUP | POLLERR)) != 0 ? 0 : -1;
	}
}

int swz_read_full(int fd, void *buffer, size_t length, int timeout_ms)
{
	uint8_t *cursor = buffer;
	int64_t deadline = timeout_ms < 0 ? -1 : monotonic_milliseconds() + timeout_ms;
	if (fd < 0 || (length != 0 && buffer == NULL) || (timeout_ms >= 0 && deadline < 0))
		return -1;
	while (length != 0) {
		int remaining = -1;
		if (deadline >= 0) {
			int64_t delta = deadline - monotonic_milliseconds();
			if (delta < 0)
				return -1;
			remaining = delta > INT_MAX ? INT_MAX : (int)delta;
		}
		if (wait_ready(fd, POLLIN, remaining) != 0)
			return -1;
		ssize_t received = read(fd, cursor, length);
		if (received < 0 && errno == EINTR)
			continue;
		if (received <= 0)
			return -1;
		cursor += (size_t)received;
		length -= (size_t)received;
	}
	return 0;
}

int swz_read_exact_eof(int fd, uint8_t *buffer, size_t length, int timeout_ms)
{
	if (swz_read_full(fd, buffer, length, timeout_ms) != 0)
		return -1;
	uint8_t trailing;
	for (;;) {
		if (wait_ready(fd, POLLIN, timeout_ms) != 0)
			return -1;
		ssize_t received = read(fd, &trailing, sizeof(trailing));
		if (received < 0 && errno == EINTR)
			continue;
		return received == 0 ? 0 : -1;
	}
}

int swz_write_full(int fd, const void *buffer, size_t length)
{
	const uint8_t *cursor = buffer;
	if (fd < 0 || (length != 0 && buffer == NULL))
		return -1;
	while (length != 0) {
		ssize_t written = write(fd, cursor, length);
		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0)
			return -1;
		cursor += (size_t)written;
		length -= (size_t)written;
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
	while (length != 0) {
		ssize_t received = getrandom(out, length, 0);
		if (received < 0 && errno == EINTR)
			continue;
		if (received <= 0)
			return -1;
		out += (size_t)received;
		length -= (size_t)received;
	}
	return 0;
}

void swz_zeroize(void *buffer, size_t length)
{
	volatile uint8_t *cursor = buffer;
	if (cursor == NULL)
		return;
	while (length-- != 0)
		*cursor++ = 0;
}

int swz_sha256(const uint8_t *data, size_t length, uint8_t digest[32])
{
	EVP_MD_CTX *context = NULL;
	unsigned int digest_length = 0;
	int result = -1;
	if (digest == NULL || (length != 0 && data == NULL) || (context = EVP_MD_CTX_new()) == NULL)
		return -1;
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
		EVP_DigestUpdate(context, data, length) == 1 &&
		EVP_DigestFinal_ex(context, digest, &digest_length) == 1 && digest_length == 32)
		result = 0;
	EVP_MD_CTX_free(context);
	return result;
}

int swz_sha256_file(const char *path, uint8_t digest[32])
{
	int fd = -1;
	EVP_MD_CTX *context = NULL;
	uint8_t buffer[65536];
	unsigned int digest_length = 0;
	int result = -1;
	if (path == NULL || digest == NULL || (fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0 ||
		(context = EVP_MD_CTX_new()) == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
		goto done;
	for (;;) {
		ssize_t received = read(fd, buffer, sizeof(buffer));
		if (received < 0 && errno == EINTR)
			continue;
		if (received < 0 || (received != 0 && EVP_DigestUpdate(context, buffer, (size_t)received) != 1))
			goto done;
		if (received == 0)
			break;
	}
	if (EVP_DigestFinal_ex(context, digest, &digest_length) == 1 && digest_length == 32)
		result = 0;
done:
	if (context != NULL)
		EVP_MD_CTX_free(context);
	if (fd >= 0)
		close(fd);
	return result;
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
	return EVP_DigestUpdate(context, prefix, sizeof(prefix)) == 1 &&
		(length == 0 || EVP_DigestUpdate(context, data, length) == 1) ? 0 : -1;
}

static int digest_update_ascii_lp(EVP_MD_CTX *context, const char *value)
{
	if (value == NULL)
		return -1;
	for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; cursor++)
		if (*cursor > 0x7fU)
			return -1;
	return digest_update_lp(context, (const uint8_t *)value, strlen(value));
}

static const char *const managed_domains[] = {
	"admission-root.v1", "host-public-key.v1", "target-policy.v1", "dependency-closure.v1",
	"invocation-policy.v1", "execution-inventory.v1", "build-record.v1", "fd-inventory.v1",
	"runtime-argv.v1", "runtime-limits.v1", "policy.v1", "auth-account-config.v1", "n-local.v1",
	"installation.v1", "endpoint-template.v1", "endpoint-actual.v1", "launch-base.v1",
	"openssh-closure.v1", "component-supervisor.v1", "component-custodian.v1", "component-dispatcher.v1",
	"component-bootstrap.v1", "component-broker.v1", "component-agent.v1", "dm-verity.v1",
	"qualification-subject.v1", "build-qualification.v1", "generation.v1", "generation-manifest.v1",
	"generation-approval.v1", "activation.v1", "connection.v1", "request-context.v1",
	"authority-context.v1", "challenge.v1", "runtime.v1", "evidence.v1", "accept.v1",
	"accepted-session.v1", "accepted-receipt.v1", "discovery.v1", "proceed.v1", "result.v1",
};

static int managed_domain_allowed(const char *domain)
{
	for (size_t index = 0; index < sizeof(managed_domains) / sizeof(managed_domains[0]); index++)
		if (strcmp(domain, managed_domains[index]) == 0)
			return 1;
	return 0;
}

static int managed_digest(const char *marker, const char *domain, const uint8_t *const parts[], const size_t lengths[], size_t count, uint8_t digest[32])
{
	EVP_MD_CTX *context = NULL;
	unsigned int digest_length = 0;
	int result = -1;
	if (marker == NULL || domain == NULL || digest == NULL || (count != 0 && (parts == NULL || lengths == NULL)) ||
		(context = EVP_MD_CTX_new()) == NULL || EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1 ||
		digest_update_ascii_lp(context, marker) != 0 || digest_update_ascii_lp(context, domain) != 0)
		goto done;
	for (size_t index = 0; index < count; index++)
		if (digest_update_lp(context, parts[index], lengths[index]) != 0)
			goto done;
	if (EVP_DigestFinal_ex(context, digest, &digest_length) == 1 && digest_length == 32)
		result = 0;
done:
	if (context != NULL)
		EVP_MD_CTX_free(context);
	return result;
}

int swz_managed_hash(const char *domain, const uint8_t *const parts[], const size_t lengths[], size_t count, uint8_t digest[32])
{
	return domain != NULL && managed_domain_allowed(domain) ? managed_digest("swz-managed.v1", domain, parts, lengths, count, digest) : -1;
}

int swz_store_commitment(const char *domain, const uint8_t *data, size_t length, char out[75])
{
	static const char hex[] = "0123456789abcdef";
	uint8_t digest[32];
	const uint8_t *parts[] = { data };
	const size_t lengths[] = { length };
	if (out == NULL || domain == NULL || managed_digest("recovery-commitment.v1", domain, parts, lengths, 1, digest) != 0)
		return -1;
	memcpy(out, "sha256:v1:", 10);
	for (size_t index = 0; index < sizeof(digest); index++) {
		out[10 + index * 2] = hex[digest[index] >> 4];
		out[11 + index * 2] = hex[digest[index] & 0x0fU];
	}
	out[74] = '\0';
	return 0;
}

static int hex_digit(char value)
{
	if (value >= '0' && value <= '9') return value - '0';
	if (value >= 'a' && value <= 'f') return value - 'a' + 10;
	return -1;
}

int swz_hex_decode(const char *text, uint8_t *out, size_t out_length)
{
	if (text == NULL || out == NULL || strlen(text) != out_length * 2)
		return -1;
	for (size_t index = 0; index < out_length; index++) {
		int high = hex_digit(text[index * 2]);
		int low = hex_digit(text[index * 2 + 1]);
		if (high < 0 || low < 0)
			return -1;
		out[index] = (uint8_t)((high << 4) | low);
	}
	return 0;
}

int swz_validate_seed_fd(int fd, uid_t owner, gid_t group)
{
	struct stat info;
	return fd >= 0 && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == owner && info.st_gid == group &&
		info.st_size == 32 && (info.st_mode & 0777) == 0400 ? 0 : -1;
}

int swz_read_seed_fd(int fd, uint8_t seed[32])
{
	uint8_t trailing;
	int result = -1;
	if (seed == NULL || swz_validate_seed_fd(fd, geteuid(), getegid()) != 0 || lseek(fd, 0, SEEK_SET) < 0 || swz_read_full(fd, seed, 32, 5000) != 0)
		goto done;
	for (;;) {
		ssize_t received = read(fd, &trailing, sizeof(trailing));
		if (received < 0 && errno == EINTR)
			continue;
		if (received == 0)
			result = 0;
		break;
	}
done:
	if (fd >= 0)
		close(fd);
	if (result != 0 && seed != NULL)
		swz_zeroize(seed, 32);
	return result;
}

static int base64_value(unsigned char value)
{
	if (value >= 'A' && value <= 'Z') return value - 'A';
	if (value >= 'a' && value <= 'z') return value - 'a' + 26;
	if (value >= '0' && value <= '9') return value - '0' + 52;
	if (value == '+') return 62;
	if (value == '/') return 63;
	return -1;
}

static int decode_base64(const char *text, uint8_t *out, size_t capacity, size_t *length)
{
	size_t text_length;
	size_t output = 0;
	if (text == NULL || out == NULL || length == NULL)
		return -1;
	text_length = strlen(text);
	if (text_length == 0 || text_length % 4 != 0)
		return -1;
	for (size_t cursor = 0; cursor < text_length; cursor += 4) {
		int a = base64_value((unsigned char)text[cursor]);
		int b = base64_value((unsigned char)text[cursor + 1]);
		int c = text[cursor + 2] == '=' ? -1 : base64_value((unsigned char)text[cursor + 2]);
		int d = text[cursor + 3] == '=' ? -1 : base64_value((unsigned char)text[cursor + 3]);
		int final = cursor + 4 == text_length;
		if (a < 0 || b < 0 || (!final && (text[cursor + 2] == '=' || text[cursor + 3] == '=')) ||
			(text[cursor + 2] == '=' && (text[cursor + 3] != '=' || (b & 0x0f) != 0)) ||
			(text[cursor + 2] != '=' && c < 0) ||
			(text[cursor + 3] == '=' && text[cursor + 2] != '=' && (c & 0x03) != 0) ||
			(text[cursor + 3] != '=' && d < 0))
			return -1;
		if (output + 1 > capacity) return -1;
		out[output++] = (uint8_t)((a << 2) | (b >> 4));
		if (text[cursor + 2] != '=') {
			if (output + 1 > capacity) return -1;
			out[output++] = (uint8_t)((b << 4) | (c >> 2));
		}
		if (text[cursor + 3] != '=') {
			if (output + 1 > capacity) return -1;
			out[output++] = (uint8_t)((c << 6) | d);
		}
	}
	*length = output;
	return 0;
}

int swz_load_ed25519_public_file(const char *path, uint8_t public_key[32])
{
	char document[256];
	uint8_t decoded[64];
	size_t decoded_length = 0;
	struct stat info;
	int fd = -1;
	ssize_t length;
	int result = -1;
	if (path == NULL || public_key == NULL || (fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0 || fstat(fd, &info) != 0 ||
		!S_ISREG(info.st_mode) || info.st_size <= 0 || info.st_size >= (off_t)sizeof(document))
		goto done;
	do {
		length = read(fd, document, sizeof(document) - 1);
	} while (length < 0 && errno == EINTR);
	if (length <= 0 || length >= (ssize_t)sizeof(document))
		goto done;
	document[length] = '\0';
	if (document[length - 1] == '\n')
		document[--length] = '\0';
	if (strchr(document, '\n') != NULL || strncmp(document, "ssh-ed25519 ", 12) != 0)
		goto done;
	char *encoded = document + 12;
	if (strchr(encoded, ' ') != NULL || decode_base64(encoded, decoded, sizeof(decoded), &decoded_length) != 0 || decoded_length != 51 ||
		memcmp(decoded, "\0\0\0\vssh-ed25519\0\0\0 ", 19) != 0)
		goto done;
	memcpy(public_key, decoded + 19, 32);
	result = 0;
done:
	if (fd >= 0)
		close(fd);
	swz_zeroize(decoded, sizeof(decoded));
	if (result != 0 && public_key != NULL)
		swz_zeroize(public_key, 32);
	return result;
}

static int read_parent_pid(pid_t pid, pid_t *parent)
{
	char path[64];
	char line[512];
	char *close_paren;
	int fd;
	int written = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	ssize_t length;
	long value;
	if (written <= 0 || (size_t)written >= sizeof(path) || parent == NULL || (fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0)
		return -1;
	do {
		length = read(fd, line, sizeof(line) - 1);
	} while (length < 0 && errno == EINTR);
	close(fd);
	if (length <= 0 || length >= (ssize_t)sizeof(line))
		return -1;
	line[length] = '\0';
	close_paren = strrchr(line, ')');
	if (close_paren == NULL || sscanf(close_paren + 2, "%*c %ld", &value) != 1 || value <= 0)
		return -1;
	*parent = (pid_t)value;
	return 0;
}

int swz_is_descendant(pid_t pid, pid_t ancestor)
{
	if (pid <= 0 || ancestor <= 0)
		return 0;
	for (unsigned int depth = 0; depth < 128 && pid > 1; depth++) {
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

int swz_pidfd_is_live(int pidfd)
{
	struct pollfd descriptor = { .fd = pidfd, .events = POLLIN };
	return pidfd >= 0 && swz_pidfd_send_signal(pidfd, 0) == 0 && poll(&descriptor, 1, 0) == 0 ? 0 : -1;
}

int swz_pidfd_target_pid(int pidfd, pid_t *pid)
{
	char path[64];
	char document[256];
	char *line;
	int fd;
	ssize_t length;
	long value;
	int written = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
	if (pidfd < 0 || pid == NULL || written <= 0 || (size_t)written >= sizeof(path) ||
		(fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0)
		return -1;
	do {
		length = read(fd, document, sizeof(document) - 1);
	} while (length < 0 && errno == EINTR);
	close(fd);
	if (length <= 0 || length >= (ssize_t)sizeof(document))
		return -1;
	document[length] = '\0';
	line = strstr(document, "Pid:");
	if (line == NULL || sscanf(line + 4, "%ld", &value) != 1 || value <= 0)
		return -1;
	*pid = (pid_t)value;
	return 0;
}

int swz_wait_final(pid_t pid, int pidfd, int timeout_ms, int *status)
{
	siginfo_t info;
	int64_t deadline = timeout_ms < 0 ? -1 : monotonic_milliseconds() + timeout_ms;
	if (pid <= 0 || pidfd < 0 || status == NULL || (timeout_ms >= 0 && deadline < 0))
		return -1;
	for (;;) {
		int remaining = -1;
		if (deadline >= 0) {
			int64_t delta = deadline - monotonic_milliseconds();
			if (delta < 0)
				return -1;
			remaining = delta > INT_MAX ? INT_MAX : (int)delta;
		}
		if (wait_ready(pidfd, POLLIN, remaining) != 0)
			return -1;
		memset(&info, 0, sizeof(info));
#ifdef P_PIDFD
		if (waitid(P_PIDFD, (id_t)pidfd, &info, WEXITED | WNOHANG) != 0)
			return -1;
#else
		if (waitid((idtype_t)3, (id_t)pidfd, &info, WEXITED | WNOHANG) != 0)
			return -1;
#endif
		if (info.si_pid == 0)
			continue;
		pid_t waited;
		do {
			waited = waitpid(pid, status, 0);
		} while (waited < 0 && errno == EINTR);
		return waited == pid ? 0 : -1;
	}
}

int swz_process_starttime(pid_t pid, uint64_t *starttime)
{
	char path[64];
	char document[4096];
	char *tokens[24];
	char *save = NULL;
	char *close_paren;
	int fd;
	int written = snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
	ssize_t length;
	size_t count = 0;
	if (starttime == NULL || written <= 0 || (size_t)written >= sizeof(path) || (fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0)
		return -1;
	do {
		length = read(fd, document, sizeof(document) - 1);
	} while (length < 0 && errno == EINTR);
	close(fd);
	if (length <= 0 || length >= (ssize_t)sizeof(document))
		return -1;
	document[length] = '\0';
	close_paren = strrchr(document, ')');
	if (close_paren == NULL || close_paren[1] != ' ')
		return -1;
	for (char *token = strtok_r(close_paren + 2, " ", &save); token != NULL; token = strtok_r(NULL, " ", &save)) {
		if (count >= sizeof(tokens) / sizeof(tokens[0]))
			return -1;
		tokens[count++] = token;
	}
	if (count < 20)
		return -1;
	char *end = NULL;
	unsigned long long value = strtoull(tokens[19], &end, 10);
	if (end == tokens[19] || *end != '\0' || value == 0)
		return -1;
	*starttime = (uint64_t)value;
	return 0;
}

static int namespace_stat(pid_t pid, const char *name, dev_t *device, ino_t *inode)
{
	char path[64];
	struct stat info;
	int written = snprintf(path, sizeof(path), "/proc/%ld/ns/%s", (long)pid, name);
	if (written <= 0 || (size_t)written >= sizeof(path) || device == NULL || inode == NULL || stat(path, &info) != 0)
		return -1;
	*device = info.st_dev;
	*inode = info.st_ino;
	return 0;
}

int swz_process_namespace(pid_t pid, struct swz_namespace_identity *identity)
{
	if (identity == NULL || namespace_stat(pid, "mnt", &identity->mount_device, &identity->mount_inode) != 0 ||
		namespace_stat(pid, "pid", &identity->pid_device, &identity->pid_inode) != 0 ||
		namespace_stat(pid, "net", &identity->net_device, &identity->net_inode) != 0)
		return -1;
	return 0;
}

int swz_pidfd_process_in_tree(int pidfd, pid_t candidate, const struct swz_namespace_identity *expected_namespace)
{
	pid_t root;
	struct swz_namespace_identity candidate_namespace;
	if (swz_pidfd_is_live(pidfd) != 0 || swz_pidfd_target_pid(pidfd, &root) != 0 || !swz_is_descendant(candidate, root) ||
		swz_process_namespace(candidate, &candidate_namespace) != 0)
		return -1;
	if (expected_namespace != NULL && (candidate_namespace.mount_device != expected_namespace->mount_device || candidate_namespace.mount_inode != expected_namespace->mount_inode ||
		candidate_namespace.pid_device != expected_namespace->pid_device || candidate_namespace.pid_inode != expected_namespace->pid_inode ||
		candidate_namespace.net_device != expected_namespace->net_device || candidate_namespace.net_inode != expected_namespace->net_inode))
		return -1;
	return 0;
}

int swz_peer_credentials(int fd, pid_t *pid, uid_t *uid, gid_t *gid)
{
	struct ucred credentials;
	socklen_t length = sizeof(credentials);
	if (fd < 0 || pid == NULL || uid == NULL || gid == NULL || getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 || length != sizeof(credentials))
		return -1;
	*pid = credentials.pid;
	*uid = credentials.uid;
	*gid = credentials.gid;
	return 0;
}

static int domain_label_matches(char *label, size_t length, const char *expected_domain)
{
	if (label == NULL || expected_domain == NULL || length == 0 || length >= 256)
		return -1;
	label[length] = '\0';
	if (strchr(expected_domain, ':') != NULL)
		return strcmp(label, expected_domain) == 0 ? 0 : -1;
	char *cursor = label;
	while (cursor != NULL) {
		char *separator = strchr(cursor, ':');
		if (separator != NULL)
			*separator = '\0';
		if (strcmp(cursor, expected_domain) == 0)
			return 0;
		if (separator == NULL)
			break;
		cursor = separator + 1;
	}
	return -1;
}

int swz_peer_domain_matches(int fd, const char *expected_domain)
{
#ifdef SO_PEERSEC
	char label[256];
	socklen_t length = sizeof(label) - 1;
	if (fd < 0 || expected_domain == NULL || getsockopt(fd, SOL_SOCKET, SO_PEERSEC, label, &length) != 0 || length == 0 || length >= sizeof(label))
		return -1;
	return domain_label_matches(label, length, expected_domain);
#else
	(void)fd;
	(void)expected_domain;
	return -1;
#endif
}

int swz_process_domain_matches(const char *expected_domain)
{
	char label[256];
	int fd;
	ssize_t length;
	if (expected_domain == NULL || (fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0)
		return -1;
	do {
		length = read(fd, label, sizeof(label) - 1);
	} while (length < 0 && errno == EINTR);
	close(fd);
	if (length <= 0 || length >= (ssize_t)sizeof(label))
		return -1;
	while (length > 0 && (label[length - 1] == '\n' || label[length - 1] == '\r'))
		length--;
	return domain_label_matches(label, (size_t)length, expected_domain);
}

int swz_get_socket_cookie(int fd, uint64_t *cookie)
{
#ifdef SO_COOKIE
	socklen_t length = sizeof(*cookie);
	return fd >= 0 && cookie != NULL && getsockopt(fd, SOL_SOCKET, SO_COOKIE, cookie, &length) == 0 && length == sizeof(*cookie) && *cookie != 0 ? 0 : -1;
#else
	(void)fd;
	(void)cookie;
	return -1;
#endif
}

int swz_send_fd(int channel_fd, int fd_to_send, const void *payload, size_t payload_length)
{
	char control[CMSG_SPACE(sizeof(int))];
	struct iovec vector = { .iov_base = (void *)payload, .iov_len = payload_length };
	struct msghdr message = { .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *header;
	if (channel_fd < 0 || fd_to_send < 0 || (payload_length != 0 && payload == NULL) || payload_length > 4096 || (header = CMSG_FIRSTHDR(&message)) == NULL)
		return -1;
	memset(control, 0, sizeof(control));
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(header), &fd_to_send, sizeof(fd_to_send));
	return sendmsg(channel_fd, &message, MSG_NOSIGNAL) == (ssize_t)payload_length ? 0 : -1;
}

int swz_receive_fd(int channel_fd, int *received_fd, void *payload, size_t payload_capacity, size_t *payload_length)
{
	char control[CMSG_SPACE(sizeof(int))];
	struct iovec vector = { .iov_base = payload, .iov_len = payload_capacity };
	struct msghdr message = { .msg_iov = &vector, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control) };
	struct cmsghdr *header;
	int count = 0;
	ssize_t received;
	if (channel_fd < 0 || received_fd == NULL || payload_length == NULL || (payload_capacity != 0 && payload == NULL))
		return -1;
	memset(control, 0, sizeof(control));
	received = recvmsg(channel_fd, &message, 0);
	if (received < 0 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
		return -1;
	for (header = CMSG_FIRSTHDR(&message); header != NULL; header = CMSG_NXTHDR(&message, header)) {
		if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS || header->cmsg_len != CMSG_LEN(sizeof(int)) || ++count != 1)
			return -1;
		memcpy(received_fd, CMSG_DATA(header), sizeof(*received_fd));
	}
	if (count != 1 || *received_fd < 0 || swz_close_on_exec(*received_fd) != 0)
		return -1;
	*payload_length = (size_t)received;
	return 0;
}

int swz_secure_socket_path(const char *path, uid_t owner)
{
	struct stat info;
	return path != NULL && lstat(path, &info) == 0 && S_ISSOCK(info.st_mode) && info.st_uid == owner && (info.st_mode & 0077) == 0 ? 0 : -1;
}

int swz_parse_fd(const char *text, int *fd)
{
	char *end = NULL;
	long value;
	if (text == NULL || fd == NULL || *text == '\0')
		return -1;
	errno = 0;
	value = strtol(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || value < 0 || value > INT_MAX)
		return -1;
	*fd = (int)value;
	return 0;
}

static int nonzero_bytes(const uint8_t *value, size_t length)
{
	uint8_t combined = 0;
	for (size_t index = 0; index < length; index++)
		combined |= value[index];
	return combined != 0;
}

int swz_build_registration_record(uint8_t out[SWZ_REGISTRATION_BYTES], const uint8_t generation_raw32[32], const uint8_t accepted_connection_raw32[32], const uint8_t connection_cookie_raw32[32])
{
	if (out == NULL || generation_raw32 == NULL || accepted_connection_raw32 == NULL || connection_cookie_raw32 == NULL ||
		!nonzero_bytes(generation_raw32, 32) || !nonzero_bytes(accepted_connection_raw32, 32) || !nonzero_bytes(connection_cookie_raw32, 32))
		return -1;
	memcpy(out, SWZ_REGISTRATION_MAGIC, 8);
	memcpy(out + 8, generation_raw32, 32);
	memcpy(out + 40, accepted_connection_raw32, 32);
	memcpy(out + 72, connection_cookie_raw32, 32);
	return 0;
}

int swz_validate_registration_record(const uint8_t record[SWZ_REGISTRATION_BYTES])
{
	return record != NULL && memcmp(record, SWZ_REGISTRATION_MAGIC, 8) == 0 && nonzero_bytes(record + 8, 32) && nonzero_bytes(record + 40, 32) && nonzero_bytes(record + 72, 32) ? 0 : -1;
}

int swz_build_context_record(uint8_t out[SWZ_CONTEXT_BYTES], const uint8_t session_raw32[32], const uint8_t generation_raw32[32], const uint8_t accepted_connection_raw32[32], const uint8_t connection_cookie_raw32[32])
{
	if (out == NULL || session_raw32 == NULL || generation_raw32 == NULL || accepted_connection_raw32 == NULL || connection_cookie_raw32 == NULL ||
		!nonzero_bytes(session_raw32, 32) || !nonzero_bytes(generation_raw32, 32) || !nonzero_bytes(accepted_connection_raw32, 32) || !nonzero_bytes(connection_cookie_raw32, 32))
		return -1;
	memcpy(out, SWZ_CONTEXT_MAGIC, 8);
	memcpy(out + 8, session_raw32, 32);
	memcpy(out + 40, generation_raw32, 32);
	memcpy(out + 72, accepted_connection_raw32, 32);
	memcpy(out + 104, connection_cookie_raw32, 32);
	return 0;
}

int swz_validate_context_record(const uint8_t record[SWZ_CONTEXT_BYTES])
{
	return record != NULL && memcmp(record, SWZ_CONTEXT_MAGIC, 8) == 0 && nonzero_bytes(record + 8, 32) && nonzero_bytes(record + 40, 32) && nonzero_bytes(record + 72, 32) && nonzero_bytes(record + 104, 32) ? 0 : -1;
}

int swz_read_context_record(int fd, uint8_t session_raw32[32], uint8_t generation_raw32[32], uint8_t accepted_connection_raw32[32], uint8_t connection_cookie_raw32[32])
{
	uint8_t record[SWZ_CONTEXT_BYTES];
	int result = -1;
	if (session_raw32 == NULL || generation_raw32 == NULL || accepted_connection_raw32 == NULL || connection_cookie_raw32 == NULL ||
		swz_read_exact_eof(fd, record, sizeof(record), 5000) != 0 || swz_validate_context_record(record) != 0)
		goto done;
	memcpy(session_raw32, record + 8, 32);
	memcpy(generation_raw32, record + 40, 32);
	memcpy(accepted_connection_raw32, record + 72, 32);
	memcpy(connection_cookie_raw32, record + 104, 32);
	result = 0;
done:
	swz_zeroize(record, sizeof(record));
	if (result != 0) {
		if (session_raw32 != NULL) swz_zeroize(session_raw32, 32);
		if (generation_raw32 != NULL) swz_zeroize(generation_raw32, 32);
		if (accepted_connection_raw32 != NULL) swz_zeroize(accepted_connection_raw32, 32);
		if (connection_cookie_raw32 != NULL) swz_zeroize(connection_cookie_raw32, 32);
	}
	return result;
}

int swz_literal_ipv4(const char *text, uint8_t out[4])
{
	struct in_addr address;
	char canonical[INET_ADDRSTRLEN];
	if (text == NULL || out == NULL || inet_pton(AF_INET, text, &address) != 1 || inet_ntop(AF_INET, &address, canonical, sizeof(canonical)) == NULL ||
		strcmp(text, canonical) != 0 || address.s_addr == htonl(INADDR_ANY) || (ntohl(address.s_addr) >> 28) == 0xE)
		return -1;
	memcpy(out, &address, sizeof(address));
	return 0;
}

int swz_confine_process(void)
{
	struct rlimit core = { .rlim_cur = 0, .rlim_max = 0 };
	return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 && prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 && setrlimit(RLIMIT_CORE, &core) == 0 ? 0 : -1;
}
