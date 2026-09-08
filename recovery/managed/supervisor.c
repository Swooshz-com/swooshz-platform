#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static void on_signal(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static int valid_owned_file(const char *path, int executable)
{
	struct stat info;
	return path != NULL && lstat(path, &info) == 0 && S_ISREG(info.st_mode) && (info.st_mode & 0022) == 0 && (!executable || (info.st_mode & 0111) != 0) ? 0 : -1;
}

static int ensure_runtime_directory(void)
{
	struct stat info;
	if (mkdir("/run/swz", 0700) != 0 && errno != EEXIST)
		return -1;
	return stat("/run/swz", &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == geteuid() && (info.st_mode & 0077) == 0 ? 0 : -1;
}

static int acquire_generation_lock(int *lock_fd)
{
	struct stat info;
	if (lock_fd == NULL || mkdir("/run/swz/recovery-generation.lock", 0700) != 0 ||
		stat("/run/swz/recovery-generation.lock", &info) != 0 || !S_ISDIR(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0077) != 0 ||
		(*lock_fd = open("/run/swz/recovery-generation.lock", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)) < 0 || flock(*lock_fd, LOCK_EX | LOCK_NB) != 0)
		return -1;
	return 0;
}

static void release_generation_lock(int lock_fd)
{
	if (lock_fd >= 0)
		close(lock_fd);
	(void)rmdir("/run/swz/recovery-generation.lock");
}

static int remove_owned_socket(const char *path)
{
	struct stat info;
	if (lstat(path, &info) != 0) {
		return errno == ENOENT ? 0 : -1;
	}
	if (!S_ISSOCK(info.st_mode) || info.st_uid != geteuid() || (info.st_mode & 0077) != 0)
		return -1;
	return unlink(path);
}

static int bind_runtime_socket(const char *path, int type, int backlog)
{
	struct sockaddr_un address;
	int fd = -1;
	if (remove_owned_socket(path) != 0 || (fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0)) < 0)
		return -1;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(address.sun_path))
		goto fail;
	memcpy(address.sun_path, path, strlen(path) + 1);
	if (bind(fd, (const struct sockaddr *)&address, sizeof(address)) != 0 || chmod(path, 0600) != 0 || listen(fd, backlog) != 0 || swz_secure_socket_path(path, geteuid()) != 0)
		goto fail;
	return fd;
fail:
	close(fd);
	(void)remove_owned_socket(path);
	return -1;
}

static void cleanup_runtime_socket(const char *path, int *fd)
{
	if (fd != NULL && *fd >= 0) {
		close(*fd);
		*fd = -1;
	}
	if (path != NULL)
		(void)remove_owned_socket(path);
}

static int open_seed_descriptor(int supplied_fd)
{
	int flags;
	if (supplied_fd < 0 || swz_validate_seed_fd(supplied_fd, geteuid(), getegid()) != 0)
		return -1;
	flags = fcntl(supplied_fd, F_GETFD);
	if (flags < 0 || fcntl(supplied_fd, F_SETFD, flags & ~FD_CLOEXEC) != 0)
		return -1;
	return supplied_fd;
}

static int read_word(int fd, const char expected[8])
{
	char word[8];
	return swz_read_full(fd, word, sizeof(word), 5000) == 0 && memcmp(word, expected, sizeof(word)) == 0 ? 0 : -1;
}

static int start_custodian(int seed_fd, int agent_listener_fd, int *control_fd, pid_t *custodian_pid, int *custodian_pidfd)
{
	int channels[2] = { -1, -1 };
	pid_t child;
	int pidfd = -1;
	if (control_fd == NULL || custodian_pid == NULL || custodian_pidfd == NULL || socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channels) != 0)
		return -1;
	child = fork();
	if (child < 0)
		goto fail;
	if (child == 0) {
		char seed_text[16];
		char listener_text[16];
		char control_text[16];
		int seed_flags = fcntl(seed_fd, F_GETFD);
		int listener_flags = fcntl(agent_listener_fd, F_GETFD);
		int control_flags = fcntl(channels[1], F_GETFD);
		if (seed_flags < 0 || listener_flags < 0 || control_flags < 0 || fcntl(seed_fd, F_SETFD, seed_flags & ~FD_CLOEXEC) != 0 ||
			fcntl(agent_listener_fd, F_SETFD, listener_flags & ~FD_CLOEXEC) != 0 || fcntl(channels[1], F_SETFD, control_flags & ~FD_CLOEXEC) != 0 ||
			snprintf(seed_text, sizeof(seed_text), "%d", seed_fd) <= 0 || snprintf(listener_text, sizeof(listener_text), "%d", agent_listener_fd) <= 0 || snprintf(control_text, sizeof(control_text), "%d", channels[1]) <= 0)
			_exit(126);
		close(channels[0]);
		(void)clearenv();
		execl(SWZ_CUSTODIAN_PATH, SWZ_CUSTODIAN_PATH, "--seed-fd", seed_text, "--agent-listener-fd", listener_text, "--control-fd", control_text, (char *)NULL);
		_exit(127);
	}
	close(channels[1]);
	channels[1] = -1;
	pidfd = swz_pidfd_open(child);
	if (pidfd < 0 || read_word(channels[0], "SWZRDY01") != 0)
		goto fail_child;
	*control_fd = channels[0];
	*custodian_pid = child;
	*custodian_pidfd = pidfd;
	return 0;
fail_child:
	if (pidfd >= 0) {
		(void)swz_pidfd_send_signal(pidfd, SIGTERM);
		(void)swz_wait_final(child, pidfd, 1000, &(int){ 0 });
		close(pidfd);
	}
fail:
	if (channels[0] >= 0)
		close(channels[0]);
	if (channels[1] >= 0)
		close(channels[1]);
	return -1;
}

static int send_registration(int control_fd, int sshd_pidfd, const uint8_t generation_raw32[32], const uint8_t connection_raw32[32], const uint8_t cookie_raw32[32])
{
	uint8_t record[SWZ_REGISTRATION_BYTES] = { 0 };
	int result = -1;
	if (swz_build_registration_record(record, generation_raw32, connection_raw32, cookie_raw32) == 0 &&
		swz_send_fd(control_fd, sshd_pidfd, record, sizeof(record)) == 0 &&
		read_word(control_fd, "SWZRGOK1") == 0 && swz_pidfd_is_live(sshd_pidfd) == 0)
		result = 0;
	swz_zeroize(record, sizeof(record));
	return result;
}

static int disable_signing(int control_fd)
{
	return swz_write_full(control_fd, "SWZDIS01", 8) == 0 && read_word(control_fd, "SWZDSOK1") == 0 ? 0 : -1;
}

static int retire_custodian(int control_fd)
{
	return swz_write_full(control_fd, "SWZRET01", 8) == 0 && read_word(control_fd, "SWZRTOK1") == 0 ? 0 : -1;
}

static void stop_custodian(int control_fd, pid_t pid, int pidfd, int registration_complete)
{
	int status = 0;
	if (registration_complete && control_fd >= 0 && retire_custodian(control_fd) == 0) {
		(void)swz_wait_final(pid, pidfd, 5000, &status);
	} else {
		if (control_fd >= 0)
			(void)shutdown(control_fd, SHUT_RDWR);
		(void)swz_pidfd_send_signal(pidfd, SIGTERM);
		if (swz_wait_final(pid, pidfd, 1000, &status) != 0) {
			(void)swz_pidfd_send_signal(pidfd, SIGKILL);
			(void)swz_wait_final(pid, pidfd, 1000, &status);
		}
	}
}

static void stop_registered_process(pid_t pid, int pidfd)
{
	int status = 0;
	if (swz_pidfd_send_signal(pidfd, SIGTERM) != 0 || swz_wait_final(pid, pidfd, 1000, &status) != 0) {
		(void)swz_pidfd_send_signal(pidfd, SIGKILL);
		(void)swz_wait_final(pid, pidfd, 1000, &status);
	}
}

static int child_wait_gate(int gate_fd, int connection_fd, int listener_fd, int agent_listener_fd, int session_listener_fd, int control_fd, int seed_fd)
{
	uint8_t grant;
	if (dup2(connection_fd, STDIN_FILENO) < 0 || dup2(connection_fd, STDOUT_FILENO) < 0 || swz_confine_process() != 0 ||
		swz_read_exact_eof(gate_fd, &grant, 1, 30000) != 0 || grant != SWZ_EXEC_GATE_BYTE)
		_exit(126);
	close(gate_fd);
	close(connection_fd);
	close(listener_fd);
	close(agent_listener_fd);
	close(session_listener_fd);
	close(control_fd);
	close(seed_fd);
	(void)clearenv();
	execl(SWZ_SSHD_PATH, SWZ_SSHD_PATH, "-i", "-e", "-f", SWZ_SSHD_CONFIG_PATH, (char *)NULL);
	_exit(127);
}

static int serve_session_control(int session_listener_fd, pid_t sshd_pid, int sshd_pidfd, const struct swz_namespace_identity *sshd_namespace,
	const uint8_t session_raw32[32], const uint8_t generation_raw32[32], const uint8_t connection_raw32[32], const uint8_t cookie_raw32[32], int *child_status)
{
	int context_delivered = 0;
	int child_reaped = 0;
	int status = 0;
	if (child_status == NULL)
		return -1;
	while (!child_reaped && !stop_requested) {
		struct pollfd descriptors[2] = {
			{ .fd = sshd_pidfd, .events = POLLIN },
			{ .fd = session_listener_fd, .events = context_delivered ? 0 : POLLIN },
		};
		int polled = poll(descriptors, 2, 1000);
		if (polled < 0 && errno == EINTR)
			continue;
		if (polled < 0)
			return -1;
		if ((descriptors[1].revents & POLLIN) != 0) {
			int control = accept4(session_listener_fd, NULL, NULL, SOCK_CLOEXEC);
			if (control >= 0) {
				pid_t peer_pid;
				uid_t peer_uid;
				gid_t peer_gid;
				uint8_t context[SWZ_CONTEXT_BYTES];
				int valid = swz_peer_credentials(control, &peer_pid, &peer_uid, &peer_gid) == 0 &&
					swz_pidfd_process_in_tree(sshd_pidfd, peer_pid, sshd_namespace) == 0 &&
					swz_peer_domain_matches(control, SWZ_EXPECTED_BOOTSTRAP_DOMAIN) == 0 &&
					swz_build_context_record(context, session_raw32, generation_raw32, connection_raw32, cookie_raw32) == 0;
				(void)peer_uid;
				(void)peer_gid;
				if (valid && !context_delivered) {
					valid = swz_write_full(control, context, sizeof(context)) == 0 && shutdown(control, SHUT_WR) == 0;
					if (valid)
						context_delivered = 1;
				}
				swz_zeroize(context, sizeof(context));
				close(control);
			}
		}
		if ((descriptors[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
			if (swz_wait_final(sshd_pid, sshd_pidfd, 0, &status) != 0)
				return -1;
			child_reaped = 1;
		}
	}
	if (!child_reaped && stop_requested)
		return -1;
	*child_status = status;
	return context_delivered && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int run_generation(int seed_fd, const uint8_t generation_raw32[32], const uint8_t *session_override)
{
	int listener_fd = -1;
	int connection_fd = -1;
	int agent_listener_fd = -1;
	int session_listener_fd = -1;
	int custody_fd = -1;
	int custody_pidfd = -1;
	int sshd_pidfd = -1;
	pid_t custody_pid = -1;
	pid_t sshd_pid = -1;
	int gate[2] = { -1, -1 };
	int child_status = 0;
	int registered = 0;
	int result = -1;
	uint8_t session_raw32[32] = { 0 };
	uint8_t connection_raw32[32] = { 0 };
	uint8_t cookie_raw32[32] = { 0 };
	struct swz_namespace_identity sshd_namespace;
	struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(22222) };
	if (valid_owned_file(SWZ_SSHD_PATH, 1) != 0 || valid_owned_file(SWZ_SSHD_CONFIG_PATH, 0) != 0 ||
		inet_pton(AF_INET, "10.0.2.15", &address.sin_addr) != 1 ||
		(session_override == NULL ? swz_random_bytes(session_raw32, sizeof(session_raw32)) : (memcpy(session_raw32, session_override, sizeof(session_raw32)), 0)) != 0 ||
		(connection_raw32[0] = 1, swz_random_bytes(connection_raw32 + 1, sizeof(connection_raw32) - 1) != 0) ||
		(cookie_raw32[0] = 1, swz_random_bytes(cookie_raw32 + 1, sizeof(cookie_raw32) - 1) != 0))
		goto cleanup;
	listener_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener_fd < 0 || bind(listener_fd, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener_fd, 1) != 0)
		goto cleanup;
	connection_fd = accept4(listener_fd, NULL, NULL, SOCK_CLOEXEC);
	if (connection_fd < 0)
		goto cleanup;
	close(listener_fd);
	listener_fd = -1;
	agent_listener_fd = bind_runtime_socket(SWZ_HOST_KEY_AGENT_SOCKET_PATH, SOCK_STREAM, 1);
	session_listener_fd = bind_runtime_socket(SWZ_SESSION_CONTROL_SOCKET_PATH, SOCK_SEQPACKET, 1);
	if (agent_listener_fd < 0 || session_listener_fd < 0 || start_custodian(seed_fd, agent_listener_fd, &custody_fd, &custody_pid, &custody_pidfd) != 0)
		goto cleanup;
	close(seed_fd);
	seed_fd = -1;
	if (pipe2(gate, O_CLOEXEC) != 0)
		goto cleanup;
	sshd_pid = fork();
	if (sshd_pid < 0)
		goto pregrant_failure;
	if (sshd_pid == 0)
		return child_wait_gate(gate[0], connection_fd, listener_fd, agent_listener_fd, session_listener_fd, custody_fd, seed_fd);
	close(gate[0]);
	gate[0] = -1;
	sshd_pidfd = swz_pidfd_open(sshd_pid);
	if (sshd_pidfd < 0 || swz_process_namespace(sshd_pid, &sshd_namespace) != 0 || send_registration(custody_fd, sshd_pidfd, generation_raw32, connection_raw32, cookie_raw32) != 0)
		goto pregrant_failure;
	registered = 1;
	if (swz_write_full(gate[1], (uint8_t[]){ SWZ_EXEC_GATE_BYTE }, 1) != 0)
		goto pregrant_failure;
	close(gate[1]);
	gate[1] = -1;
	if (serve_session_control(session_listener_fd, sshd_pid, sshd_pidfd, &sshd_namespace, session_raw32, generation_raw32, connection_raw32, cookie_raw32, &child_status) == 0) {
		result = 0;
	} else {
		(void)disable_signing(custody_fd);
		cleanup_runtime_socket(SWZ_SESSION_CONTROL_SOCKET_PATH, &session_listener_fd);
		stop_registered_process(sshd_pid, sshd_pidfd);
	}
	if (disable_signing(custody_fd) != 0)
		result = -1;
	goto cleanup;
pregrant_failure:
	if (registered)
		(void)disable_signing(custody_fd);
	cleanup_runtime_socket(SWZ_SESSION_CONTROL_SOCKET_PATH, &session_listener_fd);
	if (sshd_pidfd >= 0 && sshd_pid > 0)
		stop_registered_process(sshd_pid, sshd_pidfd);
cleanup:
	if (gate[1] >= 0)
		close(gate[1]);
	if (gate[0] >= 0)
		close(gate[0]);
	if (custody_fd >= 0 && custody_pidfd >= 0 && custody_pid > 0) {
		stop_custodian(custody_fd, custody_pid, custody_pidfd, registered);
	}
	if (sshd_pidfd >= 0)
		close(sshd_pidfd);
	if (custody_pidfd >= 0)
		close(custody_pidfd);
	if (custody_fd >= 0)
		close(custody_fd);
	cleanup_runtime_socket(SWZ_HOST_KEY_AGENT_SOCKET_PATH, &agent_listener_fd);
	cleanup_runtime_socket(SWZ_SESSION_CONTROL_SOCKET_PATH, &session_listener_fd);
	if (connection_fd >= 0)
		close(connection_fd);
	if (listener_fd >= 0)
		close(listener_fd);
	if (seed_fd >= 0)
		close(seed_fd);
	swz_zeroize(session_raw32, sizeof(session_raw32));
	swz_zeroize(connection_raw32, sizeof(connection_raw32));
	swz_zeroize(cookie_raw32, sizeof(cookie_raw32));
	return result;
}

static int parse_raw32(const char *text, uint8_t raw[32])
{
	return text != NULL && raw != NULL && swz_hex_decode(text, raw, 32) == 0 && memcmp(raw, (uint8_t[32]){ 0 }, 32) != 0 ? 0 : -1;
}

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s --inetd --generation-raw32 HEX64 [--session-raw32 HEX64] --seed-fd FD\n", program);
}

int main(int argc, char **argv)
{
	int inetd = 0;
	int seed_fd = -1;
	const char *generation_text = NULL;
	const char *session_text = NULL;
	uint8_t generation_raw32[32] = { 0 };
	uint8_t session_raw32[32] = { 0 };
	int lock_fd = -1;
	static const struct option options[] = {
		{ "inetd", no_argument, NULL, 'i' },
		{ "generation-raw32", required_argument, NULL, 'g' },
		{ "session-raw32", required_argument, NULL, 'u' },
		{ "seed-fd", required_argument, NULL, 's' },
		{ NULL, 0, NULL, 0 },
	};
	int option;
	while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
		switch (option) {
		case 'i': inetd = 1; break;
		case 'g': generation_text = optarg; break;
		case 'u': session_text = optarg; break;
		case 's': if (swz_parse_fd(optarg, &seed_fd) != 0) return 64; break;
		default: usage(argv[0]); return 64;
		}
	}
	if (!inetd || parse_raw32(generation_text, generation_raw32) != 0 ||
		(session_text != NULL && parse_raw32(session_text, session_raw32) != 0) ||
		(seed_fd = open_seed_descriptor(seed_fd)) < 0 || ensure_runtime_directory() != 0 || acquire_generation_lock(&lock_fd) != 0) {
		if (seed_fd >= 0) close(seed_fd);
		return 75;
	}
	(void)signal(SIGPIPE, SIG_IGN);
	struct sigaction action = { .sa_handler = on_signal };
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGINT, &action, NULL) != 0) {
		release_generation_lock(lock_fd);
		close(seed_fd);
		swz_zeroize(session_raw32, sizeof(session_raw32));
		return 70;
	}
	int result = run_generation(seed_fd, generation_raw32, session_text == NULL ? NULL : session_raw32);
	release_generation_lock(lock_fd);
	swz_zeroize(generation_raw32, sizeof(generation_raw32));
	swz_zeroize(session_raw32, sizeof(session_raw32));
	return result == 0 ? 0 : 1;
}
