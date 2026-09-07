#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested;

static void on_signal(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static int valid_digest_text(const char *text)
{
	uint8_t raw[32];
	return text != NULL && swz_hex_decode(text, raw, sizeof(raw)) == 0;
}

static int valid_runtime_path(const char *path)
{
	size_t length = path == NULL ? 0 : strlen(path);
	if (path == NULL || path[0] != '/' || length >= sizeof(((struct sockaddr_un *)0)->sun_path))
		return -1;
	if (strstr(path, "//") != NULL || strstr(path, "/../") != NULL ||
	    (length >= 3 && strcmp(path + length - 3, "/..") == 0))
		return -1;
	return 0;
}

static int valid_owned_executable(const char *path)
{
	struct stat info;
	return valid_runtime_path(path) == 0 && lstat(path, &info) == 0 &&
	    S_ISREG(info.st_mode) && info.st_uid == getuid() &&
	    (info.st_mode & 0022) == 0 && (info.st_mode & S_IXUSR) != 0;
}

static int valid_owned_config(const char *path)
{
	struct stat info;
	return valid_runtime_path(path) == 0 && lstat(path, &info) == 0 &&
	    S_ISREG(info.st_mode) && info.st_uid == getuid() &&
	    (info.st_mode & 0022) == 0;
}

static int runtime_environment(const char *generation)
{
	const char *accepted = getenv("SWZ_ACCEPTED");
	const char *authorized = getenv("SWZ_LAUNCH_AUTHORIZED");
	const char *lifecycle = getenv("SWZ_LIFECYCLE");
	const char *environment_generation = getenv("SWZ_GENERATION");
	return accepted != NULL && strcmp(accepted, "1") == 0 &&
	    authorized != NULL && strcmp(authorized, "1") == 0 &&
	    lifecycle != NULL && strcmp(lifecycle, "ACTIVE") == 0 &&
	    environment_generation != NULL && generation != NULL &&
	    strcmp(environment_generation, generation) == 0;
}

static int parse_port(const char *text, uint16_t *port)
{
	char *end = NULL;
	errno = 0;
	unsigned long value = text == NULL ? 0UL : strtoul(text, &end, 10);
	if (errno != 0 || end == text || end == NULL || *end != '\0' ||
	    value == 0UL || value > 65535UL || port == NULL)
		return -1;
	*port = (uint16_t)value;
	return 0;
}

static int remove_owned_socket(const char *path)
{
	struct stat info;
	if (lstat(path, &info) != 0) {
		if (errno == ENOENT)
			return 0;
		return -1;
	}
	if (!S_ISSOCK(info.st_mode) || info.st_uid != getuid() || (info.st_mode & 0077) != 0)
		return -1;
	return unlink(path);
}

static int make_lock_path(const char *socket_path, char *out, size_t out_size)
{
	int written = snprintf(out, out_size, "%s.generation-lock", socket_path);
	return written > 0 && (size_t)written < out_size ? 0 : -1;
}

static int acquire_generation_lock(const char *lock_path)
{
	if (mkdir(lock_path, 0700) != 0)
		return -1;
	int lock = open(lock_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (lock < 0 || flock(lock, LOCK_EX | LOCK_NB) != 0) {
		if (lock >= 0)
			close(lock);
		(void)rmdir(lock_path);
		return -1;
	}
	return lock;
}

static void release_generation_lock(int lock, const char *lock_path)
{
	close(lock);
	(void)rmdir(lock_path);
}

static int handshake(int fd, const char *generation)
{
	char input[192];
	size_t used = 0;
	for (;;) {
		struct pollfd event = { .fd = fd, .events = POLLIN };
		int ready = poll(&event, 1, 3000);
		if (ready <= 0 || (event.revents & (POLLERR | POLLNVAL)) != 0 ||
		    (event.revents & POLLIN) == 0)
			return -1;
		ssize_t count = read(fd, input + used, sizeof(input) - used - 1);
		if (count <= 0)
			return -1;
		used += (size_t)count;
		input[used] = '\0';
		if (memchr(input, '\n', used) != NULL)
			break;
		if (used + 1 >= sizeof(input))
			return -1;
	}
	char expected[128];
	int written = snprintf(expected, sizeof(expected), "SWZ-CONNECTION-V1 %s\n", generation);
	if (written <= 0 || (size_t)written >= sizeof(expected) ||
	    used != (size_t)written || memcmp(input, expected, used) != 0)
		return -1;
	static const char response[] = "SWZ-CONNECTION-ACCEPTED\n";
	return swz_write_full(fd, response, sizeof(response) - 1);
}

static int accept_one(int listener, const char *generation)
{
	int connection = accept(listener, NULL, NULL);
	if (connection < 0)
		return stop_requested ? 0 : -1;
	(void)swz_close_on_exec(connection);
#ifdef SO_PEERCRED
	struct ucred credentials;
	socklen_t credentials_length = sizeof(credentials);
	if (getsockopt(connection, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_length) != 0 ||
	    credentials.uid != getuid() || credentials.pid <= 0) {
		close(connection);
		return -1;
	}
#endif
	int result = handshake(connection, generation);
	(void)shutdown(connection, SHUT_WR);
	close(connection);
	return result;
}

static int wait_child_bounded(pid_t child)
{
	int pidfd = swz_pidfd_open(child);
	if (pidfd < 0)
		return -1;
	struct pollfd event = { .fd = pidfd, .events = POLLIN };
	int ready = poll(&event, 1, 30000);
	if (ready <= 0) {
		(void)swz_pidfd_send_signal(pidfd, SIGTERM);
		ready = poll(&event, 1, 1000);
		if (ready <= 0) {
			(void)swz_pidfd_send_signal(pidfd, SIGKILL);
			ready = poll(&event, 1, 1000);
		}
	}
	close(pidfd);
	if (ready <= 0)
		return -1;
	int status = 0;
	pid_t waited;
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited != child || !WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int run_inetd(const char *address_text, uint16_t port, const char *sshd_path, const char *config_path, const char *generation)
{
	uint8_t address_bytes[4];
	if (swz_literal_ipv4(address_text, address_bytes) != 0)
		return -1;
	int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0)
		return -1;
	int reuse = 1;
	struct sockaddr_in address;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	memcpy(&address.sin_addr, address_bytes, sizeof(address_bytes));
	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
	    bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
	    listen(listener, 1) != 0) {
		close(listener);
		return -1;
	}
	printf("SUPERVISOR_INETD_ACTIVE generation=%s address=%s port=%u pid=%ld\n",
	    generation, address_text, (unsigned int)port, (long)getpid());
	fflush(stdout);
	int connection = accept(listener, NULL, NULL);
	if (connection < 0) {
		close(listener);
		return -1;
	}
	(void)swz_close_on_exec(connection);
	pid_t child = fork();
	if (child < 0) {
		close(connection);
		close(listener);
		return -1;
	}
	if (child == 0) {
		if (dup2(connection, STDIN_FILENO) < 0 || dup2(connection, STDOUT_FILENO) < 0)
			_exit(126);
		if (connection > STDERR_FILENO)
			close(connection);
		execl(sshd_path, sshd_path, "-i", "-e", "-f", config_path, (char *)NULL);
		_exit(127);
	}
	close(connection);
	int result = wait_child_bounded(child);
	close(listener);
	printf("SUPERVISOR_INETD_RETIRED generation=%s pid=%ld\n", generation, (long)getpid());
	fflush(stdout);
	return result;
}

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s --socket ABSOLUTE_PATH --generation HEX64 [--once]\n", program);
	fprintf(stderr, "       %s --inetd --address IPV4 --port PORT --sshd PATH --config PATH --generation HEX64\n", program);
}

int main(int argc, char **argv)
{
	const char *socket_path = NULL;
	const char *generation = NULL;
	const char *inetd_address = NULL;
	const char *port_text = NULL;
	const char *sshd_path = NULL;
	const char *config_path = NULL;
	int inetd = 0;
	int once = 0;
	int option;
	static const struct option options[] = {
		{ "socket", required_argument, NULL, 's' },
		{ "generation", required_argument, NULL, 'g' },
		{ "once", no_argument, NULL, '1' },
		{ "inetd", no_argument, NULL, 'i' },
		{ "address", required_argument, NULL, 'a' },
		{ "port", required_argument, NULL, 'p' },
		{ "sshd", required_argument, NULL, 'h' },
		{ "config", required_argument, NULL, 'f' },
		{ NULL, 0, NULL, 0 },
	};
	while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
		if (option == 's')
			socket_path = optarg;
		else if (option == 'g')
			generation = optarg;
		else if (option == '1')
			once = 1;
		else if (option == 'i')
			inetd = 1;
		else if (option == 'a')
			inetd_address = optarg;
		else if (option == 'p')
			port_text = optarg;
		else if (option == 'h')
			sshd_path = optarg;
		else if (option == 'f')
			config_path = optarg;
		else {
			usage(argv[0]);
			return 64;
		}
	}
	if (generation == NULL || !valid_digest_text(generation) || !runtime_environment(generation)) {
		usage(argv[0]);
		return 64;
	}
	if (inetd) {
		uint16_t port = 0;
		char lock_path[sizeof(((struct sockaddr_un *)0)->sun_path) + 32];
		if (socket_path != NULL || inetd_address == NULL || port_text == NULL ||
		    sshd_path == NULL || config_path == NULL || parse_port(port_text, &port) != 0 ||
		    valid_owned_executable(sshd_path) != 0 || valid_owned_config(config_path) != 0 ||
		    make_lock_path("/run/swz/inetd.sock", lock_path, sizeof(lock_path)) != 0)
			return 64;
		int lock = acquire_generation_lock(lock_path);
		if (lock < 0)
			return 75;
		int result = run_inetd(inetd_address, port, sshd_path, config_path, generation);
		release_generation_lock(lock, lock_path);
		return result == 0 ? 0 : 1;
	}
	if (socket_path == NULL || valid_runtime_path(socket_path) != 0) {
		usage(argv[0]);
		return 64;
	}
	struct sigaction action = { .sa_handler = on_signal };
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	if (sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGINT, &action, NULL) != 0)
		return 70;
	char lock_path[sizeof(((struct sockaddr_un *)0)->sun_path) + 32];
	if (make_lock_path(socket_path, lock_path, sizeof(lock_path)) != 0)
		return 64;
	int lock = acquire_generation_lock(lock_path);
	if (lock < 0)
		return 75;
	if (remove_owned_socket(socket_path) != 0) {
		release_generation_lock(lock, lock_path);
		return 75;
	}
	int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0) {
		release_generation_lock(lock, lock_path);
		return 71;
	}
	struct sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
	if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
	    chmod(socket_path, 0600) != 0 || listen(listener, 1) != 0) {
		close(listener);
		(void)unlink(socket_path);
		release_generation_lock(lock, lock_path);
		return 71;
	}
	printf("SUPERVISOR_ACTIVE generation=%s pid=%ld\n", generation, (long)getpid());
	fflush(stdout);
	(void)once;
	/* A generation owns exactly one recovery connection before retirement. */
	int result = accept_one(listener, generation);
	close(listener);
	(void)unlink(socket_path);
	printf("SUPERVISOR_RETIRED generation=%s pid=%ld\n", generation, (long)getpid());
	fflush(stdout);
	release_generation_lock(lock, lock_path);
	return result == 0 ? 0 : 1;
}
