#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define AGENT_MAX_PACKET 262144U
#define CUSTODY_MAX_PUBLIC_KEY 4096U

static int valid_hex(const char *text, size_t octets)
{
	uint8_t decoded[32];
	return text != NULL && octets <= sizeof(decoded) &&
	    swz_hex_decode(text, decoded, octets) == 0;
}

static int valid_path(const char *path)
{
	size_t length = path == NULL ? 0 : strlen(path);
	if (path == NULL || path[0] != '/' || length < 2 ||
	    length >= sizeof(((struct sockaddr_un *)0)->sun_path))
		return -1;
	if (strstr(path, "//") != NULL || strstr(path, "/../") != NULL ||
	    (length >= 3 && strcmp(path + length - 3, "/..") == 0))
		return -1;
	return 0;
}

static int owned_regular_file(const char *path, mode_t required_mode)
{
	struct stat info;
	if (lstat(path, &info) != 0 || !S_ISREG(info.st_mode) ||
	    info.st_uid != getuid())
		return -1;
	if (required_mode != 0) {
		if ((info.st_mode & 0077) != 0 || (info.st_mode & 0777) != required_mode)
			return -1;
	} else if ((info.st_mode & S_IXUSR) == 0) {
		return -1;
	}
	return 0;
}

static int remove_owned_socket(const char *path)
{
	struct stat info;
	if (lstat(path, &info) != 0)
		return errno == ENOENT ? 0 : -1;
	if (!S_ISSOCK(info.st_mode) || info.st_uid != getuid() || (info.st_mode & 0077) != 0)
		return -1;
	return unlink(path);
}

static int load_public_blob(const char *path, uint8_t *blob, size_t capacity, size_t *length)
{
	if (owned_regular_file(path, 0644) != 0)
		return -1;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;
	char text[CUSTODY_MAX_PUBLIC_KEY];
	ssize_t count = read(fd, text, sizeof(text) - 1);
	close(fd);
	if (count <= 0)
		return -1;
	text[count] = '\0';
	char *cursor = text;
	while (*cursor == ' ' || *cursor == '\t')
		cursor++;
	if (strncmp(cursor, "ssh-ed25519", 11) != 0 ||
	    (cursor[11] != ' ' && cursor[11] != '\t'))
		return -1;
	cursor += 11;
	while (*cursor == ' ' || *cursor == '\t')
		cursor++;
	char *end = cursor;
	while (*end != '\0' && *end != ' ' && *end != '\t' && *end != '\r' && *end != '\n')
		end++;
	if (end == cursor)
		return -1;
	*end = '\0';
	size_t encoded_length = strlen(cursor);
	if (encoded_length > 4096 || capacity < 51)
		return -1;
	if (encoded_length == 0 || encoded_length % 4 != 0)
		return -1;
	uint8_t decoded[CUSTODY_MAX_PUBLIC_KEY];
	int decoded_length = EVP_DecodeBlock(decoded, (const unsigned char *)cursor, (int)encoded_length);
	if (decoded_length <= 0)
		return -1;
	while (encoded_length > 0 && cursor[encoded_length - 1] == '=')
		decoded_length--;
	if (decoded_length != 51 || memcmp(decoded, "\0\0\0\vssh-ed25519\0\0\0 ", 19) != 0)
		return -1;
	memcpy(blob, decoded, 51);
	*length = 51;
	return 0;
}

static int make_backend_path(const char *socket_path, char *out, size_t out_size)
{
	int written = snprintf(out, out_size, "%s.agent-%ld", socket_path, (long)getpid());
	return written > 0 && (size_t)written < out_size ? 0 : -1;
}

static int connect_socket(const char *path)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	struct sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static pid_t start_agent(const char *agent_path, const char *backend_path)
{
	pid_t child = fork();
	if (child != 0)
		return child;
	if (setenv("SSH_AUTH_SOCK", backend_path, 1) != 0)
		_exit(126);
	int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
	if (null_fd >= 0) {
		(void)dup2(null_fd, STDIN_FILENO);
		(void)dup2(null_fd, STDOUT_FILENO);
		(void)dup2(null_fd, STDERR_FILENO);
		if (null_fd > STDERR_FILENO)
			close(null_fd);
	}
	execl(agent_path, agent_path, "-D", "-a", backend_path, (char *)NULL);
	_exit(127);
}

static int add_key(const char *add_path, const char *backend_path, const char *private_key)
{
	pid_t child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		if (setenv("SSH_AUTH_SOCK", backend_path, 1) != 0)
			_exit(126);
		int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (null_fd >= 0) {
			(void)dup2(null_fd, STDIN_FILENO);
			(void)dup2(null_fd, STDOUT_FILENO);
			(void)dup2(null_fd, STDERR_FILENO);
			if (null_fd > STDERR_FILENO)
				close(null_fd);
		}
		execl(add_path, add_path, "-q", private_key, (char *)NULL);
		_exit(127);
	}
	int status = 0;
	pid_t waited;
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited != child)
		return -1;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int wait_for_socket(const char *path)
{
	for (unsigned int attempt = 0; attempt < 200; attempt++) {
		if (lstat(path, &(struct stat){ 0 }) == 0 && swz_secure_socket_path(path, getuid()) == 0) {
			int probe = connect_socket(path);
			if (probe >= 0) {
				close(probe);
				return 0;
			}
		}
		struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000L };
		(void)nanosleep(&delay, NULL);
	}
	return -1;
}

static int terminate_agent(pid_t agent_pid)
{
	int pidfd = swz_pidfd_open(agent_pid);
	if (pidfd < 0)
		return -1;
	int result = swz_pidfd_send_signal(pidfd, SIGTERM);
	close(pidfd);
	int status = 0;
	for (unsigned int attempt = 0; attempt < 100; attempt++) {
		pid_t waited = waitpid(agent_pid, &status, WNOHANG);
		if (waited == agent_pid) {
			if (result != 0)
				return -1;
			if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
				return 0;
			if (WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM)
				return 0;
			return -1;
		}
		if (waited < 0 && errno != EINTR)
			return -1;
		struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000L };
		(void)nanosleep(&delay, NULL);
	}
	(void)kill(agent_pid, SIGKILL);
	if (waitpid(agent_pid, &status, 0) != agent_pid)
		return -1;
	return -1;
}

static int read_exact(int fd, uint8_t *buffer, size_t length, int *clean_eof)
{
	size_t used = 0;
	*clean_eof = 0;
	while (used < length) {
		ssize_t count = read(fd, buffer + used, length - used);
		if (count < 0 && errno == EINTR)
			continue;
		if (count == 0) {
			if (used == 0)
				*clean_eof = 1;
			return -1;
		}
		if (count < 0)
			return -1;
		used += (size_t)count;
	}
	return 0;
}

static int read_packet(int fd, uint8_t **packet, size_t *length)
{
	uint8_t header[4];
	int clean_eof = 0;
	if (read_exact(fd, header, sizeof(header), &clean_eof) != 0)
		return clean_eof ? 1 : -1;
	uint32_t packet_length = ((uint32_t)header[0] << 24) |
	    ((uint32_t)header[1] << 16) | ((uint32_t)header[2] << 8) | header[3];
	if (packet_length == 0 || packet_length > AGENT_MAX_PACKET)
		return -1;
	uint8_t *value = malloc(packet_length);
	if (value == NULL)
		return -1;
	if (read_exact(fd, value, packet_length, &clean_eof) != 0) {
		free(value);
		return -1;
	}
	*packet = value;
	*length = packet_length;
	return 0;
}

static int write_packet(int fd, const uint8_t *packet, size_t length)
{
	if (length == 0 || length > AGENT_MAX_PACKET)
		return -1;
	uint8_t header[4] = {
		(uint8_t)(length >> 24), (uint8_t)(length >> 16),
		(uint8_t)(length >> 8), (uint8_t)length,
	};
	return swz_write_full(fd, header, sizeof(header)) == 0 &&
	    swz_write_full(fd, packet, length) == 0 ? 0 : -1;
}

static int valid_sign_request(const uint8_t *packet, size_t length, const uint8_t *public_blob, size_t public_length)
{
	if (length < 1 + 4 + 4 + 4 || packet[0] != 13)
		return -1;
	size_t offset = 1;
	uint32_t key_length = ((uint32_t)packet[offset] << 24) |
	    ((uint32_t)packet[offset + 1] << 16) | ((uint32_t)packet[offset + 2] << 8) | packet[offset + 3];
	offset += 4;
	if (key_length != public_length || offset + key_length > length ||
	    memcmp(packet + offset, public_blob, public_length) != 0)
		return -1;
	offset += key_length;
	if (offset + 4 > length)
		return -1;
	uint32_t data_length = ((uint32_t)packet[offset] << 24) |
	    ((uint32_t)packet[offset + 1] << 16) | ((uint32_t)packet[offset + 2] << 8) | packet[offset + 3];
	offset += 4;
	if (data_length == 0 || data_length > 65536 || offset + data_length + 4 != length)
		return -1;
	offset += data_length;
	uint32_t flags = ((uint32_t)packet[offset] << 24) |
	    ((uint32_t)packet[offset + 1] << 16) | ((uint32_t)packet[offset + 2] << 8) | packet[offset + 3];
	return flags == 0 ? 0 : -1;
}

static int authorize_peer(
	int fd,
	pid_t owner_pid,
	const char *session,
	const char *generation,
	const char *cookie)
{
#ifdef SO_PEERCRED
	struct ucred credentials;
	socklen_t length = sizeof(credentials);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
	    credentials.uid != getuid() || credentials.pid <= 0 ||
	    !swz_is_descendant(credentials.pid, owner_pid))
		return -1;
	if (swz_proc_env_equals(credentials.pid, "SWZ_ACCEPTED", "1") != 0 ||
	    swz_proc_env_equals(credentials.pid, "SWZ_SESSION", session) != 0 ||
	    swz_proc_env_equals(credentials.pid, "SWZ_GENERATION", generation) != 0 ||
	    swz_proc_env_equals(credentials.pid, "SWZ_CONNECTION_COOKIE", cookie) != 0 ||
	    swz_proc_env_equals(credentials.pid, "SWZ_LIFECYCLE", "ACTIVE") != 0)
		return -1;
#else
	(void)fd;
	(void)owner_pid;
	(void)session;
	(void)generation;
	(void)cookie;
	return -1;
#endif
	return 0;
}

static int proxy_connection(int client, int backend, const uint8_t *public_blob, size_t public_length)
{
	for (;;) {
		uint8_t *request = NULL;
		size_t request_length = 0;
		int read_result = read_packet(client, &request, &request_length);
		if (read_result == 1)
			return 0;
		if (read_result != 0)
			return -1;
		int request_type = request[0];
		int valid = request_type == 11 && request_length == 1;
		if (request_type == 13)
			valid = valid_sign_request(request, request_length, public_blob, public_length) == 0;
		if (!valid || (request_type != 11 && request_type != 13) ||
		    write_packet(backend, request, request_length) != 0) {
			static const uint8_t failure[] = { 5 };
			(void)write_packet(client, failure, sizeof(failure));
			free(request);
			return -1;
		}
		free(request);
		uint8_t *response = NULL;
		size_t response_length = 0;
		read_result = read_packet(backend, &response, &response_length);
		if (read_result != 0) {
			free(response);
			return -1;
		}
		int response_type = response[0];
		if ((request_type == 11 && response_type != 12 && response_type != 5) ||
		    (request_type == 13 && response_type != 14 && response_type != 5) ||
		    write_packet(client, response, response_length) != 0) {
			free(response);
			return -1;
		}
		free(response);
	}
}

static int parse_pid(const char *text, pid_t *result)
{
	char *end = NULL;
	errno = 0;
	long value = text == NULL ? 0 : strtol(text, &end, 10);
	if (errno != 0 || end == text || end == NULL || *end != '\0' || value <= 0)
		return -1;
	*result = (pid_t)value;
	return 0;
}

static int expected_environment(const char *session, const char *generation, const char *cookie, pid_t owner_pid)
{
	const char *accepted = getenv("SWZ_ACCEPTED");
	const char *environment_session = getenv("SWZ_SESSION");
	const char *environment_generation = getenv("SWZ_GENERATION");
	const char *environment_cookie = getenv("SWZ_CONNECTION_COOKIE");
	const char *lifecycle = getenv("SWZ_LIFECYCLE");
	return owner_pid > 0 && swz_is_descendant(getpid(), owner_pid) &&
	    accepted != NULL && strcmp(accepted, "1") == 0 &&
	    environment_session != NULL && strcmp(environment_session, session) == 0 &&
	    environment_generation != NULL && strcmp(environment_generation, generation) == 0 &&
	    environment_cookie != NULL && strcmp(environment_cookie, cookie) == 0 &&
	    lifecycle != NULL && strcmp(lifecycle, "ACTIVE") == 0;
}

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s --socket PATH --agent PATH --add PATH --private-key PATH --public-key PATH --owner-pid PID --cookie HEX64 --session HEX64 --generation HEX64\n", program);
}

int main(int argc, char **argv)
{
	const char *socket_path = NULL;
	const char *agent_path = NULL;
	const char *add_path = NULL;
	const char *private_key = NULL;
	const char *public_key = NULL;
	const char *owner_pid_text = NULL;
	const char *cookie = NULL;
	const char *session = NULL;
	const char *generation = NULL;
	int option;
	static const struct option options[] = {
		{ "socket", required_argument, NULL, 's' },
		{ "agent", required_argument, NULL, 'a' },
		{ "add", required_argument, NULL, 'd' },
		{ "private-key", required_argument, NULL, 'k' },
		{ "public-key", required_argument, NULL, 'p' },
		{ "owner-pid", required_argument, NULL, 'o' },
		{ "cookie", required_argument, NULL, 'c' },
		{ "session", required_argument, NULL, 'n' },
		{ "generation", required_argument, NULL, 'g' },
		{ NULL, 0, NULL, 0 },
	};
	while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
		if (option == 's')
			socket_path = optarg;
		else if (option == 'a')
			agent_path = optarg;
		else if (option == 'd')
			add_path = optarg;
		else if (option == 'k')
			private_key = optarg;
		else if (option == 'p')
			public_key = optarg;
		else if (option == 'o')
			owner_pid_text = optarg;
		else if (option == 'c')
			cookie = optarg;
		else if (option == 'n')
			session = optarg;
		else if (option == 'g')
			generation = optarg;
		else {
			usage(argv[0]);
			return 64;
		}
	}
	pid_t owner_pid = 0;
	if (valid_path(socket_path) != 0 || valid_path(agent_path) != 0 ||
	    valid_path(add_path) != 0 || valid_path(private_key) != 0 ||
	    valid_path(public_key) != 0 || owned_regular_file(agent_path, 0) != 0 ||
	    owned_regular_file(add_path, 0) != 0 || owned_regular_file(private_key, 0600) != 0 ||
	    parse_pid(owner_pid_text, &owner_pid) != 0 || !valid_hex(cookie, 32) ||
	    !valid_hex(session, 32) || !valid_hex(generation, 32) ||
	    !expected_environment(session, generation, cookie, owner_pid))
		return 64;
	uint8_t public_blob[256];
	size_t public_length = 0;
	if (load_public_blob(public_key, public_blob, sizeof(public_blob), &public_length) != 0)
		return 65;
	char backend_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	if (make_backend_path(socket_path, backend_path, sizeof(backend_path)) != 0 ||
	    remove_owned_socket(socket_path) != 0)
		return 66;
	pid_t agent_pid = start_agent(agent_path, backend_path);
	if (agent_pid <= 0) {
		(void)unlink(backend_path);
		return 67;
	}
	if (wait_for_socket(backend_path) != 0 || add_key(add_path, backend_path, private_key) != 0) {
		(void)terminate_agent(agent_pid);
		(void)unlink(backend_path);
		return 67;
	}
	int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0) {
		(void)terminate_agent(agent_pid);
		(void)unlink(backend_path);
		return 68;
	}
	struct sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	(void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", socket_path);
	if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
	    chmod(socket_path, 0600) != 0 || listen(listener, 1) != 0 ||
	    swz_secure_socket_path(socket_path, getuid()) != 0) {
		close(listener);
		(void)unlink(socket_path);
		(void)terminate_agent(agent_pid);
		(void)unlink(backend_path);
		return 69;
	}
	int backend = connect_socket(backend_path);
	int client = accept(listener, NULL, NULL);
	int result = -1;
	if (client >= 0 && backend >= 0 &&
	    authorize_peer(client, owner_pid, session, generation, cookie) == 0)
		result = proxy_connection(client, backend, public_blob, public_length);
	if (client >= 0)
		close(client);
	if (backend >= 0)
		close(backend);
	close(listener);
	(void)unlink(socket_path);
	(void)unlink(backend_path);
	if (terminate_agent(agent_pid) != 0)
		result = -1;
	return result == 0 ? 0 : 70;
}
