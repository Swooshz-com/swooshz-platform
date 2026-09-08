#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>

#define SWZ_READY "SWZRDY01"
#define SWZ_DISABLE "SWZDIS01"
#define SWZ_DISABLE_ACK "SWZDSOK1"
#define SWZ_RETIRE "SWZRET01"
#define SWZ_RETIRE_ACK "SWZRTOK1"

#define SSH_AGENT_FAILURE 5U
#define SSH_AGENTC_REQUEST_IDENTITIES 11U
#define SSH_AGENT_IDENTITIES_ANSWER 12U
#define SSH2_AGENTC_SIGN_REQUEST 13U
#define SSH2_AGENT_SIGN_RESPONSE 14U
#define MAX_AGENT_PACKET 65536U

struct custody_state {
	int control_fd;
	int listener_fd;
	int registered_pidfd;
	pid_t registered_root_pid;
	uint64_t registered_starttime;
	struct swz_namespace_identity registered_namespace;
	uint8_t registration[SWZ_REGISTRATION_BYTES];
	int armed;
	int registration_expected;
};

static uint32_t read_u32(const uint8_t *value)
{
	return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) | ((uint32_t)value[2] << 8) | value[3];
}

static void write_u32(uint8_t *value, uint32_t input)
{
	value[0] = (uint8_t)(input >> 24);
	value[1] = (uint8_t)(input >> 16);
	value[2] = (uint8_t)(input >> 8);
	value[3] = (uint8_t)input;
}

static int send_control_word(int fd, const char word[8])
{
	return swz_write_full(fd, word, 8);
}

static int derive_host_key(int seed_fd, const uint8_t public_key[32], EVP_PKEY **key_out, uint8_t key_blob[51])
{
	uint8_t seed[32] = { 0 };
	uint8_t derived[32] = { 0 };
	size_t public_length = sizeof(derived);
	EVP_PKEY *key = NULL;
	int result = -1;
	if (public_key == NULL || key_out == NULL || key_blob == NULL || swz_read_seed_fd(seed_fd, seed) != 0)
		goto done;
	key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed));
	swz_zeroize(seed, sizeof(seed));
	if (key == NULL || EVP_PKEY_get_raw_public_key(key, derived, &public_length) != 1 || public_length != sizeof(derived) || memcmp(derived, public_key, sizeof(derived)) != 0)
		goto done;
	memset(key_blob, 0, 51);
	key_blob[3] = 11;
	memcpy(key_blob + 4, "ssh-ed25519", 11);
	key_blob[18] = 32;
	memcpy(key_blob + 19, public_key, 32);
	*key_out = key;
	key = NULL;
	result = 0;
done:
	swz_zeroize(seed, sizeof(seed));
	swz_zeroize(derived, sizeof(derived));
	if (key != NULL)
		EVP_PKEY_free(key);
	return result;
}

static int registration_valid_for_client(const struct custody_state *state, int client_fd)
{
	pid_t peer_pid;
	uid_t peer_uid;
	gid_t peer_gid;
	uint64_t starttime;
	uint64_t cookie;
	(void)peer_uid;
	(void)peer_gid;
	if (state == NULL || client_fd < 0 || !state->armed || state->registered_pidfd < 0 ||
		swz_peer_credentials(client_fd, &peer_pid, &peer_uid, &peer_gid) != 0 ||
		swz_pidfd_process_in_tree(state->registered_pidfd, peer_pid, &state->registered_namespace) != 0 ||
		swz_process_starttime(state->registered_root_pid, &starttime) != 0 || starttime != state->registered_starttime ||
		swz_peer_domain_matches(client_fd, SWZ_EXPECTED_SSHD_DOMAIN) != 0 || swz_get_socket_cookie(client_fd, &cookie) != 0)
		return -1;
	return 0;
}

static int send_agent_packet(int fd, const uint8_t *payload, size_t length)
{
	uint8_t header[4];
	if (payload == NULL || length == 0 || length > MAX_AGENT_PACKET)
		return -1;
	write_u32(header, (uint32_t)length);
	return swz_write_full(fd, header, sizeof(header)) == 0 && swz_write_full(fd, payload, length) == 0 ? 0 : -1;
}

static int send_agent_failure(int fd)
{
	const uint8_t failure[] = { SSH_AGENT_FAILURE };
	return send_agent_packet(fd, failure, sizeof(failure));
}

static int send_identities(int fd, const uint8_t key_blob[51])
{
	static const char comment[] = "swooshz-recovery-host";
	uint8_t payload[1 + 4 + 4 + 51 + 4 + sizeof(comment) - 1];
	uint8_t *cursor = payload;
	*cursor++ = SSH_AGENT_IDENTITIES_ANSWER;
	write_u32(cursor, 1);
	cursor += 4;
	write_u32(cursor, 51);
	cursor += 4;
	memcpy(cursor, key_blob, 51);
	cursor += 51;
	write_u32(cursor, sizeof(comment) - 1);
	cursor += 4;
	memcpy(cursor, comment, sizeof(comment) - 1);
	return send_agent_packet(fd, payload, sizeof(payload));
}

static int read_string(const uint8_t *payload, size_t length, size_t *cursor, const uint8_t **value, size_t *value_length)
{
	uint32_t part_length;
	if (payload == NULL || cursor == NULL || value == NULL || value_length == NULL || *cursor > length || length - *cursor < 4)
		return -1;
	part_length = read_u32(payload + *cursor);
	*cursor += 4;
	if (part_length > length - *cursor)
		return -1;
	*value = payload + *cursor;
	*value_length = part_length;
	*cursor += part_length;
	return 0;
}

static int sign_request(int fd, EVP_PKEY *key, const uint8_t key_blob[51], const uint8_t *payload, size_t length)
{
	const uint8_t *requested_key;
	const uint8_t *data;
	size_t requested_length;
	size_t data_length;
	size_t cursor = 1;
	uint8_t signature[64];
	size_t signature_length = sizeof(signature);
	uint8_t response[1 + 4 + 4 + 11 + 4 + sizeof(signature)];
	uint8_t *response_cursor = response;
	EVP_MD_CTX *context = NULL;
	int result = -1;
	if (length < 1 || read_string(payload, length, &cursor, &requested_key, &requested_length) != 0 || requested_length != 51 || memcmp(requested_key, key_blob, 51) != 0 ||
		read_string(payload, length, &cursor, &data, &data_length) != 0 || data_length == 0 || data_length > MAX_AGENT_PACKET || cursor + 4 != length || read_u32(payload + cursor) != 0)
		return send_agent_failure(fd);
	context = EVP_MD_CTX_new();
	if (context == NULL || EVP_DigestSignInit(context, NULL, NULL, NULL, key) != 1 || EVP_DigestSign(context, signature, &signature_length, data, data_length) != 1 || signature_length != sizeof(signature))
		goto done;
	*response_cursor++ = SSH2_AGENT_SIGN_RESPONSE;
	write_u32(response_cursor, 83);
	response_cursor += 4;
	write_u32(response_cursor, 11);
	response_cursor += 4;
	memcpy(response_cursor, "ssh-ed25519", 11);
	response_cursor += 11;
	write_u32(response_cursor, sizeof(signature));
	response_cursor += 4;
	memcpy(response_cursor, signature, sizeof(signature));
	result = send_agent_packet(fd, response, (size_t)(response_cursor + sizeof(signature) - response));
done:
	if (context != NULL)
		EVP_MD_CTX_free(context);
	swz_zeroize(signature, sizeof(signature));
	return result;
}

static int serve_client(const struct custody_state *state, EVP_PKEY *key, const uint8_t key_blob[51], int client_fd)
{
	uint8_t header[4];
	uint8_t payload[MAX_AGENT_PACKET];
	if (registration_valid_for_client(state, client_fd) != 0)
		return -1;
	for (;;) {
		uint32_t length;
		if (swz_read_full(client_fd, header, sizeof(header), 2000) != 0)
			return -1;
		length = read_u32(header);
		if (length == 0 || length > MAX_AGENT_PACKET || swz_read_full(client_fd, payload, length, 2000) != 0 || registration_valid_for_client(state, client_fd) != 0)
			return -1;
		switch (payload[0]) {
		case SSH_AGENTC_REQUEST_IDENTITIES:
			if (length != 1 || send_identities(client_fd, key_blob) != 0)
				return -1;
			break;
		case SSH2_AGENTC_SIGN_REQUEST:
			if (sign_request(client_fd, key, key_blob, payload, length) != 0)
				return -1;
			break;
		default:
			(void)send_agent_failure(client_fd);
			return -1;
		}
	}
}

static int install_registration(struct custody_state *state, const uint8_t record[SWZ_REGISTRATION_BYTES], int pidfd)
{
	struct swz_namespace_identity namespace_identity;
	pid_t root_pid;
	uint64_t starttime;
	if (state == NULL || record == NULL || state->armed || !state->registration_expected || pidfd < 0 || swz_validate_registration_record(record) != 0 || swz_pidfd_is_live(pidfd) != 0 ||
		swz_pidfd_target_pid(pidfd, &root_pid) != 0 || root_pid <= 1 || swz_process_starttime(root_pid, &starttime) != 0 || starttime == 0 ||
		swz_process_namespace(root_pid, &namespace_identity) != 0)
		return -1;
	memcpy(state->registration, record, sizeof(state->registration));
	state->registered_pidfd = pidfd;
	state->registered_root_pid = root_pid;
	state->registered_starttime = starttime;
	state->registered_namespace = namespace_identity;
	state->armed = 1;
	state->registration_expected = 0;
	return 0;
}

static void disarm(struct custody_state *state)
{
	if (state == NULL)
		return;
	state->armed = 0;
	if (state->listener_fd >= 0) {
		close(state->listener_fd);
		state->listener_fd = -1;
	}
	if (state->registered_pidfd >= 0) {
		close(state->registered_pidfd);
		state->registered_pidfd = -1;
	}
	swz_zeroize(state->registration, sizeof(state->registration));
}

static int serve(struct custody_state *state, EVP_PKEY *key, const uint8_t key_blob[51])
{
	if (state == NULL || key == NULL || key_blob == NULL || send_control_word(state->control_fd, SWZ_READY) != 0)
		return -1;
	for (;;) {
		struct pollfd descriptors[2] = {
			{ .fd = state->control_fd, .events = POLLIN },
			{ .fd = state->listener_fd, .events = state->listener_fd >= 0 ? POLLIN : 0 },
		};
		int result = poll(descriptors, 2, 1000);
		if (result < 0 && errno == EINTR)
			continue;
		if (result < 0)
			return -1;
		if ((descriptors[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
			if (state->registration_expected) {
				uint8_t payload[SWZ_REGISTRATION_BYTES];
				size_t length = 0;
				int pidfd = -1;
				if (swz_receive_fd(state->control_fd, &pidfd, payload, sizeof(payload), &length) != 0 ||
					length != SWZ_REGISTRATION_BYTES || install_registration(state, payload, pidfd) != 0) {
					if (pidfd >= 0)
						close(pidfd);
					return -1;
				}
				if (send_control_word(state->control_fd, "SWZRGOK1") != 0)
					return -1;
			} else {
				uint8_t word[8];
				if (swz_read_full(state->control_fd, word, sizeof(word), 5000) != 0)
					return -1;
				if (memcmp(word, SWZ_DISABLE, sizeof(word)) == 0) {
					disarm(state);
					if (send_control_word(state->control_fd, SWZ_DISABLE_ACK) != 0)
						return -1;
				} else if (memcmp(word, SWZ_RETIRE, sizeof(word)) == 0) {
					disarm(state);
					if (send_control_word(state->control_fd, SWZ_RETIRE_ACK) != 0)
						return -1;
					return 0;
				} else {
					return -1;
				}
			}
		}
		if (state->listener_fd >= 0 && (descriptors[1].revents & POLLIN) != 0) {
			int client_fd = accept4(state->listener_fd, NULL, NULL, SOCK_CLOEXEC);
			if (client_fd >= 0) {
				(void)serve_client(state, key, key_blob, client_fd);
				close(client_fd);
			}
		}
	}
}

int main(int argc, char **argv)
{
	int seed_fd = -1;
	int listener_fd = -1;
	int control_fd = -1;
	uint8_t public_key[32] = { 0 };
	uint8_t key_blob[51] = { 0 };
	EVP_PKEY *key = NULL;
	struct custody_state state = { .control_fd = -1, .listener_fd = -1, .registered_pidfd = -1, .registration_expected = 1 };
	int result = 64;
	if (argc != 7 || strcmp(argv[1], "--seed-fd") != 0 || strcmp(argv[3], "--agent-listener-fd") != 0 || strcmp(argv[5], "--control-fd") != 0 ||
		swz_parse_fd(argv[2], &seed_fd) != 0 || swz_parse_fd(argv[4], &listener_fd) != 0 || swz_parse_fd(argv[6], &control_fd) != 0 ||
		seed_fd == listener_fd || seed_fd == control_fd || listener_fd == control_fd || swz_load_ed25519_public_file(SWZ_HOST_PUBLIC_KEY_PATH, public_key) != 0)
		goto done;
	int passed_seed_fd = seed_fd;
	seed_fd = -1;
	if (derive_host_key(passed_seed_fd, public_key, &key, key_blob) != 0 || swz_confine_process() != 0)
		goto done;
	state.control_fd = control_fd;
	state.listener_fd = listener_fd;
	if (serve(&state, key, key_blob) == 0)
		result = 0;
done:
	disarm(&state);
	if (seed_fd >= 0)
		close(seed_fd);
	if (control_fd >= 0)
		close(control_fd);
	listener_fd = -1;
	if (key != NULL)
		EVP_PKEY_free(key);
	swz_zeroize(public_key, sizeof(public_key));
	swz_zeroize(key_blob, sizeof(key_blob));
	return result;
}
