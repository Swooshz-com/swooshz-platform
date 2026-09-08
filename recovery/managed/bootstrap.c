#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static int context_magic_is_fixed(void)
{
	static const uint8_t expected[] = SWZ_CONTEXT_MAGIC;
	return sizeof(expected) - 1 == 8 && memcmp(expected, "SWZCTX01", 8) == 0 ? 0 : -1;
}

static int connect_session_control(uint8_t session_raw32[32], uint8_t generation_raw32[32], uint8_t connection_raw32[32], uint8_t cookie_raw32[32])
{
	struct sockaddr_un address;
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0 || context_magic_is_fixed() != 0 || swz_secure_socket_path(SWZ_SESSION_CONTROL_SOCKET_PATH, 0) != 0)
		goto fail;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	if (strlen(SWZ_SESSION_CONTROL_SOCKET_PATH) >= sizeof(address.sun_path))
		goto fail;
	memcpy(address.sun_path, SWZ_SESSION_CONTROL_SOCKET_PATH, strlen(SWZ_SESSION_CONTROL_SOCKET_PATH) + 1);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 || swz_read_context_record(fd, session_raw32, generation_raw32, connection_raw32, cookie_raw32) != 0)
		goto fail;
	close(fd);
	return 0;
fail:
	if (fd >= 0)
		close(fd);
	return -1;
}

static int make_hex(const uint8_t value[32], char output[65])
{
	static const char hex[] = "0123456789abcdef";
	if (value == NULL || output == NULL)
		return -1;
	for (size_t index = 0; index < 32; index++) {
		output[index * 2] = hex[value[index] >> 4];
		output[index * 2 + 1] = hex[value[index] & 0x0fU];
	}
	output[64] = '\0';
	return 0;
}

static int emit_payload(uint8_t message, uint64_t sequence, const char session_hex[65])
{
	uint8_t nonce[32];
	char payload[256];
	const char *name = swz_message_name(message);
	int length;
	struct swz_frame frame;
	if (name == NULL || session_hex == NULL || swz_random_bytes(nonce, sizeof(nonce)) != 0 ||
		(length = snprintf(payload, sizeof(payload), "[\"%s\",2,\"swz-managed.v1\",\"%s\"]", name, session_hex)) <= 0 || (size_t)length >= sizeof(payload))
		return -1;
	memset(&frame, 0, sizeof(frame));
	frame.direction = SWZ_REMOTE_TO_LOCAL;
	frame.message = message;
	frame.sequence = sequence;
	memcpy(frame.nonce, nonce, sizeof(frame.nonce));
	frame.payload_length = (uint32_t)length;
	frame.payload = (const uint8_t *)payload;
	return swz_frame_write_fd(STDOUT_FILENO, &frame);
}

static int read_expected(uint8_t expected_message, uint8_t expected_direction, uint64_t expected_sequence, uint8_t *buffer, size_t *length)
{
	struct swz_frame frame;
	if (swz_frame_read_fd(STDIN_FILENO, buffer, SWZ_MAX_FRAME, length, 10000) != 0 || swz_frame_decode(buffer, *length, &frame) != 0 ||
		frame.direction != expected_direction || frame.message != expected_message || frame.sequence != expected_sequence || swz_frame_is_canonical_json(frame.payload, frame.payload_length) != 0)
		return -1;
	return 0;
}

static int read_boot_session(const uint8_t *buffer, size_t length, char session_hex[65])
{
	struct swz_frame frame;
	static const char prefix[] = "[\"BOOT\",2,\"swz-managed.v1\",\"";
	static const char suffix[] = "\"]";
	const size_t expected_length = sizeof(prefix) - 1 + 64 + sizeof(suffix) - 1;
	uint8_t raw[32];
	if (session_hex == NULL || swz_frame_decode(buffer, length, &frame) != 0 || frame.direction != SWZ_LOCAL_TO_REMOTE || frame.message != SWZ_BOOT || frame.sequence != 1 ||
		swz_frame_is_canonical_json(frame.payload, frame.payload_length) != 0 || frame.payload_length != expected_length || memcmp(frame.payload, prefix, sizeof(prefix) - 1) != 0 ||
		memcmp(frame.payload + sizeof(prefix) - 1 + 64, suffix, sizeof(suffix) - 1) != 0)
		return -1;
	memcpy(session_hex, frame.payload + sizeof(prefix) - 1, 64);
	session_hex[64] = '\0';
	return swz_hex_decode(session_hex, raw, sizeof(raw));
}

static int handoff_context(const uint8_t session_raw32[32], const uint8_t generation_raw32[32], const uint8_t connection_raw32[32], const uint8_t cookie_raw32[32])
{
	uint8_t context[SWZ_CONTEXT_BYTES];
	int channel[2] = { -1, -1 };
	int result = -1;
	if (swz_build_context_record(context, session_raw32, generation_raw32, connection_raw32, cookie_raw32) != 0 || pipe2(channel, O_CLOEXEC) != 0 ||
		fcntl(channel[0], F_SETFD, fcntl(channel[0], F_GETFD) & ~FD_CLOEXEC) < 0 || swz_write_full(channel[1], context, sizeof(context)) != 0)
		goto done;
	close(channel[1]);
	channel[1] = -1;
	if (dup2(channel[0], SWZ_CONTEXT_FD) < 0)
		goto done;
	if (channel[0] != SWZ_CONTEXT_FD)
		close(channel[0]);
	channel[0] = -1;
	if (clearenv() != 0 || swz_confine_process() != 0)
		goto done;
	execl(SWZ_BROKER_PATH, SWZ_BROKER_PATH, (char *)NULL);
done:
	if (channel[0] >= 0) close(channel[0]);
	if (channel[1] >= 0) close(channel[1]);
	swz_zeroize(context, sizeof(context));
	return result;
}

int main(int argc, char **argv)
{
	uint8_t session_raw32[32] = { 0 };
	uint8_t generation_raw32[32] = { 0 };
	uint8_t connection_raw32[32] = { 0 };
	uint8_t cookie_raw32[32] = { 0 };
	uint8_t boot_raw32[32] = { 0 };
	uint8_t buffer[SWZ_MAX_FRAME];
	char session_hex[65];
	size_t length = 0;
	int result = 65;
	(void)argv;
	if (argc != 1 || clearenv() != 0 || swz_confine_process() != 0 ||
		swz_process_domain_matches(SWZ_EXPECTED_BOOTSTRAP_DOMAIN) != 0 ||
		connect_session_control(session_raw32, generation_raw32, connection_raw32, cookie_raw32) != 0 ||
		swz_frame_read_fd(STDIN_FILENO, buffer, sizeof(buffer), &length, 10000) != 0 || read_boot_session(buffer, length, session_hex) != 0 ||
		swz_hex_decode(session_hex, boot_raw32, sizeof(boot_raw32)) != 0 || memcmp(boot_raw32, session_raw32, sizeof(boot_raw32)) != 0)
		goto done;
	if (emit_payload(SWZ_CHALLENGE, 2, session_hex) != 0 || read_expected(SWZ_EVIDENCE, SWZ_LOCAL_TO_REMOTE, 3, buffer, &length) != 0 ||
		read_expected(SWZ_ACCEPT, SWZ_REMOTE_TO_LOCAL, 4, buffer, &length) != 0 || emit_payload(SWZ_ACCEPTED, 5, session_hex) != 0)
		goto done;
	result = handoff_context(session_raw32, generation_raw32, connection_raw32, cookie_raw32) == 0 ? 0 : 74;
done:
	swz_zeroize(session_raw32, sizeof(session_raw32));
	swz_zeroize(generation_raw32, sizeof(generation_raw32));
	swz_zeroize(connection_raw32, sizeof(connection_raw32));
	swz_zeroize(cookie_raw32, sizeof(cookie_raw32));
	swz_zeroize(boot_raw32, sizeof(boot_raw32));
	return result;
}
