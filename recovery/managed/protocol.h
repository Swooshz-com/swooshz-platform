#ifndef SWZ_MANAGED_PROTOCOL_H
#define SWZ_MANAGED_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define SWZ_MAGIC "SWZFRM02"
#define SWZ_MAGIC_BYTES 8U
#define SWZ_VERSION 2U
#define SWZ_MAX_CONTROL_PAYLOAD 4096U
#define SWZ_MAX_FRAME 65536U
#define SWZ_MAX_SESSION_FRAMES 16U
#define SWZ_MAX_SESSION_BYTES 1048576U
#define SWZ_FRAME_HEADER_BYTES 56U

enum swz_direction {
	SWZ_LOCAL_TO_REMOTE = 1,
	SWZ_REMOTE_TO_LOCAL = 2
};

enum swz_message {
	SWZ_BOOT = 1,
	SWZ_CHALLENGE = 2,
	SWZ_EVIDENCE = 3,
	SWZ_ACCEPT = 4,
	SWZ_ACCEPTED = 5,
	SWZ_DISCOVERY = 6,
	SWZ_RESTORE_BEGIN = 7,
	SWZ_PROCEED = 8,
	SWZ_RESULT = 9,
	SWZ_ABORT = 10
};

struct swz_frame {
	uint8_t direction;
	uint8_t message;
	uint64_t sequence;
	uint8_t nonce[32];
	uint32_t payload_length;
	const uint8_t *payload;
};

int swz_frame_encode(const struct swz_frame *frame, uint8_t *out, size_t out_size, size_t *written);
int swz_frame_decode(const uint8_t *input, size_t input_size, struct swz_frame *frame);
int swz_frame_validate(const struct swz_frame *frame);
int swz_frame_is_canonical_json(const uint8_t *payload, size_t length);

#endif
