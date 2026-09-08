#ifndef SWZ_MANAGED_PROTOCOL_H
#define SWZ_MANAGED_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define SWZ_FRAME_MAGIC "SWZFRM02"
#define SWZ_FRAME_HEADER_BYTES 56U
#define SWZ_PROTOCOL_VERSION 2U
#define SWZ_MAX_CONTROL_PAYLOAD_BYTES 4096U
#define SWZ_MAX_FRAME_BYTES 65536U
#define SWZ_MAX_SESSION_FRAMES 16U
#define SWZ_MAX_SESSION_BYTES 1048576U

enum swz_message_type {
    SWZ_BOOT = 1,
    SWZ_CHALLENGE = 2,
    SWZ_EVIDENCE = 3,
    SWZ_ACCEPT = 4,
    SWZ_ACCEPTED = 5,
    SWZ_DISCOVERY = 6,
    SWZ_RESTORE_BEGIN = 7,
    SWZ_PROCEED = 8,
    SWZ_RESULT = 9,
    SWZ_BROKER_FINAL = 10,
    SWZ_ERROR = 255
};

struct swz_frame {
    uint8_t direction;
    uint16_t type;
    uint8_t flags;
    uint64_t sequence;
    unsigned char previous_hash[32];
    unsigned char *payload;
    uint32_t payload_length;
};

int swz_frame_encode(const struct swz_frame *frame, unsigned char *out,
                     size_t capacity, size_t *written);
int swz_frame_decode(const unsigned char *bytes, size_t length,
                     struct swz_frame *frame, unsigned char *payload,
                     size_t payload_capacity);
int swz_frame_hash(const unsigned char *bytes, size_t length,
                   unsigned char out[32]);
int swz_frame_write(int fd, const struct swz_frame *frame);
int swz_frame_read(int fd, struct swz_frame *frame, unsigned char *payload,
                   size_t payload_capacity);
int swz_frame_type_is_valid(uint16_t type);

#endif

