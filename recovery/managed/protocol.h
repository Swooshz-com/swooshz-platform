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
    SWZ_READY_RESERVED = 2,
    SWZ_CHALLENGE = 3,
    SWZ_EVIDENCE = 4,
    SWZ_ACCEPT = 5,
    SWZ_ACCEPTED = 6,
    SWZ_DISCOVERY = 7,
    SWZ_RESTORE_BEGIN = 8,
    SWZ_PROCEED = 9,
    SWZ_RESULT = 10,
    SWZ_ABORT = 11
};

struct swz_frame {
    uint8_t direction;
    uint16_t type;
    uint8_t flags;
    uint64_t sequence;
    unsigned char n_local[32];
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
const char *swz_message_name(uint16_t type);
int swz_managed_payload_validate(const unsigned char *payload, size_t length,
                                 uint16_t type);
int swz_managed_payload_string_field(const unsigned char *payload, size_t length,
                                     size_t index, char *out, size_t capacity);
int swz_managed_payload_predecessor(const unsigned char *payload, size_t length,
                                    unsigned char out[32]);

#endif
