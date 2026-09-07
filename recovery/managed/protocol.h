#ifndef SWZ_MANAGED_PROTOCOL_H
#define SWZ_MANAGED_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define SWZ_MANAGED_SCHEMA "swz-managed.v1"
#define SWZ_STORE_MARKER "store-json.v1"
#define SWZ_MAX_CONTROL_PAYLOAD_BYTES 4096U
#define SWZ_MAX_FRAME_BYTES 65536U
#define SWZ_MAX_SESSION_FRAMES 16U
#define SWZ_MAX_SESSION_BYTES 1048576U
#define SWZ_FRAME_HEADER_BYTES 56U
#define SWZ_STORE_COMMITMENT_PREFIX "sha256:v1:"

typedef struct {
    const uint8_t *data;
    size_t length;
} swz_bytes;

int swz_sha256(const uint8_t *data, size_t length, uint8_t output[32]);
int swz_lp_append(uint8_t *output, size_t capacity, size_t *offset, swz_bytes value);
int swz_managed_hash(const char *domain, const swz_bytes *parts, size_t part_count, uint8_t output[32]);
int swz_store_commitment(const char *domain, swz_bytes store_bytes, char output[75]);
int swz_store_transition_id(swz_bytes store_bytes, char output[60]);
int swz_store_wire_encode(const char *schema_id, swz_bytes store_bytes, uint8_t *output, size_t capacity, size_t *written);
int swz_hex_lower(const uint8_t *input, size_t length, char *output, size_t capacity);
int swz_hex_decode_32(const char *input, uint8_t output[32]);

#endif
