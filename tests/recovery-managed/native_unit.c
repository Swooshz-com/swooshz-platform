#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int decode_hex(const char *text, uint8_t *output, size_t capacity, size_t *written) {
    size_t length;
    size_t index;
    if (text == NULL || output == NULL || written == NULL) return -1;
    length = strlen(text);
    if ((length % 2U) != 0U || length / 2U > capacity) return -1;
    for (index = 0U; index < length / 2U; ++index) {
        uint8_t high;
        uint8_t low;
        char high_char = text[index * 2U];
        char low_char = text[index * 2U + 1U];
        if (high_char >= '0' && high_char <= '9') high = (uint8_t)(high_char - '0');
        else if (high_char >= 'a' && high_char <= 'f') high = (uint8_t)(high_char - 'a' + 10);
        else return -1;
        if (low_char >= '0' && low_char <= '9') low = (uint8_t)(low_char - '0');
        else if (low_char >= 'a' && low_char <= 'f') low = (uint8_t)(low_char - 'a' + 10);
        else return -1;
        output[index] = (uint8_t)((high << 4U) | low);
    }
    *written = length / 2U;
    return 0;
}

static int print_hex(const uint8_t *value, size_t length) {
    char text[16385];
    if (swz_hex_lower(value, length, text, sizeof(text)) != 0) return -1;
    puts(text);
    return 0;
}

static int identity_golden(void) {
    static const uint8_t installation_uuid[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t boot_uuid[16] = {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x47, 0x67, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f};
    static const uint8_t admission_key[32] = {0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
    static const uint8_t host_key[32] = {0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc, 0x9c, 0x98, 0x2c, 0xf2, 0xec, 0x49, 0x68, 0xcc, 0x0c, 0xd5, 0x5f, 0x12, 0xaf, 0x46, 0x60, 0xc0};
    static const uint8_t controller_key[32] = {0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x0a, 0xc5, 0xde, 0xb9, 0x11, 0x54, 0x89, 0x08, 0x02, 0x5};
    static const uint8_t uidgid_map[31] = {0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x01, 0x00, 0x00};
    static const uint8_t target_policy[32] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
    uint8_t admission_blob[51];
    uint8_t host_blob[51];
    uint8_t controller_blob[51];
    uint8_t endpoint[10] = {0x01, 0x01, 0x00, 0x02, 0xc0, 0x00, 0x02, 0x0a, 0x56, 0xce};
    uint8_t installation[32];
    uint8_t endpoint_template[32];
    uint8_t endpoint_actual[32];
    uint8_t algorithm[11] = {0};
    uint8_t key_length[4] = {0, 0, 0, 32};
    swz_bytes parts[7];
    swz_bytes endpoint_parts[2];
    swz_bytes actual_parts[4];
    char text[65];
    size_t index;
    memcpy(algorithm, "ssh-ed25519", 11U);
    for (index = 0U; index < 51U; ++index) {
        admission_blob[index] = 0U;
        host_blob[index] = 0U;
        controller_blob[index] = 0U;
    }
    admission_blob[0] = 0U; admission_blob[1] = 0U; admission_blob[2] = 0U; admission_blob[3] = 11U;
    host_blob[0] = 0U; host_blob[1] = 0U; host_blob[2] = 0U; host_blob[3] = 11U;
    controller_blob[0] = 0U; controller_blob[1] = 0U; controller_blob[2] = 0U; controller_blob[3] = 11U;
    memcpy(admission_blob + 4U, algorithm, 11U); memcpy(host_blob + 4U, algorithm, 11U); memcpy(controller_blob + 4U, algorithm, 11U);
    memcpy(admission_blob + 15U, key_length, 4U); memcpy(host_blob + 15U, key_length, 4U); memcpy(controller_blob + 15U, key_length, 4U);
    memcpy(admission_blob + 19U, admission_key, 32U); memcpy(host_blob + 19U, host_key, 32U); memcpy(controller_blob + 19U, controller_key, 32U);
    parts[0] = (swz_bytes){installation_uuid, sizeof(installation_uuid)};
    parts[1] = (swz_bytes){admission_blob, sizeof(admission_blob)};
    parts[2] = (swz_bytes){host_blob, sizeof(host_blob)};
    parts[3] = (swz_bytes){controller_blob, sizeof(controller_blob)};
    parts[4] = (swz_bytes){endpoint, sizeof(endpoint)};
    parts[5] = (swz_bytes){uidgid_map, sizeof(uidgid_map)};
    parts[6] = (swz_bytes){target_policy, sizeof(target_policy)};
    if (swz_managed_hash("installation.v1", parts, 7U, installation) != 0) return -1;
    endpoint_parts[0] = (swz_bytes){installation, sizeof(installation)};
    endpoint_parts[1] = (swz_bytes){endpoint, sizeof(endpoint)};
    if (swz_managed_hash("endpoint-template.v1", endpoint_parts, 2U, endpoint_template) != 0) return -1;
    actual_parts[0] = (swz_bytes){endpoint_template, sizeof(endpoint_template)};
    actual_parts[1] = (swz_bytes){boot_uuid, sizeof(boot_uuid)};
    actual_parts[2] = (swz_bytes){(const uint8_t *)"\0\0\0\0\0\0\0\7", 8U};
    actual_parts[3] = (swz_bytes){(const uint8_t *)"\0\0\0\0\0\0\0\13", 8U};
    if (swz_managed_hash("endpoint-actual.v1", actual_parts, 4U, endpoint_actual) != 0) return -1;
    if (swz_hex_lower(installation, 32U, text, sizeof(text)) != 0) return -1;
    puts(text);
    if (swz_hex_lower(endpoint_template, 32U, text, sizeof(text)) != 0) return -1;
    puts(text);
    if (swz_hex_lower(endpoint_actual, 32U, text, sizeof(text)) != 0) return -1;
    puts(text);
    return 0;
}

int main(int argc, char **argv) {
    uint8_t input[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    size_t length;
    if (argc == 2 && strcmp(argv[1], "identity-golden") == 0) return identity_golden();
    if (argc == 3 && strcmp(argv[1], "store-transition-id") == 0) {
        char result[60];
        if (decode_hex(argv[2], input, sizeof(input), &length) != 0 || swz_store_transition_id((swz_bytes){input, length}, result) != 0) return 2;
        puts(result);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "store-wire") == 0) {
        uint8_t result[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
        size_t written;
        if (decode_hex(argv[3], input, sizeof(input), &length) != 0 || swz_store_wire_encode(argv[2], (swz_bytes){input, length}, result, sizeof(result), &written) != 0) return 2;
        return print_hex(result, written) == 0 ? 0 : 2;
    }
    if (argc == 4 && strcmp(argv[1], "store-commitment") == 0) {
        char result[75];
        if (decode_hex(argv[3], input, sizeof(input), &length) != 0 || swz_store_commitment(argv[2], (swz_bytes){input, length}, result) != 0) return 2;
        puts(result);
        return 0;
    }
    fputs("usage: native_unit identity-golden | store-transition-id HEX | store-wire SCHEMA HEX | store-commitment DOMAIN HEX\n", stderr);
    return 2;
}
