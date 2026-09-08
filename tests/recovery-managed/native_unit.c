#define _GNU_SOURCE

#include "platform.h"
#include "protocol.h"

#include <stdio.h>
#include <string.h>

static void put_u32(unsigned char out[4], unsigned int value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static void key_blob(const unsigned char key[32], unsigned char out[51])
{
    put_u32(out, 11U);
    memcpy(out + 4U, "ssh-ed25519", 11U);
    put_u32(out + 15U, 32U);
    memcpy(out + 19U, key, 32U);
}

static int identity_kat(void)
{
    static const unsigned char installation_uuid[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static const unsigned char boot_uuid[16] = {
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x47, 0x67,
        0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f
    };
    static const unsigned char admission_key[32] = {
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
    };
    static const unsigned char host_key[32] = {
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
        0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
        0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
        0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
    };
    static const unsigned char controller_key[32] = {
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3,
        0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
        0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac,
        0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25
    };
    static const unsigned char uidgid_map[] = {
        0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x01,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x86, 0xa0, 0x00, 0x01, 0x00, 0x00
    };
    unsigned char admission_blob[51];
    unsigned char host_blob[51];
    unsigned char controller_blob[51];
    unsigned char endpoint[10] = { 1U, 1U, 0U, 2U, 192U, 0U, 2U, 10U, 0x56U, 0xceU };
    unsigned char target_policy[32];
    const unsigned char *parts[7];
    size_t lengths[7] = { 16U, 51U, 51U, 51U, 10U, sizeof(uidgid_map), 32U };
    unsigned char installation[32];
    unsigned char template[32];
    unsigned char actual[32];
    unsigned char device[8];
    unsigned char inode[8];
    char hex[65];

    memset(target_policy, 0x11, sizeof(target_policy));
    key_blob(admission_key, admission_blob);
    key_blob(host_key, host_blob);
    key_blob(controller_key, controller_blob);
    parts[0] = installation_uuid;
    parts[1] = admission_blob;
    parts[2] = host_blob;
    parts[3] = controller_blob;
    parts[4] = endpoint;
    parts[5] = uidgid_map;
    parts[6] = target_policy;
    if (swz_managed_hash("installation.v1", parts, lengths, 7U, installation) != 0) {
        return -1;
    }
    parts[0] = installation;
    parts[1] = endpoint;
    if (swz_managed_hash("endpoint-template.v1", parts, (size_t[2]){ 32U, 10U }, 2U, template) != 0) {
        return -1;
    }
    put_u32(device, 0U);
    put_u32(device + 4U, 7U);
    put_u32(inode, 0U);
    put_u32(inode + 4U, 11U);
    parts[0] = template;
    parts[1] = boot_uuid;
    parts[2] = device;
    parts[3] = inode;
    if (swz_managed_hash("endpoint-actual.v1", parts, (size_t[4]){ 32U, 16U, 8U, 8U }, 4U, actual) != 0 ||
        swz_hex(installation, sizeof(installation), hex, sizeof(hex)) != 0) {
        return -1;
    }
    printf("installation=%s\n", hex);
    if (swz_hex(template, sizeof(template), hex, sizeof(hex)) != 0) {
        return -1;
    }
    printf("endpoint_template=%s\n", hex);
    if (swz_hex(actual, sizeof(actual), hex, sizeof(hex)) != 0) {
        return -1;
    }
    printf("endpoint_actual=%s\n", hex);
    return 0;
}

static int frame_kat(void)
{
    static const unsigned char payload[] = "[]\n";
    struct swz_frame frame;
    unsigned char encoded[SWZ_FRAME_HEADER_BYTES + sizeof(payload) - 1U];
    unsigned char decoded_payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    size_t written;

    memset(&frame, 0, sizeof(frame));
    frame.direction = 1U;
    frame.type = SWZ_BOOT;
    frame.payload = (unsigned char *)payload;
    frame.payload_length = (uint32_t)(sizeof(payload) - 1U);
    if (swz_frame_encode(&frame, encoded, sizeof(encoded), &written) != 0 ||
        written != sizeof(encoded) || memcmp(encoded, SWZ_FRAME_MAGIC, 8U) != 0 ||
        swz_frame_decode(encoded, written, &frame, decoded_payload,
                         sizeof(decoded_payload)) != 0 ||
        memcmp(decoded_payload, payload, sizeof(payload) - 1U) != 0) {
        return -1;
    }
    return 0;
}

int main(void)
{
    return identity_kat() == 0 && frame_kat() == 0 ? 0 : 1;
}

