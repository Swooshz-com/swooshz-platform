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
    static const unsigned char run374_uidgid_map[31] = {
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

    _Static_assert(sizeof(uidgid_map) == 31U, "Run-374 UIDGIDMap length");
    if (sizeof(uidgid_map) != sizeof(run374_uidgid_map) ||
        memcmp(uidgid_map, run374_uidgid_map, sizeof(run374_uidgid_map)) != 0) {
        return -1;
    }

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
    /* Frozen independently generated Run-395 BOOT payload; Python KATs use the same bytes. */
    static const unsigned char payload[] =
        "[\"BOOT\",2,\"swz-managed.v1\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"epoch-qualified-001\",\"authority-qualified-001\",\"2026-09-07T00:00:00.000000Z\",\"0101010101010101010101010101010101010101010101010101010101010101\",\"0202020202020202020202020202020202020202020202020202020202020202\",\"0303030303030303030303030303030303030303030303030303030303030303\",\"0404040404040404040404040404040404040404040404040404040404040404\",\"0505050505050505050505050505050505050505050505050505050505050505\",\"0606060606060606060606060606060606060606060606060606060606060606\"]";
    static const unsigned char n_local[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    struct swz_frame frame;
    unsigned char encoded[SWZ_FRAME_HEADER_BYTES + sizeof(payload) - 1U];
    unsigned char decoded_payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char digest[32];
    char digest_hex[65];
    size_t written;

    memset(&frame, 0, sizeof(frame));
    frame.direction = 1U;
    frame.type = SWZ_BOOT;
    frame.sequence = 0U;
    memcpy(frame.n_local, n_local, sizeof(n_local));
    frame.payload = (unsigned char *)payload;
    frame.payload_length = (uint32_t)(sizeof(payload) - 1U);
    if (swz_frame_encode(&frame, encoded, sizeof(encoded), &written) != 0 ||
        written != sizeof(encoded) || memcmp(encoded, SWZ_FRAME_MAGIC, 8U) != 0 ||
        swz_frame_decode(encoded, written, &frame, decoded_payload,
                         sizeof(decoded_payload)) != 0 ||
        memcmp(decoded_payload, payload, sizeof(payload) - 1U) != 0 ||
        memcmp(frame.n_local, n_local, sizeof(n_local)) != 0 ||
        swz_frame_hash(encoded, written, digest) != 0 ||
        swz_hex(digest, sizeof(digest), digest_hex, sizeof(digest_hex)) != 0 ||
        strcmp(digest_hex, "b3597e136042c085e45f3b6399323f9c95929d34532f435eb06eae8f86751a48") != 0) {
        return -1;
    }
    printf("boot_frame_hash=%s\n", digest_hex);
    return 0;
}

static int complete_frame_kat(void)
{
    static const char *const kat_payloads[] = {
        "[\"BOOT\",2,\"swz-managed.v1\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"epoch-qualified-001\",\"authority-qualified-001\",\"2026-09-07T00:00:00.000000Z\",\"0101010101010101010101010101010101010101010101010101010101010101\",\"0202020202020202020202020202020202020202020202020202020202020202\",\"0303030303030303030303030303030303030303030303030303030303030303\",\"0404040404040404040404040404040404040404040404040404040404040404\",\"0505050505050505050505050505050505050505050505050505050505050505\",\"0606060606060606060606060606060606060606060606060606060606060606\"]",
        "[\"CHALLENGE\",2,\"swz-managed.v1\",\"b3597e136042c085e45f3b6399323f9c95929d34532f435eb06eae8f86751a48\",\"0707070707070707070707070707070707070707070707070707070707070707\",\"0808080808080808080808080808080808080808080808080808080808080808\",\"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\",\"b3597e136042c085e45f3b6399323f9c95929d34532f435eb06eae8f86751a48\",\"123456789\"]",
        "[\"EVIDENCE\",2,\"swz-managed.v1\",\"5918524914ad7611afaaac885b97cb81e3089a7c2d263b7b211b55952029c6d2\",\"0101010101010101010101010101010101010101010101010101010101010101\",\"0202020202020202020202020202020202020202020202020202020202020202\",\"0303030303030303030303030303030303030303030303030303030303030303\",\"0707070707070707070707070707070707070707070707070707070707070707\",\"0303030303030303030303030303030303030303030303030303030303030303\",\"0404040404040404040404040404040404040404040404040404040404040404\",\"0909090909090909090909090909090909090909090909090909090909090909\",\"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\",\"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\",\"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c\",\"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d\",\"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e\",\"1111111111111111111111111111111111111111111111111111111111111111\",\"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\",\"1212121212121212121212121212121212121212121212121212121212121212\",\"1313131313131313131313131313131313131313131313131313131313131313\",\"1414141414141414141414141414141414141414141414141414141414141414\",\"0808080808080808080808080808080808080808080808080808080808080808\",\"abababababababababababababababababababababababababababababababab\",\"0505050505050505050505050505050505050505050505050505050505050505\",\"0606060606060606060606060606060606060606060606060606060606060606\",\"7fd2615afbb294c7ef0cfd04ed6c2b8bb50a58f06633a258e5abf23cf5cfecf9\",[\"12345678-1234-4234-8234-123456789abc\",\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\",\"10\",\"11\",\"12\",\"13\",\"14\",true,true,0,\"0\",true,\"abababababababababababababababababababababababababababababababab\",\"1717171717171717171717171717171717171717171717171717171717171717\",\"1818181818181818181818181818181818181818181818181818181818181818\"],\"5b20b178f1d8932b7a3d271c5f7792b74965b1e72f2a56d66700edf926b5161e\"]",
        "[\"ACCEPT\",2,\"swz-managed.v1\",\"74012acca6d496aff8f4892d0a5022f48f96f38a7c64f58eadf4fa17af4dc3a8\",\"0808080808080808080808080808080808080808080808080808080808080808\",\"0303030303030303030303030303030303030303030303030303030303030303\",\"0505050505050505050505050505050505050505050505050505050505050505\",\"5b20b178f1d8932b7a3d271c5f7792b74965b1e72f2a56d66700edf926b5161e\",\"74012acca6d496aff8f4892d0a5022f48f96f38a7c64f58eadf4fa17af4dc3a8\",\"e7313abbcd229f1e67942ad2322e14705e502fcb95b62f866e72a806c59c2844\"]",
        "[\"ACCEPTED\",2,\"swz-managed.v1\",\"bc18c5ff12cf30ce832f2b5ba5f605d5043643276752ca3426e3a50b27638532\",\"0808080808080808080808080808080808080808080808080808080808080808\",\"0707070707070707070707070707070707070707070707070707070707070707\",\"e7313abbcd229f1e67942ad2322e14705e502fcb95b62f866e72a806c59c2844\",\"1515151515151515151515151515151515151515151515151515151515151515\",\"abababababababababababababababababababababababababababababababab\"]"
    };
    static const char *const expected_hashes[] = {
        "b3597e136042c085e45f3b6399323f9c95929d34532f435eb06eae8f86751a48",
        "5918524914ad7611afaaac885b97cb81e3089a7c2d263b7b211b55952029c6d2",
        "74012acca6d496aff8f4892d0a5022f48f96f38a7c64f58eadf4fa17af4dc3a8",
        "bc18c5ff12cf30ce832f2b5ba5f605d5043643276752ca3426e3a50b27638532",
        "0143c3e5f2d54409b2b1a5406a237ff0cffe293695719ab7df1140d5021b11be"
    };
    static const uint16_t types[] = {
        SWZ_BOOT, SWZ_CHALLENGE, SWZ_EVIDENCE, SWZ_ACCEPT, SWZ_ACCEPTED
    };
    static const uint8_t directions[] = { 1U, 2U, 2U, 1U, 2U };
    static const char *const labels[] = {
        "boot", "challenge", "evidence", "accept", "accepted"
    };
    static const unsigned char n_local[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    size_t index;

    for (index = 0U; index < sizeof(kat_payloads) / sizeof(kat_payloads[0]);
         ++index) {
        struct swz_frame frame;
        unsigned char encoded[SWZ_FRAME_HEADER_BYTES + 4096U];
        unsigned char decoded_payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
        unsigned char digest[32];
        char digest_hex[65];
        char frame_hex[(SWZ_FRAME_HEADER_BYTES + 4096U) * 2U + 1U];
        size_t payload_length = strlen(kat_payloads[index]);
        size_t written;

        memset(&frame, 0, sizeof(frame));
        frame.direction = directions[index];
        frame.type = types[index];
        frame.sequence = index;
        memcpy(frame.n_local, n_local, sizeof(n_local));
        frame.payload = (unsigned char *)kat_payloads[index];
        frame.payload_length = (uint32_t)payload_length;
        if (swz_frame_encode(&frame, encoded, sizeof(encoded), &written) != 0 ||
            swz_frame_decode(encoded, written, &frame, decoded_payload,
                             sizeof(decoded_payload)) != 0 ||
            memcmp(decoded_payload, kat_payloads[index], payload_length) != 0 ||
            memcmp(frame.n_local, n_local, sizeof(n_local)) != 0 ||
            swz_frame_hash(encoded, written, digest) != 0 ||
            swz_hex(digest, sizeof(digest), digest_hex, sizeof(digest_hex)) != 0 ||
            strcmp(digest_hex, expected_hashes[index]) != 0) {
            return -1;
        }
        if (swz_hex(encoded, written, frame_hex, sizeof(frame_hex)) != 0) {
            return -1;
        }
        printf("%s_frame_hash=%s\n%s_frame_hex=%s\n", labels[index], digest_hex,
               labels[index], frame_hex);
    }
    return 0;
}

int main(void)
{
    return identity_kat() == 0 && frame_kat() == 0 && complete_frame_kat() == 0 ? 0 : 1;
}
