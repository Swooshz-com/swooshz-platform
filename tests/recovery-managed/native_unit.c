#define _POSIX_C_SOURCE 200809L
#include "platform.h"
#include "protocol.h"

#include <stdio.h>
#include <string.h>

static void put_u32(uint8_t output[4], uint32_t value)
{
	output[0] = (uint8_t)(value >> 24);
	output[1] = (uint8_t)(value >> 16);
	output[2] = (uint8_t)(value >> 8);
	output[3] = (uint8_t)value;
}

static void put_u64(uint8_t output[8], uint64_t value)
{
	for (size_t index = 0; index < 8; index++) {
		output[7 - index] = (uint8_t)value;
		value >>= 8;
	}
}

static int public_blob(const uint8_t key[32], uint8_t output[51])
{
	put_u32(output, 11);
	memcpy(output + 4, "ssh-ed25519", 11);
	put_u32(output + 15, 32);
	memcpy(output + 19, key, 32);
	return 0;
}

static void hex_encode(const uint8_t input[32], char output[65])
{
	static const char hex[] = "0123456789abcdef";
	for (size_t index = 0; index < 32; index++) {
		output[index * 2] = hex[input[index] >> 4];
		output[index * 2 + 1] = hex[input[index] & 0x0f];
	}
	output[64] = '\0';
}

static int identity_kat(void)
{
	static const uint8_t installation_uuid[16] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	};
	static const uint8_t boot_uuid[16] = {
		0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x47, 0x67,
		0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
	};
	static const uint8_t admission_key[32] = {
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
	};
	static const uint8_t host_key[32] = {
		0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
		0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
		0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
		0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
	};
	static const uint8_t controller_key[32] = {
		0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3,
		0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0, 0x58,
		0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac,
		0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
	};
	static const uint8_t policy[32] = {
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	};
	static const uint8_t uidgid_map[] = {
		0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x86, 0xa0, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x01, 0x00,
		0x00,
	};
	static const uint8_t endpoint[10] = {
		0x01, 0x01, 0x00, 0x02, 0xc0, 0x00, 0x02, 0x0a, 0x56, 0xce,
	};
	uint8_t admission_blob[51];
	uint8_t host_blob[51];
	uint8_t controller_blob[51];
	uint8_t device[8];
	uint8_t inode[8];
	uint8_t installation[32];
	uint8_t endpoint_template[32];
	uint8_t endpoint_actual[32];
	public_blob(admission_key, admission_blob);
	public_blob(host_key, host_blob);
	public_blob(controller_key, controller_blob);
	const uint8_t *installation_parts[] = {
		installation_uuid, admission_blob, host_blob, controller_blob,
		endpoint, uidgid_map, policy,
	};
	const size_t installation_lengths[] = { 16, 51, 51, 51, 10, sizeof(uidgid_map), 32 };
	if (swz_managed_hash("installation.v1", installation_parts, installation_lengths, 7, installation) != 0)
		return -1;
	const uint8_t *template_parts[] = { installation, endpoint };
	const size_t template_lengths[] = { 32, 10 };
	if (swz_managed_hash("endpoint-template.v1", template_parts, template_lengths, 2, endpoint_template) != 0)
		return -1;
	put_u64(device, 7);
	put_u64(inode, 11);
	const uint8_t *actual_parts[] = { endpoint_template, boot_uuid, device, inode };
	const size_t actual_lengths[] = { 32, 16, 8, 8 };
	if (swz_managed_hash("endpoint-actual.v1", actual_parts, actual_lengths, 4, endpoint_actual) != 0)
		return -1;
	char installation_hex[65];
	char template_hex[65];
	char actual_hex[65];
	hex_encode(installation, installation_hex);
	hex_encode(endpoint_template, template_hex);
	hex_encode(endpoint_actual, actual_hex);
	return strcmp(installation_hex, "e8a0ef6f2c154a38e9b514b1d1c1692c9ff4128e0e73916003833c2377fd597f") == 0 &&
	    strcmp(template_hex, "198d57f1638a38bb74fcb7e6c0800a44263cf2eea4afbf6fa5e2f1ebd921af3a") == 0 &&
	    strcmp(actual_hex, "d7b07ef7b4a95aea2f1914496733af29f5073ac6e6d52bcb0c5fd3675d9566fb") == 0 ? 0 : -1;
}

static int protocol_kat(void)
{
	static const uint8_t payload[] = "[\"ACCEPT\",2,\"swz-managed.v1\"]";
	struct swz_frame input = {
		.direction = SWZ_LOCAL_TO_REMOTE,
		.message = SWZ_ACCEPT,
		.sequence = 4,
		.payload_length = (uint32_t)(sizeof(payload) - 1),
		.payload = payload,
	};
	memset(input.nonce, 0x42, sizeof(input.nonce));
	uint8_t wire[SWZ_MAX_FRAME];
	size_t length = 0;
	if (swz_frame_encode(&input, wire, sizeof(wire), &length) != 0)
		return -1;
	struct swz_frame decoded;
	if (swz_frame_decode(wire, length, &decoded) != 0 ||
	    decoded.message != SWZ_ACCEPT || decoded.sequence != 4 ||
	    decoded.payload_length != sizeof(payload) - 1 ||
	    memcmp(decoded.payload, payload, sizeof(payload) - 1) != 0)
		return -1;
	return 0;
}

static int registration_kat(void)
{
	uint8_t generation[32];
	uint8_t connection[32];
	uint8_t cookie[32];
	uint8_t record[SWZ_REGISTRATION_BYTES];
	uint8_t context[SWZ_CONTEXT_BYTES];
	uint8_t zero[32] = { 0 };
	for (size_t index = 0; index < 32; index++) {
		generation[index] = (uint8_t)(0x10U + index);
		connection[index] = (uint8_t)(0x40U + index);
		cookie[index] = (uint8_t)(0x70U + index);
	}
	if (swz_build_registration_record(record, generation, connection, cookie) != 0 ||
		swz_validate_registration_record(record) != 0 ||
		memcmp(record, SWZ_REGISTRATION_MAGIC, 8) != 0 ||
		memcmp(record + 8, generation, 32) != 0 ||
		memcmp(record + 40, connection, 32) != 0 ||
		memcmp(record + 72, cookie, 32) != 0)
		return -1;
	record[0] ^= 1U;
	if (swz_validate_registration_record(record) == 0)
		return -1;
	record[0] ^= 1U;
	memset(record + 8, 0, 32);
	if (swz_validate_registration_record(record) == 0)
		return -1;
	if (swz_build_registration_record(record, zero, connection, cookie) == 0 ||
		swz_build_registration_record(record, generation, zero, cookie) == 0 ||
		swz_build_registration_record(record, generation, connection, zero) == 0)
		return -1;
	if (swz_build_context_record(context, generation, generation, connection, cookie) != 0 ||
		swz_validate_context_record(context) != 0 ||
		memcmp(context, SWZ_CONTEXT_MAGIC, 8) != 0 ||
		memcmp(context + 8, generation, 32) != 0 ||
		memcmp(context + 40, generation, 32) != 0 ||
		memcmp(context + 72, connection, 32) != 0 ||
		memcmp(context + 104, cookie, 32) != 0)
		return -1;
	memset(context + 104, 0, 32);
	if (swz_validate_context_record(context) == 0)
		return -1;
	return 0;
}

int main(void)
{
	if (identity_kat() != 0 || protocol_kat() != 0 || registration_kat() != 0)
		return 1;
	puts("NATIVE_IDENTITY_KAT=PASS");
	puts("NATIVE_PROTOCOL_KAT=PASS");
	puts("NATIVE_REGISTRATION_KAT=PASS");
	return 0;
}
