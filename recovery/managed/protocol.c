#include "protocol.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t block[64];
    size_t block_length;
} sha256_context;

static const uint32_t ROUND_CONSTANTS[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rotate_right(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32U - count));
}

static uint32_t choose(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t sigma0(uint32_t x) {
    return rotate_right(x, 2U) ^ rotate_right(x, 13U) ^ rotate_right(x, 22U);
}

static uint32_t sigma1(uint32_t x) {
    return rotate_right(x, 6U) ^ rotate_right(x, 11U) ^ rotate_right(x, 25U);
}

static uint32_t small_sigma0(uint32_t x) {
    return rotate_right(x, 7U) ^ rotate_right(x, 18U) ^ (x >> 3U);
}

static uint32_t small_sigma1(uint32_t x) {
    return rotate_right(x, 17U) ^ rotate_right(x, 19U) ^ (x >> 10U);
}

static uint32_t load_u32_be(const uint8_t *input) {
    return ((uint32_t)input[0] << 24U) | ((uint32_t)input[1] << 16U) |
           ((uint32_t)input[2] << 8U) | (uint32_t)input[3];
}

static void store_u32_be(uint8_t *output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24U);
    output[1] = (uint8_t)(value >> 16U);
    output[2] = (uint8_t)(value >> 8U);
    output[3] = (uint8_t)value;
}

static void sha256_compress(sha256_context *context, const uint8_t block[64]) {
    uint32_t schedule[64];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    size_t index;

    for (index = 0U; index < 16U; ++index) {
        schedule[index] = load_u32_be(block + index * 4U);
    }
    for (index = 16U; index < 64U; ++index) {
        schedule[index] = small_sigma1(schedule[index - 2U]) + schedule[index - 7U] +
                          small_sigma0(schedule[index - 15U]) + schedule[index - 16U];
    }
    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];
    for (index = 0U; index < 64U; ++index) {
        uint32_t temp1 = h + sigma1(e) + choose(e, f, g) + ROUND_CONSTANTS[index] + schedule[index];
        uint32_t temp2 = sigma0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

static void sha256_init(sha256_context *context) {
    context->state[0] = 0x6a09e667U;
    context->state[1] = 0xbb67ae85U;
    context->state[2] = 0x3c6ef372U;
    context->state[3] = 0xa54ff53aU;
    context->state[4] = 0x510e527fU;
    context->state[5] = 0x9b05688cU;
    context->state[6] = 0x1f83d9abU;
    context->state[7] = 0x5be0cd19U;
    context->bit_count = 0U;
    context->block_length = 0U;
}

static void sha256_update(sha256_context *context, const uint8_t *data, size_t length) {
    size_t consumed = 0U;
    while (consumed < length) {
        size_t available = 64U - context->block_length;
        size_t take = length - consumed;
        if (take > available) {
            take = available;
        }
        memcpy(context->block + context->block_length, data + consumed, take);
        context->block_length += take;
        consumed += take;
        context->bit_count += (uint64_t)take * 8U;
        if (context->block_length == 64U) {
            sha256_compress(context, context->block);
            context->block_length = 0U;
        }
    }
}

static void sha256_final(sha256_context *context, uint8_t output[32]) {
    uint64_t bit_count = context->bit_count;
    size_t index;
    context->block[context->block_length++] = 0x80U;
    while (context->block_length != 56U) {
        if (context->block_length == 64U) {
            sha256_compress(context, context->block);
            context->block_length = 0U;
        }
        context->block[context->block_length++] = 0U;
    }
    for (index = 0U; index < 8U; ++index) {
        context->block[56U + index] = (uint8_t)(bit_count >> (56U - index * 8U));
    }
    sha256_compress(context, context->block);
    for (index = 0U; index < 8U; ++index) {
        store_u32_be(output + index * 4U, context->state[index]);
    }
}

static int ascii_cstring(const char *value, size_t *length) {
    size_t index;
    if (value == NULL || length == NULL) return -1;
    *length = strlen(value);
    for (index = 0U; index < *length; ++index) {
        if ((unsigned char)value[index] > 0x7FU) return -1;
    }
    return 0;
}

static int strict_utf8(const uint8_t *data, size_t length) {
    size_t index = 0U;
    if (data == NULL && length != 0U) return -1;
    while (index < length) {
        uint8_t first = data[index++];
        if (first <= 0x7FU) continue;
        if (first >= 0xC2U && first <= 0xDFU) {
            if (index >= length || data[index] < 0x80U || data[index] > 0xBFU) return -1;
            ++index;
            continue;
        }
        if (first == 0xE0U) {
            if (index + 1U >= length || data[index] < 0xA0U || data[index] > 0xBFU ||
                data[index + 1U] < 0x80U || data[index + 1U] > 0xBFU) return -1;
            index += 2U;
            continue;
        }
        if ((first >= 0xE1U && first <= 0xECU) || (first >= 0xEEU && first <= 0xEFU)) {
            if (index + 1U >= length || data[index] < 0x80U || data[index] > 0xBFU ||
                data[index + 1U] < 0x80U || data[index + 1U] > 0xBFU) return -1;
            index += 2U;
            continue;
        }
        if (first == 0xEDU) {
            if (index + 1U >= length || data[index] < 0x80U || data[index] > 0x9FU ||
                data[index + 1U] < 0x80U || data[index + 1U] > 0xBFU) return -1;
            index += 2U;
            continue;
        }
        if (first == 0xF0U) {
            if (index + 2U >= length || data[index] < 0x90U || data[index] > 0xBFU ||
                data[index + 1U] < 0x80U || data[index + 1U] > 0xBFU ||
                data[index + 2U] < 0x80U || data[index + 2U] > 0xBFU) return -1;
            index += 3U;
            continue;
        }
        if (first >= 0xF1U && first <= 0xF3U) {
            if (index + 2U >= length || data[index] < 0x80U || data[index] > 0xBFU ||
                data[index + 1U] < 0x80U || data[index + 1U] > 0xBFU ||
                data[index + 2U] < 0x80U || data[index + 2U] > 0xBFU) return -1;
            index += 3U;
            continue;
        }
        if (first == 0xF4U) {
            if (index + 2U >= length || data[index] < 0x80U || data[index] > 0x8FU ||
                data[index + 1U] < 0x80U || data[index + 1U] > 0xBFU ||
                data[index + 2U] < 0x80U || data[index + 2U] > 0xBFU) return -1;
            index += 3U;
            continue;
        }
        return -1;
    }
    return 0;
}

int swz_sha256(const uint8_t *data, size_t length, uint8_t output[32]) {
    sha256_context context;
    if ((data == NULL && length != 0U) || output == NULL) {
        return -1;
    }
    sha256_init(&context);
    sha256_update(&context, data, length);
    sha256_final(&context, output);
    return 0;
}

int swz_lp_append(uint8_t *output, size_t capacity, size_t *offset, swz_bytes value) {
    size_t index;
    if (output == NULL || offset == NULL || value.length > UINT32_MAX || *offset > capacity ||
        capacity - *offset < 4U || value.length > capacity - *offset - 4U ||
        (value.length != 0U && value.data == NULL)) {
        return -1;
    }
    output[*offset] = (uint8_t)(value.length >> 24U);
    output[*offset + 1U] = (uint8_t)(value.length >> 16U);
    output[*offset + 2U] = (uint8_t)(value.length >> 8U);
    output[*offset + 3U] = (uint8_t)value.length;
    *offset += 4U;
    for (index = 0U; index < value.length; ++index) {
        output[*offset + index] = value.data[index];
    }
    *offset += value.length;
    return 0;
}

int swz_managed_hash(const char *domain, const swz_bytes *parts, size_t part_count, uint8_t output[32]) {
    uint8_t preimage[16384];
    size_t offset = 0U;
    size_t index;
    swz_bytes marker = {(const uint8_t *)SWZ_MANAGED_SCHEMA, sizeof(SWZ_MANAGED_SCHEMA) - 1U};
    swz_bytes domain_bytes;
    if (domain == NULL || parts == NULL || output == NULL || part_count > 64U) {
        return -1;
    }
    domain_bytes.data = (const uint8_t *)domain;
    if (ascii_cstring(domain, &domain_bytes.length) != 0) return -1;
    if (swz_lp_append(preimage, sizeof(preimage), &offset, marker) != 0 ||
        swz_lp_append(preimage, sizeof(preimage), &offset, domain_bytes) != 0) {
        return -1;
    }
    for (index = 0U; index < part_count; ++index) {
        if (swz_lp_append(preimage, sizeof(preimage), &offset, parts[index]) != 0) {
            return -1;
        }
    }
    return swz_sha256(preimage, offset, output);
}

int swz_hex_lower(const uint8_t *input, size_t length, char *output, size_t capacity) {
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    if (input == NULL || output == NULL || length > (SIZE_MAX - 1U) / 2U || capacity < length * 2U + 1U) {
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        output[index * 2U] = alphabet[input[index] >> 4U];
        output[index * 2U + 1U] = alphabet[input[index] & 0x0FU];
    }
    output[length * 2U] = '\0';
    return 0;
}

int swz_hex_decode_32(const char *input, uint8_t output[32]) {
    size_t index;
    if (input == NULL || output == NULL || strlen(input) != 64U) {
        return -1;
    }
    for (index = 0U; index < 32U; ++index) {
        uint8_t high;
        uint8_t low;
        char high_char = input[index * 2U];
        char low_char = input[index * 2U + 1U];
        if (high_char >= '0' && high_char <= '9') high = (uint8_t)(high_char - '0');
        else if (high_char >= 'a' && high_char <= 'f') high = (uint8_t)(high_char - 'a' + 10);
        else return -1;
        if (low_char >= '0' && low_char <= '9') low = (uint8_t)(low_char - '0');
        else if (low_char >= 'a' && low_char <= 'f') low = (uint8_t)(low_char - 'a' + 10);
        else return -1;
        output[index] = (uint8_t)((high << 4U) | low);
    }
    return 0;
}

int swz_store_commitment(const char *domain, swz_bytes store_bytes, char output[75]) {
    uint8_t preimage[16384];
    uint8_t digest[32];
    size_t offset = 0U;
    swz_bytes marker = {(const uint8_t *)"recovery-commitment.v1", sizeof("recovery-commitment.v1") - 1U};
    swz_bytes domain_bytes;
    if (domain == NULL || output == NULL || store_bytes.data == NULL || store_bytes.length == 0U || store_bytes.length > SWZ_MAX_CONTROL_PAYLOAD_BYTES ||
        ascii_cstring(domain, &domain_bytes.length) != 0) {
        return -1;
    }
    domain_bytes.data = (const uint8_t *)domain;
    if (swz_lp_append(preimage, sizeof(preimage), &offset, marker) != 0 ||
        swz_lp_append(preimage, sizeof(preimage), &offset, domain_bytes) != 0 ||
        swz_lp_append(preimage, sizeof(preimage), &offset, store_bytes) != 0 ||
        swz_sha256(preimage, offset, digest) != 0) {
        return -1;
    }
    memcpy(output, SWZ_STORE_COMMITMENT_PREFIX, sizeof(SWZ_STORE_COMMITMENT_PREFIX) - 1U);
    return swz_hex_lower(digest, sizeof(digest), output + sizeof(SWZ_STORE_COMMITMENT_PREFIX) - 1U, 75U - (sizeof(SWZ_STORE_COMMITMENT_PREFIX) - 1U));
}

int swz_store_transition_id(swz_bytes store_bytes, char output[60]) {
    uint8_t preimage[12288];
    uint8_t digest[32];
    size_t offset = 0U;
    swz_bytes marker = {(const uint8_t *)"restore-transition-id.v2", sizeof("restore-transition-id.v2") - 1U};
    if (output == NULL || store_bytes.data == NULL || store_bytes.length == 0U || store_bytes.length > SWZ_MAX_CONTROL_PAYLOAD_BYTES ||
        swz_lp_append(preimage, sizeof(preimage), &offset, marker) != 0 ||
        swz_lp_append(preimage, sizeof(preimage), &offset, store_bytes) != 0 ||
        swz_sha256(preimage, offset, digest) != 0) {
        return -1;
    }
    memcpy(output, "restore-v2-", sizeof("restore-v2-") - 1U);
    if (swz_hex_lower(digest, 24U, output + sizeof("restore-v2-") - 1U, 60U - (sizeof("restore-v2-") - 1U)) != 0) {
        return -1;
    }
    output[59] = '\0';
    return 0;
}

static int append_json_string(uint8_t *output, size_t capacity, size_t *offset, const uint8_t *data, size_t length) {
    size_t index;
    const char *hex = "0123456789abcdef";
    if (output == NULL || offset == NULL || (data == NULL && length != 0U) || *offset > capacity) {
        return -1;
    }
    if (capacity - *offset < 1U) return -1;
    output[(*offset)++] = '"';
    for (index = 0U; index < length; ++index) {
        uint8_t value = data[index];
        if (value == '"' || value == '\\') {
            if (capacity - *offset < 2U) return -1;
            output[(*offset)++] = '\\';
            output[(*offset)++] = value;
        } else if (value == '\b' || value == '\f' || value == '\n' || value == '\r' || value == '\t') {
            const char escapes[] = {'b', 'f', 'n', 'r', 't'};
            if (capacity - *offset < 2U) return -1;
            output[(*offset)++] = '\\';
            output[(*offset)++] = escapes[value == '\b' ? 0 : value == '\f' ? 1 : value == '\n' ? 2 : value == '\r' ? 3 : 4];
        } else if (value < 0x20U) {
            if (capacity - *offset < 6U) return -1;
            output[(*offset)++] = '\\';
            output[(*offset)++] = 'u';
            output[(*offset)++] = '0';
            output[(*offset)++] = '0';
            output[(*offset)++] = hex[value >> 4U];
            output[(*offset)++] = hex[value & 0x0FU];
        } else {
            if (capacity - *offset < 1U) return -1;
            output[(*offset)++] = value;
        }
    }
    if (capacity - *offset < 1U) return -1;
    output[(*offset)++] = '"';
    return 0;
}

int swz_store_wire_encode(const char *schema_id, swz_bytes store_bytes, uint8_t *output, size_t capacity, size_t *written) {
    size_t offset = 0U;
    swz_bytes marker = {(const uint8_t *)SWZ_STORE_MARKER, sizeof(SWZ_STORE_MARKER) - 1U};
    swz_bytes schema;
    if (schema_id == NULL || output == NULL || written == NULL || store_bytes.data == NULL || store_bytes.length == 0U ||
        store_bytes.length > SWZ_MAX_CONTROL_PAYLOAD_BYTES) {
        return -1;
    }
    if (strcmp(schema_id, "restore-ledger-transition-data.v2") != 0 &&
        strcmp(schema_id, "restore-begin-evidence.v2") != 0 &&
        strcmp(schema_id, "swz-recovery-result.v2") != 0) return -1;
    if (strict_utf8(store_bytes.data, store_bytes.length) != 0) return -1;
    if (store_bytes.data[store_bytes.length - 1U] != '\n' || (store_bytes.length > 1U && store_bytes.data[store_bytes.length - 2U] == '\n')) {
        return -1;
    }
    schema.data = (const uint8_t *)schema_id;
    schema.length = strlen(schema_id);
    if (offset + 1U > capacity) return -1;
    output[offset++] = '[';
    if (append_json_string(output, capacity, &offset, marker.data, marker.length) != 0) return -1;
    if (offset + 1U > capacity) return -1;
    output[offset++] = ',';
    if (append_json_string(output, capacity, &offset, schema.data, schema.length) != 0) return -1;
    if (offset + 1U > capacity) return -1;
    output[offset++] = ',';
    if (append_json_string(output, capacity, &offset, store_bytes.data, store_bytes.length) != 0) return -1;
    if (offset + 1U > capacity) return -1;
    output[offset++] = ']';
    if (offset > SWZ_MAX_CONTROL_PAYLOAD_BYTES) return -1;
    *written = offset;
    return 0;
}
