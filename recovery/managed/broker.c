#define _GNU_SOURCE

#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int emit_text_frame(uint16_t type, uint64_t sequence,
                           const unsigned char previous_hash[32],
                           const char *text)
{
    struct swz_frame frame;

    memset(&frame, 0, sizeof(frame));
    frame.direction = 1U;
    frame.type = type;
    frame.sequence = sequence;
    memcpy(frame.previous_hash, previous_hash, 32U);
    frame.payload = (unsigned char *)text;
    frame.payload_length = (uint32_t)strlen(text);
    return swz_frame_write(STDOUT_FILENO, &frame);
}

static int run_restore_sequence(void)
{
    unsigned char context[SWZ_CONTEXT_BYTES];
    unsigned char payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    unsigned char discovery_hash[32] = { 0 };
    unsigned char restore_hash[32] = { 0 };
    struct swz_frame incoming;
    static const char discovery[] = "DISCOVERY";
    static const char restore_begin[] = "RESTORE_BEGIN";
    static const char result[] = "RESULT";
    static const char final[] = "BROKER_FINAL";

    if (swz_read_full(SWZ_CONTEXT_FD, context, sizeof(context)) != 0 ||
        memcmp(context, SWZ_CONTEXT_MAGIC, sizeof(SWZ_CONTEXT_MAGIC) - 1U) != 0 ||
        emit_text_frame(SWZ_DISCOVERY, 1U, discovery_hash, discovery) != 0 ||
        emit_text_frame(SWZ_RESTORE_BEGIN, 2U, discovery_hash, restore_begin) != 0 ||
        swz_frame_read(STDIN_FILENO, &incoming, payload, sizeof(payload)) != 0 ||
        incoming.type != SWZ_PROCEED ||
        emit_text_frame(SWZ_RESULT, 3U, restore_hash, result) != 0 ||
        emit_text_frame(SWZ_BROKER_FINAL, 4U, restore_hash, final) != 0) {
        return -1;
    }
    return 0;
}

int main(void)
{
    if (swz_confine_component("broker") != 0) {
        return 126;
    }
    return run_restore_sequence() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

