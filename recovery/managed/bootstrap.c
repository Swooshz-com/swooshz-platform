#define _GNU_SOURCE

#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int send_boot_frame(const unsigned char *context, size_t length)
{
    struct swz_frame frame;

    memset(&frame, 0, sizeof(frame));
    frame.direction = 1U;
    frame.type = SWZ_BOOT;
    frame.sequence = 1U;
    frame.payload = (unsigned char *)context;
    frame.payload_length = (uint32_t)length;
    return swz_frame_write(STDOUT_FILENO, &frame);
}

static int exchange_admission(void)
{
    unsigned char payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    struct swz_frame incoming;
    struct swz_frame outgoing;

    memset(&incoming, 0, sizeof(incoming));
    if (swz_frame_read(STDIN_FILENO, &incoming, payload, sizeof(payload)) != 0 ||
        incoming.type != SWZ_CHALLENGE) {
        return -1;
    }
    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.direction = 1U;
    outgoing.type = SWZ_EVIDENCE;
    outgoing.sequence = incoming.sequence + 1U;
    outgoing.previous_hash[0] = 1U;
    outgoing.payload = payload;
    outgoing.payload_length = incoming.payload_length;
    if (swz_frame_write(STDOUT_FILENO, &outgoing) != 0 ||
        swz_frame_read(STDIN_FILENO, &incoming, payload, sizeof(payload)) != 0 ||
        incoming.type != SWZ_ACCEPT) {
        return -1;
    }
    memset(&outgoing, 0, sizeof(outgoing));
    outgoing.direction = 1U;
    outgoing.type = SWZ_ACCEPTED;
    outgoing.sequence = incoming.sequence + 1U;
    outgoing.previous_hash[0] = 2U;
    outgoing.payload = payload;
    outgoing.payload_length = incoming.payload_length;
    return swz_frame_write(STDOUT_FILENO, &outgoing);
}

int main(void)
{
    unsigned char context[SWZ_CONTEXT_BYTES];

    if (swz_confine_component("bootstrap") != 0 ||
        swz_read_full(SWZ_CONTEXT_FD, context, sizeof(context)) != 0 ||
        memcmp(context, "SWZCTX01", sizeof(SWZ_CONTEXT_MAGIC) - 1U) != 0 ||
        send_boot_frame(context, sizeof(context)) != 0 ||
        exchange_admission() != 0) {
        return 126;
    }
    execl(SWZ_BROKER_PATH, SWZ_BROKER_PATH, (char *)NULL);
    return errno == ENOENT ? 127 : 126;
}
