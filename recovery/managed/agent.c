#define _GNU_SOURCE

#include "platform.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int copy_restore_stream(int source_fd, int destination_fd)
{
    unsigned char buffer[65536];
    ssize_t received;

    for (;;) {
        do {
            received = read(source_fd, buffer, sizeof(buffer));
        } while (received < 0 && errno == EINTR);
        if (received == 0) {
            break;
        }
        if (received < 0 || swz_write_full(destination_fd, buffer,
                                           (size_t)received) != 0) {
            return -1;
        }
    }
    return fsync(destination_fd);
}

static int verify_terminal_input_eof(void)
{
    unsigned char byte;
    ssize_t result = read(STDIN_FILENO, &byte, sizeof(byte));

    return result == 0 ? 0 : -1;
}

static int await_proceed_and_eof(void)
{
    unsigned char payload[SWZ_MAX_CONTROL_PAYLOAD_BYTES];
    struct swz_frame incoming;

    if (swz_frame_read(STDIN_FILENO, &incoming, payload, sizeof(payload)) != 0 ||
        incoming.type != SWZ_PROCEED || incoming.direction != 1U ||
        incoming.sequence != 7U || verify_terminal_input_eof() != 0) {
        return -1;
    }
    return 0;
}

int main(void)
{
    int source_fd = fcntl(4, F_GETFD);
    int destination_fd = fcntl(5, F_GETFD);

    if (swz_confine_component("agent") != 0) {
        return 126;
    }
    if (source_fd < 0 || destination_fd < 0 || copy_restore_stream(4, 5) != 0) {
        return 126;
    }
    return await_proceed_and_eof() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
