#include "platform.h"

#include <string.h>

static const uint8_t EXPECTED_COMMAND[] = "SWOOSHZ_RECOVERY_V1";

int swz_dispatcher_validate_command(const uint8_t *command, size_t command_length) {
    if (command == NULL || command_length != sizeof(EXPECTED_COMMAND) - 1U) return -1;
    return memcmp(command, EXPECTED_COMMAND, sizeof(EXPECTED_COMMAND) - 1U) == 0 ? 0 : -1;
}
