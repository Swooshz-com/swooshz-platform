#include "platform.h"

#include <stddef.h>

int swz_custodian_authorize(uint32_t owner_pid, uint64_t connection_cookie, const uint8_t session_identity[32]) {
    if (owner_pid == 0U || connection_cookie == 0U || session_identity == NULL) return -1;
    return 0;
}

int swz_custodian_sign(uint32_t owner_pid, uint64_t connection_cookie, const uint8_t session_identity[32], const uint8_t *message, size_t message_length, uint8_t signature[64]) {
    (void)message;
    (void)message_length;
    (void)signature;
    /* The private key is never present in this process. Signing is supplied by
       a separately enrolled protected key service after these bindings pass. */
    if (swz_custodian_authorize(owner_pid, connection_cookie, session_identity) != 0) return -1;
    return -1;
}
