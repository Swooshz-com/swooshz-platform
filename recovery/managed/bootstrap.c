#include "platform.h"

int swz_bootstrap_validate_nonces(const uint8_t local_nonce[32], const uint8_t remote_nonce[32]) {
    size_t index;
    uint8_t local_nonzero = 0U;
    uint8_t remote_nonzero = 0U;
    if (local_nonce == NULL || remote_nonce == NULL) return -1;
    for (index = 0U; index < 32U; ++index) {
        local_nonzero |= local_nonce[index];
        remote_nonzero |= remote_nonce[index];
    }
    return (local_nonzero != 0U && remote_nonzero != 0U && !swz_constant_time_equal(local_nonce, remote_nonce, 32U)) ? 0 : -1;
}
