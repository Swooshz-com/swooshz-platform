#include "platform.h"

#include <string.h>

int swz_supervisor_init(swz_generation *generation, const uint8_t identity[32]) {
    return swz_generation_init(generation, identity);
}

int swz_supervisor_accept_one(swz_generation *generation, swz_connection *connection, const uint8_t session_identity[32]) {
    if (generation == NULL || connection == NULL || session_identity == NULL || generation->state != SWZ_GENERATION_ACTIVE || generation->active_connections != 0U) return -1;
    if (swz_connection_init(connection, session_identity) != 0) return -1;
    generation->active_connections = 1U;
    return 0;
}

int swz_supervisor_retire(swz_generation *generation) {
    if (generation == NULL || generation->active_connections != 0U || generation->state != SWZ_GENERATION_RETIRING) return -1;
    return swz_generation_advance(generation, SWZ_GENERATION_OFFLINE);
}
