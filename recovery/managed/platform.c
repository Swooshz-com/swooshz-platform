#include "platform.h"

#include <string.h>

static bool generation_transition_allowed(swz_generation_state current, swz_generation_state target) {
    return (current == SWZ_GENERATION_OFFLINE && target == SWZ_GENERATION_QUALIFIED) ||
           (current == SWZ_GENERATION_QUALIFIED && target == SWZ_GENERATION_ACTIVE) ||
           (current == SWZ_GENERATION_ACTIVE && target == SWZ_GENERATION_DRAINING) ||
           (current == SWZ_GENERATION_DRAINING && target == SWZ_GENERATION_RETIRING) ||
           (current == SWZ_GENERATION_RETIRING && target == SWZ_GENERATION_OFFLINE);
}

static bool connection_transition_allowed(swz_connection_state current, swz_connection_state target) {
    return (current == SWZ_CONN_ACCEPTED_SOCKET && (target == SWZ_CONN_SSH_AUTHENTICATED || target == SWZ_CONN_FAILED)) ||
           (current == SWZ_CONN_SSH_AUTHENTICATED && (target == SWZ_CONN_BOOTSTRAP || target == SWZ_CONN_FAILED)) ||
           (current == SWZ_CONN_BOOTSTRAP && (target == SWZ_CONN_CHALLENGE || target == SWZ_CONN_FAILED)) ||
           (current == SWZ_CONN_CHALLENGE && (target == SWZ_CONN_EVIDENCE || target == SWZ_CONN_FAILED)) ||
           (current == SWZ_CONN_EVIDENCE && (target == SWZ_CONN_CONTROLLER_VALIDATED || target == SWZ_CONN_FAILED)) ||
           (current == SWZ_CONN_CONTROLLER_VALIDATED && (target == SWZ_CONN_ACCEPT_SENT || target == SWZ_CONN_FAILED)) ||
           (current == SWZ_CONN_ACCEPT_SENT && (target == SWZ_CONN_REMOTE_ACCEPTED || target == SWZ_CONN_FAILED)) ||
           (current == SWZ_CONN_REMOTE_ACCEPTED && (target == SWZ_CONN_OPERATIONAL || target == SWZ_CONN_FAILED)) ||
           (current == SWZ_CONN_OPERATIONAL && target == SWZ_CONN_FAILED);
}

static bool broker_transition_allowed(swz_broker_state current, swz_broker_state target) {
    return (current == SWZ_BROKER_REMOTE_ACCEPTED && (target == SWZ_BROKER_DISCOVERY || target == SWZ_BROKER_CONSUMED_UNCERTAINTY)) ||
           (current == SWZ_BROKER_DISCOVERY && (target == SWZ_BROKER_CAS_A || target == SWZ_BROKER_CONSUMED_UNCERTAINTY)) ||
           (current == SWZ_BROKER_CAS_A && (target == SWZ_BROKER_RESTORE_BEGIN_DURABLE || target == SWZ_BROKER_CONSUMED_UNCERTAINTY)) ||
           (current == SWZ_BROKER_RESTORE_BEGIN_DURABLE && (target == SWZ_BROKER_PROCEED || target == SWZ_BROKER_CONSUMED_UNCERTAINTY)) ||
           (current == SWZ_BROKER_PROCEED && (target == SWZ_BROKER_HALF_CLOSED || target == SWZ_BROKER_CONSUMED_UNCERTAINTY)) ||
           (current == SWZ_BROKER_HALF_CLOSED && (target == SWZ_BROKER_REMOTE_EOF || target == SWZ_BROKER_CONSUMED_UNCERTAINTY)) ||
           (current == SWZ_BROKER_REMOTE_EOF && (target == SWZ_BROKER_RESTORE_AUTHORIZED || target == SWZ_BROKER_CONSUMED_UNCERTAINTY)) ||
           (current == SWZ_BROKER_RESTORE_AUTHORIZED && (target == SWZ_BROKER_RESULT || target == SWZ_BROKER_CONSUMED_UNCERTAINTY)) ||
           (current == SWZ_BROKER_RESULT && (target == SWZ_BROKER_FINAL || target == SWZ_BROKER_CONSUMED_UNCERTAINTY));
}

int swz_generation_init(swz_generation *generation, const uint8_t identity[32]) {
    if (generation == NULL || identity == NULL) return -1;
    memset(generation, 0, sizeof(*generation));
    generation->state = SWZ_GENERATION_OFFLINE;
    memcpy(generation->identity, identity, sizeof(generation->identity));
    return 0;
}

int swz_generation_advance(swz_generation *generation, swz_generation_state target) {
    if (generation == NULL || !generation_transition_allowed(generation->state, target)) return -1;
    if (target == SWZ_GENERATION_ACTIVE && generation->active_connections != 0U) return -1;
    generation->state = target;
    return 0;
}

int swz_connection_init(swz_connection *connection, const uint8_t session_identity[32]) {
    if (connection == NULL || session_identity == NULL) return -1;
    memset(connection, 0, sizeof(*connection));
    connection->state = SWZ_CONN_ACCEPTED_SOCKET;
    memcpy(connection->session_identity, session_identity, sizeof(connection->session_identity));
    return 0;
}

int swz_connection_advance(swz_connection *connection, swz_connection_state target) {
    if (connection == NULL || !connection_transition_allowed(connection->state, target)) return -1;
    connection->state = target;
    if (target == SWZ_CONN_REMOTE_ACCEPTED) connection->recovery_effect_reachable = true;
    if (target == SWZ_CONN_OPERATIONAL) connection->store_mutation_reachable = true;
    if (target == SWZ_CONN_FAILED) {
        connection->store_mutation_reachable = false;
        connection->recovery_effect_reachable = false;
    }
    return 0;
}

int swz_connection_fail(swz_connection *connection) {
    return swz_connection_advance(connection, SWZ_CONN_FAILED);
}

int swz_broker_init(swz_broker *broker) {
    if (broker == NULL) return -1;
    memset(broker, 0, sizeof(*broker));
    broker->state = SWZ_BROKER_REMOTE_ACCEPTED;
    return 0;
}

int swz_broker_advance(swz_broker *broker, swz_broker_state target) {
    if (broker == NULL || !broker_transition_allowed(broker->state, target)) return -1;
    broker->state = target;
    return 0;
}

int swz_broker_mark_uncertain(swz_broker *broker) {
    if (broker == NULL || broker->state == SWZ_BROKER_FINAL || broker->state == SWZ_BROKER_CONSUMED_UNCERTAINTY) return -1;
    broker->state = SWZ_BROKER_CONSUMED_UNCERTAINTY;
    return 0;
}

bool swz_connection_can_mutate_store(const swz_connection *connection) {
    return connection != NULL && connection->state == SWZ_CONN_OPERATIONAL && connection->store_mutation_reachable;
}

bool swz_connection_can_recover(const swz_connection *connection) {
    return connection != NULL && connection->state == SWZ_CONN_OPERATIONAL && connection->recovery_effect_reachable;
}

bool swz_broker_can_authorize_restore(const swz_broker *broker) {
    return broker != NULL && broker->state == SWZ_BROKER_RESTORE_AUTHORIZED && broker->restore_begin_durable && broker->remote_eof && broker->trailing_input_bytes == 0U && broker->half_close_count == 1U;
}

bool swz_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length) {
    uint8_t difference = 0U;
    size_t index;
    if (left == NULL || right == NULL) return false;
    for (index = 0U; index < length; ++index) difference |= (uint8_t)(left[index] ^ right[index]);
    return difference == 0U;
}
