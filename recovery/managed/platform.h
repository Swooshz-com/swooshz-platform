#ifndef SWZ_MANAGED_PLATFORM_H
#define SWZ_MANAGED_PLATFORM_H

#include "protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    SWZ_GENERATION_OFFLINE = 0,
    SWZ_GENERATION_QUALIFIED = 1,
    SWZ_GENERATION_ACTIVE = 2,
    SWZ_GENERATION_DRAINING = 3,
    SWZ_GENERATION_RETIRING = 4
} swz_generation_state;

typedef enum {
    SWZ_CONN_ACCEPTED_SOCKET = 0,
    SWZ_CONN_SSH_AUTHENTICATED = 1,
    SWZ_CONN_BOOTSTRAP = 2,
    SWZ_CONN_CHALLENGE = 3,
    SWZ_CONN_EVIDENCE = 4,
    SWZ_CONN_CONTROLLER_VALIDATED = 5,
    SWZ_CONN_ACCEPT_SENT = 6,
    SWZ_CONN_REMOTE_ACCEPTED = 7,
    SWZ_CONN_OPERATIONAL = 8,
    SWZ_CONN_FAILED = 9
} swz_connection_state;

typedef enum {
    SWZ_BROKER_REMOTE_ACCEPTED = 0,
    SWZ_BROKER_DISCOVERY = 1,
    SWZ_BROKER_CAS_A = 2,
    SWZ_BROKER_RESTORE_BEGIN_DURABLE = 3,
    SWZ_BROKER_PROCEED = 4,
    SWZ_BROKER_HALF_CLOSED = 5,
    SWZ_BROKER_REMOTE_EOF = 6,
    SWZ_BROKER_RESTORE_AUTHORIZED = 7,
    SWZ_BROKER_RESULT = 8,
    SWZ_BROKER_FINAL = 9,
    SWZ_BROKER_CONSUMED_UNCERTAINTY = 10
} swz_broker_state;

typedef struct {
    swz_generation_state state;
    uint8_t identity[32];
    uint32_t active_connections;
} swz_generation;

typedef struct {
    swz_connection_state state;
    uint8_t session_identity[32];
    bool store_mutation_reachable;
    bool recovery_effect_reachable;
    uint32_t half_close_count;
} swz_connection;

typedef struct {
    swz_broker_state state;
    uint32_t half_close_count;
    bool store_cas_consumed;
    bool restore_begin_durable;
    bool remote_eof;
    uint32_t trailing_input_bytes;
} swz_broker;

int swz_generation_init(swz_generation *generation, const uint8_t identity[32]);
int swz_generation_advance(swz_generation *generation, swz_generation_state target);
int swz_connection_init(swz_connection *connection, const uint8_t session_identity[32]);
int swz_connection_advance(swz_connection *connection, swz_connection_state target);
int swz_connection_fail(swz_connection *connection);
int swz_broker_init(swz_broker *broker);
int swz_broker_advance(swz_broker *broker, swz_broker_state target);
int swz_broker_mark_uncertain(swz_broker *broker);
bool swz_connection_can_mutate_store(const swz_connection *connection);
bool swz_connection_can_recover(const swz_connection *connection);
bool swz_broker_can_authorize_restore(const swz_broker *broker);
bool swz_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length);

int swz_supervisor_init(swz_generation *generation, const uint8_t identity[32]);
int swz_supervisor_accept_one(swz_generation *generation, swz_connection *connection, const uint8_t session_identity[32]);
int swz_supervisor_retire(swz_generation *generation);

int swz_custodian_authorize(uint32_t owner_pid, uint64_t connection_cookie, const uint8_t session_identity[32]);
int swz_custodian_sign(uint32_t owner_pid, uint64_t connection_cookie, const uint8_t session_identity[32], const uint8_t *message, size_t message_length, uint8_t signature[64]);

int swz_dispatcher_validate_command(const uint8_t *command, size_t command_length);
int swz_bootstrap_validate_nonces(const uint8_t local_nonce[32], const uint8_t remote_nonce[32]);
int swz_launch_base_validate(bool static_native, bool pam_absent, bool dm_verity_verified, bool selinux_enforcing);

int swz_broker_discovery(swz_broker *broker);
int swz_broker_cas_a(swz_broker *broker);
int swz_broker_restore_begin(swz_broker *broker);
int swz_broker_proceed(swz_broker *broker);
int swz_broker_half_close(swz_broker *broker);
int swz_broker_remote_eof(swz_broker *broker, uint32_t trailing_input_bytes);
int swz_broker_authorize_restore(swz_broker *broker);
int swz_broker_result(swz_broker *broker);
int swz_agent_restore_allowed(const swz_broker *broker);

#endif
