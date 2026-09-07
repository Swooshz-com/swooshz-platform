#include "platform.h"

int swz_broker_discovery(swz_broker *broker) {
    return swz_broker_advance(broker, SWZ_BROKER_DISCOVERY);
}

int swz_broker_cas_a(swz_broker *broker) {
    if (broker == NULL || broker->state != SWZ_BROKER_DISCOVERY) return -1;
    broker->store_cas_consumed = true;
    return swz_broker_advance(broker, SWZ_BROKER_CAS_A);
}

int swz_broker_restore_begin(swz_broker *broker) {
    if (broker == NULL || !broker->store_cas_consumed) return -1;
    broker->restore_begin_durable = true;
    return swz_broker_advance(broker, SWZ_BROKER_RESTORE_BEGIN_DURABLE);
}

int swz_broker_proceed(swz_broker *broker) {
    return swz_broker_advance(broker, SWZ_BROKER_PROCEED);
}

int swz_broker_half_close(swz_broker *broker) {
    if (broker == NULL || broker->state != SWZ_BROKER_PROCEED || broker->half_close_count != 0U) return -1;
    broker->half_close_count = 1U;
    return swz_broker_advance(broker, SWZ_BROKER_HALF_CLOSED);
}

int swz_broker_remote_eof(swz_broker *broker, uint32_t trailing_input_bytes) {
    if (broker == NULL || broker->state != SWZ_BROKER_HALF_CLOSED) return -1;
    broker->trailing_input_bytes = trailing_input_bytes;
    if (trailing_input_bytes != 0U) return swz_broker_mark_uncertain(broker);
    broker->remote_eof = true;
    return swz_broker_advance(broker, SWZ_BROKER_REMOTE_EOF);
}

int swz_broker_authorize_restore(swz_broker *broker) {
    if (broker == NULL || broker->state != SWZ_BROKER_REMOTE_EOF || !broker->restore_begin_durable || !broker->remote_eof || broker->trailing_input_bytes != 0U || broker->half_close_count != 1U) return -1;
    return swz_broker_advance(broker, SWZ_BROKER_RESTORE_AUTHORIZED);
}

int swz_broker_result(swz_broker *broker) {
    if (broker == NULL || broker->state != SWZ_BROKER_RESTORE_AUTHORIZED) return -1;
    return swz_broker_advance(broker, SWZ_BROKER_RESULT);
}
