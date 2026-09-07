#include "platform.h"

int swz_agent_restore_allowed(const swz_broker *broker) {
    return swz_broker_can_authorize_restore(broker) ? 0 : -1;
}
