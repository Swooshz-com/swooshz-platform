CC ?= cc
BUILD ?= build
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic -D_GNU_SOURCE
CPPFLAGS ?= -I.
LDLIBS ?= -lcrypto

COMPONENTS = supervisor custodian dispatcher bootstrap broker agent launch-base
BINS = $(addprefix $(BUILD)/swz-,$(COMPONENTS))
COMMON = platform.c protocol.c

.PHONY: all clean static-closure

all: $(BINS)

$(BUILD):
	mkdir -p "$@"

$(BUILD)/swz-supervisor: supervisor.c $(COMMON) platform.h protocol.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< platform.c protocol.c $(LDLIBS) -o "$@"

$(BUILD)/swz-custodian: custodian.c $(COMMON) platform.h protocol.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< platform.c protocol.c $(LDLIBS) -o "$@"

$(BUILD)/swz-dispatcher: dispatcher.c $(COMMON) platform.h protocol.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< platform.c protocol.c $(LDLIBS) -o "$@"

$(BUILD)/swz-bootstrap: bootstrap.c $(COMMON) platform.h protocol.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< platform.c protocol.c $(LDLIBS) -o "$@"

$(BUILD)/swz-broker: broker.c $(COMMON) platform.h protocol.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< platform.c protocol.c $(LDLIBS) -o "$@"

$(BUILD)/swz-agent: agent.c $(COMMON) platform.h protocol.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< platform.c protocol.c $(LDLIBS) -o "$@"

$(BUILD)/swz-launch-base: launch-base.c $(COMMON) platform.h protocol.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< platform.c protocol.c $(LDLIBS) -o "$@"

static-closure: all
	@set -eu; for binary in $(BINS); do test -x "$$binary"; file "$$binary"; done

clean:
	rm -rf "$(BUILD)"
