CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -fno-plt -fstack-protector-strong
CPPFLAGS ?= -D_FORTIFY_SOURCE=2
LDLIBS ?= -lcrypto
BUILD ?= build

COMMON = $(BUILD)/platform.o $(BUILD)/protocol.o
COMPONENTS = $(BUILD)/swz-supervisor $(BUILD)/swz-custodian $(BUILD)/swz-dispatcher $(BUILD)/swz-bootstrap $(BUILD)/swz-broker $(BUILD)/swz-agent $(BUILD)/swz-launch-base

.PHONY: all clean static-closure

all: $(COMPONENTS)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/platform.o: platform.c platform.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/protocol.o: protocol.c protocol.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/supervisor.o: supervisor.c platform.h protocol.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/custodian.o: custodian.c platform.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/dispatcher.o: dispatcher.c platform.h protocol.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c dispatcher.c -o $@

$(BUILD)/bootstrap.o: bootstrap.c platform.h protocol.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/broker.o: broker.c platform.h protocol.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/agent.o: agent.c platform.h protocol.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/launch-base.o: launch-base.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD)/swz-supervisor: $(BUILD)/supervisor.o $(COMMON)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/swz-custodian: $(BUILD)/custodian.o $(BUILD)/platform.o
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/swz-dispatcher: $(BUILD)/dispatcher.o $(COMMON)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/swz-bootstrap: $(BUILD)/bootstrap.o $(COMMON)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/swz-broker: $(BUILD)/broker.o $(COMMON)
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/swz-agent: $(BUILD)/agent.o $(BUILD)/platform.o $(BUILD)/protocol.o
	$(CC) $(CFLAGS) $^ $(LDLIBS) -o $@

$(BUILD)/swz-launch-base: $(BUILD)/launch-base.o
	$(CC) $(CFLAGS) $^ -o $@

static-closure: all
	@set -eu; for binary in $(COMPONENTS); do file "$$binary"; ldd "$$binary"; done

clean:
	rm -rf $(BUILD)
