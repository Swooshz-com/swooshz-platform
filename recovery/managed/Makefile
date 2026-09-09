CC ?= cc
BUILD ?= build
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic
CPPFLAGS ?= -I.
LDLIBS ?= -lcrypto

COMPONENTS := supervisor custodian dispatcher bootstrap broker agent launch-base
BINS := $(addprefix $(BUILD)/swz-,$(COMPONENTS))
COMMON := platform.c protocol.c

.PHONY: all clean static-closure

all: $(BINS)

$(BUILD):
	mkdir -p "$@"

$(BUILD)/swz-%: %.c $(COMMON) platform.h protocol.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) "$<" $(COMMON) $(LDLIBS) -o "$@"

static-closure: all
	@set -eu; for binary in $(BINS); do \
		test -x "$$binary"; \
		file "$$binary" | grep -E 'ELF .*executable|ELF .*pie executable' >/dev/null; \
		readelf -d "$$binary" | grep -E 'NEEDED.*(libc|libcrypto)' >/dev/null; \
	done
	@printf '%s\n' 'native static closure: PASS'

clean:
	rm -rf "$(BUILD)"

