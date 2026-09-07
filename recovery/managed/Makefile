PYTHON ?= python3

.PHONY: all build test qualify hosted-security

all: build test

build:
	$(PYTHON) build.py --verify

test:
	$(PYTHON) -m unittest discover -s ../../tests/recovery-managed -p 'test_*.py'

qualify:
	$(PYTHON) qualify.py --deterministic

hosted-security:
	$(PYTHON) qualification-vm.py --required
