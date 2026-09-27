# SPDX-License-Identifier: GPL-2.0-only
CC ?= cc
CPPFLAGS += -Iinclude
CFLAGS ?= -O2 -g
STRICT = -std=c11 -Wall -Wextra -Werror -Wpedantic -Wconversion -Wshadow
SOURCES = src/ntw_pcie.c tests/test_pcie.c

.PHONY: all test sanitize clean
all: test

build:
	mkdir -p build

build/test_pcie: $(SOURCES) include/ntw_pcie.h Makefile | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(STRICT) $(SOURCES) -o $@

build/test_pcie_sanitize: $(SOURCES) include/ntw_pcie.h Makefile | build
	$(CC) $(CPPFLAGS) -O1 -g $(STRICT) -fsanitize=address,undefined -fno-omit-frame-pointer $(SOURCES) -o $@

test: build/test_pcie
	./build/test_pcie

sanitize: build/test_pcie_sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build/test_pcie_sanitize

clean:
	rm -f build/test_pcie build/test_pcie_sanitize
