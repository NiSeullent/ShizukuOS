# SPDX-License-Identifier: GPL-2.0-only
# ShizukuFS v1 host build: libsfs + tools, sanitizer builds for the tests, an optimised build for the benchmarks,
# and a freestanding compile check (the same sources are linked into Kernel64).
CC ?= cc
B := build
LIB := $(addprefix libsfs/,sfs_crc.c sfs_cache.c sfs_super.c sfs_inode.c sfs_extent.c sfs_alloc.c sfs_hash.c \
                          sfs_dir.c sfs_file.c sfs_jbd2.c sfs_api.c)
HOST := tools/sfs_host.c tools/sha256.c
HDRS := $(wildcard libsfs/*.h tools/*.h)
WARN := -std=c11 -Wall -Wextra -Wshadow -Wstrict-prototypes -Wno-unused-parameter -Wvla
SAN := -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer

all: $(B)/sfstool $(B)/sfstool-fast $(B)/sfsfuzz $(B)/sfsperf freestanding

$(B):
	mkdir -p $(B)

$(B)/sfstool: $(LIB) $(HOST) tools/sfstool.c $(HDRS) | $(B)
	$(CC) $(WARN) -O1 -g $(SAN) -o $@ $(LIB) $(HOST) tools/sfstool.c

$(B)/sfstool-fast: $(LIB) $(HOST) tools/sfstool.c $(HDRS) | $(B)
	$(CC) $(WARN) -O2 -g -o $@ $(LIB) $(HOST) tools/sfstool.c

$(B)/sfsfuzz: $(LIB) $(HOST) tests/sfsfuzz.c $(HDRS) | $(B)
	$(CC) $(WARN) -O1 -g $(SAN) -o $@ $(LIB) $(HOST) tests/sfsfuzz.c

$(B)/sfsperf: $(LIB) $(HOST) tests/sfsperf.c $(HDRS) | $(B)
	$(CC) $(WARN) -O2 -g -o $@ $(LIB) $(HOST) tests/sfsperf.c

# Freestanding: no libc headers beyond stddef/stdint, no red zone, no SSE (kernel code model).
freestanding: $(LIB) $(HDRS) | $(B)
	@for f in $(LIB); do $(CC) $(WARN) -O2 -ffreestanding -fno-builtin -nostdinc -isystem $$($(CC) -print-file-name=include) \
	   -mno-red-zone -mno-sse -mno-mmx -fno-stack-protector -mcmodel=kernel -fno-pic -c $$f -o $(B)/fs_$$(basename $$f .c).o || exit 1; done
	@echo "freestanding compile OK"

clean:
	rm -rf $(B)

.PHONY: all clean freestanding
