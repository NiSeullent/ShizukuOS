# SPDX-License-Identifier: GPL-2.0-only
# ShizukuFS v1 host build: libsfs + tools, sanitizer builds for the tests, an optimised build for the benchmarks,
# and a freestanding compile check (the same sources are linked into Kernel64).
CC ?= cc
B := build
LIB := $(addprefix libsfs/,sfs_crc.c sfs_cache.c sfs_super.c sfs_inode.c sfs_extent.c sfs_alloc.c sfs_hash.c \
                          sfs_dir.c sfs_file.c sfs_jbd2.c sfs_api.c sfs_access.c sfs_subject.c)
HOST := tools/sfs_host.c tools/sha256.c
HDRS := $(wildcard libsfs/*.h tools/*.h)
WARN := -std=c11 -Wall -Wextra -Wshadow -Wstrict-prototypes -Wno-unused-parameter -Wvla
SAN := -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer

all: $(B)/sfstool $(B)/sfstool-fast $(B)/sfsfuzz $(B)/sfsperf $(B)/sfsaccess $(B)/sfssubject freestanding

$(B):
	mkdir -p $(B)

$(B)/sfstool: $(LIB) $(HOST) tools/sfstool.c $(HDRS) | $(B)
	$(CC) $(WARN) -O1 -g $(SAN) -o $@ $(LIB) $(HOST) tools/sfstool.c

$(B)/sfstool-fast: $(LIB) $(HOST) tools/sfstool.c $(HDRS) | $(B)
	$(CC) $(WARN) -O2 -g -o $@ $(LIB) $(HOST) tools/sfstool.c

$(B)/sfsfuzz: $(LIB) $(HOST) tests/sfsfuzz.c $(HDRS) | $(B)
	$(CC) $(WARN) -O1 -g $(SAN) -o $@ $(LIB) $(HOST) tests/sfsfuzz.c

$(B)/sfsaccess: $(LIB) $(HOST) tests/sfsaccess.c $(HDRS) | $(B)
	$(CC) $(WARN) -O1 -g $(SAN) -o $@ $(LIB) $(HOST) tests/sfsaccess.c

$(B)/sfssubject: $(LIB) $(HOST) tests/sfssubject.c $(HDRS) | $(B)
	$(CC) $(WARN) -O1 -g $(SAN) -o $@ $(LIB) $(HOST) tests/sfssubject.c

$(B)/sfsperf: $(LIB) $(HOST) tests/sfsperf.c $(HDRS) | $(B)
	$(CC) $(WARN) -O2 -g -o $@ $(LIB) $(HOST) tests/sfsperf.c

# Freestanding: exactly the Kernel64 compiler flags (shizukudos/kbuild.py K64_FLAGS, -Werror included).
K64_FLAGS := -m64 -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-pic -fno-pie -mcmodel=kernel \
             -mno-red-zone -mgeneral-regs-only -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident \
             -fno-common -fwrapv -fno-strict-aliasing -fno-tree-loop-distribute-patterns
freestanding: $(LIB) $(HDRS) | $(B)
	@for f in $(LIB); do $(CC) $(K64_FLAGS) -c $$f -o $(B)/fs_$$(basename $$f .c).o || exit 1; done
	@echo "freestanding compile OK (Kernel64 flags)"

# Host test suites (need e2fsprogs: mkfs.ext4, e2fsck, debugfs, dumpe2fs, e2image). SFS_TMP picks the scratch dir.
test: all
	$(B)/sfsaccess $${SFS_TMP:-/tmp}
	$(B)/sfssubject
	python3 tests/run_clean_sync.py
	python3 tests/run_jbd2_interop.py
	python3 tests/run_matrix.py
	python3 tests/run_crash.py --trials 8
	python3 tests/run_fuzz.py --iterations 1500

perf: $(B)/sfsperf
	python3 tests/run_perf.py --size-mib 1024 --files 100000

clean:
	rm -rf $(B)

.PHONY: all clean freestanding test perf
