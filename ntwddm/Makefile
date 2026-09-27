CC ?= cc
CLANG ?= clang
NM ?= nm
CPPFLAGS += -Iinclude
WARNINGS = -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wstrict-prototypes
CFLAGS ?= -O2 -g
CORE = src/ntwddm.c
TEST = tests/test_ntwddm.c

.PHONY: all test sanitize freestanding freestanding32 clean
all: test freestanding

build:
	mkdir -p build

build/test_ntwddm: $(CORE) $(TEST) include/ntwddm.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 $(CORE) $(TEST) -o $@

test: build/test_ntwddm
	./build/test_ntwddm

build/test_ntwddm_sanitize: $(CORE) $(TEST) include/ntwddm.h | build
	$(CC) $(CPPFLAGS) -O1 -g $(WARNINGS) -std=c11 -fsanitize=address,undefined -fno-omit-frame-pointer $(CORE) $(TEST) -o $@

sanitize: build/test_ntwddm_sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build/test_ntwddm_sanitize

build/ntwddm.o: $(CORE) include/ntwddm.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c $(CORE) -o $@

freestanding: build/ntwddm.o
	$(NM) -u build/ntwddm.o > build/undefined-symbols.txt
	test ! -s build/undefined-symbols.txt

build/ntwddm-i386.o: $(CORE) include/ntwddm.h | build
	$(CLANG) --target=i386-none-elf $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c $(CORE) -o $@

freestanding32: build/ntwddm-i386.o
	$(NM) -u build/ntwddm-i386.o > build/undefined-symbols-i386.txt
	test ! -s build/undefined-symbols-i386.txt

clean:
	rm -rf build
