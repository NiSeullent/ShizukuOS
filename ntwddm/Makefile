CC ?= cc
CLANG ?= clang
NM ?= nm
CPPFLAGS += -Iinclude
WARNINGS = -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Wstrict-prototypes
CFLAGS ?= -O2 -g
CORE = src/ntwddm.c
THEME = src/nttheme.c src/ntstyle.c
PRESENT = src/ntwd_present.c
TEST = tests/test_ntwddm.c
THEME_TEST = tests/test_theme.c tests/sample_window.c tests/evidence.c
PRESENT_TEST = tests/test_present.c tests/sample_window.c tests/evidence.c win98/adapter.c
EVIDENCE_DIR := $(abspath build/evidence)
THEME_DIR := $(abspath theme)
HOST_DEFS = -DNTTH_EVIDENCE_DIR=\"$(EVIDENCE_DIR)\" -DNTTH_THEME_DIR=\"$(THEME_DIR)\"

.PHONY: all test sanitize freestanding freestanding32 mingw-probe evidence clean
all: test freestanding

build:
	mkdir -p build

build/test_ntwddm: $(CORE) $(TEST) include/ntwddm.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 $(CORE) $(TEST) -o $@

build/test_theme: $(CORE) $(THEME) $(THEME_TEST) include/nttheme.h include/ntwddm.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HOST_DEFS) -std=c11 $(CORE) $(THEME) $(THEME_TEST) -o $@

build/test_present: $(CORE) $(THEME) $(PRESENT) $(PRESENT_TEST) include/ntwd_present.h include/nttheme.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(HOST_DEFS) -std=c11 $(CORE) $(THEME) $(PRESENT) $(PRESENT_TEST) -o $@

test: build/test_ntwddm build/test_theme build/test_present
	mkdir -p $(EVIDENCE_DIR)
	./build/test_ntwddm
	./build/test_theme
	./build/test_present
	python3 tests/ppm_to_png.py $(EVIDENCE_DIR)
	@if command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then $(MAKE) mingw-probe; else echo 'i686-w64-mingw32-gcc not available'; fi

build/test_ntwddm_sanitize: $(CORE) $(TEST) include/ntwddm.h | build
	$(CC) $(CPPFLAGS) -O1 -g $(WARNINGS) -std=c11 -fsanitize=address,undefined -fno-omit-frame-pointer $(CORE) $(TEST) -o $@

sanitize: build/test_ntwddm_sanitize
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ./build/test_ntwddm_sanitize

build/ntwddm.o: $(CORE) include/ntwddm.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c $(CORE) -o $@

build/nttheme.o: src/nttheme.c include/nttheme.h include/ntwddm.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c src/nttheme.c -o $@

build/ntstyle.o: src/ntstyle.c include/nttheme.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c src/ntstyle.c -o $@

build/ntwd_present.o: $(PRESENT) include/ntwd_present.h include/ntwddm.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c $(PRESENT) -o $@

build/ntwddm-all.o: build/ntwddm.o build/nttheme.o build/ntstyle.o build/ntwd_present.o
	$(CC) -nostdlib -r -o $@ build/ntwddm.o build/nttheme.o build/ntstyle.o build/ntwd_present.o

freestanding: build/ntwddm.o build/ntwddm-all.o
	$(NM) -u build/ntwddm.o > build/undefined-symbols.txt
	test ! -s build/undefined-symbols.txt
	$(NM) -u build/ntwddm-all.o > build/undefined-symbols-all.txt
	test ! -s build/undefined-symbols-all.txt

build/ntwddm-i386.o: $(CORE) include/ntwddm.h | build
	$(CLANG) --target=i386-none-elf $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c $(CORE) -o $@

build/ntwddm-all-i386.o: $(CORE) $(THEME) $(PRESENT) include/ntwddm.h include/nttheme.h include/ntwd_present.h | build
	$(CLANG) --target=i386-none-elf $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c $(CORE) -o build/ntwddm-i386-core.o
	$(CLANG) --target=i386-none-elf $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c src/nttheme.c -o build/nttheme-i386.o
	$(CLANG) --target=i386-none-elf $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c src/ntstyle.c -o build/ntstyle-i386.o
	$(CLANG) --target=i386-none-elf $(CPPFLAGS) $(CFLAGS) $(WARNINGS) -std=c11 -ffreestanding -fno-builtin -fno-stack-protector -c $(PRESENT) -o build/ntwd-present-i386.o
	$(CLANG) --target=i386-none-elf -nostdlib -r -o $@ build/ntwddm-i386-core.o build/nttheme-i386.o build/ntstyle-i386.o build/ntwd-present-i386.o

freestanding32: build/ntwddm-i386.o build/ntwddm-all-i386.o
	$(NM) -u build/ntwddm-i386.o > build/undefined-symbols-i386.txt
	test ! -s build/undefined-symbols-i386.txt
	$(NM) -u build/ntwddm-all-i386.o > build/undefined-symbols-all-i386.txt
	test ! -s build/undefined-symbols-all-i386.txt

build/NTTHPROB.EXE: $(CORE) $(THEME) $(PRESENT) $(PRESENT_TEST) | build
	i686-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra -Werror -Wno-pedantic $(WARNINGS) $(HOST_DEFS) -Iinclude \
		-Wl,--subsystem,console:4.10 -Wl,--major-os-version,4 -Wl,--minor-os-version,10 \
		-Wl,--no-insert-timestamp \
		$(CORE) $(THEME) $(PRESENT) $(PRESENT_TEST) -o $@

mingw-probe: build/NTTHPROB.EXE
	@echo "built $(abspath build/NTTHPROB.EXE) without --strip-all"

clean:
	rm -rf build
