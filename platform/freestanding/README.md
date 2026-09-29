# Independent freestanding memory support

`memory.c` provides original C implementations of `memset`, `memcpy`, `memmove`
and `memcmp` for the flat i386/x86_64 address spaces used by this project.
No libc source, firmware implementation, or external runtime is embedded.
This is a separate compiler-support object: freestanding compilers can emit
standard memory calls while lowering aggregate initialization and copying.
Existing PCI and EFI sources and their validated binaries remain unchanged.

The C11 header uses ordinary C calling conventions, including cdecl with the
documented i386 compiler flags. Each nonzero operation requires valid readable
and/or writable storage for its byte count. `memcpy` requires nonoverlapping
ranges; `memmove` preserves the original bytes when ranges overlap. Fill values
are converted to `unsigned char`. Comparison uses unsigned bytes and returns
the sign of the first differing pair. Copy/fill routines return their original
destination. Zero counts perform no memory access.

`memmove` uses `uintptr_t` address ordering under the flat-address assumption;
it does not compare unrelated C pointers relationally or compute an end address
that could overflow. Volatile byte accesses prevent the compiler from replacing
these loops with calls back into the same functions. The routines provide byte
memory operations, not synchronization or device-buffer ownership.

Run the bounded host and object checks from the repository root:

```sh
python3 platform/freestanding/test.py
```

All outputs stay in `platform/freestanding/build/`. The script requires existing
GCC, Clang, binutils and compiler headers; it downloads nothing and starts no VM.
Host tests rename **only the tested implementation** to `ntwm_test_*`, so host
libc and the sanitizer runtime retain their own standard functions. The suite
checks return pointers, fill truncation, all 65,536 one-byte comparison pairs,
longer unsigned comparisons, all source/destination offsets and lengths in a
48-byte overlap region, and larger unaligned buffers through 4096 bytes.
Overlapping moves are compared both with host libc and an immutable byte oracle.

Local validation passed 1,024,736 assertions per suite with GCC 14.3.1, Clang
21.1.8, and Clang AddressSanitizer + UndefinedBehaviorSanitizer. Each suite
contains 162,380 move, 162,040 copy, 17,490 fill, and 179,216 comparison cases.
Both GCC and Clang i486 objects have no undefined symbols; relocatable links
with a caller requiring all four standard symbols also have no undefined symbols.
Exact source/object hashes and compiler flags are in `build/test-result.json`.
Clang 18 CI integration is a separate validation step owned by the project CI.

A production-compatible i486 Clang compilation and relocatable integration is:

```sh
clang --target=i386-unknown-none-elf -std=c11 -O2 -march=i486 \
  -ffreestanding -fno-builtin -fno-stack-protector -fno-pie -fno-pic \
  -fno-asynchronous-unwind-tables -mno-sse -mno-sse2 -mno-mmx -msoft-float \
  -c platform/freestanding/memory.c -o build/platform/memory.o
ld -m elf_i386 -r build/platform/pci.o build/platform/memory.o \
  -o build/platform/pci-complete.o
nm -u build/platform/pci-complete.o
```

Use compatible flags for `pci.o` and create the output directory first. The
last command must print nothing; an unresolved dependency remains a failure.
These host/object checks do not claim execution inside Windows 98 or firmware.
