# ShizukuFS bitmap-clear verification

`libsfs/sfs_alloc.c` clears pending frees through the existing transaction path.
Its private `clear_bits` helper returns the exact
number of bits that were already zero. Any such bit still causes the existing
caller to report corruption; this optimization does not forgive double frees.

For fewer than 16 bits the helper uses the original bit loop and returns before
chunk processing. Larger runs preserve partial-byte edges and count allocated
bits in each full 64-bit word using unsigned SWAR arithmetic, then clear it.
`memcpy` accepts unaligned bitmap addresses; the bit count is independent of byte
order. Remaining whole bytes are counted and cleared before the final bit edge.
No allocation search, preallocation window, metadata accounting, checksum,
journal ordering, filesystem format or public ABI changes.

Run from the repository root with a fresh output directory:

```sh
python3 shizukufs/v1/tests/test_alloc_bitmap.py --out build/alloc-bitmap-check
```

The runner extracts the public baseline allocator at commit
`d612d9f36854c9c6bd2a2a8bd895e99e762fbca7`. The C fixture includes each actual
production translation unit; an independent simple bit oracle compares every
byte and the already-zero count. It covers every single-byte value and interval,
all bitmap address offsets modulo 16, word/byte edges, empty ranges, all-zero,
all-one, alternating and deterministic random bitmaps, and repeated frees. The
right bitmap boundary meets the heap redzone in sanitized cases.

Validation uses strict GCC and Clang ASan/UBSan. Both original and modified full
allocator translation units compile with the actual `K64_FLAGS` literal from
`shizukudos/kbuild.py`. Their undefined-symbol lists must match; the disassembly
must not contain POPCNT, TZCNT or LZCNT. This checks the baseline x86-64 compile
contract and absence of new compiler-runtime dependencies, without building or
running a complete kernel.

The bounded benchmark measures host CPU time for the actual compiled helper,
excluding bitmap preparation. Seven samples per case cover three bit patterns,
aligned and partial-byte starts and 1–32,768-bit ranges. A second pass reverses
baseline/candidate order. Calls per sample are limited to 8,192 and all bitmap
storage, including misalignment, is limited to one MiB. Each case checks its count against an independent
expected checksum. The CPU-clock resolution and measured timer-pair cost are
recorded, and each median must exceed that measured timer floor by at least 20.

Short synthetic calls may remain slower because the host compiler inlines the
small original helper into the benchmark wrapper but outlines the larger new
helper. In the checked complete Kernel64 allocator objects, both helpers are
inlined into `sfs_apply_pending_frees`. Retaining the original small bit loop
does not establish equal execution time under every compiler and caller.
Performance acceptance is restricted to the tested runs of at least 512 bits.
The ratios measure this host helper's CPU cost, not physical disk throughput,
NTFS superiority, filesystem-wide latency or VM speed.

Each invocation records source/header/tool pins and every command's output in a
new directory, retaining failures. No network, filesystem image, real disk,
Windows media or VM is used. Native filesystem and OS integration remain
separate validation work.
