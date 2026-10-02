# Native FAT32 installer callback bridge — bounded host acceptance

This new pure callback adapts the existing c87b FAT32 stage to FADA's actual
`native_setup_ops_v1_t.prepare_relocation` type. It exports two hidden-sector
overlays after successful validation and preserves all caller bytes on refusal.
It ignores `ctx` and provides no custody, destructive authority or I/O.
No existing installer, build file or provider is wired by this change.

The four-sector fixture uses literal 64MiB geometry without allocating a volume.
It checks backup sectors 6 and 10, unequal valid FSInfo snapshots, literal target
DWORDs at first LBA 1, 0x12345678 and UINT32_MAX, deterministic complete outputs,
input preservation, all four input/output overlaps, adjacent disjoint storage,
NULL and wrapping spans, malformed geometry/pairs and invalid target intervals.
Caller storage must actually be mapped; integer bounds do not establish that.
Publication has failure atomicity, without a concurrent hardware-atomic claim.

Actual commands, each run once in the authorized local fallback worktree:

```text
python3 -B shizukudos/install/tests/test_native_fat32_install_bridge_host.py --legacy-control
python3 -B shizukudos/install/tests/test_native_fat32_install_bridge_host.py
```

The first command compiled an explicitly synthetic unrelocated adapter using the
real stage's validation. GCC and Clang ASan/UBSan each executed 118 checks with
8 expected literal relocation failures; outer exit was 1 and the control receipt
records PASS. This is not an existing historical installer implementation.
The bridge implementation was then authored; the unchanged fixture and runner
executed 118/0 under each compiler, outer exit 0. Six selected MinGW x64/i386
objects compiled, including a callback assignment without a cast against the
actual held headers. The i386 stage requires `__udivdi3`; objects were not linked.

RED receipt: `build/native-fat32-install-bridge-v1/red/result.json`,
SHA256 `f339c452a04273478ca4869d3f1591fe5b00400a775e1ccf3ec08c6f4e93be4d`.
GREEN receipt: `build/native-fat32-install-bridge-v1/green/result.json`,
SHA256 `3c49bfdabcd21aa530ddf341ef519d52e48c60a5eb5b50ac4492a90dd9713931`.
Readback: `build/native-fat32-install-bridge-v1/verification.json`,
SHA256 `7208fc71a05cb1d1837c1d36cfd35e64065071436ed5a5190fb79614f2c30602`.
All 8 RED / 9 GREEN current and frozen inputs, 6 tool executables and complete
20 / 58 artifact maps rehashed without mismatch. All 4 / 16 owned leaders were
reaped, with no timeout, interrupt, cleanup error or live process group.
The entire evidence leaf including readback used 4,410,792 regular-file bytes.
The final receipt is excluded from its own artifact map and hashed by the caller.

Compiles have 60-second deadlines; other commands 25 seconds, followed by bounded
.5-second TERM / 1.5-second KILL cleanup when needed. Child core size is zero and
per-file size 4MiB; aggregate usage is checked before/after commands and includes
terminal receipt bytes against 16MiB. This is an observed aggregate check, not a
hard aggregate quota or a subprocess PIPE RAM bound. Recorded dependency rules
are observed after compilation, not presealed preprocessing admission. External
compiler support, libc and sysroot closure remain unsealed.

Adoption order: hold FADA's `native_install.h` SHA256
`4db7a21fa40cc54b37b18e4029cbb5f7a72e6e30c3d9b5428ee341303e9996c9` and
its `plat.h` SHA256
`4eda76b2df7a64aa6715f249e23e4c7c3793819c41449cab1423ac4b8baefdf4`;
retain c87b's relocate header/source; add this bridge header/source to the setup
build; separately review an actual provider assignment to
`shz_native_fat32_install_prepare_relocation`. The bridge header deliberately
includes `native_install.h`, which is absent from the c87b base. Its return
values preserve the stage's zero-success / negative-refusal contract.

FADA's actual `relocation()` source was inspected: it independently checks both
offsets, original/replacement DWORDs and snapshot preservation, then freezes
overlays. The full storage fixture uses a 34MiB image and 40MiB targets, exceeding
this unit's 16MiB evidence limit; it was not executed or modified. Actual full
core/provider composition, whole-image hashes, flush/readback, native Windows 98
boot, AP/SMP, VM and ISO acceptance remain unproved. Existing desktop installer
paths and the old 2048 gate were not changed. NAS recovered during this unit;
ROOT will transfer exact sources/evidence there. No execution from NAS is claimed.
