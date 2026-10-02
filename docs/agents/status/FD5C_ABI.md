# FD5C ABI channel safety

Assigned scope: shared IPC constructor, channel layout validation and pool
ownership arithmetic. Windows 98 remains the product OS and VMM execution
authority; these helpers support the existing Shizuku backend connection.

Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52`.

Owned files:

- `shizukudos/abi/shz_ipc.h`
- `shizukudos/abi/test_abi.c`
- `docs/agents/status/FD5C_ABI.md`

## Changes and decisions

The original channel validator accepted overlapping header, owner table, rings
and pool as long as each independent range fit. A third domain could allocate
pool blocks, transfers could truncate a destination owner to one byte, and a
`UINT32_MAX` release rounded its block count to zero and reported success.
On i386, 16,777,216 slots wrapped the ring size to 192 bytes and produced an
accepted, unusable channel while modifying the caller's storage.

The constructor now checks ring-size representability and both rings' fit
before subtracting sizes or writing. It refuses missing pool capacity, invalid
domain pairs, out-of-range channel IDs and misaligned storage. Valid existing
geometry and the ABI 1.1 structure layouts are preserved.

Channel validation first checks the supplied window length, then aligned,
ordered and disjoint header/owner-table/ring/pool extents. The owner table must
hold one byte per pool block. Both actual ring headers must agree with the
channel's slot count and slot size. Ring selection rejects nonparticipants.
Pool allocation, validation and transfer accept only channel participants;
owner zero means free, never a caller entitled to allocate or transfer a free
block. Block counts use wide arithmetic before narrowing.

Generation zero and the full `uint32_t` generation range remain accepted:
the existing ABI does not reserve zero. A future ABI minor remains accepted
under the same major. No service number, message opcode, success stub or
capability claim was added.

The caller still supplies accessible memory. Channel geometry must remain
stable while peers use it; initialization/reinitialization requires exclusive
ownership. These checks are not protection against concurrent hostile header
rewrites, and pool transfer/rundown serialization remains the caller's duty.

## Verification

All commands used existing local tools, wrote only ignored project `build/`
outputs, and made no network, installation, guest or client-setting changes.
The parent completed the original baseline before the full post-change run.

| Test | Original baseline | Fixed source |
| --- | --- | --- |
| GCC full ABI host model | 3,665,461 checks | 3,665,542 checks |
| Clang ASan/UBSan full ABI host model | 3,665,447 checks | 3,665,528 checks |
| Clang TSan full ABI host model | 3,665,447 checks | 3,665,528 checks |

`python3 -B shizukudos/abi/test_abi.py` exited zero. It also passed freestanding
32-bit, 64-bit and i686 MinGW compilation; independent Python CRC/frame decoding;
and agreement on 6,000 WIN64 frames (1,234 accepted CREATE, 303 accepted console,
4,463 rejected). Wire structure sizes remain message 64, ring 192, channel 128,
boot info 472 bytes, ABI 1.1.

The new `--channel-safety` test mode passes 81 focused checks under GCC and
Clang ASan/UBSan. It covers constructor refusal without storage modification,
overlapping/short/unaligned layout, owner table extent, ring metadata mismatch,
domain ownership and transfer, overflowed release length, cross-block ownership,
and valid 64 KiB geometry. `--channel-layout` and `--pool-safety` isolate the two
validator groups. These tests also run in the full suite.

Before production changes, original code failed the new constructor, overlapping
layout and third-domain pool regressions. Additional source-bound, libc-free
ELF32 execution against the frozen original header exited 15, identifying size
wrap, incorrectly accepted ring/channel and modified storage; fixed source
exited zero. A separate overflowed pool release runner exited 1 with the original
header and zero with the fix. Inputs and logs are in ignored `build/fd5c-abi/`:
`red*.log`, `green*.log`, `size32-*.log`, `pool-rounding-*.log` and
`full-suite.log`. The first temporary ELF32 harness compile failed because its
local copy helper collided with a header local; renaming that test helper
resolved the compile error before either ELF32 execution.

## Handoff

Dependencies: the root integration owner coordinates the new ABI payload-header
lane and VxD concurrency/stale-response lane. No peer worktree, Git index or
historical receipt was changed. Other agents' concurrent source changes are
outside this report's ownership.

Current blockers: none for this bounded implementation. Independent review and
combined subsystem verification are assigned by the coordinator.

Remaining work: native Windows 98 VxD/VMM/channel2 positive acceptance and
concurrent peer shutdown/restart behavior remain separate gates. Standard ABI
tests execute on the 64-bit host; the shipped conditional i386 size assertions
need a 32-bit host build to execute, while the additional owned ELF32 runner
provides this session's actual 32-bit evidence.

Code commit: `7252e3e` (coordinator). Independent core_audit review approved;
root recompiled and passed all 81 focused checks with GCC and Clang ASan/UBSan.
This agent made no Git index or commit mutations.

Snapshot code follow-up committed by coordinator as `c6c6577`. Full shared
runner exited zero: GCC3,665,554 checks; ClangASan/UBSan and TSan3,665,540
each; freestanding32/64/MinGW, independent Python CRC/frames and6,000 C/Python
verdicts all passed. Log `build/fd5c-abi-snapshot-full.log`; previous artifacts
remain preserved in `build/fd5c-abi-before-snapshot`.

## Ring snapshot follow-up

Assigned follow-up on coordinator HEAD `cded260eebbfff5117104a5785cea0a41860f4fc`:
the same three owned files, with no layout, ABI version or peer-source changes.
The former receiver copied the shared header first, then separately copied the
shared frame for CRC and payload. It could therefore return a header and payload
that never formed the checked frame. The receiver now copies the fixed 256-byte
slot once into a naturally aligned private union. Header validation, CRC and
returned payload all use that copy; the returned header retains its original
checksum. Existing validation order, error reasons and tail-consumption rules
are preserved.

The new `--ring-snapshot` regression uses the existing environment memcpy hook
at the real production copy boundary. Immediately after its first shared read,
the sender slot is replaced with a different valid frame. Independent Python
`struct` and `zlib` calculations established that both 72-byte frames have CRC
`0x1d562b37`, but the first header and second payload have CRC `0x9fb5bbc9`.
Strict GCC and Clang runs of the unchanged receiver both returned that mixed
frame as success and failed the new coherence assertion. Fixed GCC and Clang
ASan/UBSan pass all 12 focused checks and return the complete first frame.
The deterministic fixture models a broken peer between copy operations without
a timing-dependent concurrent host data race; it does not copy the receiver's
implementation.

Focused logs, original header and independent collision vectors are retained
under ignored `build/fd5c-abi/snapshot/`: `red-gcc.log`, `red-clang.log`,
`green-gcc.log`, `green-clang-asan.log`, `pre-snapshot.h` and
`collision-vectors.log`. The first fixture compile identified a missing
`stdint.h` include before either successful red execution; adding the include
resolved it. Isolated complete host executables passed 3,665,540 checks each
with GCC and Clang ASan/UBSan (`full-gcc.log`, `full-clang-asan.log`). These runs
omit the command-line sample outputs; the standard runner adds 14 GCC sample
checks. Freestanding GCC 32/64-bit and i686 MinGW header syntax checks exited
zero. Root subsequently passed the full standard ABI runner and final PE32
end-to-end checks after the combined-source freeze (see FD5C_VALIDATION.md).

This change supplies consistency of the checked and returned private bytes,
not an atomic snapshot against a concurrently hostile writer or CRC-based
authentication. Ring/channel metadata must still remain immutable during use;
shared pool writes, ownership transfer, shutdown and reinitialization retain
their existing caller-serialization requirements. Positive native Windows 98
acceptance remains outside this host regression. Follow-up commit: `c6c6577`.
Root completed the full ABI runner and final linked PE32 regression after this
change; their exact scopes/results are recorded in FD5C_VALIDATION.md. This agent
changed no Git index or commit.
