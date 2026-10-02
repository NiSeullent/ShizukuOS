# NT process priority component checkpoint

Isolated ROOT worktree: `/root/Win98-Modern-nt-proc-c957-20261002`, based on
reviewed public `8603a051`. The other chat adopted that prior NT/CPU consumer
as canonical `960ecb0`, retaining its newer memory and Supervisor source.
This successor does not edit that canonical checkout.

Full project acceptance remains actual Windows 98 on ShizukuDOS, with VMM,
USER/GDI and Explorer ownership preserved. The website is deployed; the final
installer/ISO, modern application acceptance and native boot remain separate
unfinished work. This checkpoint is an UP Kernel64/Win64 API component.

## Reviewed behavior

Native process information class 18 now uses the exact two-byte
`{Foreground, PriorityClass}` ABI. Its native ordinals 1/2/3/5/6 convert to the
five supported Win32 flags; internal process storage retains those flags.
Ordinal 0 is declared UNKNOWN and refused by this setter subset. Realtime
and every nonzero Foreground request return NOT_SUPPORTED. Queries report
Foreground zero without claiming foreground boosts or resource scheduling.

Both raw NT and the retained private four-byte Win32 transport use the same
referenced-process two-pass retarget. The IRQ guard covers validation of every
published eligible user thread and the complete mutation pass. Relative and
saturated increments, mask 1, running quantum remainder and aging grants are
preserved. A late validation refusal changes no earlier thread or class.

Public GetPriorityClass and SetPriorityClass now use native class 18. Queries
require either QUERY_INFORMATION or QUERY_LIMITED_INFORMATION; setters require
SET_INFORMATION. Queries hold an object reference and snapshot metadata under
IRQ exclusion. Retained exited-process queries remain valid; setters refuse
termination/teardown. ProcessBasicInformation now derives its base from the
same mapper (4/6/8/10/13), while its prior access/length contract is retained.

Class 18 accepts exactly two bytes; both short and oversized query buffers
return INFO_LENGTH_MISMATCH with required length 2. A failed return-length
write reports ACCESS_VIOLATION. These status-order details are this backend's
chosen contract, not a claim of exhaustive Windows compatibility.

Process background BEGIN/END previously returned success after only changing
DLL-global metadata, with an invented very-low memory report. Those requests
now return ERROR_NOT_SUPPORTED and leave actual process/memory settings
unchanged. The existing process-information regression is updated to test
that explicit unsupported subset.

## Frozen host evidence

Meaningful original-production RED v3:
`build/nt-proc-host-red-v3/result.json`, SHA
`d0ef946c052909d5a6d5802d00d89100e2db81671c866cb8cc49e76913b6cd00`.
GCC O2 and Clang ASan/UBSan each ran 9,493 checks with 355 failures; the
existing thread/queue baseline remained 4,456/0. Raw class 18 returned
INVALID_INFO_CLASS; HIGH ProcessBasic base stayed 8; a SET-only public getter
succeeded; process background BEGIN/END returned success. RED v1's additional
incorrect READY-quantum expectation was corrected in v2; every receipt is
preserved.

GREEN v1 with byte-identical RED-v3 tests:
`build/nt-proc-host-green-v1/result.json`, SHA
`f49058404e05ffea861824d6206ff6cb9f28dabcd3428b22471e0fdaee841576`.
Both compilers ran 11,221/0, and eight actual frozen translation units
compiled. All 256 source pins, 270 artifacts and three compiler executables
match current and frozen bytes. Host C SHA
`4aca58c15e276b0b79434f3a0be3fdbf52915d4b39d1543aa82967e1de1974c8`;
runner SHA `8d288f538a49d01bc2b92cadaa6e134e2dba0fff52b7df5219e053f77a0cda79`.

Actual production dispatch/query/set/wrapper/init/queue/reference/free bodies
and complete process/TCB/object schemas execute in the fixture. Handle
insertion/closing, teardown publication, IRQs, clocks, allocation, TLS and
VAD destruction remain explicit platform adapters. Exact host process-slot
reuse follows the production last-reference process-free body; it does not
prove concurrent close/reclaim, real heap UAF detection or native guest reuse.
External compiler support programs, sysroots and sanitizer libraries are not
separately sealed. No hardware context switch or AP executes in this fixture.

## Fresh build and guest admission

Actual compiler/header closure is PASS: 222 inventory sources, 221 actual
C dependency units, 398 pinned sources and 619 artifacts. Independent live
and frozen C selection, header-mutation and omitted-process-C controls pass.
Receipt `build/nt-proc-c957-cpp-closure-v1/result.json`, SHA
`c8b1013966d9c7b5a1e2d7fbf02b23fb3e67770552f4584ce134e2644d64dd49`.
The new header occurs in both actual ipc_proc dependency profiles.

Fresh four-kernel producer is PASS in 96.32 seconds: all 222 live/frozen
source pins, seven tool binaries, producer and ten copied artifacts remain
stable. Its 219 recorded kernel C commands plus two stub builders produce
six ELF images with no undefined symbols. Verification receipt SHA is
`e73e604af9cbe94eae487f217550b0c6e0d68002e20f4bf160a01d9ac27ab67c`;
build receipt SHA `ee37512066c3f7fe11a930f186982a750b64180427da453d4358dd3b44a61dde`;
source/driver ZIP SHA `d8b2005b0bb38cf97a2f200914e4e809288ed6152cd79c02b2d215418a62e7de`.
These outputs are component binaries, not a Windows 98 installation image.

Fresh selected NTDLL and Kernel32 producer is PASS in 99.79 seconds.
Actual local dependency scans cover 17 NTDLL and 53 Kernel32 C units using
the production flags; the new ABI header occurs in k32_procinfo's dependencies.
All six recorded resource/compiler calls exit zero. All 325 source pins,
655 before/after input pins, 408 artifacts and 81 generated inputs match
current bytes after independent review. Generated resources, definitions,
assembly and import libraries are pinned before their consumers run.
Receipt SHA `2d62e63cc9d3bfb188df684625656500356e60dc5111e6277b245107f4d061db`;
NTDLL SHA `3e753284c8d3b5c306bfa79687319ac9899cfcef3ef23ce80ecdc58762f9cd19`;
Kernel32 SHA `657b32e160ff8cf3f77fada35b21eb81862c9f9d80827c3d65cc12204da302e9`.
External toolchain support programs/sysroots/libraries remain outside this
local closure proof; the full Win64 runtime was not rebuilt.

Selected probe producer is PASS in 19.08 seconds. Four actual GCC dependency
scans and eight total recorded compiler/resource calls exit zero. Its 327
sources, 743 starting inputs, 1,071 before/after inputs, 12 first-consumption
generated inputs and complete 342 artifacts are stable. Receipt SHA
`b821c8dcfb215cec5ec1976a07af2ec47ddbaa23a62de486e9b4c3e1ecfca237`.
The exact five-member SHZARC01 archive SHA is
`92ad2dfb883b389b8e4a2f5ff64d30f84e5ad417916254e97fb05e09c0f27b0c`.
It contains the two fresh DLLs, two fresh probes and only the retained
historical T_HELLO extracted from the pinned public test archive.

The guest sources are independently reviewed and frozen: priority probe SHA
`a01c2f6186c9442e22ec3e973c33641d1950aa21d9ccecaf6bd649a0472a0ca9`,
process regression SHA
`3ac31cbd53d45f5d13ef4b996dc31dbd8ece1450bec29abe7a8872bd9caa1712`.
Their observed successful counts are 654 and 215. The original 321 priority
checks and original helper bodies remain intact before appended process tests.
The real child uses existing historical T_HELLO; cleanup and wait bounds
remain checked, and no manufactured termination counts as natural completion.

One bounded actual KVM UP guest is PASS in 6.81 seconds with these fresh
artifacts: both probes report the exact counts above with zero failures,
exit zero and no fault. All 35 distinct PMA checks pass; the single PMA
summary reports failures 0 and CPUs 1. Kernel terminal self-test count and
SHZ-EXIT are zero; QEMU exits 1 through isa-debug-exit without timeout.
All 1,493 source/tool/producer/artifact input pins remain unchanged.
Receipt `build/nt-proc-c957-api-guest-v1/result.json` SHA
`8440b1ce4e941cd0288c8ac6750e3affeeeedb0e86fef7e6b3821ffa9fbc830b`;
serial SHA `257c07011c6ba4b80972907215ee1ba82fbea56b37a58225ffb89dc01354e2c2`.
The evaluator's positive PMA/terminal gates and correspondence of all four
actual dependency commands to their sealed proofs were independently reviewed
before the sole execution. This is whole success for this small component
guest; it does not rebuild the full runtime or establish native Windows 98,
modern applications, AP scheduling or final installation/ISO acceptance.

## Review provenance and remaining boundaries

Independent source/host review admits the five production paths and exact
RED/GREEN test bytes. Authoritative clarified plan SHA is
`b9b3dfb9efd2fa56cc7808fbc3eafeae43f0bab30e21b7bb58ffc058733f67ef`.
An earlier design message reported stale plan SHA `da932d7c...` after the
clarification append; that metadata mismatch is preserved and corrected here.

Scheduler online mask remains 1 and AP admission remains unsupported. IRQ
exclusion does not establish SMP safety for process/object/handle tables or
batched retargeting. Future AP execution requires those separate contracts.
ROOT uses no NAS allocation, private media, competing native VM or final ISO
promotion. Existing original PMA useful-work failure 361 and diagnostic-clone
failures remain separate unresolved receipts; no new pass erases them.
