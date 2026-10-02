# Strict process query and loaded-image mapped-name component

Implemented in ROOT's isolated `Win98-Modern-nt-fullquery-c957-20261002`
tree on reviewed `e22b5af7`. This is an independently reviewed UP component
change. Actual Windows 98 desktop/VMM, AP/SMP lifetime, ordinary mapped-file
sections, modern applications, installer and final ISO are not verified here.
Other chats retain native ESP/boot, canonical kernel/Supervisor and app-build
ownership. ROOT did not use or allocate the native NAS workspace.

## Resulting behavior

GetProcessMitigationPolicy now checks full PROCESS_QUERY_INFORMATION through
private query 17. Its existing DEP and zero mitigation-options reporting is
unchanged. Limited-query handles remain valid for existing modern class-3
time/info consumers; class 3 and the old PID-based class-5 module ABI are
unchanged. Native process class 0 is not used as an access validator.

K32GetMappedFileNameW uses private query 18 and its fixed 272-byte packet:
address, retained PID, zero reserved field and 256-byte loaded-image path.
The kernel holds the checked process object and verifies reciprocal identity
under one UP IRQ guard. Actual ldr_module_at lookup and path copying finish
inside that guard; output then uses owned local bytes after reference release.
There is no handle-to-PID module-list round trip or stale list count in this
wrapper. Subtraction-based membership avoids base-plus-size overflow. Exited
or teardown targets retain their PID and return an empty live-image path.

The frontend retains actual native-volume/UTF-8 formatting and the existing
current-process VirtualQuery free/private distinction. Successful output
returns the character count excluding NUL. Truncation writes size-1 characters
and NUL, sets error 122 and returns size, including size 1. Refusals preserve
the caller's output buffer. This is loaded-image support; a generic
section-backed file provider, PSAPI v1 forwarding and the ANSI API remain
separate work.

## Reproduction and host verification

Before any production edit, two reviewers found and corrected a fixture
header-basename collision and a missing live nonempty output-lifetime control.
The actual frontend nt.h is selected by its canonical frozen path; candidate
class 18 cannot silently fall back to a fixture packet. Both actual kernel and
frontend packet layouts are consumed and their field offsets checked.

The first execution failed compilation because the fixture duplicated the
actual ntsys.h MEM_FREE definition. That whole FAIL is retained as setup
evidence. Only the redundant line was removed before the next reviewed run.
It is not behavioral RED evidence.

The pristine e22 behavioral RED ran actual selected production bodies:
GCC and Clang ASAN/UBSAN each reported **2526 checks, 421 failures**. The old
PID lookup actually crossed final-reference process free and modeled slot
reuse, returning the replacement owner's path. The old module-list
ReturnLength seam returned an uncopied decoy heap row even with an extra real
process reference. Fixture C/Python bytes are identical between final RED and
GREEN; only the three planned production files differ.

GREEN reported **2526 checks, 0 failures** in each compiler and compiled six
real frozen translation units: sysk32_proc, ldr, sysk32, k32_procinfo, k32_utf
and k32_volume. All ten commands were admitted, normally reaped and had no
timeout/interrupt. The 257 source and 281 artifact maps, 40 selected body
pins, actual schemas, tools and logs were independently rehashed. The compiled
host dispatcher uses selected actual cases; its whole k32_query hash is a
provenance pin rather than a claim that every unrelated case was executed.

Actual module lookup/path copying were observed with both a held reference
and IRQ exclusion. The live nonempty packet control captured ORIGINAL bytes,
performed actual module release/final close/process free, explicitly replaced
the static storage, and still returned the captured ORIGINAL packet. Host
IRQ, user-copy, allocation, current-thread, VirtualQuery, image/edge and module
publication boundaries remain explicit adapters; this is not physical kernel
allocator UAF or SMP execution evidence.

Preserved time regressions passed 1292/0 normal, 34/0 zero-clock and 34/0 wrap
in each compiler, plus seven actual translation units. Preserved priority
regressions passed 11221/0 in each compiler plus eight actual units. The latter
legacy producer records actual return codes but has no separate per-command
admission/abort fields; its receipt does not establish the new owned-group
cleanup guarantees. The dedicated producer retains the previously negatively
tested owned-group helper, refusing timeout/interrupt even with a zero-status
leader and killing the owned group after TERM.

## Fresh builds and sole actual guest

The actual six-profile kernel dependency check covered 222 inventory inputs
and 221 GCC -MM units, with no missing local dependencies. Both frozen-only
header mutation and omitted-C controls passed and restored their source bytes.
Its 398 source and 619 artifact maps were independently verified. The frontend
nt.h is in that inventory but is not consumed by kernel -MM units; frontend
ABI consumption is established by the host and actual DLL/probe compiles.

All four kernels compiled and linked from the frozen 222-source inventory;
six ELF undefined-symbol checks were empty. The source/driver ZIP has exactly
223 unique matching members. Both selected DLLs were rebuilt, with 70 actual
local dependency units, six resource/link/import calls, 655 input pins,
81 generated-input pins and 408 artifacts. Fresh probes used four actual
dependency units, eight compiler/link calls and a complete 342-artifact map.
Their five-member archive contains the fresh NTDLL, KERNEL32 and two probes,
plus only the explicitly historical T_HELLO from the preserved older archive.
It is not a full current Win64 runtime.

One bounded actual KVM UP guest completed in **8.52 seconds**:
**654/0 priority + 620/0 process checks**, both applications exit 0/fault 0,
35 distinct PMA PASS rows, one zero-failure CPU1 summary, kernel done 0 and
SHZ-EXIT:0. QEMU returned its expected debug-exit status 1, was reaped and did
not time out. All 1493 input pins remained unchanged. The process append keeps
the prior 431 assertions and adds 137 current-process and 52 natural-child
checks. Remote image identity comes from the actual queried PEB and an exact
eight-byte ReadProcessMemory result; both bounded waits and natural process
and thread exit 7 precede retained empty-path checks. Forced cleanup is not
credited as natural completion.

## Immutable receipts in this tree

| Evidence | SHA-256 |
| --- | --- |
| Initial compiler-only FAIL | `bee23904eb74b9c42c8cf9cd538771ffe8833fd641c8cba01bb3116edc0b0d30` |
| Behavioral host RED v2 | `560494c165240d27c17b9a71041a7e181d4004682ccf4c930221f8c5b17336ce` |
| Host GREEN v1 | `7cd0be40b546d6e92e033452fa5d18347d086e57405512efd85a841649d3f468` |
| Time regression | `fd09ee1d33ce22d6949f167d4c6582e96a4c3851764b528d8776fa061a354f39` |
| Priority regression | `b65e359d3acb9fe9c802898a2fb4cec4747b54006731a2ea29b1578b606d0449` |
| Kernel dependency closure | `48c241b302bcb5e9cbad8657456db00f98d00c25ab9cff64feec0b2fccdfd377` |
| Four-kernel verification | `96534c0af8ad0f999c01c56133d1cd958566fe4582bc7493fb3f816ba49555db` |
| Actual kernel build receipt | `c3b95df82906e6556f0c6e09a92f53e10e5ad4e580b5c55548f2a2720eacd26a` |
| Source and driver ZIP | `dd8e3eac8c20a819e4219c94ba36334e748eccf615641a8c36cbf953e839e673` |
| Two-DLL producer | `6f7b31a8349931698c99357f2d2e34a585b7b4ba2eb9a51ab0555ee33e44d475` |
| Probe producer | `c0bd4d44ec016244743f31f08e50c6aca3fa82a5173ea0a3ca83101558ff9354` |
| Sole actual guest | `4334de8008e0d5f07954d6f0b0181d74c389ec560f19bfe18dbf773d563e01a4` |
| Guest raw serial | `83e3d3e5472d662459879d39c2671f0a0719ef38100d3aa245f7efea7412390a` |

Receipts are under the fresh `build/nt-fullquery-c957-*` directories; dedicated
host receipts use `build/nt-full-query-host-*`. Public source handoff is exactly
three production files, two host fixtures, the guest append, plan and status.
External compiler support programs, complete sysroots/libraries and Python
internals are not independently sealed. The inherited CPP producer's bounded
subprocess timeout is not the dedicated producer's owned-group cleanup proof.
The original whole PMA 361 failure and its diagnostic failures remain retained
and unresolved. This successful new component run does not close them or
establish native Windows 98/VMM/AP/modern-app/installer/final-ISO acceptance.
