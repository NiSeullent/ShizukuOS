# Native32 SSPI provider binding — 6970 prospective integration

Windows98 remains the product OS. ShizukuDOS replaces MS-DOS; Kernel32/64
serve that system. Existing native x86 M98SSPI, SSPI stream and Mbed TLS3.6.7
are the reusable engine/provider, with native ROOT snapshot, CryptoAPI RNG
and Windows UTC adapters. The separate Mbed TLS4.2 client has a different
entropy callback success ABI; these implementations must not be mixed.

Canonical master163f owns the actual DOS/VMM executor and replacement boot.
7707 retains secure_transport; cb43 retains the loader/browser boundary.
This narrow ownbranch proposal was sent through shared coordination. Peer
files/indexes are unchanged; an ownership ACK or adoption is not presumed.

## Frozen existing module and missing feature

The nine legacy_provider_bridge files are restored byte-for-byte from
canonical committed3a9f0c4bc840075971797edaa42fdb65f1672cab. They all match
the current canonical worktree. Source import is not runtime verification.

Original native.c SHA256:
4457ca742c23368f759ef74ed5e45f3a3a119e1c8ab3a6cd4d3ecbc2e7640968.
Original table.c SHA256:
c6fbe91b0ba24a68b2fcaef1f265b82071a738036ac331fdc6eb6f3986d5004d.
Native provider source SHA256:
32b6bbd23d7ed61c40d86e08711c631140dfeb3ee6e5e1a6427d9eebb2955672.
Native provider export definition SHA256:
d31e87e33f0b51bb175265e0f05a073749e1785d3d4d2cb34713ae7dd59566a7.

The existing NTWPROV contract supports five get_api_table providers. It
rejects SECUR32 before loading anything; M98SSPI instead exposes standard
ANSI SSPI exports and InitSecurityInterfaceA. This new profile is a feature
integration, not a claimed defect in the existing five-provider contract.

## Binding contract

Retain the five original table-provider paths. Add only explicit
SECUR32.DLL -> absolute private directory/M98SSPI.DLL selection. Require the
native PE/read/executable bounds checks and typed WINAPI init invocation.
Use a fixed-width108B version1 prefix: version plus26 DWORD slots, ending
with Encrypt/Decrypt at offsets100/104. This is not the full modern SDK
function-table size. The13 supported slots must exactly match their actual
executable exports;13 unsupported slots must beNULL. Init and EndInput are
separate executable exports. Import/ExportContext are callable unsupported
operations, not functioning context migration.

Reject Unicode, unknown names and ordinals before load/initialization.
Malformed PE/table, missing/mismatched/foreign/non-executable exports and
unsupported nonzero slots fail before returning a pointer; failed initial
loads are unloaded and uncached. A verified module stays pinned in the
context. Later corruption must refuse new addresses without unloading behind
previously returned live pointers. Closing requires all threads/callbacks
finished and every SSPI context, credential and owned buffer released.

The context's process-local Windows critical section serializes lookups.
Loading can block and enters the Windows loader; this is ordinary usermode
code, not an interrupt or VMM callback operation. Caller lifetime rules apply
after lookup; the bridge does not own or execute credential operations.
Explicit-path loading and module references follow the [Microsoft loader
contract](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya).

## Actual execution plan and scope

The new fixture includes complete unchanged native.c and table.c, replacing
only Windows load/read/export/heap/lock boundaries. It constructs independent
wire tables and real low-address callable init functions. Environment/ABI
preflight failure cannot establish RED. Preserve positive/missing/malformed
controls for the original five modules; cover selection, full identity,
negative tables/exports, rollback/retry, cache and close. Credential/TLS calls
must remain0. Freeze the fixture before any production edit.

Run unchanged-production prospective RED on a hosted runner, then review the
small provider-binding hunk and run identical HOST/ASan/UBSan GREEN. All temp,
capture, binaries and self-inclusive receipt share a new8MiB root above the
unchanged20GiB floor. No local below-floor compiler/VM exception. Tests,
runner and workflow are prepared by disjoint agents; root owns production.
At the initial e2473df source-only checkpoint, no compiler/test had executed
for this new profile. Actual subsequent execution is recorded below.

Native_loader's --providers execution policy remains disabled. This binding
does not register an OS provider or connect Kernel64 secur32, which currently
returns unsupported package/context errors. Actual Windows98↔K64 forwarding
needs the peer-owned VMM callback/caller/lifecycle contract and separately
reviewed versioned wire operation, handles and buffer ownership. Generic IPC
is not an SSPI implementation. Native ROOT, OS TLS1.3, modern-app and final
ISO acceptance remain required and unverified.

## Actual unchanged-production prospective RED

Frozen fixture/guard/workflow commit
bef7fac30e080935f0639baa57561a12f911cfb3 ran in hosted
[run36927313281](https://github.com/NiSeullent/Win98-Modern/actions/runs/36927313281),
job110587717204. The actual ABI-qualified fixture completed651 checks:
423 exact prospective omission failures and228 passing controls. GCC compiled
both complete production TUs successfully. All4 commands were reaped with
exit codes0,0,0,1; the test's1 is assertion RED, not an infrastructure failure.
Original native.c4457ca/table.c c6fbe pins, frozen C/shim/guard and nine-input
before/after closure matched. Actual GCC -M/-MD45-header closure matched.

Actual logged receipt112,044B SHA256
9bc7a71ec19b6e35debf644df11a681a0a1aa2516ec3e189b9ab0e730f4c0253;
actual job log263,949B SHA256
329287b6389e5813715ec5f8b13c7641f8347e97ec956c09607867c710cb8b59.
Root independently matched the full printed JSON and actual assertion capture
digests. Hosted minimum free92,387,246,080B, final output185,732B,
peak observed185,733B, resource failure absent and self-inclusive accounting
verified. Raw proof stays in bounded RAM while local physical persistence
fails the separate20GiB admission. No credential, TLS or Windows execution
is established by these loader-boundary controls.

Root's small production profile followed this actual RED. Its identical
HOST/ASan/UBSan GREEN is recorded below; native DLL/Windows integration remains
pending.
The fixed prefix follows the project's actual native provider, interpreted
using the Microsoft [ANSI dispatch-table declaration](https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-securityfunctiontablea)
and [typed init contract](https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initsecurityinterfacea).
The implementation is independently authored; no third-party source code was
copied. These modern API declarations do not certify Windows98 native support.

## Actual identical-fixture GREEN and scoped integration handoff

Production137b1469bed3828e2bfd510db85f8d9c845479a2 ran in hosted
[run36927990611](https://github.com/NiSeullent/Win98-Modern/actions/runs/36927990611),
job110589951770. HOST651 and Clang ASan/UBSan651 checks all passed. All8 actual
commands exited0 and were reaped without abort. Both assertion stderr captures
were empty. Nine source inputs matched before/after and current source, with
native.c SHA25697a33c5292773ef949df251c7615eff259305b604f8d8d8d7f20b8039f98c301.
The C fcec7015, shim49450ec8, guard1b52856e and workflow4eedf083 pins are
identical to actual RED. Actual -M/-MD closures matched:45 GCC and49 Clang
inputs, including complete production C bodies and real system headers.

Actual logged receipt196,082B SHA256
7e6caf33371e59a3efdc48a0bc9d25aed9c8478ee56ccab4b2c01ca1dc4bd9fc;
actual job log458,804B SHA256
99a03057fb75108b2122270e3b6a537d22b6f29cc025c876f523ed9ed02b24e2.
Root independently matched the full logged JSON and both exact assertion
captures. Hosted minimum free92,385,599,488B, final output1,912,328B,
peak observed1,912,329B, resource failure absent and accounting verified.
Source snapshots and resolved compiler hashes matched; implicit compiler
backends/linkers/runtime, the loaded Python implementation and transient
filesystem peaks are not fully attested.

Sole canonical/main publishers should take restore e2473df, frozen regression
bef7fac and production137b146 as scoped commits; this note does not claim that
they have received, acknowledged or merged them. Kernel64 service routing,
native_loader --providers policy, OS registration and peer-owned VMM/DOS boot
remain unchanged. The actual proof validates provider selection/table/pointer
lifetime using host Win32 boundaries. No credential/handshake/encryption path,
native DLL execution, actual Windows concurrency or latest-app acceptance ran.
