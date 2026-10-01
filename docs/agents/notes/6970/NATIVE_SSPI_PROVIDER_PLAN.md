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
No compiler/test has yet executed for this new profile.

Native_loader's --providers execution policy remains disabled. This binding
does not register an OS provider or connect Kernel64 secur32, which currently
returns unsupported package/context errors. Actual Windows98↔K64 forwarding
needs the peer-owned VMM callback/caller/lifecycle contract and separately
reviewed versioned wire operation, handles and buffer ownership. Generic IPC
is not an SSPI implementation. Native ROOT, OS TLS1.3, modern-app and final
ISO acceptance remain required and unverified.
