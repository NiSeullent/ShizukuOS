# Strict process query and loaded-image mapped-name slice

User-approved parallel Windows 98 integration work. Isolated ROOT tree
`/root/Win98-Modern-nt-fullquery-c957-20261002`, base reviewed `e22b5af7`.
The preceding exact eleven-path time/info/affinity slice is committed, clean,
independently reviewed and delivered through the shared source-only handoff.
Other chats own native DOS/Windows ESP, Supervisor/SMP and modern-app builds.
No private disk, NAS allocation, AP activation, website republish or ISO action.

## Independently established defects and chosen boundary

GetProcessMitigationPolicy and K32GetMappedFileNameW require full
PROCESS_QUERY_INFORMATION, but currently reuse class 3, which correctly
accepts either QUERY or LIMITED for the modern time/info getters. Raw native
process class 0 currently validates no query right and is not a replacement
authorization gate. Keep both existing contracts unchanged in this slice.

Mapped-name lookup converts a checked handle into PID and then reads an
unreferenced class-5 module list. Process-slot reuse and changing module lists
can invalidate its target or count. Its 128-byte list path clips the loader's
256-byte path. Public truncation returns size-1 with stale LastError; the
documented behavior is a NUL-terminated truncated buffer, return size and
ERROR_INSUFFICIENT_BUFFER. Size 1 must return 1, with an empty terminated buffer.

Add two currently unallocated private query ordinals, synchronized in the
kernel and Win64 header: K32Q_PROCESS_QUERY_ACCESS=17 and
K32Q_MAPPED_FILE_PATH=18. These are query ordinals, separate from setter
class 14. The first is a zero-payload strict QUERY gate for mitigation policy:
held reference, IRQ-protected process/object identity, retained exited-query
semantics, zero requested length, optional zero required length and balanced
reference on all outcomes. Access is checked first, then identity under IRQ;
after dropping the reference, nonzero length returns INFO_LENGTH_MISMATCH
without changing ReturnLength. The zero-length path never reads or writes
the buffer; an optional ReturnLength receives zero, with a write fault
returning ACCESS_VIOLATION. It does not manufacture process information or
change the existing mitigation capability/DEP reporting policy.

Class 18 uses a fixed 272-byte in/out packet:
`{uint64 address; uint32 pid, reserved; char path[256];}`. Only the first
eight input bytes are consumed. Require a held PROCESS_QUERY_INFORMATION
reference before interpreting the packet. After that reference check, length
below 272 follows put_out's required-size/BUFFER_TOO_SMALL behavior without
consuming the address or changing output bytes. A return-length write fault
takes put_out's existing ACCESS_VIOLATION precedence. Only sufficient length
permits the eight-byte input copy; larger buffers preserve their tail. Zero
the local packet/reserved/path storage before population. Input/output-copy
faults refuse and balance references. Under one outer IRQ guard verify the
referenced process/object
identity and capture its PID and one matching actual loaded-module path using
ldr_module_at. Address membership uses subtraction after address>=base to
avoid base+size overflow. Copy the full loader path into local packet storage
before releasing the guard/reference. Never expose module pointers or use PID
lookup/class 5. Retained exited/teardown targets have no supported live module
path and return an empty path with their retained PID. Empty path denotes no
supported loaded-image mapping; the frontend retains the existing current-
process VirtualQuery distinction for free versus private addresses. This
private packet is not a new public Windows ABI.

The mapped-name wrapper formats the captured path with its existing native
volume/UTF-8 conversion helpers. Preserve buffer guards and unchanged output
on refusal. On success return full character count excluding NUL; if it does
not fit, copy size-1 characters, append NUL, set error 122 and return size.
Neither ordinary section-backed files nor generic mapped-file names are
implemented by a loaded-module snapshot. Keep that limitation explicit.
PSAPI_VERSION1 forwarding and the ANSI variant remain separate work.

## Ownership and execution

Candidate production paths are exactly kernel64/sysk32_proc.c,
win64/include/nt.h and kernel32/k32_procinfo.c. Do not edit ldr.c, proc.c,
objects.c, sched.c, stacks, AP start, private section provider or old Q5 ABI.
Existing public priority/time/info/affinity source and old assertions must
remain unchanged. If extraction adapters need changes, limit them to loading
new actual helper bodies and preserve their assertion bytes.

1. Write dedicated host contracts before production edits. Execute actual
   selected query/wrapper/reference/free bodies and actual ldr_module_at with
   complete production process/object/module schemas. Publish every host
   copy/clock/IRQ/allocation/module-lifecycle boundary as an explicit adapter.
   Reuse the already corrected owned-process producer cleanup, with bounded
   no-timeout admission. Independently review and execute pristine baseline
   RED; keep final RED/GREEN C/Python bytes identical.
2. Test strict QUERY and QUERY|LIMITED success, LIMITED/SET/VM_READ-only denial,
   type/tag/width/closed handles, reference balance, identity and retained exit.
   Old modern class 3 must retain LIMITED success. Preserve DEP and options
   8/16-byte reporting, policy refusal/output guards and chosen private length
   behavior without asserting undocumented Windows error precedence.
3. Test actual loaded-module address/path snapshots, 200-byte path preservation,
   subtraction boundaries, size 1/name-length/name-length+1 truncation and NUL
   guards. Inject modeled module/target departure specifically at an old
   unguarded PID/list/copy seam, using actual close/last-reference process-free
   bodies before explicit slot/module republication. The new scalar snapshot
   must neither return a replacement owner's path nor depend on a list count.
   Observe actual ldr_module_at and selected path copy with both IRQ exclusion
   and a held reference. Model retirement only at an unguarded boundary; never
   force departure inside old module_copy's own guard. Test scalar pointer/path
   lifetime as well as process-slot reference lifetime.
   Model loader publication/retirement openly; do not claim native loader UAF
   or SMP verification from the host fixture.
4. Independently review production and assertions, run GCC/Clang sanitizer
   contracts, real affected translation-unit compiles and preserved regressions.
   Then freeze actual compiler closure, four kernels, both selected DLLs and
   fresh probes. Add guest checks through only the process-probe append,
   preserving its original 431 checks and the 654 priority probe unchanged.
   Cover independent rights, real current/remote image addresses, truncation
   sentinels, checked natural child lifetime and closed/exited target refusal
   or retained empty mapping according to the documented private subset.
5. Preflight and run one bounded actual UP guest with all positive PMA/kernel
   terminal gates. Independently review exact public files and terminal maps,
   commit and hand off source-only to other chats for their next canonical epoch.

Actual Windows 98 retains VMM/USER/GDI/Explorer ownership. IRQ guards provide
UP exclusion only; no AP/object/loader SMP lifetime claim. External toolchain
internals/sysroots/libraries, full current runtime, native Windows, modern
applications and installer/final ISO remain outside this component. Original
PMA361 and diagnostic failures are retained and unresolved.

Primary contracts: [GetProcessMitigationPolicy](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessmitigationpolicy),
[GetMappedFileNameW](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamew),
[memory-mapped file information](https://learn.microsoft.com/en-us/windows/win32/psapi/memory-mapped-file-information).
