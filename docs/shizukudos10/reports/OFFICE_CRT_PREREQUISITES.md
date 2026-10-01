# Latest LibreOffice publisher-runtime prerequisites

The unmodified LibreOffice 26.8.0 launcher first failed to import the project's
missing C++ ostream flush method. A separate application tree adds the same
verified publisher MSI's AMD64 VC14.44 runtime DLLs; it preserves the original
package and earlier guest evidence. The publisher MSVCP runtime then failed at
`ucrtbase!__strncnt`. After its actual guest contract passed, the next real
application attempt failed at `ucrtbase!_lock_locales`.

These are standalone Kernel64 application attempts. They do not establish
installed Windows 98 execution, successful LibreOffice startup, version output,
document editing or whole-API compatibility.

## Refreshed eager-import audit

The audit reads the actual private `app-runtime-v4/WIN64.IMG` archive, SHA-256
`dabf0aaaca14dadceff6e5382f088114dec2c67076d61ce5d1447973efb2a47d`, and the
publisher `program/msvcp140.dll`, SHA-256
`0f885b509a685d2bbfa652fed26b5fb31d88fbdab0a978c641d1c7b8aa460aa9`.
CRT API-set contracts resolve to the existing UCRT host; core API-set contracts
resolve to the existing Kernel32 host. The audit compares named PE exports,
not behavior.

| Provider/family | Remaining publisher eager imports in V4 | Available implementation foundation |
| --- | --- | --- |
| UCRT locale locking | `_lock_locales`, `_unlock_locales` | Real native recursive critical sections. Existing `crt_lock` uses nonrecursive SRW and cannot substitute. |
| UCRT time snapshots | `_Getdays`, `_Getmonths`, `_Gettnames`, `_Strftime`, `_W_Getdays`, `_W_Getmonths`, `_W_Gettnames`, `_Wcsftime` | Existing genuine C-locale formatter, caller-owned heap, pinned upstream snapshot ABI. |
| UCRT secure randomness | `rand_s` | Existing `NtShzRandom` CSPRNG backend, used by real BCrypt/ProcessPrng/SystemFunction036 implementations. |
| Kernel32 event/semaphore creation | `CreateEventExW`, `CreateSemaphoreExW` | Existing `NtCreateEvent`/`NtCreateSemaphore` objects. Ex wrappers must retain desired access, flags, inheritance and failure semantics. |
| Kernel32 threadpool work | `CreateThreadpoolWork`, `SubmitThreadpoolWork`, `CloseThreadpoolWork`, `FreeLibraryWhenCallbackReturns` | Original Win98 work/callback backend in `src/m98_threadpool.c`; it requires an explicit AMD64/runtime integration and lifecycle review. |
| Kernel32 threadpool timer | `CreateThreadpoolTimer`, `SetThreadpoolTimer`, `WaitForThreadpoolTimerCallbacks`, `CloseThreadpoolTimer` | Shared object lifetime/callback scheduling foundation; cancellation, outstanding callbacks and close behavior must be real. |
| Kernel32 threadpool waits | `CreateThreadpoolWait`, `SetThreadpoolWait`, `CloseThreadpoolWait` | Real kernel waits plus shared callback lifecycle; handles, timeouts and callback cancellation cannot be replaced by inert handles. |
| Kernel32 process memory barrier | `FlushProcessWriteBuffers` | Requires a process-wide barrier appropriate to the actual scheduling/CPU profile. A local fence does not establish a future multicore implementation. |

There are exactly 25 missing publisher MSVCP eager imports in V4. The audited
Kernel32/UCRT portion of `soffice.com` additionally lacks `GetBinaryTypeW`;
`PathCchCanonicalizeEx` and `__strncnt` are present. The launcher SHA-256 is
`95016b59e08da1e6cbb02fc8f027593c076bf47df795092578afdd995306ac85`.
The complete original closure is preserved in ignored
`libreoffice-msi-vc14-startup-chain.json`; actual application receipts are in the
integrator's private `build/modern-apps/libreoffice-msi-vc14-v4/` directory.

## Narrow UCRT ports

`ucrt_office_locale.c` supplies actual recursive mutual exclusion with
race-safe initialization publication. The global C-locale tables and object are
immutable; `_configthreadlocale` changes per-thread state only. Future global
locale mutation must acquire this same lock. No existing source or global
configuration was changed. Matching owned lock/unlock calls and module lifetime
are required, as with the native CRT.

GCC and Clang AddressSanitizer/undefined-behavior-sanitizer runs each pass 35
checks, including 60,000 protected updates, simultaneous initialization and
nested ownership that blocks another thread until the outer unlock. The full
AMD64 UCRT and actual API-set guest test compile with strict warnings. Guest
execution is a separate integrator-owned gate; host evidence does not prove
native guest critical-section behavior.

`ucrt_office_time.c/.h` supplies the eight time helpers in separate source files.
The 712-byte MSVCR110+ structure has 43 narrow pointers, two 32-bit metadata
fields, 43 UTF-16 pointers and a locale-name pointer at the pinned offsets.
Each snapshot owns all referenced strings in one malloc allocation. Day and
month lists are also independently caller-owned.

Supplied snapshots control the actual weekday/month/AM-PM strings and date/time
pictures. Wide snapshots retain UTF-16; unrepresentable narrow output fails
under the existing C-byte encoding. NULL snapshots delegate the existing real
C-locale formatter. Non-C snapshot metadata fails explicitly; these additions
do not manufacture unsupported locale selection.

GCC and Clang AddressSanitizer/undefined-behavior-sanitizer runs each pass 117
checks for ownership and ABI, all strings, independent snapshots, modified
names/pictures, quoted apostrophes, Korean UTF-16, encoding failure, exact
capacity, invalid callbacks and allocation failure. The full AMD64 UCRT and
guest test compile, and the PE exposes all eight names. Guest execution and
the next real LibreOffice attempt remain separate checks.

Exact new-file hashes, absent-before state, diffs, compiler commands and output
hashes are preserved in ignored `tools/office-locale-port/source-receipt.json`
and `tools/office-time-port/source-receipt.json` beneath the publisher-input
assessment directory. No acquired application binary or runtime DLL is added
to version control.

`ucrt_office_random.c` adds `rand_s` through the existing `NtShzRandom` backend,
also used by BCrypt and ProcessPrng. NULL invokes the actual CRT invalid-parameter
handler and returns EINVAL; entropy failure clears the entire output and returns
EINVAL. Success preserves errno and the separate `rand`/`srand` sequence. GCC
and Clang ASan/UBSan each pass five host checks, including injected partial
entropy failure and both endpoints of the unsigned range. The integrator subsequently executed the actual guest entropy contract: 71
assertions passed, with normal exit and no fault.

`kernel32/k32_office_binary.c/.h` adds `GetBinaryTypeW/A` by opening and reading
the actual file. Bounded header/section reads distinguish PE32/PE32+, reject PE
DLLs, and recognize DOS and explicit Windows/OS2/DOS-extender NE targets. PE
headers take precedence over the COM filename extension, which matters for the
actual AMD64 LibreOffice `soffice.com`. Non-MZ COM/PIF extension fallbacks follow
the reviewed source contract. Ambiguous old NE targets and LE/LX return
ERROR_NOT_SUPPORTED; this parser does not claim complete executable loading.
Actual open/read errors survive cleanup and failures leave the caller's type
untouched. The ANSI front end uses the real system code-page conversion.

GCC and Clang ASan/UBSan each pass 40,050 classification checks. These include
PE32/PE32+, machine/magic mismatches, raw/virtual extent failures, recognized NE,
injected read failures, 20,000 bounded malformed inputs, and all four actual
publisher executables: LibreOffice, Legcord, Chromium and Steam. The tests only
read those inputs. Both production source objects and real-file guest contract
EXEs compile/link with strict AMD64 flags. Separate full native UCRT and Kernel32
builds also pass and expose the actual required names, with 859 and 642 named
exports respectively. All compilation input hashes remain unchanged before and
after the build. The exact receipt is ignored
`tools/office-runtime-next/source-receipt.json`, with host, object/EXE and full
DLL receipts linked from it. These counts and classifications do not establish
successful application startup.

## Source review and family boundaries

The new algorithms are original project GPL-2.0-only source. ABI, ownership and
failure paths were reviewed against pinned
[Wine 11 locale/time source](https://github.com/wine-mirror/wine/tree/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/msvcrt)
and [ReactOS MSVCRT source](https://github.com/reactos/reactos/tree/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/msvcrt).
No upstream implementation code was copied.

The full catalogue's `threadpool` family in `porting/groups.json` includes work,
wait, timer, I/O, cleanup groups and deferred callback resources. The existing
Win98 work subset does not finish that family or supply the absent standalone
Kernel64 exports. The original work implementation has real queue ownership,
running/pending counts, cancellation, callback references and deferred library
release; those are foundations to preserve, not names to alias.

## Implemented current 14 Kernel32 prerequisites

The new `k32_office_threadpool.c` adapts the original project's owned queue,
callback instances and deferred cleanup to the actual standalone AMD64 kernel.
Real worker threads dispatch work, timers and waits. The shared monitor grows
workers when queued callbacks meet a fully busy pool and retries real thread
creation failures. Native thread-slot exhaustion remains an actual failure.

Pending and running callbacks each retain their object. Close releases caller
ownership while queued/running work survives. Callback waits hold their own
references and cancellation removes pending callbacks separately from running
ones. Deferred library release occurs after the callback and finalization return;
no user callback executes under the scheduler's critical section.

The timer scheduler uses the native 100 ns system clock for relative/absolute
due times, periodic firing and bounded arithmetic. Disarm stops future scheduling;
callback cancellation and waiting remain separate operations. Wait buckets hold
up to 63 actual waitable handles plus a control event. Each unlocked wait snapshot
retains its wait objects; native waits capture referenced kernel objects. A
replacement signals the control event at index zero before closing the previous
owned registration handle. Native any-wait selection checks the lowest index
first, and an arm-generation comparison prevents an old snapshot from dispatching
a replacement registration. Independent review refuted an initial numeric-handle
reuse concern after checking this ordering and actual kernel references; the
frozen scheduling source was preserved. Wait callbacks are one-shot.
A NULL wait handle ignores the timeout argument and disarms. Native object type
and SYNCHRONIZE rights are checked before registration: Event, Semaphore, Timer,
Thread and Process are supported by the genuine current backend. Mutex requests
raise the documented threadpool handle exception; unsupported types fail explicitly.

Default callback environments, finalization, long-running hints and deferred
resources are supported. Unavailable custom pools, cleanup groups, activation
contexts and priority requests fail explicitly. Full threadpool I/O and those
remaining environments are still family work; these 14 prerequisite names do
not complete the catalogue's whole threadpool family.

The separate `k32_office_sync.c` implements EventEx/SemaphoreEx using native
objects, exact requested access including zero, supported flags and actual
inheritance. Narrow `sysx.c` changes retain and enforce native object access,
propagate OBJ_INHERIT, publish named objects atomically and prevent signed
semaphore count overflow. Both alertable and nonalertable event/semaphore waits
require SYNCHRONIZE. Explicit security descriptors that the current backend
cannot honor return ERROR_NOT_SUPPORTED; they are never discarded.
`ipc_core.c` preserves the integrator/socket lane's handle publication and
last-socket-close changes while adding the two narrow alertable rights checks.

FlushProcessWriteBuffers performs an actual architectural full fence under the
runtime's verified single active processor profile. An unsupported SMP profile
raises explicitly; this is not evidence for a future multiprocessor barrier.
The private system-information class 0x102 delegates real measured idle/kernel/
user CPU times to the integrator's backend. Standard class 8 is not supplied or
claimed by this hook.

The exact production scheduling source passes 305 GCC and 295 Clang ASan/UBSan
host assertions; the counts include live worker/callback observations. Coverage
includes real execution, blocked callback cancellation, close while active,
deferred release, relative and periodic timers, signal/timeout and replacement
waits, denied/unsupported wait handles and 64 independent handles across bucket
boundaries. The exact native access helper passes 20 checks under both compilers.
Strict native kernel object compilation and a full AMD64 Kernel32 rebuild pass.
The actual DLL contains all 14 eager prerequisite exports among 665 named names;
all full-build source input hashes remain unchanged.

Both actual guest contracts compile/link with strict warnings. They test actual
child handle inheritance and rights, callback ownership, pending cancellation,
timer/wait behavior and deferred release of a loaded module. The integrator's V11
threadpool guest passed 22 assertions and failed one: `version.dll` remained
mapped after deferred FreeLibrary. Actual work, timer and wait callbacks executed.
The V11 runtime `LdrUnloadDll` only decremented the load count and explicitly retained the
image. The meaningful unload failure is preserved. Real detach callbacks,
dependency ownership, loader-list retirement and kernel image unmapping are a
separate required loader change; the deferred API is not declared fully verified.
These results do not establish successful latest LibreOffice startup. The earlier
real-file binary-classification guest contract passed 21 assertions, with normal
exit and no fault.

Exact absent-before state, original lower-layer before hashes, frozen after
hashes and source diffs are preserved in ignored
`tools/office-runtime-next/threadpool-sync-source-receipt.json`. It links the
host and full native receipts. All 10 files are frozen for coordinated integration;
no application payload, global client configuration or base guest image was edited.

## Newly reached real publisher export-name limit

The V11 actual launcher reached the publisher MSVCP140 `flush` export lookup and
reported a malformed export directory. This was a latent parser limit reached
after prerequisite imports were implemented. V7 had failed while linking MSVCP's
`rand_s` dependency, before returning to the launcher's `flush` lookup. V2 and V3
kernel receipts contain identical PE parser, loader and lazy-file-view hashes.

The actual FAT-image MSVCP140 file equals the application-tree file byte for
byte: 557,728 bytes, SHA-256
`0f885b509a685d2bbfa652fed26b5fb31d88fbdab0a978c641d1c7b8aa460aa9`.
The exact old production parser accepts the image but returns PE_E_EXPORT for
named `flush`; ordinal 873 succeeds at RVA 0xb540. Its linear name search copies
each preceding export into a 128-byte buffer. Export index 430 is a valid
159-byte decorated name; the real table contains 1,515 exports, 198 names at
least 128 bytes and a maximum length of 183.

The narrow `pe_parse.c` change compares names directly within their backed file
extent, validating ASCII and a terminator even after an unequal candidate. It
does not allocate, truncate names or change ordinal lookup and forwarder caps.
This implements the
[PE format's variable-length, NUL-terminated export names](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
The previous parser hash is
`5862bfe35f0faddc14479097b043a2994de50883e552521e54959d09b88ce7b0`;
the frozen corrected hash is
`83d478852e634eb0a258f407b22a1d4e350e1701ffb8d0aa1f56175a61bdfeb4`.

The new production-parser-linked `test_pe_export_names.c` passes 3,658 checks
under GCC and Clang ASan/UBSan, using the unchanged publisher DLL as input.
It checks all 198 long names against their actual ordinal addresses, including
`flush`, plus exact case, prefix mismatches, NUL at the backed extent boundary,
missing NUL, invalid ASCII and invalid name RVAs. The old production parser
fails this regression contract. Existing parser tests pass 3,822,525 checks and
300,000 mutations per compiler; the strict native kernel object compiles.
Another agent independently reviewed comparison bounds and ownership.
The ignored `tools/office-runtime-next/pe-export-source-receipt.json` preserves
the exact diffs, source/input hashes and compiler receipts. Guest application
execution of this new parser remains the integrator's separate gate.

Read-only downstream inventory also identifies the distinct 160-byte import
name buffers and ntdll's 127-byte requested-procedure-name truncation. Actual
`mergedlo.dll` imports include names up to 309 bytes. These paths were not
silently changed with this narrow export lookup repair.

## Frozen meaningful document-conversion gate

`tools/run_libreoffice_conversion.py` prepares a fresh, disposable publisher
disk copy and fixed headless commands. Its fixture contains known English and
Korean Writer paragraphs. The ODT scenario requires actual FODT-to-ODT conversion,
then reopening that ODT to produce UTF-8 text. Output verification reads ZIP
mimetype, manifest and content XML, validates CRC and bounded extents, and
compares actual paragraph and text content. The PDF scenario uses pdfinfo and
pdftotext to check actual pages and extracted Unicode content.

The runner uses a distinct owned disk copy with snapshot disabled so generated
files can be read back. Original publisher image/tree, kernel and runtime hashes
must remain unchanged. Clean process exit, successful disk flush, native kernel
selftests, read-only filesystem checking and bounded output extraction are
required. No produced document or application success is accepted from a timeout
or loader failure. Whole-application and installed-Windows-98 verification flags
remain false even if a particular document gate passes.

Thirteen host tests pass. The runner hash is
`5090e90a23f1358966f49be849531514c74dfd2dc09125541f7631f00da89ca3`;
`tests/test_libreoffice_conversion.py` is
`8786985279fcd592127c97d08801290ea4295e8617a6f29bfe62a05764ea4de1`.
The ignored `tools/office-runtime-next/conversion-source-receipt.json` preserves
new-file diffs and host results. No guest conversion was run in this source lane;
startup/import closure must pass first.

## Actual LibreOffice find64i32 prerequisite

The integrator's actual LibreOffice V12 trial with kernel V5 passes the corrected
MSVCP export lookup and reaches `clucene.dll`'s eager UCRT `_findnext64i32` import.
Its loader failure remains an application failure; no conversion result is inferred.

The new `ucrt_office_find.c` adapts the existing real `_findfirst64` and
`_findnext64` directory enumerator. Its separately declared ABI is checked at
compile time: the full record is 304 bytes, the 64-time/32-size record is 296
bytes, and its name begins at byte 36. All three timestamps remain 64-bit and
file size uses the low 32 bits, matching the pinned Wine
`db11d0fe6a169c457e23d007e20404643d067aa8/dlls/msvcrt/dir.c`
choice. The adapter does not create an overflow failure, change native search
handle ownership or truncate an intptr handle. Failed enumeration preserves
the backend errno and leaves caller output unchanged. `lowio.c` remains byte
identical at `f337d934972e58487211f1ccb5d36d36c7c5b4643642be7a0989a2401653b720`.

The exact production adapter passes 4,012 controlled-boundary host checks under
GCC and Clang ASan/UBSan. These check ABI bounds, times beyond 2038, low-32 sizes,
full handles, error propagation and failed output preservation. A separate
compiled guest creates two actual files, enumerates their names and sizes, tests
end-of-search and closed-handle errors, then deletes its fixtures. The complete
native UCRT DLL builds with 861 exports, including both new functions. Another
agent reviewed the record layouts, handle and output lifetime without finding
a concrete new defect. Guest execution remains a separate integrator gate.
The ignored `tools/office-runtime-next/find64i32-source-receipt.json` records
exact new-file diffs, compiler commands and unchanged source hashes.

## Genuine bounded dynamic unload foundation

The actual V11 threadpool result remains 22 PASS and one deferred-unload FAIL.
The new source foundation requires a new actual guest result before changing
that evidence. No lookup filter or weakened assertion substitutes for unmapping.

The kernel owns explicit LoadLibrary/AddRef references, process-lifetime pins,
startup roots and unique eager/forwarder dependency edges. Reachability from
these roots selects unreachable dynamic import cycles as one retirement set.
Private operations 0x42/0x43 prepare and commit that set with an owner-thread
and monotonic token. The kernel mutex is released before user callbacks. ntdll
runs DLL_PROCESS_DETACH with NULL reserved in reverse dependency-completion
order, delivers reason-2 notifications while all selected images are mapped,
then commits actual unlinking of all three PEB lists, VAD reservation release,
and module/edge record disposal. Completed commits publish real unload trace
records. Published entry batches retain their shared storage until process exit.

Active loader callbacks and pending initialization reject retirement; failed
preparation restores the reference. The runtime also avoids repeating executable
TLS callbacks on subsequent LoadLibrary calls. Notification registrations stay
owned through recursive dispatch and self-unregistration; newly registered
callbacks do not receive an already active event. Startup roots cannot be freed.
The profile explicitly rejects retirement of static-TLS modules because existing
per-thread arrays and templates share allocations. It neither reuses their slots
nor silently pins them. Explicit references are bounded at 65,534 and retirement
sets at 1,024 modules. Callback abort or a partial commit remains an explicit
failure with its transaction retained until process teardown; callback flags
prevent repeated detach at shutdown and prevent thread callbacks on retiring
images. Recursive retirement does not execute duplicate detach callbacks.

Lazy image metadata has a module-owner reference plus active page-in references.
A blocked read retains the metadata, retirement prevents new page-ins, and the
returning reader checks retired state and the exact current VAD/image identity
before publishing its page. This prevents stale I/O from repopulating a retired
or reused address. The permanent kernel file view retains its existing lifetime.

The production lifetime header passes 576,023 host checks per compiler, including
12,000 randomized cyclic graphs against a separate DFS oracle. Exact extracted
production reference/prepare/commit bodies pass 44 injected-boundary checks;
exact `ldr_image_fault` passes 53 checks with retirement during fs_read, reused
address identity, racing page-in, short read, teardown and allocation failure.
GCC and Clang ASan/UBSan pass all three contracts. Strict native kernel objects
and the complete ntdll DLL compile and link. Two test-only DLL fixtures form a
real A-to-B import edge; the compiled guest requires actual detach ordering,
independently held dependency lifetime, active-callback release rejection,
notification self-unregistration, failed revival, unload trace, all three list
removals, actual MEM_FREE reservations, clean reload and process-lifetime pin.
The fixture sources stay under tests and are not installed as application APIs.
Actual guest execution remains the integrator's separate gate.

The ignored `tools/office-runtime-next/unload-source-receipt.json` records exact
before/after source hashes and diffs, production-body identities, compiler
commands and binaries. The source lane never modified the private tree or ran
QEMU. The integrator separately reported the new find64i32 guest 19 PASS and
actual LibreOffice V16's next missing MPR WNetCloseEnum import; neither constitutes
LibreOffice document conversion or full application success.
