# Genuine shared NT bootstrap functions

This additive family supplies eight real NT DLL functions consumed by the
pinned official Firefox 157 startup image. The functions are shared runtime
contracts and contain no application names, version facade or whitelist.
Static imports and standalone fixtures do not establish that Firefox, Office,
Chromium, Discord or Steam work. Application/VM execution remains root-owned.

`RtlCompareMemory` returns the length of the matching initial byte sequence.
Unicode comparisons use descriptor lengths, including embedded NULs, and return
ordinal UTF-16 code-unit differences. Case-insensitive comparisons reuse the
actual immutable Unicode 14.0.0 `kernel32/unidata.h` table through a new pure
helper, without linking to kernel32. This table is generated Unicode data,
not Windows NLS data. Its single-character uppercase policy retains a code
unit when uppercase expands to several characters, and does not case-map
supplementary surrogate pairs. No locale collation, newer case table or exact
Windows NLS equivalence is claimed. The independent host oracle checks all
BMP code units against Python's single-code-unit uppercase result.

ANSI conversion ports the pinned Wine UTF-8 decoder and conversion bodies,
using the runtime's actual fixed ACP65001. A truncated sequence clamps to the
real input end, avoiding Wine's out-of-range pointer formation. Other malformed
subsequence replacements preserve the pinned Wine contract, including its
truncated-input consumption; these are explicit reference cases rather than
a claim that Python's replacement policy is identical. Valid UTF-8 conversion
is independently checked using Python UTF-16 encoding. Embedded NULs use the
explicit ANSI descriptor length. The genuine process heap owns allocations,
and caller-buffer overlaps use a bounded owned snapshot before widening.
Required output Length is published on overflow, matching the documented
legacy contract; no success is returned for allocation or buffer errors.

Unicode duplication preserves flags 0, 1 and 3, real allocation/free ownership,
embedded NULs and descriptor self-aliasing. Invalid flags, odd UTF-16 byte
lengths, missing buffers, inconsistent lengths and a terminating-NUL USHORT
overflow fail honestly. Destination buffers are never arbitrarily freed.
Caller descriptors must identify valid readable/writable storage; raw pointers
are not turned into a pretend probing or exception-handling facility.

Run-once preserves the native eight-byte object and its low-bit state: new 0,
synchronous initialization 1, complete 2 plus aligned context, and asynchronous
state 3. Only the two requested synchronous public entry points are added.
A failed callback returns STATUS_UNSUCCESSFUL and allows a later retry; a
successful callback publishes its context with release/acquire ordering.
The callback receives the caller's actual context-output pointer, including
NULL. A misaligned successful callback context returns INVALID_PARAMETER,
retaining the pinned Wine in-progress behavior. Callers must not reinitialize
or forcibly kill an active initialization/registered waiter. Different-object
callback reentry works; same-object recursive initialization blocks as a normal
synchronous once contract. No fake recursion success or callback exception
recovery is introduced.

The pinned Wine keyed-event backend is unavailable here, so synchronization
uses the existing genuine NT alert/thread parking provider. Its wake-all call
currently removes at most 64 waiters. Private bucket-locked stack registrations
count contenders before they park; completion publishes state, then drains
ceil(count/64) batches under that lock. Late parkers check the already changed
word, and registered nodes cannot leave borrowed stack storage before unlink.
No shared synchronization provider or kernel ABI changes are required. The
independent host fixture deliberately parks 95 contenders and limits each
wake call to the actual provider's 64-node maximum. Cross-API concurrent
initialization by another provider is not an added supported protocol;
completed native state/context representation is preserved.

The performance wrapper invokes the genuine NtQueryPerformanceCounter and
returns its actual success/failure. Unlike Wine's unconditional TRUE wrapper,
invalid destinations and backend failures do not claim a counter was supplied.
The native fixture independently brackets the RTL call with real NT samples.

Every old named export's exact ordinal is pinned from the actual immutable V42
NT DLL, with old holes and Nt/Zw aliases separately preserved. New exports use
only fresh 495..502. The initial ORIGINAL source inventory missed two legitimate
root-owned thread-error-mode providers; that first failure is preserved. Root
authorized an exact read-only-verified copy of the already frozen/actual V38
`thread_error_mode.c`. The root-owned builder must consume and validate the
new ordinal map; this batch does not modify the shared builder or existing
provider C/header files.

Source provenance: Wine commit
`db11d0fe6a169c457e23d007e20404643d067aa8`, local immutable Git objects only,
`dlls/ntdll/{rtlstr.c,locale.c,locale_private.h,sync.c,time.c,ntdll.spec}` and
reference tests. The selected UTF-8 bodies and adapted RTL strings retain
LGPL-2.1-or-later notices and their original authors. The independently written
once/clock/prefix functions and reuse of the existing Unicode table are
GPL-2.0-only. The copied root thread-error-mode provider retains its own LGPL
notice. Pinned full originals, selected-body receipts and license text are
preserved in the owned artifact directory.

Primary contracts: [RTL string conversion](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlansistringtounicodestring),
[RTL Unicode comparison](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcompareunicodestring),
[RTL memory prefix](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcomparememory),
[RTL once execution](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlrunonceexecuteonce),
[once callback and reserved context bits](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-rtl_run_once_init_fn),
[NT performance counter](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntqueryperformancecounter),
and the pinned [Wine NT implementation](https://gitlab.winehq.org/wine/wine/-/tree/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/ntdll).

Host results identify real pthread contention, explicit host provider adapters,
Unicode/UTF-8 oracles and exact consumed source hashes. The native executable
uses actual process heap/free, kernel performance clock, pinned exports and
eight genuine OS threads. Failed worker joins terminate the whole fixture
before releasing borrowed contexts or shared events. No application support
percentage is inferred from assertion counts, builds or static import closure.
