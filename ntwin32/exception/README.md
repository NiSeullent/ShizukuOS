# Windows 98 Shizuku's Second Edition — exception core port

This is a bounded, freestanding **ReactOS-reference-derived handler registry and
dispatcher**, not working Windows 98 vectored exception handling. Its provenance
and GPL version 2 notice are retained in [PROVENANCE.md](PROVENANCE.md). Kernel
and user entry work is specified in [NATIVE_BINDING.md](NATIVE_BINDING.md).

Implemented operations are initialization, exception/continue-handler add and
remove, ordered dispatch, synchronized state inspection, and nonblocking close.
The caller supplies allocation/release and a real mutual-exclusion lock. A handler
receives the original record/context pointers through a portable two-pointer
structure and a caller cookie. These are opaque to the core: no NT `CONTEXT`
layout, `stdcall` wrapper or `Rtl*`/`AddVectored*` export is claimed.

The two lists share a 128-live-registration limit; up to 64 concurrent or nested
dispatch calls are admitted. `k32veh.c` is the Win32-shaped add/remove adapter
used by `NTW32.DLL`. It keeps numeric handles, rejects a NULL callback, and is
not a substitute for kernel trap delivery. Allocation occurs only during registration, outside
the lock. Dispatch pins a fixed stack snapshot without allocating; each selected
callback executes outside the lock. A nonzero `first` puts a registration at the
head; zero appends. Return -1 stops that list with CONTINUE_EXECUTION; other
callback returns continue searching. Continue-list dispatch exposes that same
result for diagnostics; a future native continuation caller must treat it as
notification, not as authority to undo an already validated continuation.

The stronger custom mutation policy is explicit:

* A dispatch snapshots only registrations present at entry. Additions become
  visible to a later or nested dispatch, never appended to the current snapshot.
* Removal unlinks immediately and drops the registration reference exactly once.
  Repeated or wrong-list removal returns NOT_FOUND. Numeric handles never repeat
  within a registry lifetime; exhaustion fails instead of reusing an old token.
  Handles are registry-local and are not Windows opaque registration pointers.
* A removed snapshot entry is skipped if its invocation has not yet been
  reserved under the lock. Removal after that reservation may return before the
  callback begins. Already reserved or executing callbacks can still finish.
* Snapshot references keep nodes alive, including early-stop and close paths.
  Final release is outside the lock and can reenter inspection. Code and cookie
  ownership remain the caller's responsibility: pending removal does not permit
  unloading a DLL or freeing its cookie. Join potentially reserving dispatches
  before retiring them. Counts are a snapshot, not a synchronization barrier.

`ntwe_remove` returns OK when its node was freed, PENDING when dispatch references
remain, or a negative error. `ntwe_close` permanently rejects new dispatch/add,
detaches both lists and reports PENDING while dispatch references are active. It
does not wait, so callback-driven close cannot deadlock on itself. Registry
storage, its service table and lock must outlive **all public calls**, including
registration allocators and release callbacks. Close/zero-dispatch stats never
authorize destroying storage while another caller can enter. Initialization,
reinitialization and destruction require external exclusion.

All pointer arguments must be valid, initialized objects of the declared types;
outputs must not alias registry/internal memory or objects concurrently modified
by another thread. Null/invalid-kind arguments and capacity/allocation/closed
failures leave output handles/dispositions untouched. Allocators return aligned,
distinct memory; lock callbacks must not fail and must provide memory ordering.
Callbacks and services must return normally. A foreign unwind, `longjmp`, fault
that abandons the C frame, corrupted registry or hung callback is not repaired by
this core. Native exception-safe cleanup remains an explicit binding prerequisite.

Run host tests (writes a new private RAM build directory by default):

```text
python3 -B ntwin32/exception/test.py
python3 -B ntwin32/exception/test.py --output /dev/shm/ntw-exception-owned-build
```

The runner tests strict GCC, Clang and nonrecovering ASan/UBSan, real pthread
controlled removal/close races, reentry, snapshot semantics, callback ordering,
allocation failure, double removal, token exhaustion and recursion limits. Four
threads also register/dispatch/remove concurrently. Callback counts in that stress
case intentionally vary with scheduling; fixed counts are not falsely required
to agree between compilers. Both i486 freestanding object builds must have no
undefined symbols or compiler runtime helpers. Receipts bind local source files,
upstream provenance, compiler commands and resulting artifacts. No VM is started.

Remaining native work includes first-chance ingress, debugger ordering, safe
record/context capture, SEH interoperation, noncontinuable exceptions, valid
context restoration, abnormal-unwind cleanup, process/thread initialization,
DLL-unload coordination and Win32 ABI adapters. KernelEx integration is absent.
