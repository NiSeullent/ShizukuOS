# ReactOS reference port and licenses

This directory starts a **ReactOS-reference-derived** exception subsystem. It is
not covered by the older claim that every file in `ntwin32/` was independently
implemented without ReactOS. It does not change or relabel the frozen earlier
components. The user's later instruction expressly selected ReactOS-based staged
kernel and application porting.

The official repository was pinned through its GitHub commit API to
[`cae3c053d47024545c773148185319075eae0202`](https://github.com/reactos/reactos/tree/cae3c053d47024545c773148185319075eae0202)
(2026-09-27). Only small source files were read; no full checkout, upstream script
or binary was executed. Exact URLs, lengths and SHA-256 values are in
[provenance.json](provenance.json).

| Local file | Source relationship | License |
| --- | --- | --- |
| `veh.c` | Adapts the two lists, registration ordering, shared synchronization and handler-reference lifetime design in ReactOS `sdk/lib/rtl/vectoreh.c`; original notice naming Thomas Weidenmueller retained. Rewritten allocation interface, handles, snapshot traversal, removal and close behavior are project changes. | Distributed under GPL version 2; upstream directs to root `COPYING`. |
| `veh.h` | Original portable, explicitly non-Win32 interface for the adapted core. | GPL-2.0-only |
| `test_veh.c`, `test.py` | Original synthetic host models/build checks; no upstream tests copied. | GPL-2.0-only |
| `COPYING.ReactOS` | Exact pinned upstream root `COPYING`, including the license's original notice. | GNU GPL version 2 text; verbatim redistribution permitted. |
| Documentation and `provenance.json` | Original analysis of the pinned paths and implementation scope. | GPL-2.0-only |

The upstream leaf has no separate later-version grant; this port distributes its
derivative under GPL version 2 and preserves the referenced license text without
inventing an alternative license. This note is the per-file trace, not a blanket
license inference for unrelated ReactOS directories.

Before the port, the matching Wine registration/removal and dispatch routines in
[`dlls/ntdll/exception.c`](https://github.com/wine-mirror/wine/blob/4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf/dlls/ntdll/exception.c)
were compared at `4e819f054dd2d9ee855ee3f1e30d8c1bb8f80fcf` (2026-09-25).
That file retains copyrights of Turchanov Sergey and Alexandre Julliard and is
LGPL-2.1-or-later. **No Wine implementation is copied here**. Its comparison
showed a similar reference-counted registration design, dispatch outside the lock,
deferred freeing, and NT-specific continuation/raise dependencies. Its current
exception traversal and continue-handler registration are not taken as evidence
that Win98 supports either API.

The ReactOS reference holds an active entry until dispatch drops its reference;
its comment makes repeated removal the caller's responsibility. The new port
unlinks immediately and marks inactive, so repeated remove cannot decrement a
dispatch-owned reference. It pins the complete bounded traversal snapshot before
calling handlers, avoiding use of an unpinned `next` pointer across allocator or
callback reentry. This intentionally changes mutation visibility and handles;
it is not evidence of identical Windows Add/Remove semantics.

Primary Microsoft interface references:
[vectored exception order](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling),
[AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler),
[AddVectoredContinueHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredcontinuehandler).
The documented APIs require newer Windows versions; this directory publishes no
substitute export and no native compatibility percentage.
