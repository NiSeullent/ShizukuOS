CoWaitForMultipleHandles local wait boundary
===========================================

This implementation waits real kernel event/mutex/thread handles and runs
real queued APCs. MTA and uninitialized callers use WaitForMultipleObjectsEx.
An actual STA uses the existing message queue to service sent callbacks, DDE
and paint messages. COWAIT_DISPATCH_WINDOW_MESSAGES additionally dispatches
ordinary window/input messages; COWAIT_DISPATCH_CALLS has no meaning outside
ASTA and is ignored as Microsoft documents. The runtime has no ASTA, COM RPC
call window or remote proxy/stub provider. This function does not invent RPC
delivery or turn an absent COM class/transport into success.

Registered per-thread IMessageFilter is honored via an owned AddRef snapshot;
callbacks run without a registration/window/kernel lock. Reentrant replacement
or unregistration cannot destroy the snapshot before it is released.
PENDINGMSG_CANCELCALL returns RPC_E_CALL_CANCELED. WAITNOPROCESS preserves
queued window messages; default processing remains bounded to 100 messages
before polling real wait objects again. No outgoing RPC call exists, so the
filter's task is NULL and pending type is TOPLEVEL. WM_QUIT is retained and
reposted with its real code. Finite deadlines use genuine 64-bit elapsed time,
and a processed message can genuinely signal the waited object. Object/APC
and abandoned-mutex results preserve their documented wait index values.

Explicit unsupported boundaries: COWAIT_INPUTAVAILABLE returns E_NOTIMPL
because the current queue lacks seen-input generations. STA COWAIT_WAITALL
also returns E_NOTIMPL because matching queue input cannot yet be included
atomically with all handles. STA supports at most 63 handles (one queue slot);
the real MTA object wait supports 64. These failures are not compatible API
coverage. The small user32 prerequisite fixes zero-time **wait-any** polling
and ready-object priority over queue wakeups; it does not claim a new WAITALL
or seen-input implementation.

The real gfx_msg.c queue reports posted/DDE/quit availability with
QS_POSTMESSAGE, so the default wait mask includes that level as well as
QS_ALLPOSTMESSAGE. The current provider applies WM ranges to WM_QUIT too;
a dedicated matching quit peek preserves and reposts it. The exact host
model honors these current provider details instead of assuming that a
Windows-like message retrieval backend already exists. The genuine guest
fixture posts DDE into the actual queue and completes only when its real
window callback signals the waited kernel event.

The actual LibreOffice 26.8.0.3 tag resolves to commit
bce0998afefdbc355585ca324285661a2170ba77. Its
include/systools/win32/wait_for_multiple_objects.hxx calls CoWait with bit8
COWAIT_DISPATCH_CALLS and maps RPC_S_CALLPENDING to WAIT_TIMEOUT. The sal
condition implementation creates and waits real event handles. The V20 loader
stopped on the required sal3.dll import before this code existed; resolving an
import or passing wait fixtures alone is not a LibreOffice functionality result.

Primary contracts/reference:

- https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cowaitformultiplehandles
- https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/ne-combaseapi-cowait_flags
- https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/combase/combase.c
- https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/combase/combase.c
- https://raw.githubusercontent.com/LibreOffice/core/bce0998afefdbc355585ca324285661a2170ba77/include/systools/win32/wait_for_multiple_objects.hxx

Both pinned Wine and ReactOS implement the same underlying object/message
wait split and special DDE/paint/sent-message polling. Their full apartment,
RPC transport and TLS structures cannot be transplanted into this runtime.
This original body uses the existing real Shizuku providers, snapshots the
registered filter safely across callbacks, enforces finite elapsed deadlines,
and bounds unsupported queue cases instead of inheriting their assumptions.
