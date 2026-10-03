/* Win98 Winsock2/KERNEL32 backend and exports for the socket completion bridge.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Exports keep the exact WS2_32 / ConnectEx argument contracts under
 * ShizukuLc_* names; the libuv port routes its socket calls here (see
 * tools/modern_apps/legcord_win98_libuv.patch). Imports are limited to
 * functions present in the Win98 SE KERNEL32 and WS2_32 export inventory.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stddef.h>
#include "lc_iocp.h"
#include "lc_sock.h"

_Static_assert(sizeof(void *) == 4, "PE32 Win98 provider");

BOOL WINAPI ShizukuLc_PostQueuedCompletionStatus(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED);
int lc_sock_native_attach(HINSTANCE);
void lc_sock_native_detach(void);
DWORD lc_sock_native_associate(HANDLE, uint32_t, ULONG_PTR);

static CRITICAL_SECTION sock_lock;
static lc_sock_context sock_context;
static HMODULE self_module;
static char self_path[MAX_PATH];

static void s_enter(void *o) { (void)o; EnterCriticalSection(&sock_lock); }
static void s_leave(void *o) { (void)o; LeaveCriticalSection(&sock_lock); }
static uintptr_t s_event_create(void *o, int manual)
{
    (void)o;
    return (uintptr_t)CreateEventA(NULL, manual ? TRUE : FALSE, FALSE, NULL);
}
static void s_event_reset(void *o, uintptr_t e) { (void)o; ResetEvent((HANDLE)e); }
static void s_event_set(void *o, uintptr_t e) { (void)o; SetEvent((HANDLE)e); }
static void s_event_close(void *o, uintptr_t e) { (void)o; CloseHandle((HANDLE)e); }
static uint32_t s_wait_any(void *o, const uintptr_t *events, uint32_t count)
{
    HANDLE h[MAXIMUM_WAIT_OBJECTS];
    DWORD r;
    (void)o;
    if (!count || count > MAXIMUM_WAIT_OBJECTS) return LC_SOCK_WAIT_FAILED;
    for (uint32_t i = 0; i < count; i++) h[i] = (HANDLE)events[i];
    r = WaitForMultipleObjects(count, h, FALSE, INFINITE);
    return r < WAIT_OBJECT_0 + count ? r - WAIT_OBJECT_0 : LC_SOCK_WAIT_FAILED;
}

struct start { void (*fn)(void *); void *arg; };
static struct start worker_start;
static DWORD WINAPI s_thread(LPVOID p)
{
    struct start *s = p;
    s->fn(s->arg); /* ends in s_thread_exit */
    return 0;
}
static int s_thread_start(void *o, void (*fn)(void *), void *arg)
{
    HANDLE t;
    HMODULE pin;
    DWORD id;
    (void)o;
    /* The worker owns a module reference so FreeLibrary cannot unmap code it
     * is still running; it drops it with FreeLibraryAndExitThread. */
    if (!self_path[0] || !(pin = LoadLibraryA(self_path))) return 0;
    worker_start.fn = fn; /* called under the bridge lock; one worker at a time */
    worker_start.arg = arg;
    if (!(t = CreateThread(NULL, 0, s_thread, &worker_start, 0, &id))) {
        FreeLibrary(pin);
        return 0;
    }
    CloseHandle(t);
    return 1;
}
static void s_thread_exit(void *o) { (void)o; FreeLibraryAndExitThread(self_module, 0); }
static void s_io_result(void *o, uintptr_t sock, void *ov, uint32_t *bytes, uint32_t *wsaerr)
{
    DWORD n = 0, flags = 0;
    (void)o;
    if (WSAGetOverlappedResult((SOCKET)sock, (LPWSAOVERLAPPED)ov, &n, FALSE, &flags)) {
        *bytes = n;
        *wsaerr = 0;
    } else {
        *bytes = n;
        *wsaerr = (uint32_t)WSAGetLastError();
    }
}
static void s_connect_result(void *o, uintptr_t sock, uintptr_t event, uint32_t *wsaerr)
{
    WSANETWORKEVENTS ne;
    (void)o;
    if (WSAEnumNetworkEvents((SOCKET)sock, (WSAEVENT)event, &ne) == SOCKET_ERROR)
        *wsaerr = (uint32_t)WSAGetLastError();
    else if (!(ne.lNetworkEvents & FD_CONNECT))
        *wsaerr = WSAEINVAL; /* event signaled without FD_CONNECT: report, never invent success */
    else
        *wsaerr = (uint32_t)ne.iErrorCode[FD_CONNECT_BIT];
    WSAEventSelect((SOCKET)sock, NULL, 0); /* socket stays nonblocking, as libuv set it */
}
static void s_finish(void *o, void *ov, uint32_t status, uint32_t bytes, uintptr_t caller_event)
{
    LPOVERLAPPED p = ov;
    (void)o;
    p->Internal = status;
    p->InternalHigh = bytes;
    p->hEvent = (HANDLE)caller_event;
    if (caller_event) SetEvent((HANDLE)caller_event);
}
static int s_post(void *o, uint32_t port, uint32_t bytes, uintptr_t key, void *ov, uint32_t *error)
{
    BOOL ok;
    (void)o;
    ok = ShizukuLc_PostQueuedCompletionStatus((HANDLE)(uintptr_t)port, bytes, key, (LPOVERLAPPED)ov);
    if (!ok) *error = GetLastError();
    return ok != 0;
}

static LONG sock_ready;

int lc_sock_native_attach(HINSTANCE instance)
{
    static const lc_sock_ops ops = { NULL, s_enter, s_leave, s_event_create, s_event_reset, s_event_set,
                                     s_event_close, s_wait_any, s_thread_start, s_thread_exit,
                                     s_io_result, s_connect_result, s_finish, s_post };
    self_module = instance;
    if (!GetModuleFileNameA(instance, self_path, sizeof self_path)) return 0;
    InitializeCriticalSection(&sock_lock);
    if (!lc_sock_init(&sock_context, &ops)) return 0;
    sock_ready = 1;
    return 1;
}

/* FreeLibrary path only: the worker pins the module, so reaching here means
 * no worker runs; associations would mean the caller leaked sockets. */
void lc_sock_native_detach(void)
{
    sock_ready = 0;
    if (lc_sock_release(&sock_context)) DeleteCriticalSection(&sock_lock);
}

/* Called by ShizukuLc_CreateIoCompletionPort for an existing, validated port. */
DWORD lc_sock_native_associate(HANDLE file, uint32_t port, ULONG_PTR key)
{
    int type = 0, len = sizeof type;
    uint32_t error = 0;
    if (!sock_ready) return ERROR_DLL_INIT_FAILED;
    if (getsockopt((SOCKET)file, SOL_SOCKET, SO_TYPE, (char *)&type, &len) == SOCKET_ERROR)
        return ERROR_NOT_SUPPORTED; /* not a socket: Win98 has no other completion source */
    if (!lc_sock_associate(&sock_context, port, (uintptr_t)file, key, &error)) return error;
    return 0;
}

static int arm(SOCKET s, LPWSAOVERLAPPED ov, unsigned kind, uint32_t *token)
{
    uintptr_t event = 0;
    uint32_t error = 0;
    int r;
    if (!sock_ready) {
        WSASetLastError(WSANOTINITIALISED);
        return LC_SOCK_FAILED;
    }
    /* NT: an event handle with bit 0 set suppresses the port completion. */
    if (!ov || ((uintptr_t)ov->hEvent & 1)) return LC_SOCK_PASSTHROUGH;
    r = lc_sock_begin(&sock_context, (uintptr_t)s, ov, (uintptr_t)ov->hEvent, kind, token, &event, &error);
    if (r == LC_SOCK_ARMED) ov->hEvent = (WSAEVENT)event;
    else if (r == LC_SOCK_FAILED) WSASetLastError(error == LC_NO_SYSTEM_RESOURCES ? WSAENOBUFS : WSAEINVAL);
    return r;
}

static int settle(int result, LPWSAOVERLAPPED ov, WSAEVENT caller_event, uint32_t token)
{
    int error;
    if (result == 0) {
        lc_sock_commit(&sock_context, token, 0); /* NT also queues immediate successes */
        return 0;
    }
    error = WSAGetLastError();
    if (error == WSA_IO_PENDING) {
        lc_sock_commit(&sock_context, token, 0);
    } else {
        ov->hEvent = caller_event;
        lc_sock_abort(&sock_context, token);
    }
    WSASetLastError(error);
    return SOCKET_ERROR;
}

int WSAAPI ShizukuLc_WSARecv(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD received, LPDWORD flags,
                             LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE routine)
{
    uint32_t token = 0;
    WSAEVENT caller = ov ? ov->hEvent : NULL;
    int r = routine ? LC_SOCK_PASSTHROUGH : arm(s, ov, LC_SOCK_IO, &token);
    if (r == LC_SOCK_FAILED) return SOCKET_ERROR;
    if (r == LC_SOCK_PASSTHROUGH) return WSARecv(s, bufs, count, received, flags, ov, routine);
    return settle(WSARecv(s, bufs, count, received, flags, ov, NULL), ov, caller, token);
}

int WSAAPI ShizukuLc_WSASend(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent, DWORD flags,
                             LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE routine)
{
    uint32_t token = 0;
    WSAEVENT caller = ov ? ov->hEvent : NULL;
    int r = routine ? LC_SOCK_PASSTHROUGH : arm(s, ov, LC_SOCK_IO, &token);
    if (r == LC_SOCK_FAILED) return SOCKET_ERROR;
    if (r == LC_SOCK_PASSTHROUGH) return WSASend(s, bufs, count, sent, flags, ov, routine);
    return settle(WSASend(s, bufs, count, sent, flags, ov, NULL), ov, caller, token);
}

int WSAAPI ShizukuLc_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD received, LPDWORD flags,
                                 struct sockaddr *from, LPINT fromlen, LPWSAOVERLAPPED ov,
                                 LPWSAOVERLAPPED_COMPLETION_ROUTINE routine)
{
    uint32_t token = 0;
    WSAEVENT caller = ov ? ov->hEvent : NULL;
    int r = routine ? LC_SOCK_PASSTHROUGH : arm(s, ov, LC_SOCK_IO, &token);
    if (r == LC_SOCK_FAILED) return SOCKET_ERROR;
    if (r == LC_SOCK_PASSTHROUGH) return WSARecvFrom(s, bufs, count, received, flags, from, fromlen, ov, routine);
    return settle(WSARecvFrom(s, bufs, count, received, flags, from, fromlen, ov, NULL), ov, caller, token);
}

int WSAAPI ShizukuLc_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD count, LPDWORD sent, DWORD flags,
                               const struct sockaddr *to, int tolen, LPWSAOVERLAPPED ov,
                               LPWSAOVERLAPPED_COMPLETION_ROUTINE routine)
{
    uint32_t token = 0;
    WSAEVENT caller = ov ? ov->hEvent : NULL;
    int r = routine ? LC_SOCK_PASSTHROUGH : arm(s, ov, LC_SOCK_IO, &token);
    if (r == LC_SOCK_FAILED) return SOCKET_ERROR;
    if (r == LC_SOCK_PASSTHROUGH) return WSASendTo(s, bufs, count, sent, flags, to, tolen, ov, routine);
    return settle(WSASendTo(s, bufs, count, sent, flags, to, tolen, ov, NULL), ov, caller, token);
}

/* LPFN_CONNECTEX contract for a bound, port-associated socket. Win98 has no
 * ConnectEx: emulated with FD_CONNECT selection + connect(). Initial send
 * data is not supported and is refused rather than dropped. */
BOOL PASCAL ShizukuLc_ConnectEx(SOCKET s, const struct sockaddr *name, int namelen, PVOID send_buffer,
                                DWORD send_length, LPDWORD sent, LPOVERLAPPED ov)
{
    uint32_t token = 0;
    WSAEVENT caller;
    int r, error;
    if (!ov || !name) {
        WSASetLastError(WSAEFAULT);
        return FALSE;
    }
    if (send_buffer || send_length) {
        WSASetLastError(WSAEOPNOTSUPP);
        return FALSE;
    }
    caller = ov->hEvent;
    r = arm(s, (LPWSAOVERLAPPED)ov, LC_SOCK_CONNECT, &token);
    if (r == LC_SOCK_FAILED) return FALSE;
    if (r == LC_SOCK_PASSTHROUGH) { /* no completion source without a port */
        WSASetLastError(WSAEOPNOTSUPP);
        return FALSE;
    }
    if (sent) *sent = 0;
    if (WSAEventSelect(s, (WSAEVENT)ov->hEvent, FD_CONNECT) == SOCKET_ERROR) {
        error = WSAGetLastError();
        goto failed;
    }
    if (connect(s, name, namelen) == 0) {
        WSAEventSelect(s, NULL, 0);
        lc_sock_commit(&sock_context, token, 1);
        WSASetLastError(WSA_IO_PENDING); /* completion is still queued, as for NT */
        return FALSE;
    }
    error = WSAGetLastError();
    if (error == WSAEWOULDBLOCK) {
        lc_sock_commit(&sock_context, token, 0);
        WSASetLastError(WSA_IO_PENDING);
        return FALSE;
    }
    WSAEventSelect(s, NULL, 0);
failed:
    ov->hEvent = caller;
    lc_sock_abort(&sock_context, token);
    WSASetLastError(error);
    return FALSE;
}

int WSAAPI ShizukuLc_closesocket(SOCKET s)
{
    uint32_t token = 0;
    int associated = sock_ready && lc_sock_close_begin(&sock_context, (uintptr_t)s, &token);
    int result = closesocket(s);
    if (associated) {
        int error = result ? WSAGetLastError() : 0;
        lc_sock_close_end(&sock_context, token, result == 0);
        if (result) WSASetLastError(error);
    }
    return result;
}
