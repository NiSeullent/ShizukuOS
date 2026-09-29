/* SPDX-License-Identifier: GPL-2.0-only
 * user32: windows hooks and WinEvent hooks, within ONE process.
 *
 * Hooks (SetWindowsHookEx): WH_GETMESSAGE, WH_KEYBOARD, WH_MOUSE (called while GetMessage/PeekMessage retrieves),
 * WH_CALLWNDPROC and WH_CALLWNDPROCRET (around SendMessage deliveries), WH_CBT (window creation/destruction, activation,
 * focus, minimise/maximise, move/size), WH_MSGFILTER / WH_SYSMSGFILTER (CallMsgFilter from modal loops). A hook set for
 * a thread runs on that thread; a hook set with thread id 0 applies to every thread of THIS process: installing code in
 * other processes (the DLL injection real Windows does for global hooks) does not exist, so they are never reached.
 * WH_KEYBOARD_LL / WH_MOUSE_LL, the journal hooks, WH_SHELL, WH_DEBUG and WH_FOREGROUNDIDLE are refused with
 * ERROR_NOT_SUPPORTED rather than accepted and never called.
 *
 * WinEvents (SetWinEventHook): events raised in this process (NotifyWinEvent, and the system events user32 raises:
 * object create/destroy/show/hide/focus/name/location change, foreground, move-size start/end) reach the hooks of this
 * process. Out-of-context hooks are called on the installing thread from its message loop (a private thread message);
 * in-context ones synchronously on the raising thread. Events of other processes are not delivered.
 */
#include "user32_int.h"

#define NHOOKS 64
typedef struct {
    int used, id;
    HOOKPROC proc;
    DWORD tid;                                  /* 0 = every thread of this process */
    unsigned gen;
    int calling;                                /* recursion guard: a hook is not re-entered by its own chain */
} hook_t;
static hook_t g_hooks[NHOOKS];
static unsigned g_hook_gen;

#define NWEV 64
typedef struct {
    int used;
    unsigned gen;
    DWORD emin, emax, pid, tid, flags, owner_tid;
    WINEVENTPROC proc;
} wev_t;
static wev_t g_wev[NWEV];
static unsigned g_wev_gen;

static CRITICAL_SECTION g_lock;
static volatile LONG g_lock_init;
static volatile LONG g_any_hook, g_any_wev;

static void lock(void)
{
    if (InterlockedCompareExchange(&g_lock_init, 1, 0) == 0) { InitializeCriticalSection(&g_lock); g_lock_init = 2; }
    while (g_lock_init != 2) Sleep(0);
    EnterCriticalSection(&g_lock);
}
static void unlock(void) { LeaveCriticalSection(&g_lock); }

static HHOOK hook_handle(int i) { return (HHOOK)(uintptr_t)(((uintptr_t)g_hooks[i].gen << 8) | 0x4000000u | (unsigned)i); }
static int hook_index(HHOOK h)
{
    const uintptr_t v = (uintptr_t)h;
    const int i = (int)(v & 0xff);
    if (!(v & 0x4000000u) || i >= NHOOKS || !g_hooks[i].used || hook_handle(i) != h) return -1;
    return i;
}

int u32_hook_count(void)
{
    int i, n = 0;
    for (i = 0; i < NHOOKS; ++i) n += g_hooks[i].used;
    for (i = 0; i < NWEV; ++i) n += g_wev[i].used;
    return n;
}

DLLAPI HHOOK WINAPI SetWindowsHookExW(int id, HOOKPROC proc, HINSTANCE mod, DWORD tid)
{
    int i;
    HHOOK h = 0;
    (void)mod;
    if (!proc) { SetLastError(ERROR_INVALID_FILTER_PROC); return 0; }
    switch (id) {
    case WH_GETMESSAGE: case WH_KEYBOARD: case WH_MOUSE: case WH_CALLWNDPROC: case WH_CALLWNDPROCRET: case WH_CBT:
    case WH_MSGFILTER: case WH_SYSMSGFILTER:
        break;
    case WH_KEYBOARD_LL: case WH_MOUSE_LL: case WH_JOURNALRECORD: case WH_JOURNALPLAYBACK: case WH_SHELL: case WH_DEBUG:
    case WH_FOREGROUNDIDLE:
        SetLastError(ERROR_NOT_SUPPORTED);
        return 0;
    default:
        SetLastError(ERROR_INVALID_HOOK_FILTER);
        return 0;
    }
    lock();
    for (i = 0; i < NHOOKS; ++i)
        if (!g_hooks[i].used) {
            g_hooks[i].used = 1; g_hooks[i].id = id; g_hooks[i].proc = proc; g_hooks[i].tid = tid; g_hooks[i].calling = 0;
            g_hooks[i].gen = (++g_hook_gen) & 0xffff;
            h = hook_handle(i);
            InterlockedIncrement(&g_any_hook);
            break;
        }
    unlock();
    if (!h) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return h;
}

DLLAPI HHOOK WINAPI SetWindowsHookExA(int id, HOOKPROC proc, HINSTANCE mod, DWORD tid) { return SetWindowsHookExW(id, proc, mod, tid); }
DLLAPI HHOOK WINAPI SetWindowsHookW(int id, HOOKPROC proc) { return SetWindowsHookExW(id, proc, 0, GetCurrentThreadId()); }

DLLAPI BOOL WINAPI UnhookWindowsHookEx(HHOOK h)
{
    int i;
    lock();
    i = hook_index(h);
    if (i >= 0) { g_hooks[i].used = 0; InterlockedDecrement(&g_any_hook); }
    unlock();
    if (i < 0) { SetLastError(ERROR_INVALID_HOOK_HANDLE); return FALSE; }
    return TRUE;
}

/* The chain for (id, this thread), newest first: the index of the first applicable hook after position `after` (-1: start). */
static int next_hook(int id, int after_slot, unsigned after_gen)
{
    const DWORD me = GetCurrentThreadId();
    int i, best = -1;
    unsigned best_gen = 0;
    for (i = 0; i < NHOOKS; ++i) {
        const hook_t *k = &g_hooks[i];
        if (!k->used || k->id != id || (k->tid && k->tid != me) || k->calling) continue;
        if (after_slot >= 0 && k->gen >= after_gen) continue;          /* older than the current one only */
        if (best < 0 || k->gen > best_gen) { best = i; best_gen = k->gen; }
    }
    return best;
}

static LRESULT call_chain(int id, int from_slot, unsigned from_gen, int code, WPARAM wp, LPARAM lp, int *called)
{
    int i;
    HOOKPROC p;
    LRESULT r;
    lock();
    i = next_hook(id, from_slot, from_gen);
    if (i < 0) { unlock(); if (called) *called = 0; return 0; }
    p = g_hooks[i].proc;
    g_hooks[i].calling = 1;
    unlock();
    if (called) *called = 1;
    r = p(code, wp, lp);
    lock();
    if (g_hooks[i].used) g_hooks[i].calling = 0;
    unlock();
    return r;
}

DLLAPI LRESULT WINAPI CallNextHookEx(HHOOK h, int code, WPARAM wp, LPARAM lp)
{
    int i, id;
    unsigned gen;
    lock();
    i = hook_index(h);
    id = i >= 0 ? g_hooks[i].id : 0;
    gen = i >= 0 ? g_hooks[i].gen : 0;
    unlock();
    if (i < 0) return 0;
    return call_chain(id, i, gen, code, wp, lp, 0);
}

static LRESULT call_hooks(int id, int code, WPARAM wp, LPARAM lp, int *called)
{
    if (!g_any_hook) { if (called) *called = 0; return 0; }
    return call_chain(id, -1, 0, code, wp, lp, called);
}

/* retrieval (user32_core.c): WH_GETMESSAGE may change the message; WH_KEYBOARD / WH_MOUSE may discard it */
int u32_call_msg_hooks(MSG *m, int remove)
{
    int called;
    if (!g_any_hook) return 0;
    if (m->message >= WM_KEYFIRST && m->message <= WM_KEYLAST && (m->message == WM_KEYDOWN || m->message == WM_KEYUP || m->message == WM_SYSKEYDOWN || m->message == WM_SYSKEYUP)) {
        if (call_hooks(WH_KEYBOARD, remove ? HC_ACTION : HC_NOREMOVE, m->wParam, m->lParam, &called) && called) return 1;
    } else if ((m->message >= WM_MOUSEFIRST && m->message <= WM_MOUSELAST) || (m->message >= WM_NCMOUSEMOVE && m->message <= WM_NCXBUTTONDBLCLK)) {
        MOUSEHOOKSTRUCT mh;
        mh.pt = m->pt;
        mh.hwnd = m->hwnd;
        mh.wHitTestCode = m->message >= WM_MOUSEFIRST ? HTCLIENT : (UINT)m->wParam;
        mh.dwExtraInfo = (ULONG_PTR)GetMessageExtraInfo();
        if (call_hooks(WH_MOUSE, remove ? HC_ACTION : HC_NOREMOVE, m->message, (LPARAM)&mh, &called) && called) return 1;
    }
    call_hooks(WH_GETMESSAGE, HC_ACTION, remove ? PM_REMOVE : PM_NOREMOVE, (LPARAM)m, 0);
    return 0;
}

/* a message sent to a window procedure: WH_CALLWNDPROC before, WH_CALLWNDPROCRET after */
LRESULT u32_call_wndproc_hooked(uint64_t proc, HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    CWPSTRUCT cwp;
    CWPRETSTRUCT ret;
    LRESULT r;
    if (!g_any_hook) return u32_call(proc, hwnd, msg, wp, lp);
    cwp.lParam = lp; cwp.wParam = wp; cwp.message = msg; cwp.hwnd = hwnd;
    call_hooks(WH_CALLWNDPROC, HC_ACTION, 0, (LPARAM)&cwp, 0);
    r = u32_call(proc, hwnd, msg, wp, lp);
    ret.lResult = r; ret.lParam = lp; ret.wParam = wp; ret.message = msg; ret.hwnd = hwnd;
    call_hooks(WH_CALLWNDPROCRET, HC_ACTION, 0, (LPARAM)&ret, 0);
    return r;
}

/* WH_CBT: a nonzero result prevents the operation (for the codes where Windows allows that) */
LRESULT u32_cbt(int code, WPARAM wp, LPARAM lp)
{
    int called;
    const LRESULT r = call_hooks(WH_CBT, code, wp, lp, &called);
    return called ? r : 0;
}

DLLAPI BOOL WINAPI CallMsgFilterW(LPMSG msg, int code)
{
    int called;
    if (!msg) return FALSE;
    if (call_hooks(WH_SYSMSGFILTER, code, 0, (LPARAM)msg, &called) && called) return TRUE;
    return call_hooks(WH_MSGFILTER, code, 0, (LPARAM)msg, &called) && called;
}
DLLAPI BOOL WINAPI CallMsgFilterA(LPMSG msg, int code) { return CallMsgFilterW(msg, code); }

/* ---------------------------------------------------------------- WinEvents */
static HWINEVENTHOOK wev_handle(int i) { return (HWINEVENTHOOK)(uintptr_t)(((uintptr_t)g_wev[i].gen << 8) | 0x5000000u | (unsigned)i); }
static int wev_index(HWINEVENTHOOK h)
{
    const uintptr_t v = (uintptr_t)h;
    const int i = (int)(v & 0xff);
    if (!(v & 0x5000000u) || i >= NWEV || !g_wev[i].used || wev_handle(i) != h) return -1;
    return i;
}

DLLAPI HWINEVENTHOOK WINAPI SetWinEventHook(DWORD emin, DWORD emax, HMODULE mod, WINEVENTPROC proc, DWORD pid, DWORD tid, DWORD flags)
{
    int i;
    HWINEVENTHOOK h = 0;
    if (!proc || emin > emax || ((flags & WINEVENT_INCONTEXT) && !mod)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    lock();
    for (i = 0; i < NWEV; ++i)
        if (!g_wev[i].used) {
            wev_t *e = &g_wev[i];
            e->used = 1; e->emin = emin; e->emax = emax; e->pid = pid; e->tid = tid; e->flags = flags; e->proc = proc;
            e->owner_tid = GetCurrentThreadId();
            e->gen = (++g_wev_gen) & 0xffff;
            h = wev_handle(i);
            InterlockedIncrement(&g_any_wev);
            break;
        }
    unlock();
    if (!h) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return h;
}

DLLAPI BOOL WINAPI UnhookWinEvent(HWINEVENTHOOK h)
{
    int i;
    lock();
    i = wev_index(h);
    if (i >= 0) { g_wev[i].used = 0; InterlockedDecrement(&g_any_wev); }
    unlock();
    if (i < 0) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    return TRUE;
}

DLLAPI BOOL WINAPI IsWinEventHookInstalled(DWORD event)
{
    int i, yes = 0;
    if (!g_any_wev) return FALSE;
    lock();
    for (i = 0; i < NWEV && !yes; ++i) yes = g_wev[i].used && event >= g_wev[i].emin && event <= g_wev[i].emax;
    unlock();
    return yes;
}

typedef struct { HWINEVENTHOOK h; DWORD event; HWND hwnd; LONG obj, child; DWORD tid, time; } wevrec_t;

void u32_winevent_deliver(void *p)
{
    wevrec_t *r = p;
    WINEVENTPROC proc = 0;
    int i;
    if (!r) return;
    lock();
    i = wev_index(r->h);
    if (i >= 0) proc = g_wev[i].proc;
    unlock();
    if (proc) proc(r->h, r->event, r->hwnd, r->obj, r->child, r->tid, r->time);
    HeapFree(GetProcessHeap(), 0, r);
}

DLLAPI VOID WINAPI NotifyWinEvent(DWORD event, HWND hwnd, LONG obj, LONG child)
{
    const DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId(), now = GetTickCount();
    int i;
    if (!g_any_wev) return;
    for (i = 0; i < NWEV; ++i) {
        wev_t e;
        HWINEVENTHOOK h;
        lock();
        e = g_wev[i];
        h = e.used ? wev_handle(i) : 0;
        unlock();
        if (!e.used || event < e.emin || event > e.emax) continue;
        if ((e.pid && e.pid != pid) || (e.tid && e.tid != me)) continue;
        if ((e.flags & WINEVENT_SKIPOWNPROCESS) || ((e.flags & WINEVENT_SKIPOWNTHREAD) && e.owner_tid == me)) continue;
        if (e.flags & WINEVENT_INCONTEXT) { e.proc(h, event, hwnd, obj, child, me, now); continue; }
        {
            wevrec_t *r = HeapAlloc(GetProcessHeap(), 0, sizeof *r);
            if (!r) continue;
            r->h = h; r->event = event; r->hwnd = hwnd; r->obj = obj; r->child = child; r->tid = me; r->time = now;
            if (!PostThreadMessageW(e.owner_tid, SHZ_WM_WINEVENT, (WPARAM)r, 0)) HeapFree(GetProcessHeap(), 0, r);
        }
    }
}

void u32_winevent(DWORD event, HWND hwnd, LONG obj, LONG child) { if (g_any_wev) NotifyWinEvent(event, hwnd, obj, child); }
