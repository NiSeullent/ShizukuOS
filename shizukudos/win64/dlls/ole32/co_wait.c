/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine local object/APC waits and existing STA message dispatch.
 * There is no COM RPC call window, proxy/stub transport or ASTA provider here.
 * See README-co-wait.md for explicit queue/WAITALL boundaries. This original
 * implementation follows Microsoft contracts and pinned Wine wait behavior;
 * no upstream implementation body is copied. */
#ifdef SHZ_COWAIT_HOST_TEST
#include "../../tests/cowait_host_contract.h"
#else
#include "ole32_int.h"
#include <dde.h>
#endif

static HRESULT wait_result(DWORD result, ULONG count, DWORD flags, DWORD *index)
{
    if ((result < count) || (result >= WAIT_ABANDONED_0 && result - WAIT_ABANDONED_0 < count)
        || (result == WAIT_IO_COMPLETION && (flags & COWAIT_ALERTABLE))) {
        *index = result;
        return S_OK;
    }
    if (result == WAIT_TIMEOUT) return RPC_S_CALLPENDING;
    if (result == WAIT_FAILED) {
        DWORD error = GetLastError();
        return error ? HRESULT_FROM_WIN32(error) : E_FAIL;
    }
    return E_FAIL;
}

static BOOL dispatch_one(MSG *message, DWORD flags)
{
    if (flags & COWAIT_DISPATCH_WINDOW_MESSAGES)
        return PeekMessageW(message, NULL, 0, 0, PM_REMOVE | PM_NOYIELD);
    /* The actual runtime services pending sent-message callbacks before it
     * returns a matching queued message. Arbitrary posted app/input messages
     * stay queued in this default STA mode. No COM RPC message is invented. */
    /* The current real queue applies WM ranges even to quit, so preserve it
     * through a dedicated matching peek before the special-message ranges. */
    return PeekMessageW(message, NULL, WM_QUIT, WM_QUIT, PM_REMOVE | PM_NOYIELD)
        || PeekMessageW(message, NULL, WM_DDE_FIRST, WM_DDE_LAST, PM_REMOVE | PM_NOYIELD)
        || PeekMessageW(message, NULL, 0, 0, PM_QS_PAINT | PM_QS_SENDMESSAGE | PM_REMOVE | PM_NOYIELD);
}

DLLAPI HRESULT WINAPI CoWaitForMultipleHandles(DWORD flags, DWORD timeout, ULONG count,
                                              HANDLE *handles, DWORD *index)
{
    const DWORD known = COWAIT_WAITALL | COWAIT_ALERTABLE | COWAIT_INPUTAVAILABLE
        | COWAIT_DISPATCH_CALLS | COWAIT_DISPATCH_WINDOW_MESSAGES;
    APTTYPE apartment;
    APTTYPEQUALIFIER qualifier;
    BOOL sta, repost_quit = FALSE;
    WPARAM quit_code = 0;
    ULONGLONG start;
    HRESULT status;
    DWORD result;
    HANDLE own[MAXIMUM_WAIT_OBJECTS];
    ULONG i;
    if (!index) return E_INVALIDARG;
    *index = 0;
    if (!handles || (flags & ~known)) return E_INVALIDARG;
    if (!count) return RPC_E_NO_SYNC;
    if (count > MAXIMUM_WAIT_OBJECTS) return E_INVALIDARG;
    /* The queue currently tracks pending level, not seen-input generations.
     * Do not claim the exact INPUTAVAILABLE distinction through this API. */
    if (flags & COWAIT_INPUTAVAILABLE) return E_NOTIMPL;
    for (i = 0; i < count; ++i) own[i] = handles[i];
    sta = CoGetApartmentType(&apartment, &qualifier) == S_OK
        && (apartment == APTTYPE_STA || apartment == APTTYPE_MAINSTA);
    if (!sta)
        return wait_result(WaitForMultipleObjectsEx(count, own, !!(flags & COWAIT_WAITALL),
                           timeout, !!(flags & COWAIT_ALERTABLE)), count, flags, index);
    /* STA WAITALL also requires matching queue input; the current user32
     * queue-event backend cannot enforce that atomically for a chosen mask. */
    if ((flags & COWAIT_WAITALL) || count > MAXIMUM_WAIT_OBJECTS - 1) return E_NOTIMPL;
    start = GetTickCount64();
    for (;;) {
        ULONGLONG elapsed;
        DWORD remaining, mode = flags & COWAIT_ALERTABLE ? MWMO_ALERTABLE : 0;
        DWORD queue = flags & COWAIT_DISPATCH_WINDOW_MESSAGES ? QS_ALLINPUT
            : QS_SENDMESSAGE | QS_POSTMESSAGE | QS_ALLPOSTMESSAGE | QS_PAINT;
        /* Bound message storms and check actual object/APC completion first. */
        result = WaitForMultipleObjectsEx(count, own, FALSE, 0, !!(flags & COWAIT_ALERTABLE));
        if (result != WAIT_TIMEOUT) { status = wait_result(result, count, flags, index); break; }
        elapsed = GetTickCount64() - start;
        remaining = timeout == INFINITE ? INFINITE : elapsed >= timeout ? 0 : timeout - (DWORD)elapsed;
        result = MsgWaitForMultipleObjectsEx(count, own, remaining, queue, mode);
        if (result != WAIT_OBJECT_0 + count) { status = wait_result(result, count, flags, index); break; }
        {
            IMessageFilter *filter = shz_message_filter_snapshot();
            DWORD decision = PENDINGMSG_WAITDEFPROCESS;
            unsigned processed = 0;
            MSG message;
            if (filter) {
                elapsed = GetTickCount64() - start;
                decision = IMessageFilter_MessagePending(filter, 0,
                    elapsed > MAXDWORD ? MAXDWORD : (DWORD)elapsed, PENDINGTYPE_TOPLEVEL);
                IMessageFilter_Release(filter);
            }
            if (decision == PENDINGMSG_CANCELCALL) { status = RPC_E_CALL_CANCELED; break; }
            if (decision != PENDINGMSG_WAITNOPROCESS) {
                while (processed < 100 && dispatch_one(&message, flags)) {
                    ++processed;
                    if (message.message == WM_QUIT) { repost_quit = TRUE; quit_code = message.wParam; }
                    else { TranslateMessage(&message); DispatchMessageW(&message); }
                }
            }
            /* A non-dispatched posted message leaves a level-triggered queue
             * event set. Yield briefly instead of spinning; the next loop
             * checks the real handles/deadline and does not consume it. */
            if (!processed) Sleep(1);
        }
        if (timeout != INFINITE && GetTickCount64() - start >= timeout) {
            /* A dispatched message may itself have signaled the real object.
             * Observe that completion once before reporting the deadline. */
            result = WaitForMultipleObjectsEx(count, own, FALSE, 0, !!(flags & COWAIT_ALERTABLE));
            status = wait_result(result, count, flags, index);
            break;
        }
    }
    if (repost_quit) PostQuitMessage((int)quit_code);
    return status;
}
