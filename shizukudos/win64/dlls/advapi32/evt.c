/* SPDX-License-Identifier: GPL-2.0-only
 * advapi32.dll: Event Tracing for Windows, provider side (EventRegister, EventUnregister, EventWrite, EventWriteTransfer,
 * EventSetInformation) and the classic (pre-Vista, "MOF") provider API: RegisterTraceGuidsW/A, UnregisterTraceGuids,
 * GetTraceLoggerHandle, GetTraceEnableFlags, GetTraceEnableLevel, TraceEvent.
 *
 * This system has no trace sessions: the controller APIs (StartTrace, EnableTraceEx2, ...) do not exist, so no provider can
 * ever be enabled. The functions below keep a real registration table (a provider is registered until it is unregistered,
 * handles are validated, unregistering twice fails) and behave exactly as ETW does for a provider nobody is listening to:
 * events are discarded and the calls succeed. The enable callback is never invoked, because nothing can enable a provider;
 * EventEnabled-style queries would answer "no". Nothing is buffered or logged anywhere.
 * Classic providers are registered in the same table; their WMIDPREQUEST callback is never called (nothing can enable
 * them), so no logger (session) handle ever exists: GetTraceLoggerHandle, GetTraceEnableFlags/Level and TraceEvent answer
 * ERROR_INVALID_HANDLE, which is what they answer on Windows for a handle that does not name a session.
 */
#define _ADVAPI32_
#include "nt.h"
#include <string.h>
#define EVNTAPI __stdcall
#define WMIAPI __stdcall
#include <evntprov.h>
#include <wmistr.h>
#include <evntrace.h>

typedef struct provider {
    struct provider *next;
    GUID id;
    PENABLECALLBACK callback;
    PVOID context;
} provider_t;

static provider_t *volatile g_providers;
static volatile LONG g_lock;

static void lock(void) { while (__sync_lock_test_and_set(&g_lock, 1)) NtYieldExecution(); }
static void unlock(void) { __sync_lock_release(&g_lock); }

/* Registered handles are the addresses of the table entries; a handle is valid only while its entry is listed. */
static BOOL registered(REGHANDLE h)
{
    provider_t *p;
    for (p = g_providers; p; p = p->next)
        if ((REGHANDLE)(ULONG_PTR)p == h) return TRUE;
    return FALSE;
}

DLLAPI ULONG EVNTAPI EventRegister(LPCGUID ProviderId, PENABLECALLBACK EnableCallback, PVOID CallbackContext, PREGHANDLE RegHandle)
{
    provider_t *p;
    if (!ProviderId || !RegHandle) return ERROR_INVALID_PARAMETER;
    p = RtlAllocateHeap(ShzProcessHeap(), 0, sizeof *p);
    if (!p) return ERROR_NOT_ENOUGH_MEMORY;
    p->id = *ProviderId;
    p->callback = EnableCallback;
    p->context = CallbackContext;
    lock();
    p->next = g_providers;
    g_providers = p;
    unlock();
    *RegHandle = (REGHANDLE)(ULONG_PTR)p;
    return ERROR_SUCCESS;
}

DLLAPI ULONG EVNTAPI EventUnregister(REGHANDLE RegHandle)
{
    provider_t **pp, *p = 0;
    lock();
    for (pp = (provider_t **)&g_providers; *pp; pp = &(*pp)->next)
        if ((REGHANDLE)(ULONG_PTR)*pp == RegHandle) { p = *pp; *pp = p->next; break; }
    unlock();
    if (!p) return ERROR_INVALID_HANDLE;
    RtlFreeHeap(ShzProcessHeap(), 0, p);
    return ERROR_SUCCESS;
}

DLLAPI ULONG EVNTAPI EventWriteTransfer(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, LPCGUID ActivityId, LPCGUID RelatedActivityId,
                                        ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData)
{
    BOOL ok;
    (void)ActivityId; (void)RelatedActivityId;
    if (!EventDescriptor) return ERROR_INVALID_PARAMETER;
    lock();
    ok = registered(RegHandle);
    unlock();
    if (!ok) return ERROR_INVALID_HANDLE;
    if (UserDataCount > MAX_EVENT_DATA_DESCRIPTORS || (UserDataCount && !UserData)) return ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;                                   /* no session is listening: the event is dropped */
}

DLLAPI ULONG EVNTAPI EventWrite(REGHANDLE RegHandle, PCEVENT_DESCRIPTOR EventDescriptor, ULONG UserDataCount, PEVENT_DATA_DESCRIPTOR UserData)
{
    return EventWriteTransfer(RegHandle, EventDescriptor, 0, 0, UserDataCount, UserData);
}

DLLAPI ULONG EVNTAPI EventSetInformation(REGHANDLE RegHandle, EVENT_INFO_CLASS InformationClass, PVOID EventInformation, ULONG InformationLength)
{
    BOOL ok;
    lock();
    ok = registered(RegHandle);
    unlock();
    if (!ok) return ERROR_INVALID_HANDLE;
    /* Provider metadata is only ever read by a trace session; with none, accepting a well-formed request has no effect. */
    switch ((int)InformationClass) {
    case 0:                                                 /* EventProviderBinaryTrackInfo */
    case 3:                                                 /* EventProviderUseDescriptorType */
        return ERROR_SUCCESS;
    case 2:                                                 /* EventProviderSetTraits: the blob starts with its own USHORT size */
        if (!EventInformation || InformationLength < 2 || *(const USHORT *)EventInformation != InformationLength) return ERROR_INVALID_PARAMETER;
        return ERROR_SUCCESS;
    default:
        return ERROR_INVALID_PARAMETER;
    }
}

/* ---------------------------------------------------------------- classic trace providers */
DLLAPI ULONG WMIAPI RegisterTraceGuidsW(WMIDPREQUEST RequestAddress, PVOID RequestContext, LPCGUID ControlGuid, ULONG GuidCount,
                                        PTRACE_GUID_REGISTRATION TraceGuidReg, LPCWSTR MofImagePath, LPCWSTR MofResourceName,
                                        PTRACEHANDLE RegistrationHandle)
{
    REGHANDLE h = 0;
    ULONG st, i;
    (void)RequestContext; (void)MofImagePath; (void)MofResourceName;   /* the MOF resource only serves event decoding */
    if (!RequestAddress || !ControlGuid || !RegistrationHandle || (GuidCount && !TraceGuidReg)) return ERROR_INVALID_PARAMETER;
    for (i = 0; i < GuidCount; ++i) if (!TraceGuidReg[i].Guid) return ERROR_INVALID_PARAMETER;
    st = EventRegister(ControlGuid, 0, 0, &h);
    if (st) return st;
    for (i = 0; i < GuidCount; ++i) TraceGuidReg[i].RegHandle = (HANDLE)(ULONG_PTR)h;  /* per-class handles: the registration */
    *RegistrationHandle = (TRACEHANDLE)h;
    return ERROR_SUCCESS;
}

DLLAPI ULONG WMIAPI RegisterTraceGuidsA(WMIDPREQUEST RequestAddress, PVOID RequestContext, LPCGUID ControlGuid, ULONG GuidCount,
                                        PTRACE_GUID_REGISTRATION TraceGuidReg, LPCSTR MofImagePath, LPCSTR MofResourceName,
                                        PTRACEHANDLE RegistrationHandle)
{
    (void)MofImagePath; (void)MofResourceName;
    return RegisterTraceGuidsW(RequestAddress, RequestContext, ControlGuid, GuidCount, TraceGuidReg, 0, 0, RegistrationHandle);
}

DLLAPI ULONG WMIAPI UnregisterTraceGuids(TRACEHANDLE RegistrationHandle)
{
    const ULONG st = EventUnregister((REGHANDLE)RegistrationHandle);
    return st == ERROR_INVALID_HANDLE ? ERROR_INVALID_PARAMETER : st;   /* documented error for an unknown registration */
}

DLLAPI TRACEHANDLE WMIAPI GetTraceLoggerHandle(PVOID Buffer)
{
    (void)Buffer;                             /* only an enable request's WNODE_HEADER carries a logger handle: none exists */
    shz_set_last_error(ERROR_INVALID_HANDLE);
    return (TRACEHANDLE)(ULONG_PTR)INVALID_HANDLE_VALUE;
}

DLLAPI ULONG WMIAPI GetTraceEnableFlags(TRACEHANDLE TraceHandle)
{
    (void)TraceHandle;
    shz_set_last_error(ERROR_INVALID_HANDLE);
    return 0;
}

DLLAPI UCHAR WMIAPI GetTraceEnableLevel(TRACEHANDLE TraceHandle)
{
    (void)TraceHandle;
    shz_set_last_error(ERROR_INVALID_HANDLE);
    return 0;
}

DLLAPI ULONG WMIAPI TraceEvent(TRACEHANDLE TraceHandle, PEVENT_TRACE_HEADER EventTrace)
{
    (void)TraceHandle;
    if (!EventTrace) return ERROR_INVALID_PARAMETER;
    return ERROR_INVALID_HANDLE;              /* no session handle can exist (see above) */
}
